//! Veil symmetric encryption -- AES-256-GCM with HKDF key derivation.
//!
//! This module provides authenticated symmetric encryption for data at rest.
//! A single 32-byte master key is loaded once at startup; per-context keys
//! are derived locally via HKDF and all encryption runs in-process, so
//! there are no network round-trips on the encrypt/decrypt path.
//!
//! # Architecture
//!
//! ```text
//!  +-------------------+
//!  |  Secret store     |   (caller-provided; any secure backend)
//!  |  master key (32B) |
//!  +--------+----------+
//!           |
//!           | fetched once at startup
//!           v
//!  +--------+----------+
//!  |  HKDF-SHA256      |   salt  = "veil-symmetric-v1"
//!  |  key derivation   |   info  = context bytes
//!  +--------+----------+     e.g. "cw-{user_id}-{conversation_id}"
//!           |
//!           | one derived key per context
//!           v
//!  +--------+----------+
//!  |  AES-256-GCM      |   random 12-byte nonce per encryption
//!  |  encrypt/decrypt  |   aad = context bytes (double-binding)
//!  +--------+----------+
//!           |
//!           v
//!  SymmetricEnvelope { version, nonce, ciphertext, aad, key_version }
//! ```
//!
//! # Security Properties
//!
//! - **HKDF context binding**: Each unique context string (e.g. per-user,
//!   per-conversation) produces a cryptographically independent derived key.
//!   Compromising one context key reveals nothing about other contexts.
//! - **GCM AAD double-binding**: The context is passed as Additional
//!   Authenticated Data (AAD) to AES-GCM, so even if an attacker swaps
//!   envelopes between contexts, authentication fails.
//! - **Key version rotation**: The optional `key_version` field on
//!   [`SymmetricEnvelope`] supports seamless master key rotation. Encrypt
//!   new data with the latest version; decrypt old data by selecting the
//!   matching master key version.
//! - **Nonce safety**: Every encryption generates a fresh 12-byte random
//!   nonce via the OS CSPRNG. Nonce reuse would break GCM confidentiality,
//!   so the nonce is never user-supplied.
//! - **ZeroizeOnDrop**: [`SymmetricKey`] implements `ZeroizeOnDrop`, so key
//!   material is scrubbed from memory when the key goes out of scope.
//!
//! # Example
//!
//! ```rust
//! use veil_core::symmetric::SymmetricKey;
//! use veil_core::cipher;
//!
//! // Master key loaded once at startup from your secret store
//! // (generated here for the doc-test).
//! let master = cipher::generate_key();
//!
//! // Derive a per-conversation key.
//! let context = b"cw-user42-conv7";
//! let key = SymmetricKey::derive(&master, context).unwrap();
//!
//! // Encrypt a message (context used as AAD for double-binding).
//! let envelope = key.encrypt(b"sensitive prompt", context).unwrap();
//!
//! // Serialize for storage or network transport.
//! let json = envelope.to_json().unwrap();
//!
//! // Later: deserialize and decrypt.
//! let loaded = veil_core::symmetric::SymmetricEnvelope::from_json(&json).unwrap();
//! let plaintext = key.decrypt(&loaded).unwrap();
//! assert_eq!(plaintext, b"sensitive prompt");
//! ```

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cipher;
use crate::error::{VeilError, VeilResult};

const SYMMETRIC_SALT: &[u8] = b"veil-symmetric-v1";
const SYMMETRIC_VERSION: u8 = 1;

/// A 256-bit AES-256-GCM symmetric encryption key.
///
/// Use this type when you need authenticated encryption for data at rest
/// (e.g. storing LLM prompts/responses in a database) rather than the
/// asymmetric session-based encryption used for data in transit.
///
/// # Security Properties
///
/// - Key material is exactly 256 bits (32 bytes).
/// - Implements [`ZeroizeOnDrop`], so the key bytes are scrubbed from
///   memory when the value is dropped. This limits the window during
///   which key material is accessible in process memory.
/// - Keys can be generated randomly ([`generate`](Self::generate)) or
///   derived deterministically from a master key via HKDF-SHA256
///   ([`derive`](Self::derive)).
///
/// # When to Use
///
/// | Scenario | Method |
/// |----------|--------|
/// | Standalone encryption (no master key) | [`SymmetricKey::generate`] |
/// | Per-context keys from a shared master key | [`SymmetricKey::derive`] |
/// | Restoring a key from config/env | [`SymmetricKey::from_base64`] |
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    key: [u8; 32],
}

impl SymmetricKey {
    /// Create a key from raw 32 bytes.
    ///
    /// # Arguments
    /// * `bytes` - Exactly 32 bytes of key material.
    ///
    /// # Example
    /// ```rust
    /// use veil_core::symmetric::SymmetricKey;
    /// let raw = [0xABu8; 32];
    /// let key = SymmetricKey::from_bytes(raw);
    /// assert_eq!(key.as_bytes(), &raw);
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Create a key from a base64-encoded string.
    ///
    /// # Arguments
    /// * `b64` - Standard base64 encoding of exactly 32 bytes.
    ///
    /// # Errors
    /// Returns [`VeilError::InvalidInput`] if the string is not valid base64
    /// or decodes to a length other than 32 bytes.
    ///
    /// # Example
    /// ```rust
    /// use veil_core::symmetric::SymmetricKey;
    /// let key = SymmetricKey::generate();
    /// let b64 = key.to_base64();
    /// let restored = SymmetricKey::from_base64(&b64).unwrap();
    /// assert_eq!(restored.as_bytes(), key.as_bytes());
    /// ```
    pub fn from_base64(b64: &str) -> VeilResult<Self> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let bytes = B64
            .decode(b64)
            .map_err(|e| VeilError::InvalidInput(format!("invalid base64: {e}")))?;
        if bytes.len() != 32 {
            return Err(VeilError::InvalidInput(format!(
                "key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self { key })
    }

    /// Generate a random 256-bit key using the OS CSPRNG.
    ///
    /// # Returns
    /// A fresh [`SymmetricKey`] suitable for direct use or as a master key.
    ///
    /// # Example
    /// ```rust
    /// use veil_core::symmetric::SymmetricKey;
    /// let k1 = SymmetricKey::generate();
    /// let k2 = SymmetricKey::generate();
    /// assert_ne!(k1.as_bytes(), k2.as_bytes()); // unique with overwhelming probability
    /// ```
    pub fn generate() -> Self {
        Self {
            key: cipher::generate_key(),
        }
    }

    /// Derive a context-specific key from a master key via HKDF-SHA256.
    ///
    /// The derivation uses a fixed salt (`"veil-symmetric-v1"`) and the
    /// caller-supplied `context` as the HKDF `info` parameter. This means
    /// the same `(master, context)` pair always produces the same derived
    /// key, but different contexts yield cryptographically independent keys.
    ///
    /// # Arguments
    /// * `master` - The 32-byte master key (loaded from your secret store).
    /// * `context` - Binding context bytes, e.g. `b"cw-user123-conv456"`.
    ///
    /// # Returns
    /// A deterministic [`SymmetricKey`] unique to the given master+context.
    ///
    /// # Errors
    /// Returns [`VeilError::KeyDerivation`] if HKDF expansion fails (should
    /// not happen with valid inputs).
    ///
    /// # Example
    /// ```rust
    /// use veil_core::symmetric::SymmetricKey;
    /// use veil_core::cipher;
    /// let master = cipher::generate_key();
    /// let key = SymmetricKey::derive(&master, b"cw-user1-conv42").unwrap();
    /// // Same inputs always produce the same key.
    /// let key2 = SymmetricKey::derive(&master, b"cw-user1-conv42").unwrap();
    /// assert_eq!(key.as_bytes(), key2.as_bytes());
    /// ```
    pub fn derive(master: &[u8], context: &[u8]) -> VeilResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(SYMMETRIC_SALT), master);
        let mut derived = [0u8; 32];
        hk.expand(context, &mut derived)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand: {e}")))?;
        Ok(Self { key: derived })
    }

    /// Export the raw key bytes.
    ///
    /// **Use with caution** -- the returned reference exposes key material.
    /// Prefer using [`encrypt`](Self::encrypt)/[`decrypt`](Self::decrypt)
    /// directly rather than extracting bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Export as base64 string.
    pub fn to_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        B64.encode(self.key)
    }

    /// Encrypt plaintext with AES-256-GCM.
    ///
    /// A fresh 12-byte nonce is generated from the OS CSPRNG for every call.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt (any length, including empty).
    /// * `aad` - Additional Authenticated Data. Typically the same context
    ///   string used for key derivation, providing double-binding: the key
    ///   is context-specific *and* the AAD authenticates the context.
    ///
    /// # Returns
    /// A [`SymmetricEnvelope`] containing the nonce, ciphertext+tag, and AAD.
    ///
    /// # Errors
    /// Returns [`VeilError::Encryption`] on AES-GCM failure.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> VeilResult<SymmetricEnvelope> {
        let (nonce, ciphertext) = cipher::encrypt(&self.key, plaintext, aad)?;
        Ok(SymmetricEnvelope {
            version: SYMMETRIC_VERSION,
            nonce,
            ciphertext,
            aad: aad.to_vec(),
            key_version: None,
        })
    }

    /// Encrypt with a key version tag for rotation support.
    ///
    /// Identical to [`encrypt`](Self::encrypt) but stamps the envelope with
    /// `key_version` so that consumers know which master key generation was
    /// used. During key rotation, encrypt new data with the latest version
    /// and keep old master keys available for decrypting historical data.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt.
    /// * `aad` - Additional Authenticated Data.
    /// * `key_version` - The master key version number (application-defined).
    ///
    /// # Returns
    /// A [`SymmetricEnvelope`] with `key_version` set to `Some(key_version)`.
    ///
    /// # Errors
    /// Returns [`VeilError::Encryption`] on AES-GCM failure.
    pub fn encrypt_versioned(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        key_version: u32,
    ) -> VeilResult<SymmetricEnvelope> {
        let (nonce, ciphertext) = cipher::encrypt(&self.key, plaintext, aad)?;
        Ok(SymmetricEnvelope {
            version: SYMMETRIC_VERSION,
            nonce,
            ciphertext,
            aad: aad.to_vec(),
            key_version: Some(key_version),
        })
    }

    /// Decrypt a [`SymmetricEnvelope`] and return the original plaintext.
    ///
    /// Validates the envelope version, then performs AES-256-GCM decryption.
    /// The envelope's stored `aad` must exactly match what was used during
    /// encryption -- any mismatch causes an authentication failure.
    ///
    /// # Arguments
    /// * `envelope` - The envelope produced by [`encrypt`](Self::encrypt)
    ///   or [`encrypt_versioned`](Self::encrypt_versioned).
    ///
    /// # Returns
    /// The original plaintext bytes.
    ///
    /// # Errors
    /// - [`VeilError::Envelope`] if the envelope version is unsupported.
    /// - [`VeilError::Decryption`] if authentication fails (wrong key,
    ///   tampered ciphertext, or mismatched AAD).
    pub fn decrypt(&self, envelope: &SymmetricEnvelope) -> VeilResult<Vec<u8>> {
        envelope.validate()?;
        cipher::decrypt(
            &self.key,
            &envelope.nonce,
            &envelope.ciphertext,
            &envelope.aad,
        )
    }
}

/// Wire format for symmetrically encrypted payloads.
///
/// This is the serializable container produced by [`SymmetricKey::encrypt`].
/// It carries everything needed to decrypt: the nonce, ciphertext (with
/// appended GCM tag), and the AAD that was authenticated. Unlike
/// [`VeilEnvelope`](crate::envelope::VeilEnvelope), it has no asymmetric
/// key exchange fields -- the decryptor is expected to already possess the
/// symmetric key.
///
/// # Wire Format
///
/// ```text
/// {
///   "version":     1,                    // protocol version (u8)
///   "nonce":       "<base64, 12 bytes>", // AES-GCM nonce
///   "ciphertext":  "<base64>",           // plaintext + 16-byte GCM tag
///   "aad":         "<base64>",           // authenticated context
///   "key_version": 2                     // optional, for key rotation
/// }
/// ```
///
/// Binary fields (`nonce`, `ciphertext`, `aad`) are base64-encoded in JSON
/// and raw bytes in MessagePack.
///
/// # Backward Compatibility
///
/// The `version` field allows future protocol changes. Currently only
/// version 1 is supported; [`validate`](Self::validate) rejects unknown
/// versions. The `key_version` field is optional and omitted from JSON
/// when `None`, so envelopes written before key rotation was introduced
/// remain valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymmetricEnvelope {
    /// Protocol version (currently 1).
    pub version: u8,

    /// AES-GCM nonce (12 bytes, base64 in JSON).
    #[serde(with = "crate::envelope::base64_bytes")]
    pub nonce: Vec<u8>,

    /// Ciphertext with GCM authentication tag appended.
    #[serde(with = "crate::envelope::base64_bytes")]
    pub ciphertext: Vec<u8>,

    /// Additional Authenticated Data.
    #[serde(with = "crate::envelope::base64_bytes")]
    pub aad: Vec<u8>,

    /// Key version for rotation support (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u32>,
}

impl SymmetricEnvelope {
    /// Validate that the envelope version is supported.
    ///
    /// # Errors
    /// Returns [`VeilError::Envelope`] if the version is not `1`.
    pub fn validate(&self) -> VeilResult<()> {
        if self.version != SYMMETRIC_VERSION {
            return Err(VeilError::Envelope(
                "unsupported symmetric envelope version".into(),
            ));
        }
        Ok(())
    }

    /// Serialize to a JSON string (binary fields become base64).
    ///
    /// # Errors
    /// Returns [`VeilError::Envelope`] if serialization fails.
    pub fn to_json(&self) -> VeilResult<String> {
        serde_json::to_string(self).map_err(|e| VeilError::Envelope(format!("json serialize: {e}")))
    }

    /// Deserialize from a JSON string and validate the version.
    ///
    /// # Errors
    /// - [`VeilError::Envelope`] if the JSON is malformed.
    /// - [`VeilError::Envelope`] if the version is unsupported.
    pub fn from_json(json: &str) -> VeilResult<Self> {
        let envelope: Self = serde_json::from_str(json)
            .map_err(|e| VeilError::Envelope(format!("json deserialize: {e}")))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize to MessagePack (compact binary format).
    ///
    /// Produces a smaller output than JSON, suitable for high-throughput
    /// storage or binary protocols.
    ///
    /// # Errors
    /// Returns [`VeilError::Envelope`] if serialization fails.
    pub fn to_msgpack(&self) -> VeilResult<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| VeilError::Envelope(format!("msgpack serialize: {e}")))
    }

    /// Deserialize from MessagePack bytes and validate the version.
    ///
    /// # Errors
    /// - [`VeilError::Envelope`] if the bytes are not valid MessagePack.
    /// - [`VeilError::Envelope`] if the version is unsupported.
    pub fn from_msgpack(data: &[u8]) -> VeilResult<Self> {
        let envelope: Self = rmp_serde::from_slice(data)
            .map_err(|e| VeilError::Envelope(format!("msgpack deserialize: {e}")))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Payload size in bytes (ciphertext including the 16-byte GCM tag).
    pub fn payload_size(&self) -> usize {
        self.ciphertext.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, symmetric encryption!";
        let aad = b"test-context";

        let envelope = key.encrypt(plaintext, aad).unwrap();
        let decrypted = key.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_derive_and_encrypt() {
        let master = cipher::generate_key();
        let context = b"cw-user123-conv456";

        // Derive key, encrypt
        let key = SymmetricKey::derive(&master, context).unwrap();
        let plaintext = b"derived key encryption test";
        let envelope = key.encrypt(plaintext, context).unwrap();

        // Derive same key again, decrypt
        let key2 = SymmetricKey::derive(&master, context).unwrap();
        let decrypted = key2.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_different_context_different_key() {
        let master = cipher::generate_key();
        let ctx_a = b"context-a";
        let ctx_b = b"context-b";

        let key_a = SymmetricKey::derive(&master, ctx_a).unwrap();
        let key_b = SymmetricKey::derive(&master, ctx_b).unwrap();

        // Keys derived from different contexts must differ
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());

        // Encrypt with key_a, try to decrypt with key_b — must fail
        let envelope = key_a.encrypt(b"secret", ctx_a).unwrap();
        let result = key_b.decrypt(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();

        let envelope = key1.encrypt(b"secret data", b"aad").unwrap();
        let result = key2.decrypt(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = SymmetricKey::generate();
        let envelope = key.encrypt(b"secret data", b"correct-aad").unwrap();

        // Tamper with the aad in the envelope
        let mut tampered = envelope.clone();
        tampered.aad = b"wrong-aad".to_vec();

        let result = key.decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = SymmetricKey::generate();
        let envelope = key.encrypt(b"secret data", b"aad").unwrap();

        let mut tampered = envelope.clone();
        if let Some(byte) = tampered.ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = key.decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_base64_roundtrip() {
        let key = SymmetricKey::generate();
        let b64 = key.to_base64();
        let restored = SymmetricKey::from_base64(&b64).unwrap();

        // Encrypt with original, decrypt with restored
        let envelope = key.encrypt(b"base64 roundtrip", b"ctx").unwrap();
        let decrypted = restored.decrypt(&envelope).unwrap();
        assert_eq!(decrypted, b"base64 roundtrip");
    }

    #[test]
    fn test_json_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"json roundtrip test";
        let aad = b"json-ctx";

        let envelope = key.encrypt(plaintext, aad).unwrap();
        let json = envelope.to_json().unwrap();
        let restored = SymmetricEnvelope::from_json(&json).unwrap();
        let decrypted = key.decrypt(&restored).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_msgpack_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"msgpack roundtrip test";
        let aad = b"msgpack-ctx";

        let envelope = key.encrypt(plaintext, aad).unwrap();
        let bytes = envelope.to_msgpack().unwrap();
        let restored = SymmetricEnvelope::from_msgpack(&bytes).unwrap();
        let decrypted = key.decrypt(&restored).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_versioned_encryption() {
        let key = SymmetricKey::generate();
        let plaintext = b"versioned payload";
        let aad = b"ver-ctx";

        let envelope = key.encrypt_versioned(plaintext, aad, 3).unwrap();
        assert_eq!(envelope.key_version, Some(3));

        let decrypted = key.decrypt(&envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_generate_random() {
        let k1 = SymmetricKey::generate();
        let k2 = SymmetricKey::generate();
        assert_ne!(k1.as_bytes(), k2.as_bytes(), "two random keys must differ");
    }

    #[test]
    fn test_zeroize_on_drop() {
        let mut key = SymmetricKey::generate();
        assert_ne!(key.as_bytes(), &[0u8; 32]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; 32], "key bytes not zeroized");
    }

    #[test]
    fn test_validate_rejects_wrong_version() {
        let key = SymmetricKey::generate();
        let mut envelope = key.encrypt(b"data", b"aad").unwrap();
        envelope.version = 99;

        let result = envelope.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported symmetric envelope version"));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = SymmetricKey::generate();
        let envelope = key.encrypt(b"", b"empty-ctx").unwrap();
        let decrypted = key.decrypt(&envelope).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let key = SymmetricKey::generate();
        let plaintext = vec![0x42u8; 1_000_000]; // 1MB
        let aad = b"large-payload";

        let envelope = key.encrypt(&plaintext, aad).unwrap();
        let decrypted = key.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
