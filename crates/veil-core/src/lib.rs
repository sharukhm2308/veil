//! # Veil Core
//!
//! End-to-end encryption library for LLM inference traffic.
//!
//! Veil provides application-layer encryption that keeps LLM prompts
//! and responses confidential from all intermediaries (API gateways,
//! proxies, load balancers, billing systems). Only the client and
//! the LLM inference engine can see plaintext.
//!
//! ## Protocol Overview
//!
//! 1. Server publishes its X25519 public key
//! 2. Client generates an ephemeral X25519 key pair
//! 3. Both sides compute ECDH shared secret
//! 4. HKDF derives directional AES-256-GCM session keys
//! 5. Client encrypts prompt → sends encrypted envelope + metadata
//! 6. Server decrypts, runs inference, encrypts response
//! 7. Client decrypts response
//!
//! Middleware sees only metadata (model, token estimate, key ID)
//! -- never the prompt or response content.
//!
//! ## Symmetric Encryption
//!
//! For data **at rest** (stored prompts, cached responses, audit logs),
//! Veil provides AES-256-GCM symmetric encryption with HKDF key
//! derivation. A single master key is used to derive per-context keys,
//! so all crypto runs in-process with no per-call round-trips to an
//! external key service.
//!
//! ```text
//! Master key (32 bytes)
//!   --> HKDF-SHA256 + context --> per-context AES-256-GCM key
//!   --> encrypt/decrypt with AAD = context (double-binding)
//! ```
//!
//! See the [`symmetric`] module for full details and examples.
//!
//! ### Symmetric Quick Start
//!
//! ```rust
//! use veil_core::symmetric::SymmetricKey;
//! use veil_core::cipher;
//!
//! // Master key (generated here for testing; in production, load from
//! // your secret store).
//! let master = cipher::generate_key();
//!
//! // Derive a key scoped to a specific conversation.
//! let ctx = b"cw-user42-conv7";
//! let key = SymmetricKey::derive(&master, ctx).unwrap();
//!
//! // Encrypt and decrypt.
//! let envelope = key.encrypt(b"sensitive data", ctx).unwrap();
//! let plaintext = key.decrypt(&envelope).unwrap();
//! assert_eq!(plaintext, b"sensitive data");
//! ```
//!
//! ## Quick Start (Asymmetric)
//!
//! ```rust
//! use veil_core::keys::StaticKeyPair;
//! use veil_core::session::{ClientSession, ServerSession};
//!
//! // Server generates identity key
//! let server_kp = StaticKeyPair::generate();
//!
//! // Client creates session
//! let mut client = ClientSession::new(
//!     &server_kp.public_base64(),
//!     "key-001",
//! ).unwrap();
//!
//! // Encrypt a prompt
//! let (envelope, metadata) = client.encrypt_request(
//!     b"{\"prompt\": \"Hello!\"}",
//!     "gpt-4",
//!     Some(10),
//! ).unwrap();
//!
//! // Server decrypts
//! let server = ServerSession::new(
//!     &server_kp,
//!     &metadata.ephemeral_key,
//!     "key-001",
//!     &metadata.request_id,
//!     &metadata.timestamp,
//! ).unwrap();
//! let plaintext = server.decrypt_request(&envelope).unwrap();
//! ```

/// AES-256-GCM authenticated encryption primitives (encrypt/decrypt, key generation).
pub mod cipher;
/// Asymmetric wire-format envelopes for encrypted requests and responses.
pub mod envelope;
/// Error types shared across all Veil modules.
pub mod error;
/// HKDF-based key derivation for asymmetric session keys.
pub mod kdf;
/// X25519 static and ephemeral key pairs for ECDH key exchange.
pub mod keys;
/// Asymmetric client/server sessions (ECDH + AES-256-GCM).
pub mod session;
/// Symmetric AES-256-GCM encryption with HKDF key derivation for data at rest.
pub mod symmetric;

// Re-export the most commonly used types at crate root.
pub use envelope::{VeilEnvelope, VeilMetadata};
pub use error::{VeilError, VeilResult};
pub use keys::{EphemeralKeyPair, PublicKeyInfo, StaticKeyPair};
pub use session::{ClientSession, Direction, ServerSession};
pub use symmetric::{SymmetricEnvelope, SymmetricKey};
