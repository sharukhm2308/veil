//! Python SDK for Veil E2E encrypted LLM inference.
//!
//! PyO3 bindings wrapping `veil-core` — all cryptographic operations
//! (X25519, HKDF-SHA256, AES-256-GCM) execute in Rust.
//!
//! # Example
//!
//! ```python
//! from veil_sdk import VeilKeyPair, VeilClientSession, VeilServerSession
//!
//! kp = VeilKeyPair.generate()
//! client = VeilClientSession(kp.public_base64(), "key-v1")
//! envelope, metadata = client.encrypt_request(b"hello", "model", 0)
//!
//! server = VeilServerSession(
//!     kp.secret_base64(),
//!     metadata.ephemeral_key,
//!     "key-v1",
//!     metadata.request_id,
//!     metadata.timestamp,
//! )
//! plaintext = server.decrypt_request(envelope)
//! assert plaintext == b"hello"
//! ```

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use veil_core::symmetric::{SymmetricEnvelope, SymmetricKey};
use veil_core::{
    ClientSession, ServerSession, StaticKeyPair, VeilEnvelope, VeilError, VeilMetadata,
};

// --------------------------------------------------------------------------
// Error conversion: VeilError → PyErr
// --------------------------------------------------------------------------

fn to_py_err(e: VeilError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

// --------------------------------------------------------------------------
// PyVeilEnvelope
// --------------------------------------------------------------------------

/// Encrypted envelope -- wire format for Veil asymmetric payloads.
///
/// Holds the output of a single ``VeilClientSession.encrypt_request()``
/// or ``VeilServerSession.encrypt_response()`` call.  Fields:
///
/// * **version** -- protocol version (currently ``1``)
/// * **nonce** -- 12-byte AES-GCM nonce (base64)
/// * **ciphertext** -- encrypted payload + 16-byte GCM tag (base64)
/// * **aad** -- additional authenticated data (base64, integrity-protected)
///
/// Example:
///     >>> envelope, meta = client.encrypt_request(b"hello", "gpt-4", 0)
///     >>> json_str = envelope.to_json()   # serialize for the wire
///     >>> restored = VeilEnvelope.from_json(json_str)
///     >>> assert restored.ciphertext == envelope.ciphertext
#[pyclass(name = "VeilEnvelope")]
#[derive(Clone)]
pub struct PyVeilEnvelope {
    pub(crate) inner: VeilEnvelope,
}

#[pymethods]
impl PyVeilEnvelope {
    /// Protocol version (currently 1).
    #[getter]
    fn version(&self) -> u8 {
        self.inner.version
    }

    /// Nonce as base64 string (12 bytes).
    #[getter]
    fn nonce(&self) -> String {
        B64.encode(&self.inner.nonce)
    }

    /// Ciphertext + GCM tag as base64 string.
    #[getter]
    fn ciphertext(&self) -> String {
        B64.encode(&self.inner.ciphertext)
    }

    /// Additional Authenticated Data as base64 string.
    #[getter]
    fn aad(&self) -> String {
        B64.encode(&self.inner.aad)
    }

    /// Serialize to a JSON string.
    ///
    /// Returns:
    ///     str: JSON with ``version``, ``nonce``, ``ciphertext``, and ``aad`` keys.
    ///
    /// Raises:
    ///     ValueError: If serialisation fails (should not happen in practice).
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(to_py_err)
    }

    /// Deserialize from a JSON string.
    ///
    /// Args:
    ///     json (str): JSON produced by ``to_json()``.
    ///
    /// Returns:
    ///     VeilEnvelope: The reconstructed envelope.
    ///
    /// Raises:
    ///     ValueError: If the JSON is malformed or missing required fields.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner = VeilEnvelope::from_json(json).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Serialize to a Python ``dict`` with base64-encoded binary fields.
    ///
    /// Returns:
    ///     dict: ``{"version": int, "nonce": str, "ciphertext": str, "aad": str}``
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.inner.version)?;
        dict.set_item("nonce", B64.encode(&self.inner.nonce))?;
        dict.set_item("ciphertext", B64.encode(&self.inner.ciphertext))?;
        dict.set_item("aad", B64.encode(&self.inner.aad))?;
        Ok(dict)
    }

    /// Deserialize from a Python ``dict`` with base64-encoded binary fields.
    ///
    /// Args:
    ///     dict: Dictionary with ``version``, ``nonce``, ``ciphertext``, ``aad`` keys.
    ///
    /// Returns:
    ///     VeilEnvelope: The reconstructed envelope.
    ///
    /// Raises:
    ///     ValueError: If a required key is missing or base64 is invalid.
    #[staticmethod]
    fn from_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let _version: u8 = dict
            .get_item("version")?
            .ok_or_else(|| PyValueError::new_err("missing 'version'"))?
            .extract()?;
        let nonce_b64: String = dict
            .get_item("nonce")?
            .ok_or_else(|| PyValueError::new_err("missing 'nonce'"))?
            .extract()?;
        let ct_b64: String = dict
            .get_item("ciphertext")?
            .ok_or_else(|| PyValueError::new_err("missing 'ciphertext'"))?
            .extract()?;
        let aad_b64: String = dict
            .get_item("aad")?
            .ok_or_else(|| PyValueError::new_err("missing 'aad'"))?
            .extract()?;

        let nonce = B64
            .decode(&nonce_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid nonce base64: {e}")))?;
        let ciphertext = B64
            .decode(&ct_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid ciphertext base64: {e}")))?;
        let aad = B64
            .decode(&aad_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid aad base64: {e}")))?;

        Ok(Self {
            inner: VeilEnvelope::new(nonce, ciphertext, aad),
        })
    }

    /// Payload size in bytes (nonce + ciphertext + aad).
    fn payload_size(&self) -> usize {
        self.inner.payload_size()
    }

    fn __repr__(&self) -> String {
        format!(
            "VeilEnvelope(version={}, payload_size={})",
            self.inner.version,
            self.inner.payload_size()
        )
    }
}

// --------------------------------------------------------------------------
// PyVeilMetadata
// --------------------------------------------------------------------------

/// Request metadata -- carried as HTTP headers alongside a ``VeilEnvelope``.
///
/// Created by ``VeilClientSession.encrypt_request()`` and consumed by
/// ``VeilServerSession`` to reconstruct the shared secret.
///
/// Attributes:
///     version (int): Protocol version.
///     key_id (str): Server key identifier (e.g. ``"shim-v1"``).
///     ephemeral_key (str): Client's ephemeral X25519 public key (base64).
///     model (str): Model or tool identifier.
///     token_estimate (int | None): Optional token-count hint.
///     timestamp (str): ISO-8601 request timestamp.
///     request_id (str): Unique request UUID.
///
/// Example:
///     >>> _, metadata = client.encrypt_request(b"hi", "gpt-4", 100)
///     >>> headers = metadata.to_headers()
///     >>> requests.post(url, headers=headers, data=envelope.to_json())
#[pyclass(name = "VeilMetadata")]
#[derive(Clone)]
pub struct PyVeilMetadata {
    pub(crate) inner: VeilMetadata,
}

#[pymethods]
impl PyVeilMetadata {
    #[getter]
    fn version(&self) -> u8 {
        self.inner.version
    }

    #[getter]
    fn key_id(&self) -> &str {
        &self.inner.key_id
    }

    #[getter]
    fn ephemeral_key(&self) -> &str {
        &self.inner.ephemeral_key
    }

    #[getter]
    fn model(&self) -> &str {
        &self.inner.model
    }

    #[getter]
    fn token_estimate(&self) -> Option<u32> {
        self.inner.token_estimate
    }

    #[getter]
    fn timestamp(&self) -> &str {
        &self.inner.timestamp
    }

    #[getter]
    fn request_id(&self) -> &str {
        &self.inner.request_id
    }

    /// Convert metadata to an HTTP headers ``dict``.
    ///
    /// Returns:
    ///     dict[str, str]: Header name/value pairs (``X-Veil-*``).
    fn to_headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let headers = self.inner.to_headers();
        let dict = PyDict::new(py);
        for (k, v) in headers {
            dict.set_item(k, v)?;
        }
        Ok(dict)
    }

    fn __repr__(&self) -> String {
        format!(
            "VeilMetadata(key_id='{}', model='{}', request_id='{}')",
            self.inner.key_id, self.inner.model, self.inner.request_id
        )
    }
}

// --------------------------------------------------------------------------
// PyClientSession
// --------------------------------------------------------------------------

/// Client-side encryption session with an ephemeral X25519 keypair.
///
/// Each session generates a fresh ephemeral key, giving forward secrecy:
/// compromise of a past session key does not reveal other sessions.
/// **Create one session per request -- do not reuse.**
///
/// Args:
///     server_public_key_b64 (str): Server's static X25519 public key (base64).
///     key_id (str): Server key identifier (e.g. ``"shim-v1"``).
///
/// Example:
///     >>> from veil_sdk import VeilClientSession, VeilKeyPair
///     >>> kp = VeilKeyPair.generate()
///     >>> client = VeilClientSession(kp.public_base64(), "key-v1")
///     >>> envelope, metadata = client.encrypt_request(b"prompt", "gpt-4", 0)
#[pyclass(name = "VeilClientSession")]
pub struct PyClientSession {
    inner: ClientSession,
}

#[pymethods]
impl PyClientSession {
    #[new]
    fn new(server_public_key_b64: &str, key_id: &str) -> PyResult<Self> {
        let inner = ClientSession::new(server_public_key_b64, key_id).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Encrypt a request payload.
    ///
    /// Args:
    ///     plaintext: Raw bytes to encrypt
    ///     model: Model/tool identifier (included in AAD)
    ///     token_estimate: Optional token count estimate
    ///
    /// Returns:
    ///     Tuple of (VeilEnvelope, VeilMetadata)
    fn encrypt_request(
        &mut self,
        plaintext: &[u8],
        model: &str,
        token_estimate: u32,
    ) -> PyResult<(PyVeilEnvelope, PyVeilMetadata)> {
        let est = if token_estimate > 0 {
            Some(token_estimate)
        } else {
            None
        };
        let (envelope, metadata) = self
            .inner
            .encrypt_request(plaintext, model, est)
            .map_err(to_py_err)?;
        Ok((
            PyVeilEnvelope { inner: envelope },
            PyVeilMetadata { inner: metadata },
        ))
    }

    /// Decrypt a response envelope.
    ///
    /// Args:
    ///     envelope: Encrypted response from the server
    ///
    /// Returns:
    ///     Decrypted bytes
    fn decrypt_response(&self, envelope: &PyVeilEnvelope) -> PyResult<Vec<u8>> {
        self.inner
            .decrypt_response(&envelope.inner)
            .map_err(to_py_err)
    }

    /// The client's ephemeral public key (base64).
    #[getter]
    fn ephemeral_public_base64(&self) -> String {
        self.inner.ephemeral_public_base64()
    }

    fn __repr__(&self) -> String {
        format!(
            "VeilClientSession(ephemeral_pub='{}')",
            &self.inner.ephemeral_public_base64()[..8]
        )
    }
}

// --------------------------------------------------------------------------
// PyServerSession
// --------------------------------------------------------------------------

/// Server-side decryption session.
///
/// Reconstructs the shared secret from the server's static private key
/// and the client's ephemeral public key (carried in ``VeilMetadata``).
///
/// Args:
///     secret_key_b64 (str): Server's static X25519 private key (base64).
///     client_ephemeral_b64 (str): Client's ephemeral public key (from metadata).
///     key_id (str): Server key identifier.
///     request_id (str): Request UUID (from metadata).
///     timestamp (str): Request timestamp ISO-8601 (from metadata).
///
/// Example:
///     >>> server = VeilServerSession(
///     ...     kp.secret_base64(),
///     ...     metadata.ephemeral_key,
///     ...     metadata.key_id,
///     ...     metadata.request_id,
///     ...     metadata.timestamp,
///     ... )
///     >>> plaintext = server.decrypt_request(envelope)
#[pyclass(name = "VeilServerSession")]
pub struct PyServerSession {
    inner: ServerSession,
}

#[pymethods]
impl PyServerSession {
    #[new]
    fn new(
        secret_key_b64: &str,
        client_ephemeral_b64: &str,
        key_id: &str,
        request_id: &str,
        timestamp: &str,
    ) -> PyResult<Self> {
        let keypair = StaticKeyPair::from_secret_base64(secret_key_b64).map_err(to_py_err)?;
        let inner = ServerSession::new(
            &keypair,
            client_ephemeral_b64,
            key_id,
            request_id,
            timestamp,
        )
        .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Decrypt a request envelope.
    ///
    /// Args:
    ///     envelope: Encrypted request from the client
    ///
    /// Returns:
    ///     Decrypted bytes
    fn decrypt_request(&self, envelope: &PyVeilEnvelope) -> PyResult<Vec<u8>> {
        self.inner
            .decrypt_request(&envelope.inner)
            .map_err(to_py_err)
    }

    /// Encrypt a response payload.
    ///
    /// Args:
    ///     plaintext: Raw bytes to encrypt
    ///
    /// Returns:
    ///     VeilEnvelope containing the encrypted response
    fn encrypt_response(&self, plaintext: &[u8]) -> PyResult<PyVeilEnvelope> {
        let envelope = self.inner.encrypt_response(plaintext).map_err(to_py_err)?;
        Ok(PyVeilEnvelope { inner: envelope })
    }

    fn __repr__(&self) -> String {
        "VeilServerSession(...)".to_string()
    }
}

// --------------------------------------------------------------------------
// PyStaticKeyPair (VeilKeyPair)
// --------------------------------------------------------------------------

/// X25519 static keypair for server identity.
///
/// Generate a new random keypair with ``VeilKeyPair.generate()`` or
/// restore an existing one from its base64 secret with
/// ``VeilKeyPair.from_secret_base64(b64)``.
///
/// Example:
///     >>> from veil_sdk import VeilKeyPair
///     >>> kp = VeilKeyPair.generate()
///     >>> kp.public_base64()   # share with clients
///     'nB3x...'
///     >>> kp.secret_base64()   # keep private on the server
///     'Yx9m...'
#[pyclass(name = "VeilKeyPair")]
pub struct PyStaticKeyPair {
    inner: StaticKeyPair,
}

#[pymethods]
impl PyStaticKeyPair {
    /// Generate a new random X25519 keypair.
    ///
    /// Returns:
    ///     VeilKeyPair: A freshly generated keypair.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: StaticKeyPair::generate(),
        }
    }

    /// Restore a keypair from a base64-encoded private key.
    ///
    /// Args:
    ///     b64 (str): Base64-encoded 32-byte X25519 secret key.
    ///
    /// Returns:
    ///     VeilKeyPair: The restored keypair (public key is derived).
    ///
    /// Raises:
    ///     ValueError: If the base64 is invalid or the key length is wrong.
    #[staticmethod]
    fn from_secret_base64(b64: &str) -> PyResult<Self> {
        let inner = StaticKeyPair::from_secret_base64(b64).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Private key as base64 string.
    fn secret_base64(&self) -> String {
        self.inner.secret_base64()
    }

    /// Public key as base64 string.
    fn public_base64(&self) -> String {
        self.inner.public_base64()
    }

    fn __repr__(&self) -> String {
        format!("VeilKeyPair(public='{}')", &self.inner.public_base64()[..8])
    }
}

// --------------------------------------------------------------------------
// PySymmetricEnvelope
// --------------------------------------------------------------------------

/// Symmetric encryption envelope -- wire format for AES-256-GCM payloads.
///
/// Holds the output of ``VeilSymmetricKey.encrypt()`` or
/// ``VeilSymmetricKey.encrypt_versioned()``.  Fields:
///
/// * **version** -- protocol version (currently ``1``)
/// * **nonce** -- 12-byte AES-GCM nonce (base64)
/// * **ciphertext** -- encrypted payload + 16-byte GCM tag (base64)
/// * **aad** -- additional authenticated data (base64)
/// * **key_version** -- optional ``u32`` for key-rotation workflows
///
/// All binary fields are base64-encoded when accessed from Python.
///
/// Example:
///     >>> envelope = key.encrypt(b"secret", b"context-aad")
///     >>> json_str = envelope.to_json()        # store or transmit
///     >>> restored = VeilSymmetricEnvelope.from_json(json_str)
///     >>> key.decrypt(restored) == b"secret"
///     True
#[pyclass(name = "VeilSymmetricEnvelope")]
#[derive(Clone)]
pub struct PySymmetricEnvelope {
    pub(crate) inner: SymmetricEnvelope,
}

#[pymethods]
impl PySymmetricEnvelope {
    /// Protocol version.
    #[getter]
    fn version(&self) -> u8 {
        self.inner.version
    }

    /// Nonce as base64 string (12 bytes).
    #[getter]
    fn nonce(&self) -> String {
        B64.encode(&self.inner.nonce)
    }

    /// Ciphertext + GCM tag as base64 string.
    #[getter]
    fn ciphertext(&self) -> String {
        B64.encode(&self.inner.ciphertext)
    }

    /// Additional Authenticated Data as base64 string.
    #[getter]
    fn aad(&self) -> String {
        B64.encode(&self.inner.aad)
    }

    /// Optional key version used to encrypt this envelope.
    #[getter]
    fn key_version(&self) -> Option<u32> {
        self.inner.key_version
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(to_py_err)
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner = SymmetricEnvelope::from_json(json).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Serialize to Python dict with base64-encoded binary fields.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.inner.version)?;
        dict.set_item("nonce", B64.encode(&self.inner.nonce))?;
        dict.set_item("ciphertext", B64.encode(&self.inner.ciphertext))?;
        dict.set_item("aad", B64.encode(&self.inner.aad))?;
        if let Some(kv) = self.inner.key_version {
            dict.set_item("key_version", kv)?;
        }
        Ok(dict)
    }

    /// Deserialize from Python dict with base64-encoded binary fields.
    #[staticmethod]
    fn from_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let _version: u8 = dict
            .get_item("version")?
            .ok_or_else(|| PyValueError::new_err("missing 'version'"))?
            .extract()?;
        let nonce_b64: String = dict
            .get_item("nonce")?
            .ok_or_else(|| PyValueError::new_err("missing 'nonce'"))?
            .extract()?;
        let ct_b64: String = dict
            .get_item("ciphertext")?
            .ok_or_else(|| PyValueError::new_err("missing 'ciphertext'"))?
            .extract()?;
        let aad_b64: String = dict
            .get_item("aad")?
            .ok_or_else(|| PyValueError::new_err("missing 'aad'"))?
            .extract()?;
        let key_version: Option<u32> = dict
            .get_item("key_version")?
            .map(|v| v.extract())
            .transpose()?;

        let nonce = B64
            .decode(&nonce_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid nonce base64: {e}")))?;
        let ciphertext = B64
            .decode(&ct_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid ciphertext base64: {e}")))?;
        let aad = B64
            .decode(&aad_b64)
            .map_err(|e| PyValueError::new_err(format!("invalid aad base64: {e}")))?;

        let envelope = SymmetricEnvelope {
            version: 1,
            nonce,
            ciphertext,
            aad,
            key_version,
        };
        Ok(Self { inner: envelope })
    }

    /// Payload size in bytes (nonce + ciphertext + aad).
    fn payload_size(&self) -> usize {
        self.inner.payload_size()
    }

    fn __repr__(&self) -> String {
        format!(
            "VeilSymmetricEnvelope(version={}, payload_size={}, key_version={:?})",
            self.inner.version,
            self.inner.payload_size(),
            self.inner.key_version
        )
    }
}

// --------------------------------------------------------------------------
// PySymmetricKey
// --------------------------------------------------------------------------

/// AES-256-GCM symmetric encryption key with HKDF key derivation.
///
/// Use for encrypting data at rest where both sides share a master key
/// (e.g. message storage). For E2E encryption between client and server,
/// use ``VeilClientSession`` / ``VeilServerSession`` instead.
///
/// Construction:
///     * ``VeilSymmetricKey.generate()`` -- random 256-bit key
///     * ``VeilSymmetricKey.from_bytes(raw)`` -- from 32 raw bytes
///     * ``VeilSymmetricKey.from_base64(b64)`` -- from base64 string
///     * ``VeilSymmetricKey.derive(master, context)`` -- HKDF-SHA256
///
/// Example:
///     >>> from veil_sdk import VeilSymmetricKey
///     >>> key = VeilSymmetricKey.generate()
///     >>> envelope = key.encrypt(b"secret message", b"context-aad")
///     >>> plaintext = key.decrypt(envelope)
///     >>> assert plaintext == b"secret message"
///
///     # Key derivation from master key:
///     >>> import os
///     >>> master = os.urandom(32)
///     >>> key = VeilSymmetricKey.derive(master, b"cw-user1-conv42")
///     >>> envelope = key.encrypt(b"hello", b"cw-user1-conv42")
#[pyclass(name = "VeilSymmetricKey")]
pub struct PySymmetricKey {
    inner: SymmetricKey,
}

#[pymethods]
impl PySymmetricKey {
    /// Create from raw 32-byte key material.
    ///
    /// Args:
    ///     raw (bytes): Exactly 32 bytes of key material.
    ///
    /// Returns:
    ///     VeilSymmetricKey
    ///
    /// Raises:
    ///     ValueError: If ``raw`` is not exactly 32 bytes.
    #[staticmethod]
    fn from_bytes(raw: &[u8]) -> PyResult<Self> {
        if raw.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "key must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        Ok(Self {
            inner: SymmetricKey::from_bytes(bytes),
        })
    }

    /// Create from a base64-encoded key string.
    ///
    /// Args:
    ///     b64 (str): Base64-encoded 32-byte key.
    ///
    /// Returns:
    ///     VeilSymmetricKey
    ///
    /// Raises:
    ///     ValueError: If the base64 is invalid or decodes to wrong length.
    #[staticmethod]
    fn from_base64(b64: &str) -> PyResult<Self> {
        let inner = SymmetricKey::from_base64(b64).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Generate a new random 256-bit key.
    ///
    /// Returns:
    ///     VeilSymmetricKey: A cryptographically random key.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: SymmetricKey::generate(),
        }
    }

    /// Derive a deterministic key from master material and context via HKDF-SHA256.
    ///
    /// Same ``(master, context)`` pair always produces the same derived key,
    /// enabling two parties that share a master secret to independently
    /// derive per-conversation keys without a key exchange.
    ///
    /// Args:
    ///     master (bytes): Master key material (at least 16 bytes recommended).
    ///     context (bytes): Context binding (e.g. ``b"cw-user1-conv42"``).
    ///
    /// Returns:
    ///     VeilSymmetricKey: The derived key.
    ///
    /// Raises:
    ///     ValueError: If derivation fails.
    #[staticmethod]
    fn derive(master: &[u8], context: &[u8]) -> PyResult<Self> {
        let inner = SymmetricKey::derive(master, context).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Encrypt plaintext with additional authenticated data.
    ///
    /// Args:
    ///     plaintext: Raw bytes to encrypt
    ///     aad: Additional authenticated data (integrity-protected, not encrypted)
    ///
    /// Returns:
    ///     VeilSymmetricEnvelope containing the encrypted payload
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> PyResult<PySymmetricEnvelope> {
        let envelope = self.inner.encrypt(plaintext, aad).map_err(to_py_err)?;
        Ok(PySymmetricEnvelope { inner: envelope })
    }

    /// Encrypt plaintext with additional authenticated data and a key version tag.
    ///
    /// Args:
    ///     plaintext: Raw bytes to encrypt
    ///     aad: Additional authenticated data
    ///     key_version: Key version identifier for rotation tracking
    ///
    /// Returns:
    ///     VeilSymmetricEnvelope with key_version set
    fn encrypt_versioned(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        key_version: u32,
    ) -> PyResult<PySymmetricEnvelope> {
        let envelope = self
            .inner
            .encrypt_versioned(plaintext, aad, key_version)
            .map_err(to_py_err)?;
        Ok(PySymmetricEnvelope { inner: envelope })
    }

    /// Decrypt a symmetric envelope.
    ///
    /// Args:
    ///     envelope: Encrypted envelope to decrypt (AAD is carried inside)
    ///
    /// Returns:
    ///     Decrypted bytes
    fn decrypt(&self, envelope: &PySymmetricEnvelope) -> PyResult<Vec<u8>> {
        self.inner.decrypt(&envelope.inner).map_err(to_py_err)
    }

    /// Export the key as a base64 string (44 characters).
    ///
    /// Returns:
    ///     str: Base64-encoded 32-byte key.
    fn to_base64(&self) -> String {
        self.inner.to_base64()
    }

    fn __repr__(&self) -> String {
        let b64 = self.inner.to_base64();
        let truncated = if b64.len() > 8 { &b64[..8] } else { &b64 };
        format!("VeilSymmetricKey('{truncated}...')")
    }
}

// --------------------------------------------------------------------------
// Module-level functions
// --------------------------------------------------------------------------

/// Generate a new X25519 keypair (convenience function).
///
/// Returns:
///     tuple[str, str]: ``(secret_key_b64, public_key_b64)``
///
/// Example:
///     >>> secret, public = generate_keypair()
#[pyfunction]
fn generate_keypair() -> (String, String) {
    let kp = StaticKeyPair::generate();
    (kp.secret_base64(), kp.public_base64())
}

/// Alias for ``generate_keypair()``.
///
/// Returns:
///     tuple[str, str]: ``(secret_key_b64, public_key_b64)``
#[pyfunction]
fn keygen() -> (String, String) {
    generate_keypair()
}

// --------------------------------------------------------------------------
// Module definition
// --------------------------------------------------------------------------

/// Veil SDK -- end-to-end encryption for LLM inference traffic.
///
/// Provides two encryption modes:
///
/// **Asymmetric (client <-> server)** -- X25519 ECDH + HKDF-SHA256 + AES-256-GCM
/// with per-request ephemeral keys for forward secrecy.
///
///     >>> from veil_sdk import VeilKeyPair, VeilClientSession, VeilServerSession
///     >>> kp = VeilKeyPair.generate()
///     >>> client = VeilClientSession(kp.public_base64(), "key-v1")
///     >>> envelope, metadata = client.encrypt_request(b"hello", "gpt-4", 0)
///     >>> server = VeilServerSession(
///     ...     kp.secret_base64(), metadata.ephemeral_key,
///     ...     metadata.key_id, metadata.request_id, metadata.timestamp)
///     >>> server.decrypt_request(envelope)
///     b'hello'
///
/// **Symmetric (data at rest)** -- AES-256-GCM with optional HKDF key derivation
/// for context-bound encryption (e.g. per-conversation message storage).
///
///     >>> from veil_sdk import VeilSymmetricKey
///     >>> key = VeilSymmetricKey.generate()
///     >>> env = key.encrypt(b"secret", b"aad-context")
///     >>> key.decrypt(env)
///     b'secret'
///
/// Crypto core implemented in Rust (``veil-core``), exposed to Python via PyO3.
#[pymodule]
fn veil_sdk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVeilEnvelope>()?;
    m.add_class::<PyVeilMetadata>()?;
    m.add_class::<PyClientSession>()?;
    m.add_class::<PyServerSession>()?;
    m.add_class::<PyStaticKeyPair>()?;
    m.add_class::<PySymmetricEnvelope>()?;
    m.add_class::<PySymmetricKey>()?;
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    Ok(())
}
