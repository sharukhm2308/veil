# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SSE streaming encryption (per-chunk encryption for streaming LLM responses)
- Key rotation protocol
- Rate limiting and connection pooling in proxy
- JavaScript/TypeScript SDK via NAPI-RS + WASM
- Go SDK via CGo FFI

## [Unreleased] — v0.1.1

### Added — Symmetric Encryption (veil-core)
- **`SymmetricKey`**: AES-256-GCM symmetric encryption with HKDF-SHA256 key derivation
  - `generate()`: create a random 256-bit master key
  - `from_bytes()` / `from_base64()`: load existing key material
  - `derive(context)`: HKDF key derivation with salt `"veil-symmetric-v1"` and
    caller-supplied context (e.g. `cw-{user_id}-{conversation_id}`)
  - `encrypt()` / `decrypt()`: AES-256-GCM with random 12-byte nonce and context as AAD
  - `encrypt_versioned()`: attach a `key_version` for master key rotation support
  - `ZeroizeOnDrop`: key material is scrubbed from memory when the key is dropped
- **`SymmetricEnvelope`**: wire format for symmetric ciphertext
  - Fields: `version`, `nonce`, `ciphertext`, `aad`, `key_version`
  - Serialization: `to_json()` / `from_json()` and `to_msgpack()` / `from_msgpack()`
- **`symmetric` module** in `veil-core` with comprehensive module-level docs, ASCII
  architecture diagram, security properties, and doc-test examples

### Added — Python SDK (`veil-python`, PyO3)
- **`VeilSymmetricKey`**: Python wrapper for symmetric key operations
  - `generate()`, `from_bytes()`, `from_base64()`, `derive()`, `encrypt()`,
    `encrypt_versioned()`, `decrypt()`, `to_base64()`
- **`VeilSymmetricEnvelope`**: Python wrapper for symmetric envelope (version, nonce,
  ciphertext, aad, key_version properties)
- **Asymmetric API**: `VeilKeyPair`, `VeilClientSession`, `VeilServerSession`,
  `VeilEnvelope`, `VeilMetadata` — full PyO3 bindings for the asymmetric path
- Comprehensive docstrings with Args/Returns/Raises/Example sections on all classes
- 56 pytest test cases across 8 test classes

### Added — Java SDK (`veil-jni` + `veil-java`, JNI)
- **`VeilSymmetricKey`**: Java wrapper (AutoCloseable, handle-based lifecycle)
  - `fromBytes()`, `fromBase64()`, `generate()`, `derive()`, `encrypt()`,
    `encryptVersioned()`, `decrypt()`, `toBase64()`, `close()`
- **`VeilSymmetricEnvelope`**: immutable Java data class with `toMap()` / `fromMap()`
- **Asymmetric API**: `VeilKeyPair`, `VeilClientSession`, `VeilServerSession`,
  `VeilEnvelope`, `VeilMetadata` — full JNI bindings for the asymmetric path
- Full Javadoc with usage examples, security notes, and thread safety documentation
- 43 JUnit test cases (22 symmetric key, 8 symmetric envelope, 13 asymmetric)

### Tests
- **Rust**: 94 tests (53 unit + 18 integration + 16 security + 7 doc)
- **Python**: 56 pytest test cases
- **Java**: 43 JUnit test cases
- Previously: 56 Rust tests
- Zero warnings, zero failures

## [Unreleased] — v0.2.0

### Security
- **Streaming chunk sequencing**: `encrypt_chunk()` / `decrypt_chunk()` API binds
  `stream_id`, `chunk_index`, and `is_final` into AES-256-GCM AAD — prevents
  chunk reordering, stream-swapping, and final-sentinel spoofing attacks
- **AAD hardening**: request_id + timestamp now cryptographically bound into
  every encryption operation, preventing cross-request ciphertext substitution
- **E2EE clarification**: README and docs updated to clearly describe
  in-process deployment (true E2EE) vs shim deployment (operator-visible)
  trust boundaries — previously overstated claims corrected per GPT-5.4 Pro audit

### Added
- `VeilMetadata`: new fields `stream_id`, `chunk_index`, `is_final_chunk`
  with typed HTTP headers `X-Veil-Stream-Id`, `X-Veil-Chunk-Index`, `X-Veil-Final-Chunk`
- `ClientSession::encrypt_chunk()`: encrypt streaming chunks with position-bound AAD
- `ServerSession::decrypt_chunk()`: decrypt streaming chunks with AAD verification
- `VeilMetadata::as_chunk()`: helper to derive chunk metadata from base metadata
- 13 new tests: 3 streaming unit, 2 streaming security, 2 streaming integration

### Tests
- Total: 56 tests (38 unit + 9 integration + 8 security + 1 doc)
- Previously: 43 tests
- Zero warnings, zero failures

---

## [0.1.0] - 2026-03-19

### Added

#### veil-core (Cryptographic Library)
- X25519 ECDH key exchange with ephemeral client keys (RFC 7748)
- HKDF-SHA256 key derivation with directional info strings (RFC 5869)
- AES-256-GCM authenticated encryption with random nonces (NIST SP 800-38D)
- `VeilEnvelope` wire format with MessagePack and JSON serialization
- `ClientSession` and `ServerSession` for complete key exchange workflows
- `StaticKeyPair` with JSON serialization for server key persistence
- `SessionKeys` with `ZeroizeOnDrop` for automatic key scrubbing
- Comprehensive error types (`VeilError`) with descriptive messages
- Protocol constants: `HKDF_SALT`, `C2S_INFO`, `S2C_INFO`, `C2S_AAD`, `S2C_AAD`

#### veil-client (HTTP Proxy)
- Transparent HTTP proxy that intercepts OpenAI-compatible API calls
- Automatic encryption of outgoing request bodies
- Automatic decryption of incoming response bodies
- Veil metadata headers (`X-Veil-Version`, `X-Veil-Key-Id`, `X-Veil-Ephemeral-Key`)
- Configurable listen address and upstream server URL

#### veil-server (Server Shim)
- Axum-based HTTP server that sits in front of LLM inference engines
- Automatic decryption of incoming encrypted requests
- Automatic encryption of outgoing responses
- Public key endpoint (`GET /v1/veil/public-key`) for key exchange
- Health check endpoint (`GET /health`)
- Configurable upstream LLM backend URL
- Structured logging with `tracing`

#### veil-cli (Command Line Tool)
- `keygen` — Generate server X25519 key pairs with JSON output
- `inspect` — Display public key from a key file
- `encrypt` / `decrypt` — Manual envelope encryption/decryption
- `test-roundtrip` — Verify encryption roundtrip with custom messages
- `proxy` — Launch the client-side encryption proxy
- `server` — Launch the server-side decryption shim

#### Testing
- 22 unit tests covering cipher, envelope, keys, KDF, and session modules
- 7 integration tests for E2E roundtrips, tamper detection, and cross-session isolation
- 6 security property tests for nonce uniqueness, ciphertext indistinguishability,
  key randomness, and key material size validation
- 1 doc test verifying library usage example
- **36 total tests**, all passing

#### Documentation
- `README.md` — Project overview, quick start, architecture, SDK roadmap
- `ARCHITECTURE.md` — Full protocol specification, cryptographic pipeline,
  envelope format, SDK FFI architecture
- `SECURITY.md` — Threat model, security properties, vulnerability reporting
- `CONTRIBUTING.md` — Conventional commits, development setup, PR process
- `CHANGELOG.md` — This file
- `PROJECT_PLAN.md` — Development roadmap with SDK phases

#### Deployment
- Docker multi-stage builds for client and server (`docker/`)
- Docker Compose for local development
- GitHub Actions CI pipeline (fmt, clippy, test, build)
- Python client example with self-test capability

#### Licensing
- Dual licensed under MIT and Apache-2.0

[Unreleased]: https://github.com/oxifederation/veil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/oxifederation/veil/releases/tag/v0.1.0
