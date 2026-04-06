# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Veil, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **aehthesham.gom@gmail.com**

You should receive a response within 48 hours. We will work with you to understand
and address the issue before any public disclosure.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Current release  |
| 0.2.x   | 🔜 Next release     |

## Security Model

### Cryptographic Primitives

#### Asymmetric Path (Session-based, Forward Secrecy)

| Component        | Algorithm              | Standard           |
|------------------|------------------------|--------------------|
| Key Exchange     | X25519 ECDH            | RFC 7748           |
| Key Derivation   | HKDF-SHA256            | RFC 5869           |
| Encryption       | AES-256-GCM            | NIST SP 800-38D    |
| Nonce Generation | OS CSPRNG (12 bytes)   | Per-message random |

#### Symmetric Path (Master-key, Data at Rest)

| Component        | Algorithm              | Standard           |
|------------------|------------------------|--------------------|
| Key Derivation   | HKDF-SHA256            | RFC 5869           |
| Salt             | `"veil-symmetric-v1"`  | Fixed protocol salt|
| Context Binding  | HKDF info + GCM AAD   | Double-binding     |
| Encryption       | AES-256-GCM            | NIST SP 800-38D    |
| Nonce Generation | OS CSPRNG (12 bytes)   | Per-message random |

### Threat Model

Veil protects against:
- ✅ Passive eavesdropping on prompt/response content
- ✅ Man-in-the-middle tampering (GCM authentication)
- ✅ Replay attacks (unique nonce per message)
- ✅ Intermediary data harvesting (API gateways, proxies, CDNs)
- ✅ Forward secrecy compromise (ephemeral keys per session, asymmetric path)
- ✅ Cross-context ciphertext substitution (HKDF context binding + GCM AAD, symmetric path)
- ✅ Master key compromise isolation (derived keys reveal nothing about each other)

Veil does NOT protect against:
- ❌ Compromised LLM inference engine (has the decryption key)
- ❌ Compromised client device
- ❌ Metadata analysis (model name, request size, timing)
- ❌ Side-channel attacks on the crypto implementation
- ❌ Nonce reuse (mitigated by always generating random nonces from OS CSPRNG; never user-supplied)

### Memory Safety

- All secret keys use `zeroize` for secure memory cleanup on drop
- `SymmetricKey` implements `ZeroizeOnDrop` — key material scrubbed when key goes out of scope
- Ephemeral keys are consumed (moved) after use — cannot be reused
- No unsafe code in `veil-core`
- JNI boundary (`veil-jni`) uses unsafe code for handle management —
  all unsafe blocks are documented and tested for double-free / use-after-free safety

### Dependencies

All cryptographic dependencies are well-audited Rust crates:
- `x25519-dalek` — dalek-cryptography project
- `aes-gcm` — RustCrypto project
- `hkdf` — RustCrypto project
- `sha2` — RustCrypto project
- `rand` — Rust standard CSPRNG
- `zeroize` — Secure memory zeroing

### SDK Binding Dependencies
- `pyo3` — Python FFI bindings (PyO3 project)
- `jni` — Java Native Interface bindings
