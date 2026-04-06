# Contributing to Veil

Thank you for your interest in contributing to Veil! This document provides
guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Commit Convention](#commit-convention)
- [Pull Request Process](#pull-request-process)
- [Testing Requirements](#testing-requirements)
- [Code Style](#code-style)
- [Security Reporting](#security-reporting)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
By participating, you are expected to uphold this code.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/veil.git
   cd veil
   ```
3. **Create a branch** for your work:
   ```bash
   git checkout -b feat/my-feature
   # or: fix/issue-description, docs/topic, test/coverage-area
   ```
4. **Make your changes**, ensuring tests pass
5. **Push** and open a Pull Request

---

## Development Setup

### Prerequisites

- **Rust** 1.80+ (install via [rustup](https://rustup.rs/))
- **cargo** (included with Rust)
- **Git** 2.x+

**For Python SDK development:**
- **Python** 3.9+
- **maturin** (`pip install maturin`) — builds PyO3 native extensions
- **pytest** (`pip install pytest`) — runs the Python test suite

**For Java SDK development:**
- **JDK** 11+
- **Maven** 3.6+ (`mvn`)

### Build

```bash
# Debug build (all crates)
cargo build

# Release build (optimized)
cargo build --release

# Build a specific crate
cargo build -p veil-core

# Build the Python native extension
cd crates/veil-python && maturin develop

# Build the JNI native library
cargo build -p veil-jni --release
```

### Run Tests

```bash
# Run all Rust tests (unit + integration + security + doc)
cargo test

# Run tests for a specific crate
cargo test -p veil-core

# Run a specific test
cargo test test_full_e2e_roundtrip

# Run tests with output
cargo test -- --nocapture

# Run Python SDK tests (requires maturin develop first)
cd crates/veil-python && pytest tests/ -v

# Run Java SDK tests (requires JNI library on library path)
cd crates/veil-jni/veil-java && mvn test -Djava.library.path=../../../target/release
```

### Run the CLI

```bash
# Generate keys
cargo run -- keygen --output keys.json

# Test encryption roundtrip
cargo run -- test-roundtrip --message "Hello Veil!"

# Run with verbose logging
RUST_LOG=debug cargo run -- test-roundtrip --message "Hello Veil!"
```

### Code Formatting & Linting

```bash
# Format code (required before submitting PR)
cargo fmt

# Check formatting without modifying
cargo fmt --check

# Run clippy linter (must pass with zero warnings)
cargo clippy -- -D warnings
```

---

## Commit Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.
Every commit message must follow this format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description | Example |
|------|------------|--------|
| `feat` | New feature or capability | `feat: add SSE streaming encryption` |
| `fix` | Bug fix | `fix: handle empty plaintext in cipher` |
| `docs` | Documentation only | `docs: add key rotation guide` |
| `test` | Adding or fixing tests | `test: add cross-session isolation tests` |
| `ci` | CI/CD changes | `ci: add cargo clippy to GitHub Actions` |
| `refactor` | Code restructuring (no behavior change) | `refactor: extract HKDF into separate module` |
| `perf` | Performance improvement | `perf: use AES-NI intrinsics for GCM` |
| `chore` | Maintenance tasks | `chore: update dependencies` |
| `build` | Build system changes | `build: add wasm target support` |
| `style` | Code style (formatting, semicolons) | `style: run cargo fmt` |

### Scope (Optional)

The scope indicates the crate or area affected:

```
feat(core): add envelope versioning
feat(symmetric): add HKDF key derivation
fix(server): handle connection timeout gracefully
test(client): add proxy integration tests
test(python): add symmetric key roundtrip tests
test(java): add JNI handle lifecycle tests
docs(readme): update quick start section
```

### Examples

```
feat(core): implement per-chunk SSE encryption

Add streaming encryption support where each SSE chunk is independently
encrypted with a fresh nonce using the session's s2c key.

- New `StreamingEncryptor` struct for incremental encryption
- Each chunk gets its own GCM nonce and auth tag
- Chunk ordering preserved by SSE transport layer

Closes #42
```

```
fix(server): reject requests with expired key IDs

Previously the server would attempt ECDH with a rotated-out key,
causing a cryptic decryption failure. Now returns 400 with a clear
error message indicating key rotation.

Fixes #57
```

### Breaking Changes

Append `!` after the type or add `BREAKING CHANGE:` footer:

```
feat(core)!: change envelope format to support versioning

BREAKING CHANGE: VeilEnvelope now requires a `version` field.
Existing serialized envelopes without version will fail to deserialize.
```

---

## Pull Request Process

### Before Submitting

1. ✅ All tests pass: `cargo test`
2. ✅ No clippy warnings: `cargo clippy -- -D warnings`
3. ✅ Code is formatted: `cargo fmt`
4. ✅ Commit messages follow [Conventional Commits](#commit-convention)
5. ✅ New features have tests
6. ✅ Documentation is updated if needed

### PR Template

When opening a PR, include:

```markdown
## What
Brief description of the change.

## Why
Motivation — what problem does this solve?

## How
Technical approach taken.

## Testing
How this was tested (new tests, manual verification, etc.).

## Checklist
- [ ] Tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code formatted (`cargo fmt`)
- [ ] Documentation updated
- [ ] Conventional commit messages
```

### Review Process

1. PRs require at least one approving review
2. CI must pass (fmt, clippy, test, build)
3. Maintainers may request changes
4. Squash merge is preferred for clean history

---

## Testing Requirements

### What Needs Tests

- **All cryptographic functions** — correctness, edge cases, error conditions
- **Envelope serialization** — roundtrip for all formats (MessagePack, JSON)
- **Symmetric encryption** — key generation, HKDF derivation, context isolation, versioned envelopes
- **Session management** — key exchange, cross-session isolation
- **Security properties** — nonce uniqueness, ciphertext indistinguishability,
  key randomness, tamper detection, zeroize-on-drop
- **FFI boundaries** — Python (PyO3) and Java (JNI) bindings match Rust behavior
- **Error handling** — invalid inputs, corrupted data, wrong keys

### Test Categories

| Category | Location | Purpose |
|----------|---------|--------|
| Unit tests | `crates/veil-core/src/*.rs` (`#[cfg(test)]`) | Test individual functions |
| Integration tests | `crates/veil-core/tests/integration.rs` | Test crate-level workflows |
| Security tests | `crates/veil-core/tests/security.rs` | Verify cryptographic properties |
| Doc tests | Inline in `//!` and `///` comments | Verify examples compile |
| Python tests | `crates/veil-python/tests/test_veil_sdk.py` | PyO3 binding correctness (56 tests) |
| Java tests | `crates/veil-jni/veil-java/src/test/java/` | JNI binding correctness (43 tests) |

### Writing Good Crypto Tests

```rust
#[test]
fn test_example_pattern() {
    // 1. Setup: create keys, sessions, test data
    let server_keys = StaticKeyPair::generate();
    let plaintext = b"test message";

    // 2. Exercise: perform the operation
    let result = encrypt(plaintext, &key);

    // 3. Verify: check the result
    assert!(result.is_ok());
    let ciphertext = result.unwrap();
    assert_ne!(ciphertext, plaintext); // ciphertext differs from plaintext

    // 4. Roundtrip: verify decrypt(encrypt(x)) == x
    let decrypted = decrypt(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}
```

### Writing Symmetric Encryption Tests

```rust
#[test]
fn test_symmetric_example() {
    use veil_core::symmetric::SymmetricKey;

    // 1. Generate or derive a key
    let master = SymmetricKey::generate();
    let derived = master.derive(b"user-123-conversation-456");

    // 2. Encrypt with context as AAD
    let envelope = derived.encrypt(b"secret message", b"user-123-conversation-456").unwrap();

    // 3. Roundtrip
    let plaintext = derived.decrypt(&envelope).unwrap();
    assert_eq!(plaintext, b"secret message");

    // 4. Cross-context isolation: different context must fail
    let other = master.derive(b"user-789-conversation-000");
    assert!(other.decrypt(&envelope).is_err());
}
```

---

## Code Style

### General Principles

- **Clarity over cleverness** — write code that others can understand
- **Explicit over implicit** — prefer clear type annotations and error handling
- **Safe by default** — no `unsafe` code in `veil-core` without extensive justification.
  Note: `veil-jni` necessarily contains unsafe code at the JNI boundary — all such code
  must be thoroughly documented and tested for handle safety.
- **Zero warnings** — `cargo clippy -- -D warnings` must pass

### Naming Conventions

```rust
// Types: PascalCase
struct SessionKeys { ... }
enum VeilError { ... }

// Functions/methods: snake_case
fn derive_session_keys() -> SessionKeys { ... }

// Constants: SCREAMING_SNAKE_CASE
const HKDF_SALT: &[u8] = b"veil-e2e-llm-v1";

// Modules: snake_case
mod key_exchange;
```

### Error Handling

```rust
// Use the crate's error type
use crate::error::VeilError;

// Return Result with VeilError
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, VeilError> { ... }

// Use ? for propagation
let key = derive_key(secret)?;
```

### Documentation

```rust
/// Encrypts plaintext using AES-256-GCM.
///
/// # Arguments
///
/// * `plaintext` - The data to encrypt
/// * `key` - A 256-bit AES key
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
///
/// Returns `(nonce, ciphertext)` where ciphertext includes the 16-byte GCM auth tag.
///
/// # Errors
///
/// Returns `VeilError::EncryptionFailed` if the encryption operation fails.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<...> {
```

---

## Security Reporting

**⚠️ Do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly:

1. **Email**: aehthesham.gom@gmail.com
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)
3. **Response time**: We will acknowledge within 48 hours
4. **Disclosure**: We follow [Coordinated Vulnerability Disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)

See [SECURITY.md](SECURITY.md) for our full security policy.

---

## License

By contributing to Veil, you agree that your contributions will be licensed
under the same dual license as the project: **MIT OR Apache-2.0**.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
