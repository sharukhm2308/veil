<div align="center">

# 🔐 Veil

**End-to-end encryption for LLM inference — An example, not a working model**

[![CI](https://github.com/oxifederation/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/oxifederation/veil/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/veil-core.svg)](https://crates.io/crates/veil-core)

*Your prompts are your thoughts. They deserve the same protection as your messages.*

[Quick Start](#quick-start) · [How It Works](#how-it-works) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

</div>

---

## The Problem

When you send a prompt to an LLM API, your request passes through:

```
Your App → App Server → LLM Router (e.g. OpenRouter) → LLM Providers (AWS, Google, Azure, Oracle etc.) → LLM Engine (ChatGPT, Claude, Grok etc.)
```

Every layer in that chain can read your prompts and responses in plaintext.
TLS only protects the connection between hops — not through them.

This means your confidential data — legal documents, medical records, proprietary
code, personal conversations — is visible to every piece of infrastructure
between you and the model.

## The Solution

Veil adds an **application-layer encryption envelope** around your LLM traffic.
When veil-server runs in-process with the LLM engine, only your application and the LLM inference engine can read the content:

```
  Your App ──▶ 🔒 Encrypted Blob ──▶ 🔒 ──▶ 🔒 ──▶ LLM Engine
       ▲            ▲                                    │
       │       Can't read this                           │
       └──── 🔓 Decrypted Response ◀── 🔒 ◀── 🔒 ◀─────┘
```

**Veil is inspired by Signal's principle of application-layer encryption** —
applying the same idea to LLM inference traffic so that middleware sees only
opaque encrypted blobs regardless of the transport layer.

> **Trust boundary:** When `veil-server` runs **in-process** with the LLM engine,
> this is true end-to-end encryption — only your app and the inference engine can read content.
> When deployed as a sidecar, it is application-layer encryption terminating at the shim operator.
> See [Deployment Modes](#deployment-modes) for guidance.

---


## Deployment Modes

Veil supports two deployment modes with different trust guarantees:

### Mode 1: In-Process (True E2EE) ✅

Link `veil-server` directly into your LLM inference process (e.g., as a library
embedded in llama.cpp, vLLM, Ollama, or a custom inference server):

```
Your App → [Encrypted] → Network → [Encrypted] → LLM Process
                                                      └── veil-server (decrypts)
                                                      └── Inference Engine (reads plaintext)
```

**Trust guarantee:** No party between your app and the inference engine can read content.
This is true end-to-end encryption.

### Mode 2: Sidecar Shim (Application-Layer Encryption)

Run `veil-server` as a separate process in front of a third-party LLM API:

```
Your App → [Encrypted] → veil-server (decrypts) → LLM API (plaintext)
```

**Trust guarantee:** Encryption protects traffic from your app to the shim.
The shim operator and LLM provider can still read plaintext. Choose this mode
when you control and trust the shim deployment environment.

### Prekey Endpoint (True Forward Secrecy)

Fetch one-time server prekeys before establishing a session:

```bash
curl http://localhost:8481/v1/veil/prekeys
```

Use the returned `prekey_pub` + `prekey_id` in `ClientSession::new_with_prekey()`.
The server deletes the prekey secret after first use — compromising the server
static key later **cannot** retroactively decrypt sessions that used prekeys.

## Quick Start

### 1. Build from Source

```bash
git clone https://github.com/oxifederation/veil.git
cd veil
cargo build --release
```

### 2. Generate Server Keys

```bash
./target/release/veil keygen --output server-keys.json
```

### 3. Test the Encryption Roundtrip

```bash
./target/release/veil test-roundtrip --message "Hello, encrypted world!"
```

Expected output:
```
=== Veil E2E Encryption Test ===
Original:  Hello, encrypted world!
Encrypted: <base64 envelope>
Decrypted: Hello, encrypted world!
✅ Roundtrip successful — encryption is working correctly
```

### 4. Run as a Proxy (Drop-In Replacement)

```bash
# Terminal 1: Start the Veil server shim (sits in front of your LLM)
./target/release/veil server --key-file server-keys.json --upstream http://localhost:11434

# Terminal 2: Start the Veil client proxy (your app connects here)
./target/release/veil proxy --server-url http://localhost:3100 --listen 127.0.0.1:8080

# Terminal 3: Use any OpenAI-compatible client — it just works
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3", "messages": [{"role": "user", "content": "Hello!"}]}'
```

Your traffic is now application-layer encrypted. The proxy and shim handle all crypto transparently.
For full E2EE, deploy veil-server in-process with your LLM inference engine (see [Deployment Modes](#deployment-modes)).

---

## How It Works

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────┐
│          │ OpenAI   │              │ Encrypted │              │ OpenAI   │          │
│ Your App │────API──▶│ Veil Client  │────blob──▶│ Veil Server  │────API──▶│   LLM    │
│          │◀───────  │ Proxy        │◀────────  │ Shim         │◀───────  │ Engine   │
│          │  (plain) │              │ (opaque)  │              │  (plain) │          │
└──────────┘          └──────────────┘          └──────────────┘          └──────────┘
     🔑                    🔐                       🔐                       🔑
   Sees                 Encrypts/                Gateway only             Decrypts/
  plaintext             decrypts                sees blob               encrypts
```

### Cryptographic Pipeline

**Asymmetric path** (session-based, forward secrecy):

| Stage | Algorithm | Purpose |
|-------|-----------|:--------|
| Key Exchange | X25519 ECDH | Establish shared secret; true forward secrecy via ephemeral client + one-time server prekeys |
| Key Derivation | HKDF-SHA256 | Derive directional encryption keys |
| Encryption | AES-256-GCM | Authenticated encryption of prompts/responses |

**Symmetric path** (master-key, data at rest):

| Stage | Algorithm | Purpose |
|-------|-----------|:--------|
| Key Derivation | HKDF-SHA256 | Derive context-specific keys from a master key |
| Encryption | AES-256-GCM | Authenticated encryption with context as AAD |

Every request uses a **fresh client ephemeral key** combined with a **one-time server prekey**,
providing **true forward secrecy** —
compromising the server key does not reveal past conversations.

📖 **Full protocol specification** → [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Features

- 🔒 **End-to-end encryption** — prompts and responses encrypted through all middleware
- 🔑 **True forward secrecy** — fresh client ephemeral + one-time server prekeys (`GET /v1/veil/prekeys`); server prekey secrets deleted after first use
- 🛡️ **Authenticated encryption** — AES-256-GCM detects any tampering
- 🔄 **Drop-in proxy mode** — zero changes to existing OpenAI-compatible apps
- ⚡ **Minimal overhead** — ~48 bytes per message, sub-millisecond crypto
- 📦 **Pure Rust** — memory-safe, no unsafe code in core
- 🧹 **Zeroize-on-drop** — key material scrubbed from memory after use
- 🐳 **Docker ready** — multi-stage builds for client and server
- 🔑 **Symmetric encryption** — AES-256-GCM with HKDF key derivation for data-at-rest
- 🧪 **Thoroughly tested** — 94 Rust + 56 Python + 43 Java tests covering crypto, integration, and security properties

---

## Project Structure

```
veil/
├── crates/
│   ├── veil-core/       # Pure cryptographic library (no I/O, no async)
│   │   ├── src/
│   │   │   ├── keys.rs       # X25519 key generation and ECDH
│   │   │   ├── kdf.rs        # HKDF-SHA256 key derivation (asymmetric)
│   │   │   ├── cipher.rs     # AES-256-GCM encrypt/decrypt
│   │   │   ├── envelope.rs   # Wire format (MessagePack + JSON)
│   │   │   ├── session.rs    # Client/server session management
│   │   │   ├── symmetric.rs  # Symmetric encryption (HKDF + AES-256-GCM)
│   │   │   └── error.rs      # Error types
│   │   └── tests/
│   │       ├── integration.rs   # E2E roundtrip tests
│   │       └── security.rs      # Security property tests
│   ├── veil-python/     # Python SDK via PyO3 native bindings
│   │   ├── src/lib.rs       # PyO3 wrapper classes
│   │   └── tests/           # 56 pytest test cases
│   ├── veil-jni/        # JNI native library for Java
│   │   ├── src/lib.rs       # JNI FFI bridge
│   │   └── veil-java/       # Java SDK classes + 43 JUnit tests
│   ├── veil-client/     # HTTP proxy (encrypts outgoing requests)
│   ├── veil-server/     # Axum server shim (decrypts, forwards to LLM)
│   └── veil-cli/        # CLI tool for keygen, testing, proxy, server
├── docker/              # Docker deployment configurations
├── examples/            # Integration examples (Python, etc.)
├── benches/             # Cryptographic benchmarks
├── ARCHITECTURE.md      # Full protocol specification
├── SECURITY.md          # Threat model and security policy
├── CONTRIBUTING.md      # Contribution guidelines
└── CHANGELOG.md         # Release history
```

---

## SDK Roadmap

Veil follows a **single-core, many-bindings** architecture. All cryptography lives
in `veil-core` (Rust). Language SDKs are thin FFI wrappers — one implementation,
audited once, available everywhere.

| Phase | SDK | Technology | Status |
|:-----:|-----|-----------|:------:|
| 1 | **Proxy + CLI** | Native Rust | ✅ Complete |
| 2 | **Python SDK** | PyO3 bindings | ✅ Complete |
| 3 | **Java/Kotlin SDK** | JNI bindings | ✅ Complete |
| 4 | **JavaScript/TypeScript SDK** | NAPI-RS (Node) + WASM (Browser) | 📋 Planned |
| 5 | **Go SDK** | CGo FFI | 📋 Planned |
| 6 | **Swift/Kotlin Mobile** | Mozilla UniFFI | 📋 Planned |

### Python SDK Usage

```python
from veil_sdk import VeilKeyPair, VeilClientSession, VeilSymmetricKey

# Asymmetric: session-based encryption (forward secrecy)
server_kp = VeilKeyPair.generate()
client = VeilClientSession(server_kp.public_base64(), "key-1")
envelope = client.encrypt_request(b'{"prompt": "hello"}', "gpt-4", 100)

# Symmetric: master-key encryption (data at rest)
master = VeilSymmetricKey.generate()
derived = master.derive(b"user-123-conversation-456")
encrypted = derived.encrypt(b"secret message", b"user-123-conversation-456")
plaintext = derived.decrypt(encrypted)
```

### Java SDK Usage

```java
import io.veil.VeilSymmetricKey;

// Symmetric encryption with AutoCloseable lifecycle
try (VeilSymmetricKey master = VeilSymmetricKey.generate()) {
    try (VeilSymmetricKey derived = master.derive("ctx".getBytes())) {
        var envelope = derived.encrypt("secret".getBytes(), "ctx".getBytes());
        byte[] plaintext = derived.decrypt(envelope);
    }
} // keys are zeroized on close
```

📖 **SDK architecture details** → [ARCHITECTURE.md § SDK Architecture](ARCHITECTURE.md#sdk-architecture-ffi-bindings)

---

## Benchmarks

Preliminary benchmarks on Apple M2 (single core):

| Operation | Throughput | Latency |
|-----------|-----------|:-------:|
| X25519 ECDH | ~50,000 ops/sec | ~20 µs |
| HKDF-SHA256 derivation | ~500,000 ops/sec | ~2 µs |
| AES-256-GCM encrypt (1 KB) | ~2 GB/s | ~0.5 µs |
| AES-256-GCM encrypt (1 MB) | ~4 GB/s | ~250 µs |
| Full session roundtrip | ~25,000 ops/sec | ~40 µs |

> **Veil adds < 100 µs** to your LLM API call (which typically takes 200ms–30s).
> The encryption overhead is unmeasurable in practice.

Run benchmarks yourself:

```bash
cargo bench
```

---

## Docker Deployment

```bash
# Build and run both client proxy and server shim
cd docker
docker compose up -d

# Client proxy listens on :8080
# Server shim listens on :3100
```

See [docker/](docker/) for multi-stage Dockerfiles and configuration.

---

## Security

Veil takes security seriously:

- **Cryptographic choices**: X25519, HKDF-SHA256, AES-256-GCM — industry-standard
  algorithms from the RustCrypto project
- **No unsafe code** in `veil-core` (JNI boundary unsafe code is isolated in `veil-jni`)
- **Zeroize-on-drop** for all key material (asymmetric session keys and symmetric keys)
- **94 Rust tests** including tamper detection, cross-session/cross-context isolation,
  ciphertext indistinguishability, nonce uniqueness, and zeroize verification
- **Constant-time operations** via RustCrypto's timing-safe implementations
- **Context-bound symmetric encryption** — HKDF derivation + GCM AAD double-binding
  prevents cross-context ciphertext substitution

### Reporting Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Please email aehthesham.gom@gmail.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment

We will respond within 48 hours.

📖 **Full threat model** → [SECURITY.md](SECURITY.md)

---

## Contributing

We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md)
before submitting a PR.

TL;DR:
1. Fork the repo
2. Create a feature branch (`feat/my-feature`)
3. Write tests for your changes
4. Ensure `cargo fmt && cargo clippy -- -D warnings && cargo test` passes
5. Submit a PR with a [Conventional Commit](https://www.conventionalcommits.org/) message

---

## License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

<div align="center">

**Veil** is a project by the [Concerned Technologist](https://github.com/oxifederation)

*Protecting the confidentiality of human–AI communication*

</div>
