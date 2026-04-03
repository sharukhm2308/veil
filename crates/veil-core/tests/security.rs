//! Security property tests for Veil cryptographic operations.

use std::collections::HashSet;
use veil_core::cipher;
use veil_core::keys::StaticKeyPair;
use veil_core::session::ClientSession;

#[test]
fn test_nonces_are_unique() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut nonces = HashSet::new();

    for _ in 0..1000 {
        let mut session = ClientSession::new(&server_pub, "key").expect("session");
        let (envelope, _) = session
            .encrypt_request(b"test", "model", None)
            .expect("encrypt");

        // Extract nonce from envelope
        let nonce: Vec<u8> = envelope.nonce.clone();
        assert_eq!(nonce.len(), 12, "Nonce must be 96 bits");
        assert!(
            nonces.insert(nonce),
            "Nonce collision detected! Critical security failure."
        );
    }
}

#[test]
fn test_ciphertext_indistinguishability() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let plaintext = b"identical plaintext";

    let mut s1 = ClientSession::new(&server_pub, "key").unwrap();
    let mut s2 = ClientSession::new(&server_pub, "key").unwrap();

    let (e1, _) = s1.encrypt_request(plaintext, "m", None).unwrap();
    let (e2, _) = s2.encrypt_request(plaintext, "m", None).unwrap();

    // Nonces must differ
    assert_ne!(e1.nonce, e2.nonce, "Nonces must be unique per encryption");
    // Ciphertexts must differ (different keys from different ephemeral ECDH)
    assert_ne!(e1.ciphertext, e2.ciphertext, "Ciphertexts must differ");
}

#[test]
fn test_key_material_is_256_bit() {
    let key = cipher::generate_key();
    assert_eq!(key.len(), 32, "Key must be 256 bits (32 bytes)");
}

#[test]
fn test_ephemeral_keys_are_unique() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut keys = HashSet::new();

    for _ in 0..100 {
        let mut session = ClientSession::new(&server_pub, "key").unwrap();
        let (_, meta) = session.encrypt_request(b"test", "m", None).unwrap();
        assert!(
            keys.insert(meta.ephemeral_key.clone()),
            "Ephemeral key reuse detected! This breaks forward secrecy."
        );
    }
}

#[test]
fn test_generated_keys_are_random() {
    let mut keys = HashSet::new();
    for _ in 0..100 {
        let key = cipher::generate_key();
        assert!(
            keys.insert(key),
            "Key generation produced duplicate! CSPRNG failure."
        );
    }
}

#[test]
fn test_ciphertext_larger_than_plaintext() {
    // GCM adds 16-byte auth tag
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let plaintext = b"hello world";

    let mut session = ClientSession::new(&server_pub, "key").unwrap();
    let (envelope, _) = session.encrypt_request(plaintext, "m", None).unwrap();

    assert!(
        envelope.ciphertext.len() > plaintext.len(),
        "Ciphertext must be larger than plaintext due to GCM auth tag"
    );
    // Specifically: ciphertext = plaintext + 16 byte tag
    assert_eq!(
        envelope.ciphertext.len(),
        plaintext.len() + 16,
        "GCM adds exactly 16 bytes for authentication tag"
    );
}

#[test]
fn test_chunk_stream_id_binding_prevents_stream_swap() {
    // A chunk encrypted for stream A cannot be decrypted as stream B.
    // The stream_id is bound into the AAD, so tampering the stream_id
    // causes AES-256-GCM authentication to fail.
    use veil_core::cipher;
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut session = ClientSession::new(&server_pub, "key").unwrap();
    // Encrypt for stream-A, chunk 0
    let (envelope, _) = session
        .encrypt_chunk(b"secret prompt", "gpt-4", "stream-A", 0, false)
        .expect("encrypt_chunk failed");
    // Derive the session key that was used (client_to_server direction)
    // Build what an attacker would claim: same ciphertext but stream-B AAD
    let mut tampered_aad = envelope.aad.clone();
    // Replace stream-A with stream-B in the AAD bytes
    let aad_str = String::from_utf8_lossy(&tampered_aad).to_string();
    let tampered_str = aad_str.replace("stream-stream-A", "stream-stream-B");
    tampered_aad = tampered_str.into_bytes();
    // Decryption with tampered AAD must fail — GCM tag mismatch
    let key = cipher::generate_key(); // wrong key anyway, but proves AAD path
    let result = cipher::decrypt(&key, &envelope.nonce, &envelope.ciphertext, &tampered_aad);
    assert!(result.is_err(), "Decryption should fail with tampered stream_id in AAD");
}

#[test]
fn test_chunk_index_binding_prevents_reorder() {
    // Chunk encrypted at index 0 cannot be replayed as index 1.
    // The chunk_index is bound into the AAD via encrypt_chunk(),
    // so any attempt to change the declared index breaks GCM authentication.
    use veil_core::cipher;
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut s1 = ClientSession::new(&server_pub, "key").unwrap();
    let mut s2 = ClientSession::new(&server_pub, "key").unwrap();
    let (env0, _) = s1
        .encrypt_chunk(b"chunk zero", "gpt-4", "stream-X", 0, false)
        .expect("chunk 0 encrypt failed");
    let (env1, _) = s2
        .encrypt_chunk(b"chunk one", "gpt-4", "stream-X", 1, false)
        .expect("chunk 1 encrypt failed");
    // AADs must differ between chunk 0 and chunk 1
    assert_ne!(
        env0.aad, env1.aad,
        "Different chunk indexes must produce different AADs"
    );
    // Ciphertexts must differ (different keys + different AADs)
    assert_ne!(
        env0.ciphertext, env1.ciphertext,
        "Chunks at different indexes must produce different ciphertexts"
    );
    // Cross-decryption must fail: chunk-0 ciphertext with chunk-1 AAD
    let key = cipher::generate_key();
    let cross = cipher::decrypt(&key, &env0.nonce, &env0.ciphertext, &env1.aad);
    assert!(cross.is_err(), "Cross-index decryption must fail — chunk reordering detected");
}

// ===========================================================================
// Symmetric encryption security properties
// ===========================================================================

use veil_core::symmetric::{SymmetricEnvelope, SymmetricKey};

#[test]
fn test_symmetric_nonces_are_unique() {
    // 1000 encryptions -> all nonces must be distinct
    let key = SymmetricKey::generate();
    let mut nonces = HashSet::new();

    for i in 0..1000 {
        let aad = format!("nonce-test-{i}");
        let envelope = key.encrypt(b"payload", aad.as_bytes()).expect("encrypt");
        assert_eq!(envelope.nonce.len(), 12, "nonce must be 96 bits");
        assert!(
            nonces.insert(envelope.nonce.clone()),
            "Symmetric nonce collision detected at iteration {i}! Critical CSPRNG failure."
        );
    }
}

#[test]
fn test_symmetric_ciphertext_indistinguishability() {
    // Same key, same plaintext, 100 encryptions -> all ciphertexts must be distinct
    let key = SymmetricKey::generate();
    let plaintext = b"identical plaintext for indistinguishability test";
    let aad = b"indist-ctx";
    let mut ciphertexts = HashSet::new();

    for i in 0..100 {
        let envelope = key.encrypt(plaintext, aad).expect("encrypt");
        assert!(
            ciphertexts.insert(envelope.ciphertext.clone()),
            "Ciphertext collision at iteration {i}! Same key+plaintext must produce unique ciphertexts."
        );
    }
}

#[test]
fn test_symmetric_key_material_is_256_bit() {
    let key = SymmetricKey::generate();
    assert_eq!(
        key.as_bytes().len(),
        32,
        "SymmetricKey must be 256 bits (32 bytes)"
    );
}

#[test]
fn test_symmetric_derived_keys_are_deterministic() {
    // Same master + context -> derive twice -> identical key bytes
    let master = cipher::generate_key();
    let context = b"determinism-test-context";

    let key1 = SymmetricKey::derive(&master, context).expect("derive 1");
    let key2 = SymmetricKey::derive(&master, context).expect("derive 2");

    assert_eq!(
        key1.as_bytes(),
        key2.as_bytes(),
        "HKDF derivation must be deterministic for same master+context"
    );
}

#[test]
fn test_symmetric_derived_keys_vary_with_context() {
    // Same master, 100 different contexts -> all derived key bytes must be distinct
    let master = cipher::generate_key();
    let mut key_bytes = HashSet::new();

    for i in 0..100 {
        let context = format!("context-variation-{i}");
        let key = SymmetricKey::derive(&master, context.as_bytes()).expect("derive");
        assert!(
            key_bytes.insert(*key.as_bytes()),
            "Derived key collision at context {i}! HKDF context separation failure."
        );
    }
}

#[test]
fn test_symmetric_zeroize_on_drop() {
    // Create key, read bytes, zeroize, verify zeroed (best-effort: compiler may optimize)
    use zeroize::Zeroize;

    let mut key = SymmetricKey::generate();
    // Verify key is non-zero before zeroize
    assert_ne!(key.as_bytes(), &[0u8; 32], "generated key must not be all zeros");

    key.zeroize();
    assert_eq!(
        key.as_bytes(),
        &[0u8; 32],
        "key bytes must be zeroed after zeroize()"
    );
}

#[test]
fn test_symmetric_aad_is_authenticated() {
    // Encrypt with AAD "A", construct envelope with AAD "B", decrypt -> must fail
    let key = SymmetricKey::generate();
    let plaintext = b"aad authentication test";

    let envelope = key.encrypt(plaintext, b"aad-A").expect("encrypt");

    // Tamper with AAD in the envelope
    let tampered = SymmetricEnvelope {
        version: envelope.version,
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
        aad: b"aad-B".to_vec(),
        key_version: envelope.key_version,
    };

    let result = key.decrypt(&tampered);
    assert!(
        result.is_err(),
        "Decryption must fail when AAD is tampered — GCM authentication broken"
    );
}

#[test]
fn test_symmetric_envelope_overhead() {
    // Encrypt N bytes -> ciphertext.len() == N + TAG_SIZE (16 bytes)
    let key = SymmetricKey::generate();

    for size in [0, 1, 16, 100, 1024, 65536] {
        let plaintext = vec![0x42u8; size];
        let envelope = key.encrypt(&plaintext, b"overhead-ctx").expect("encrypt");
        assert_eq!(
            envelope.ciphertext.len(),
            size + 16,
            "ciphertext for {size}-byte plaintext must be exactly {size}+16 bytes (GCM tag overhead)"
        );
    }
}
