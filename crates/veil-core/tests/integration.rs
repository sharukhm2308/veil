//! End-to-end integration tests for the Veil protocol.

use veil_core::keys::StaticKeyPair;
use veil_core::session::{ClientSession, ServerSession};

#[test]
fn test_full_e2e_roundtrip() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut client_session =
        ClientSession::new(&server_pub, "test-key").expect("Failed to create client session");

    let prompt = b"{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}";
    let (envelope, metadata) = client_session
        .encrypt_request(prompt, "gpt-4", Some(10))
        .expect("Failed to encrypt request");

    assert_eq!(metadata.model, "gpt-4");
    assert_eq!(metadata.token_estimate, Some(10));
    assert_eq!(metadata.key_id, "test-key");
    assert!(!metadata.ephemeral_key.is_empty());
    assert!(!metadata.timestamp.is_empty());
    assert!(!metadata.request_id.is_empty());

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "test-key", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt request");
    assert_eq!(decrypted, prompt);

    let response = b"{\"choices\":[{\"message\":{\"content\":\"Hello back!\"}}]}";
    let response_envelope = server_session
        .encrypt_response(response)
        .expect("Failed to encrypt response");

    let decrypted_response = client_session
        .decrypt_response(&response_envelope)
        .expect("Failed to decrypt response");
    assert_eq!(decrypted_response, response);
}

#[test]
fn test_different_sessions_produce_different_ciphertext() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session_a = ClientSession::new(&server_pub, "key-1").expect("Failed to create session A");
    let mut session_b = ClientSession::new(&server_pub, "key-1").expect("Failed to create session B");

    let prompt = b"secret prompt";

    let (envelope_a, _meta_a) = session_a
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    let (envelope_b, _meta_b) = session_b
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Different sessions should produce different ciphertexts
    assert_ne!(
        envelope_a.ciphertext, envelope_b.ciphertext,
        "Different sessions should produce different ciphertexts"
    );
}

#[test]
fn test_cross_session_decryption_works() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let prompt = b"secret prompt";
    let (envelope, meta) = session
        .encrypt_request(prompt, "model", None)
        .expect("Failed to encrypt");

    // Server creates session from the ephemeral key
    let server_session = ServerSession::new(&server_kp, &meta.ephemeral_key, "key-1", &meta.request_id, &meta.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Should decrypt with correct ephemeral key");
    assert_eq!(decrypted, prompt);
}

#[test]
fn test_large_payload_e2e() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    // 1MB payload (large context window)
    let large_prompt: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(&large_prompt, "gpt-4-turbo", Some(50000))
        .expect("Failed to encrypt large payload");

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    let decrypted = server_session
        .decrypt_request(&envelope)
        .expect("Failed to decrypt large payload");

    assert_eq!(decrypted, large_prompt);
}

#[test]
fn test_tampered_ciphertext_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the ciphertext
    if let Some(byte) = envelope.ciphertext.last_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered ciphertext should be rejected"
    );
}

#[test]
fn test_tampered_nonce_rejected() {
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut session = ClientSession::new(&server_pub, "key-1").expect("Failed to create session");

    let (mut envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    // Tamper with the nonce
    if let Some(byte) = envelope.nonce.first_mut() {
        *byte ^= 0xFF;
    }

    let server_session = ServerSession::new(&server_kp, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        server_session.decrypt_request(&envelope).is_err(),
        "Tampered nonce should be rejected"
    );
}

#[test]
fn test_wrong_server_key_rejected() {
    let server_kp_real = StaticKeyPair::generate();
    let server_kp_fake = StaticKeyPair::generate();

    let mut session = ClientSession::new(&server_kp_real.public_base64(), "key-1")
        .expect("Failed to create session");

    let (envelope, metadata) = session
        .encrypt_request(b"secret", "model", None)
        .expect("Failed to encrypt");

    let wrong_session = ServerSession::new(&server_kp_fake, &metadata.ephemeral_key, "key-1", &metadata.request_id, &metadata.timestamp)
        .expect("Failed to create server session");

    assert!(
        wrong_session.decrypt_request(&envelope).is_err(),
        "Wrong server key should fail to decrypt"
    );
}

#[test]
fn test_encrypt_decrypt_chunk_roundtrip() {
    // Full roundtrip: client encrypt_chunk -> server decrypt_chunk
    // Verifies the streaming API pair is symmetric and correct.
    let server_kp = veil_core::keys::StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut client = veil_core::session::ClientSession::new(&server_pub, "key-1").unwrap();
    let plaintext = b"streaming chunk content";
    let stream_id = "stream-abc-123";
    let chunk_index = 5u64;
    let is_final = false;
    // Client encrypts chunk
    let (envelope, meta) = client
        .encrypt_chunk(plaintext, "gpt-4", stream_id, chunk_index, is_final)
        .expect("encrypt_chunk failed");
    // Verify metadata fields are set correctly
    assert_eq!(meta.stream_id.as_deref(), Some(stream_id));
    assert_eq!(meta.chunk_index, Some(chunk_index));
    assert_eq!(meta.is_final_chunk, Some(is_final));
    // Server creates session from client metadata
    let server = veil_core::session::ServerSession::new(
        &server_kp,
        &meta.ephemeral_key,
        &meta.key_id,
        &meta.request_id,
        &meta.timestamp,
    ).expect("ServerSession::new failed");
    // Server decrypts chunk with correct stream position
    let decrypted = server
        .decrypt_chunk(&envelope, stream_id, chunk_index, is_final)
        .expect("decrypt_chunk failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_chunk_rejects_wrong_index() {
    // Server must reject chunk with wrong chunk_index (reorder attack).
    let server_kp = veil_core::keys::StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();
    let mut client = veil_core::session::ClientSession::new(&server_pub, "key-1").unwrap();
    let (envelope, meta) = client
        .encrypt_chunk(b"chunk at index 0", "gpt-4", "stream-1", 0, false)
        .expect("encrypt failed");
    let server = veil_core::session::ServerSession::new(
        &server_kp,
        &meta.ephemeral_key,
        &meta.key_id,
        &meta.request_id,
        &meta.timestamp,
    ).expect("server session failed");
    // Attempt to decrypt as chunk index 1 (wrong!) must fail
    let result = server.decrypt_chunk(&envelope, "stream-1", 1, false);
    assert!(result.is_err(), "Should reject chunk with wrong index — reorder attack detected");
}

// ===========================================================================
// Symmetric encryption integration tests
// ===========================================================================

use veil_core::symmetric::{SymmetricEnvelope, SymmetricKey};

#[test]
fn test_symmetric_full_roundtrip() {
    let key = SymmetricKey::generate();
    let plaintext = b"Hello, symmetric world!";
    let aad = b"roundtrip-context";

    let envelope = key.encrypt(plaintext, aad).expect("encrypt failed");
    let decrypted = key.decrypt(&envelope).expect("decrypt failed");

    assert_eq!(decrypted, plaintext, "plaintext must survive encrypt-decrypt roundtrip");
}

#[test]
fn test_symmetric_derive_interop() {
    // Simulate Agent <-> Relay: both derive from same master+context,
    // one encrypts, the other decrypts.
    let master = veil_core::cipher::generate_key();
    let context = b"cw-agent1-relay1-session42";

    // "Agent" side derives and encrypts
    let agent_key = SymmetricKey::derive(&master, context).expect("agent derive");
    let plaintext = b"{\"action\":\"route\",\"payload\":\"sensitive\"}";
    let envelope = agent_key.encrypt(plaintext, context).expect("agent encrypt");

    // "Relay" side derives independently and decrypts
    let relay_key = SymmetricKey::derive(&master, context).expect("relay derive");
    let decrypted = relay_key.decrypt(&envelope).expect("relay decrypt");

    assert_eq!(decrypted, plaintext, "relay must decrypt what agent encrypted");
}

#[test]
fn test_symmetric_large_payload() {
    // 1MB payload through derive -> encrypt -> serialize JSON -> deserialize -> decrypt
    let master = veil_core::cipher::generate_key();
    let context = b"large-payload-ctx";

    let key = SymmetricKey::derive(&master, context).expect("derive");
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let envelope = key.encrypt(&plaintext, context).expect("encrypt 1MB");

    // Serialize to JSON and back (simulates network/storage)
    let json = envelope.to_json().expect("to_json");
    let restored = SymmetricEnvelope::from_json(&json).expect("from_json");

    let decrypted = key.decrypt(&restored).expect("decrypt 1MB");
    assert_eq!(decrypted, plaintext, "1MB payload must survive full roundtrip");
}

#[test]
fn test_symmetric_versioned_roundtrip() {
    let key = SymmetricKey::generate();
    let plaintext = b"versioned integration test data";
    let aad = b"ver-integration-ctx";

    let envelope = key.encrypt_versioned(plaintext, aad, 2).expect("encrypt_versioned");
    assert_eq!(
        envelope.key_version,
        Some(2),
        "key_version must be set to 2"
    );

    let decrypted = key.decrypt(&envelope).expect("decrypt versioned");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_symmetric_json_wire_format() {
    // Encrypt -> to_json -> from_json -> decrypt (simulates network/storage roundtrip)
    let key = SymmetricKey::generate();
    let plaintext = b"json wire format test payload";
    let aad = b"json-wire-ctx";

    let envelope = key.encrypt(plaintext, aad).expect("encrypt");
    let json = envelope.to_json().expect("to_json");

    // Simulate receiving from network
    let received = SymmetricEnvelope::from_json(&json).expect("from_json");
    let decrypted = key.decrypt(&received).expect("decrypt from json");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_symmetric_msgpack_wire_format() {
    // Same for msgpack — simulates compact binary storage
    let key = SymmetricKey::generate();
    let plaintext = b"msgpack wire format test payload";
    let aad = b"msgpack-wire-ctx";

    let envelope = key.encrypt(plaintext, aad).expect("encrypt");
    let bytes = envelope.to_msgpack().expect("to_msgpack");

    // Simulate loading from binary storage
    let received = SymmetricEnvelope::from_msgpack(&bytes).expect("from_msgpack");
    let decrypted = key.decrypt(&received).expect("decrypt from msgpack");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_symmetric_context_isolation() {
    // Encrypt with context "cw-user1-conv1", try decrypt with derive("cw-user1-conv2") -> fails
    let master = veil_core::cipher::generate_key();

    let key_conv1 = SymmetricKey::derive(&master, b"cw-user1-conv1").expect("derive conv1");
    let key_conv2 = SymmetricKey::derive(&master, b"cw-user1-conv2").expect("derive conv2");

    let plaintext = b"conversation-1 secret message";
    let envelope = key_conv1
        .encrypt(plaintext, b"cw-user1-conv1")
        .expect("encrypt");

    // Different context key must fail to decrypt
    let result = key_conv2.decrypt(&envelope);
    assert!(
        result.is_err(),
        "decryption with different context key must fail — context isolation violated"
    );
}

#[test]
fn test_symmetric_cross_user_isolation() {
    // Different master keys (different users), same context -> decrypt fails
    let master_user_a = veil_core::cipher::generate_key();
    let master_user_b = veil_core::cipher::generate_key();
    let context = b"shared-context-name";

    let key_a = SymmetricKey::derive(&master_user_a, context).expect("derive A");
    let key_b = SymmetricKey::derive(&master_user_b, context).expect("derive B");

    let envelope = key_a.encrypt(b"user A secret", context).expect("encrypt");

    let result = key_b.decrypt(&envelope);
    assert!(
        result.is_err(),
        "user B must not decrypt user A's data even with identical context"
    );
}

#[test]
fn test_symmetric_with_asymmetric_pipeline() {
    // Full Meridian flow simulation:
    // 1. Client encrypts with asymmetric -> server decrypts
    // 2. Server stores with symmetric -> server loads from symmetric
    // 3. Server encrypts response with asymmetric -> client decrypts

    // --- Setup asymmetric session ---
    let server_kp = StaticKeyPair::generate();
    let server_pub = server_kp.public_base64();

    let mut client_session =
        ClientSession::new(&server_pub, "meridian-key").expect("client session");

    // Step 1: Client encrypts request with asymmetric encryption
    let prompt = b"{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"What is Veil?\"}]}";
    let (request_envelope, metadata) = client_session
        .encrypt_request(prompt, "gpt-4", Some(20))
        .expect("encrypt request");

    // Step 2: Server decrypts request with asymmetric
    let server_session = ServerSession::new(
        &server_kp,
        &metadata.ephemeral_key,
        "meridian-key",
        &metadata.request_id,
        &metadata.timestamp,
    )
    .expect("server session");

    let decrypted_prompt = server_session
        .decrypt_request(&request_envelope)
        .expect("decrypt request");
    assert_eq!(decrypted_prompt, prompt);

    // Step 3: Server stores decrypted prompt at rest with symmetric encryption
    let master = veil_core::cipher::generate_key();
    let storage_context = format!("cw-{}-store", metadata.request_id);
    let storage_key =
        SymmetricKey::derive(&master, storage_context.as_bytes()).expect("derive storage key");
    let stored_envelope = storage_key
        .encrypt(&decrypted_prompt, storage_context.as_bytes())
        .expect("symmetric encrypt for storage");

    // Serialize to JSON (simulate writing to database)
    let stored_json = stored_envelope.to_json().expect("serialize to json");

    // Step 4: Server loads from symmetric storage
    let loaded_envelope =
        SymmetricEnvelope::from_json(&stored_json).expect("deserialize from json");
    let loaded_key =
        SymmetricKey::derive(&master, storage_context.as_bytes()).expect("re-derive storage key");
    let loaded_prompt = loaded_key
        .decrypt(&loaded_envelope)
        .expect("decrypt from storage");
    assert_eq!(loaded_prompt, prompt);

    // Step 5: Server encrypts response with asymmetric and sends to client
    let response = b"{\"choices\":[{\"message\":{\"content\":\"Veil is an encryption library.\"}}]}";
    let response_envelope = server_session
        .encrypt_response(response)
        .expect("encrypt response");

    // Step 6: Client decrypts response
    let decrypted_response = client_session
        .decrypt_response(&response_envelope)
        .expect("decrypt response");
    assert_eq!(decrypted_response, response);
}
