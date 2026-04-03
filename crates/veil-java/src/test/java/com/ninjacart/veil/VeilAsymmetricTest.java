package com.ninjacart.veil;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the asymmetric (X25519 ECDH) classes:
 * {@link VeilKeyPair}, {@link VeilClientSession}, {@link VeilServerSession},
 * {@link VeilEnvelope}, and {@link VeilMetadata}.
 *
 * <p>These tests complement the existing {@code VeilClientSessionTest} by
 * covering additional edge cases and ensuring no regressions in the
 * asymmetric encryption path.
 *
 * <p>Requires the native library {@code libveil_jni} to be on the library path.
 * Build with: {@code cd crates/veil-jni && cargo build --release}
 * Run with: {@code mvn test -Djava.library.path=../../target/release}
 */
class VeilAsymmetricTest {

    private static final String KEY_ID = "regression-test-v1";

    // ========================================================================
    // VeilKeyPair
    // ========================================================================

    /**
     * {@link VeilKeyPair#generate()} must produce non-null, non-empty
     * secret and public keys.
     */
    @Test
    void keyPairGenerate() {
        VeilKeyPair kp = VeilKeyPair.generate();
        assertNotNull(kp.secretBase64(), "Secret key must not be null");
        assertNotNull(kp.publicBase64(), "Public key must not be null");
        assertFalse(kp.secretBase64().isEmpty(), "Secret key must not be empty");
        assertFalse(kp.publicBase64().isEmpty(), "Public key must not be empty");
        // X25519 keys are 32 bytes = 44 chars in base64
        assertEquals(44, kp.publicBase64().length(),
                "Public key base64 must be 44 characters");
    }

    /**
     * Reconstructing a keypair from a secret key must reproduce the same
     * public key, and the secret keys must match.
     */
    @Test
    void keyPairFromSecretBase64Roundtrip() {
        VeilKeyPair original = VeilKeyPair.generate();
        VeilKeyPair restored = VeilKeyPair.fromSecretBase64(original.secretBase64());

        assertEquals(original.secretBase64(), restored.secretBase64(),
                "Secret keys must match after reconstruction");
        assertEquals(original.publicBase64(), restored.publicBase64(),
                "Public keys must match after reconstruction");
    }

    // ========================================================================
    // Client -> Server Request
    // ========================================================================

    /**
     * A client session encrypts a request; the server session (with the
     * matching keypair) must successfully decrypt it.
     */
    @Test
    void clientServerRequestRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] plaintext = "{\"query\":\"test request\"}".getBytes(StandardCharsets.UTF_8);

        VeilEnvelope envelope;
        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            envelope = client.encryptRequest(plaintext, "model-a");
        }

        try (VeilServerSession server = new VeilServerSession(
                kp.secretBase64(),
                envelope.getEphemeralKey(),
                envelope.getKeyId(),
                envelope.getRequestId(),
                envelope.getTimestamp())) {

            byte[] decrypted = server.decryptRequest(envelope);
            assertArrayEquals(plaintext, decrypted,
                    "Server must decrypt the client's request");
        }
    }

    /**
     * The server encrypts a response; the same client session that sent
     * the request must successfully decrypt it.
     */
    @Test
    void serverResponseRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] request = "request".getBytes(StandardCharsets.UTF_8);
        byte[] response = "{\"result\":\"success\"}".getBytes(StandardCharsets.UTF_8);

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope reqEnvelope = client.encryptRequest(request, "model");

            try (VeilServerSession server = new VeilServerSession(
                    kp.secretBase64(),
                    reqEnvelope.getEphemeralKey(),
                    reqEnvelope.getKeyId(),
                    reqEnvelope.getRequestId(),
                    reqEnvelope.getTimestamp())) {

                server.decryptRequest(reqEnvelope);
                VeilEnvelope respEnvelope = server.encryptResponse(response);

                byte[] decrypted = client.decryptResponse(respEnvelope);
                assertArrayEquals(response, decrypted,
                        "Client must decrypt the server's response");
            }
        }
    }

    /**
     * Full bidirectional roundtrip: client encrypts request, server decrypts,
     * server encrypts response, client decrypts.
     */
    @Test
    void fullBidirectionalRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] reqPayload = "{\"prompt\":\"explain ML\"}".getBytes(StandardCharsets.UTF_8);
        byte[] respPayload = "{\"answer\":\"Machine Learning is...\"}".getBytes(StandardCharsets.UTF_8);

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope reqEnv = client.encryptRequest(reqPayload, "chat");

            try (VeilServerSession server = new VeilServerSession(
                    kp.secretBase64(),
                    reqEnv.getEphemeralKey(),
                    reqEnv.getKeyId(),
                    reqEnv.getRequestId(),
                    reqEnv.getTimestamp())) {

                byte[] decryptedReq = server.decryptRequest(reqEnv);
                assertArrayEquals(reqPayload, decryptedReq);

                VeilEnvelope respEnv = server.encryptResponse(respPayload);
                byte[] decryptedResp = client.decryptResponse(respEnv);
                assertArrayEquals(respPayload, decryptedResp);
            }
        }
    }

    /**
     * Decrypting a request with the wrong server key must throw
     * {@link VeilException}.
     */
    @Test
    void wrongServerKeyFails() {
        VeilKeyPair correctKey = VeilKeyPair.generate();
        VeilKeyPair wrongKey = VeilKeyPair.generate();
        byte[] plaintext = "secret data".getBytes(StandardCharsets.UTF_8);

        VeilEnvelope envelope;
        try (VeilClientSession client = new VeilClientSession(correctKey.publicBase64(), KEY_ID)) {
            envelope = client.encryptRequest(plaintext, "model");
        }

        VeilEnvelope captured = envelope;
        assertThrows(VeilException.class, () -> {
            try (VeilServerSession server = new VeilServerSession(
                    wrongKey.secretBase64(),
                    captured.getEphemeralKey(),
                    captured.getKeyId(),
                    captured.getRequestId(),
                    captured.getTimestamp())) {
                server.decryptRequest(captured);
            }
        }, "Wrong server key must cause decryption to fail");
    }

    /**
     * A large payload (1 MB) must survive the asymmetric encrypt/decrypt
     * roundtrip.
     */
    @Test
    void largePayloadRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] large = new byte[1024 * 1024];
        new SecureRandom().nextBytes(large);

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope envelope = client.encryptRequest(large, "model");

            try (VeilServerSession server = new VeilServerSession(
                    kp.secretBase64(),
                    envelope.getEphemeralKey(),
                    envelope.getKeyId(),
                    envelope.getRequestId(),
                    envelope.getTimestamp())) {

                byte[] decrypted = server.decryptRequest(envelope);
                assertArrayEquals(large, decrypted,
                        "1 MB payload must survive asymmetric roundtrip");
            }
        }
    }

    /**
     * An empty payload must survive the asymmetric encrypt/decrypt roundtrip.
     */
    @Test
    void emptyPayloadRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] empty = new byte[0];

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope envelope = client.encryptRequest(empty, "model");

            try (VeilServerSession server = new VeilServerSession(
                    kp.secretBase64(),
                    envelope.getEphemeralKey(),
                    envelope.getKeyId(),
                    envelope.getRequestId(),
                    envelope.getTimestamp())) {

                byte[] decrypted = server.decryptRequest(envelope);
                assertArrayEquals(empty, decrypted,
                        "Empty payload must survive asymmetric roundtrip");
            }
        }
    }

    // ========================================================================
    // VeilEnvelope serialization
    // ========================================================================

    /**
     * {@link VeilEnvelope#toMap()} and {@link VeilEnvelope#fromMap(Map)}
     * must produce an identical envelope.
     */
    @Test
    void envelopeToMapFromMapRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope original = client.encryptRequest(
                    "roundtrip".getBytes(StandardCharsets.UTF_8), "model");

            Map<String, Object> map = original.toMap();
            VeilEnvelope restored = VeilEnvelope.fromMap(map);

            assertEquals(original.getVersion(), restored.getVersion());
            assertEquals(original.getNonce(), restored.getNonce());
            assertEquals(original.getCiphertext(), restored.getCiphertext());
            assertEquals(original.getAad(), restored.getAad());
            assertEquals(original.getEphemeralKey(), restored.getEphemeralKey());
            assertEquals(original.getKeyId(), restored.getKeyId());
            assertEquals(original.getTimestamp(), restored.getTimestamp());
            assertEquals(original.getRequestId(), restored.getRequestId());
        }
    }

    // ========================================================================
    // VeilMetadata
    // ========================================================================

    /**
     * The metadata produced after encrypting a request must contain
     * the expected X-Veil-* HTTP headers.
     */
    @Test
    void metadataToHeadersContainsVeilHeaders() {
        VeilKeyPair kp = VeilKeyPair.generate();

        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            client.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "chat");

            VeilMetadata metadata = client.getLastMetadata();
            assertNotNull(metadata, "getLastMetadata() must not be null after encrypt");

            Map<String, String> headers = metadata.toHeaders();
            assertTrue(headers.containsKey("X-Veil-Version"), "Must contain X-Veil-Version");
            assertTrue(headers.containsKey("X-Veil-Ephemeral-Key"), "Must contain X-Veil-Ephemeral-Key");
            assertTrue(headers.containsKey("X-Veil-Timestamp"), "Must contain X-Veil-Timestamp");
            assertTrue(headers.containsKey("X-Veil-Request-Id"), "Must contain X-Veil-Request-Id");

            assertFalse(headers.get("X-Veil-Ephemeral-Key").isEmpty(),
                    "Ephemeral key header must not be empty");
            assertFalse(headers.get("X-Veil-Request-Id").isEmpty(),
                    "Request ID header must not be empty");
        }
    }

    // ========================================================================
    // AutoCloseable
    // ========================================================================

    /**
     * Both client and server sessions must be usable with
     * try-with-resources and must not throw on close.
     */
    @Test
    void sessionAutoCloseable() {
        VeilKeyPair kp = VeilKeyPair.generate();

        // Client session auto-close
        assertDoesNotThrow(() -> {
            try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
                client.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "model");
            }
        }, "Client session try-with-resources must not throw");

        // Server session auto-close (need a valid envelope first)
        VeilEnvelope envelope;
        try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            envelope = client.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "model");
        }

        VeilEnvelope captured = envelope;
        assertDoesNotThrow(() -> {
            try (VeilServerSession server = new VeilServerSession(
                    kp.secretBase64(),
                    captured.getEphemeralKey(),
                    captured.getKeyId(),
                    captured.getRequestId(),
                    captured.getTimestamp())) {
                server.decryptRequest(captured);
            }
        }, "Server session try-with-resources must not throw");
    }

    /**
     * Closing a client session twice must not throw.
     */
    @Test
    void clientSessionCloseIdempotent() {
        VeilKeyPair kp = VeilKeyPair.generate();
        VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID);
        session.close();
        assertDoesNotThrow(session::close, "Second close() on client session must not throw");
    }

    /**
     * Using a closed client session must throw {@link VeilException}.
     */
    @Test
    void closedClientSessionThrows() {
        VeilKeyPair kp = VeilKeyPair.generate();
        VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID);
        session.close();

        assertThrows(VeilException.class,
                () -> session.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "model"),
                "Closed client session must throw on encrypt");
    }
}
