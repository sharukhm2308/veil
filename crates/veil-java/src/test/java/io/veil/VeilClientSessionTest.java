package io.veil;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Java Veil SDK (JNI bindings to Rust veil-core).
 *
 * <p>Requires the native library {@code libveil_jni} to be on the library path.
 * Build with: {@code cd crates/veil-jni && cargo build --release}
 * Run with: {@code mvn test -Djava.library.path=../../target/release}
 */
class VeilClientSessionTest {

    private static final String KEY_ID = "test-key-v1";

    @Test
    void keyPairGeneration() {
        VeilKeyPair kp = VeilKeyPair.generate();
        assertNotNull(kp.secretBase64());
        assertNotNull(kp.publicBase64());
        assertFalse(kp.secretBase64().isEmpty());
        assertFalse(kp.publicBase64().isEmpty());
    }

    @Test
    void keyPairFromSecret() {
        VeilKeyPair kp1 = VeilKeyPair.generate();
        VeilKeyPair kp2 = VeilKeyPair.fromSecretBase64(kp1.secretBase64());
        assertEquals(kp1.publicBase64(), kp2.publicBase64());
        assertEquals(kp1.secretBase64(), kp2.secretBase64());
    }

    @Test
    void encryptProducesValidEnvelope() {
        VeilKeyPair kp = VeilKeyPair.generate();

        try (VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope env = session.encryptRequest(
                    "{\"query\": \"hello\"}".getBytes(StandardCharsets.UTF_8), "test-model");

            assertEquals(1, env.getVersion());
            assertEquals(KEY_ID, env.getKeyId());
            assertNotNull(env.getRequestId());
            assertFalse(env.getRequestId().isEmpty());
            assertNotNull(env.getTimestamp());
            assertNotNull(env.getEphemeralKey());
            assertNotNull(env.getNonce());
            assertNotNull(env.getCiphertext());
            assertNotNull(env.getAad());
        }
    }

    @Test
    void differentSessionsProduceDifferentCiphertexts() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] plaintext = "same message".getBytes(StandardCharsets.UTF_8);

        try (VeilClientSession s1 = new VeilClientSession(kp.publicBase64(), KEY_ID);
             VeilClientSession s2 = new VeilClientSession(kp.publicBase64(), KEY_ID)) {

            VeilEnvelope e1 = s1.encryptRequest(plaintext, "model");
            VeilEnvelope e2 = s2.encryptRequest(plaintext, "model");

            assertNotEquals(e1.getCiphertext(), e2.getCiphertext());
            assertNotEquals(e1.getNonce(), e2.getNonce());
            assertNotEquals(e1.getEphemeralKey(), e2.getEphemeralKey());
        }
    }

    @Test
    void envelopeSerializationRoundtrip() {
        VeilKeyPair kp = VeilKeyPair.generate();

        try (VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            VeilEnvelope env = session.encryptRequest(
                    "test".getBytes(StandardCharsets.UTF_8), "model");

            Map<String, Object> map = env.toMap();
            VeilEnvelope restored = VeilEnvelope.fromMap(map);

            assertEquals(env.getVersion(), restored.getVersion());
            assertEquals(env.getNonce(), restored.getNonce());
            assertEquals(env.getCiphertext(), restored.getCiphertext());
            assertEquals(env.getAad(), restored.getAad());
            assertEquals(env.getEphemeralKey(), restored.getEphemeralKey());
            assertEquals(env.getKeyId(), restored.getKeyId());
            assertEquals(env.getTimestamp(), restored.getTimestamp());
            assertEquals(env.getRequestId(), restored.getRequestId());
        }
    }

    @Test
    void fullRoundTrip() {
        VeilKeyPair kp = VeilKeyPair.generate();
        byte[] plaintext = "{\"query\": \"What is ML?\"}".getBytes(StandardCharsets.UTF_8);

        // Client encrypts
        VeilEnvelope envelope;
        VeilClientSession client = new VeilClientSession(kp.publicBase64(), KEY_ID);
        envelope = client.encryptRequest(plaintext, "chat");

        // Server decrypts
        try (VeilServerSession server = new VeilServerSession(
                kp.secretBase64(),
                envelope.getEphemeralKey(),
                envelope.getKeyId(),
                envelope.getRequestId(),
                envelope.getTimestamp())) {

            byte[] decrypted = server.decryptRequest(envelope);
            assertArrayEquals(plaintext, decrypted);

            // Server encrypts response
            byte[] responseBytes = "{\"result\": \"ok\"}".getBytes(StandardCharsets.UTF_8);
            VeilEnvelope respEnvelope = server.encryptResponse(responseBytes);
            assertNotNull(respEnvelope.getCiphertext());
            assertNotNull(respEnvelope.getNonce());

            // Client decrypts response
            byte[] decryptedResp = client.decryptResponse(respEnvelope);
            assertArrayEquals(responseBytes, decryptedResp);
        }

        client.close();
    }

    @Test
    void wrongKeyCannotDecrypt() {
        VeilKeyPair correctKey = VeilKeyPair.generate();
        VeilKeyPair wrongKey = VeilKeyPair.generate();
        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);

        VeilEnvelope envelope;
        try (VeilClientSession session = new VeilClientSession(correctKey.publicBase64(), KEY_ID)) {
            envelope = session.encryptRequest(plaintext, "model");
        }

        // Trying to decrypt with wrong key should fail
        assertThrows(VeilException.class, () -> {
            try (VeilServerSession server = new VeilServerSession(
                    wrongKey.secretBase64(),
                    envelope.getEphemeralKey(),
                    envelope.getKeyId(),
                    envelope.getRequestId(),
                    envelope.getTimestamp())) {
                server.decryptRequest(envelope);
            }
        });
    }

    @Test
    void closedSessionThrows() {
        VeilKeyPair kp = VeilKeyPair.generate();
        VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID);
        session.close();

        assertThrows(VeilException.class, () ->
                session.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "model"));
    }

    @Test
    void metadataFields() {
        VeilKeyPair kp = VeilKeyPair.generate();

        try (VeilClientSession session = new VeilClientSession(kp.publicBase64(), KEY_ID)) {
            session.encryptRequest("test".getBytes(StandardCharsets.UTF_8), "chat-model");

            assertNotNull(session.getRequestId());
            assertNotNull(session.getTimestamp());
            assertNotNull(session.getEphemeralPublicB64());
            assertFalse(session.getRequestId().isEmpty());
        }
    }
}
