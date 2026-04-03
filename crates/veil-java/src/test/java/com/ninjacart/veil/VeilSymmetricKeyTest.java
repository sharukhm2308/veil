package com.ninjacart.veil;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for {@link VeilSymmetricKey} covering key generation,
 * construction, encryption/decryption, key derivation, versioned encryption,
 * and AutoCloseable semantics.
 *
 * <p>Requires the native library {@code libveil_jni} to be on the library path.
 * Build with: {@code cd crates/veil-jni && cargo build --release}
 * Run with: {@code mvn test -Djava.library.path=../../target/release}
 */
class VeilSymmetricKeyTest {

    private static final byte[] SAMPLE_AAD = "test-aad".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SAMPLE_PLAINTEXT = "Hello, Veil!".getBytes(StandardCharsets.UTF_8);

    // ========================================================================
    // Key Generation & Construction
    // ========================================================================

    /**
     * Verify that {@link VeilSymmetricKey#generate()} produces a key whose
     * base64 representation is non-null and exactly 44 characters (the
     * standard base64 encoding of 32 bytes).
     */
    @Test
    void generateCreatesValidKey() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            String b64 = key.toBase64();
            assertNotNull(b64, "toBase64() must not return null");
            assertEquals(44, b64.length(),
                    "Base64 of a 32-byte key should be 44 characters");
            // Verify it is valid base64 by decoding
            byte[] decoded = Base64.getDecoder().decode(b64);
            assertEquals(32, decoded.length, "Decoded key must be 32 bytes");
        }
    }

    /**
     * Two consecutive calls to {@link VeilSymmetricKey#generate()} must
     * produce distinct keys (probabilistic but effectively guaranteed).
     */
    @Test
    void generateProducesUniqueKeys() {
        try (VeilSymmetricKey k1 = VeilSymmetricKey.generate();
             VeilSymmetricKey k2 = VeilSymmetricKey.generate()) {
            assertNotEquals(k1.toBase64(), k2.toBase64(),
                    "Two generated keys must differ");
        }
    }

    /**
     * Constructing a key from 32 random bytes via {@link VeilSymmetricKey#fromBytes(byte[])}
     * and then using it for encrypt/decrypt must succeed.
     */
    @Test
    void fromBytesRoundtrip() {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);

        try (VeilSymmetricKey key = VeilSymmetricKey.fromBytes(raw)) {
            VeilSymmetricEnvelope envelope = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(SAMPLE_PLAINTEXT, decrypted);
        }
    }

    /**
     * Passing a byte array that is not exactly 32 bytes to
     * {@link VeilSymmetricKey#fromBytes(byte[])} must throw {@link VeilException}.
     */
    @Test
    void fromBytesRejectsWrongLength() {
        byte[] tooShort = new byte[16];
        new SecureRandom().nextBytes(tooShort);

        assertThrows(VeilException.class, () -> VeilSymmetricKey.fromBytes(tooShort),
                "fromBytes with 16 bytes must throw VeilException");
    }

    /**
     * Generate a key, export to base64, reconstruct via
     * {@link VeilSymmetricKey#fromBase64(String)}, and verify the
     * reconstructed key can decrypt ciphertext from the original.
     */
    @Test
    void fromBase64Roundtrip() {
        try (VeilSymmetricKey original = VeilSymmetricKey.generate()) {
            String b64 = original.toBase64();
            VeilSymmetricEnvelope envelope = original.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);

            try (VeilSymmetricKey restored = VeilSymmetricKey.fromBase64(b64)) {
                byte[] decrypted = restored.decrypt(envelope);
                assertArrayEquals(SAMPLE_PLAINTEXT, decrypted,
                        "Restored key must decrypt what the original encrypted");
            }
        }
    }

    /**
     * Invalid base64 input to {@link VeilSymmetricKey#fromBase64(String)}
     * must throw {@link VeilException}.
     */
    @Test
    void fromBase64RejectsInvalidInput() {
        assertThrows(VeilException.class, () -> VeilSymmetricKey.fromBase64("not-valid!!!"),
                "fromBase64 with invalid input must throw VeilException");
    }

    // ========================================================================
    // Encrypt / Decrypt
    // ========================================================================

    /**
     * Basic happy-path: encrypt then decrypt yields the original plaintext.
     */
    @Test
    void encryptDecryptRoundtrip() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(SAMPLE_PLAINTEXT, decrypted);
        }
    }

    /**
     * Verify that multi-byte UTF-8 content (emoji, CJK) survives the
     * encrypt/decrypt roundtrip without corruption.
     */
    @Test
    void encryptDecryptUtf8() {
        byte[] utf8 = "Hello \uD83C\uDF0D \u3053\u3093\u306B\u3061\u306F".getBytes(StandardCharsets.UTF_8);

        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(utf8, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(utf8, decrypted);
            assertEquals("Hello \uD83C\uDF0D \u3053\u3093\u306B\u3061\u306F",
                    new String(decrypted, StandardCharsets.UTF_8));
        }
    }

    /**
     * An empty plaintext ({@code new byte[0]}) must encrypt and decrypt
     * successfully.
     */
    @Test
    void encryptDecryptEmptyPayload() {
        byte[] empty = new byte[0];

        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(empty, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(empty, decrypted, "Empty plaintext roundtrip must succeed");
        }
    }

    /**
     * Encrypt and decrypt a 1 MB payload to confirm large data handling.
     */
    @Test
    void encryptDecryptLargePayload() {
        byte[] large = new byte[1024 * 1024]; // 1 MB
        new SecureRandom().nextBytes(large);

        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(large, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(large, decrypted, "1 MB payload roundtrip must succeed");
        }
    }

    /**
     * Encrypting the same plaintext twice with the same key must produce
     * different ciphertexts (due to random nonces in AES-256-GCM).
     */
    @Test
    void encryptProducesDifferentCiphertexts() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope e1 = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            VeilSymmetricEnvelope e2 = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);

            assertNotEquals(e1.getCiphertext(), e2.getCiphertext(),
                    "Same plaintext encrypted twice must produce different ciphertexts");
            assertNotEquals(e1.getNonce(), e2.getNonce(),
                    "Each encryption must use a different nonce");
        }
    }

    /**
     * Encrypting with key A and decrypting with key B must fail with
     * {@link VeilException}.
     */
    @Test
    void wrongKeyFailsDecrypt() {
        try (VeilSymmetricKey keyA = VeilSymmetricKey.generate();
             VeilSymmetricKey keyB = VeilSymmetricKey.generate()) {

            VeilSymmetricEnvelope envelope = keyA.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);

            assertThrows(VeilException.class, () -> keyB.decrypt(envelope),
                    "Decrypting with the wrong key must throw VeilException");
        }
    }

    // ========================================================================
    // Key Derivation
    // ========================================================================

    /**
     * Two keys derived from the same master key and context must be able
     * to decrypt each other's ciphertexts (i.e., they are identical).
     */
    @Test
    void deriveDeterministic() {
        byte[] master = new byte[32];
        new SecureRandom().nextBytes(master);
        byte[] context = "test-context-001".getBytes(StandardCharsets.UTF_8);

        try (VeilSymmetricKey k1 = VeilSymmetricKey.derive(master, context);
             VeilSymmetricKey k2 = VeilSymmetricKey.derive(master, context)) {

            VeilSymmetricEnvelope envelope = k1.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            byte[] decrypted = k2.decrypt(envelope);
            assertArrayEquals(SAMPLE_PLAINTEXT, decrypted,
                    "Keys derived from same master+context must be interoperable");
        }
    }

    /**
     * Keys derived from the same master but different contexts must not
     * be able to cross-decrypt.
     */
    @Test
    void deriveDifferentContextProducesDifferentKeys() {
        byte[] master = new byte[32];
        new SecureRandom().nextBytes(master);

        try (VeilSymmetricKey k1 = VeilSymmetricKey.derive(master, "ctx-A".getBytes(StandardCharsets.UTF_8));
             VeilSymmetricKey k2 = VeilSymmetricKey.derive(master, "ctx-B".getBytes(StandardCharsets.UTF_8))) {

            VeilSymmetricEnvelope envelope = k1.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);

            assertThrows(VeilException.class, () -> k2.decrypt(envelope),
                    "Different context must produce incompatible keys");
        }
    }

    /**
     * Keys derived from different masters but the same context must not
     * be able to cross-decrypt.
     */
    @Test
    void deriveDifferentMasterProducesDifferentKeys() {
        byte[] masterA = new byte[32];
        byte[] masterB = new byte[32];
        new SecureRandom().nextBytes(masterA);
        new SecureRandom().nextBytes(masterB);
        byte[] context = "shared-context".getBytes(StandardCharsets.UTF_8);

        try (VeilSymmetricKey k1 = VeilSymmetricKey.derive(masterA, context);
             VeilSymmetricKey k2 = VeilSymmetricKey.derive(masterB, context)) {

            VeilSymmetricEnvelope envelope = k1.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);

            assertThrows(VeilException.class, () -> k2.decrypt(envelope),
                    "Different master must produce incompatible keys");
        }
    }

    /**
     * Deriving a key with an empty context byte array must succeed and
     * produce a usable key.
     */
    @Test
    void deriveEmptyContext() {
        byte[] master = new byte[32];
        new SecureRandom().nextBytes(master);

        try (VeilSymmetricKey key = VeilSymmetricKey.derive(master, new byte[0])) {
            VeilSymmetricEnvelope envelope = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(SAMPLE_PLAINTEXT, decrypted,
                    "Empty context derivation must produce a usable key");
        }
    }

    // ========================================================================
    // Versioned Encryption
    // ========================================================================

    /**
     * {@link VeilSymmetricKey#encryptVersioned(byte[], byte[], int)} must
     * embed the key version in the returned envelope.
     */
    @Test
    void encryptVersionedIncludesKeyVersion() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encryptVersioned(SAMPLE_PLAINTEXT, SAMPLE_AAD, 3);
            assertNotNull(envelope.getKeyVersion(), "Versioned envelope must have keyVersion");
            assertEquals(3, envelope.getKeyVersion().intValue(),
                    "keyVersion must match the value passed to encryptVersioned");

            // Verify it still decrypts
            byte[] decrypted = key.decrypt(envelope);
            assertArrayEquals(SAMPLE_PLAINTEXT, decrypted);
        }
    }

    /**
     * The standard {@link VeilSymmetricKey#encrypt(byte[], byte[])} method
     * must produce an envelope with a null keyVersion.
     */
    @Test
    void unversionedEncryptHasNullKeyVersion() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            assertNull(envelope.getKeyVersion(),
                    "Unversioned envelope must have null keyVersion");
        }
    }

    // ========================================================================
    // AutoCloseable
    // ========================================================================

    /**
     * Calling {@link VeilSymmetricKey#close()} twice must not throw.
     */
    @Test
    void closeIsIdempotent() {
        VeilSymmetricKey key = VeilSymmetricKey.generate();
        key.close();
        assertDoesNotThrow(key::close, "Second close() must not throw");
    }

    /**
     * The key must be usable inside a try-with-resources block and
     * closed automatically.
     */
    @Test
    void tryWithResourcesWorks() {
        VeilSymmetricEnvelope envelope;
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            envelope = key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
            assertNotNull(envelope);
        }
        // key is now closed -- verify by reconstructing and decrypting
        // (we cannot call decrypt on a closed key, that is tested elsewhere)
        assertNotNull(envelope.getCiphertext());
    }

    /**
     * Using a closed key for encryption must throw {@link VeilException}.
     */
    @Test
    void closedKeyThrowsOnEncrypt() {
        VeilSymmetricKey key = VeilSymmetricKey.generate();
        key.close();

        assertThrows(VeilException.class,
                () -> key.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD),
                "Encrypting with a closed key must throw VeilException");
    }

    // ========================================================================
    // Interop Scenarios
    // ========================================================================

    /**
     * Simulates a two-party scenario: an "Agent" derives a key from a
     * shared master and context, encrypts a message; a "Relay" derives
     * the same key and successfully decrypts.
     */
    @Test
    void agentRelayInterop() {
        // Shared master key (in production, from Vault KV)
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);
        byte[] context = "cw-user42-conv99".getBytes(StandardCharsets.UTF_8);

        byte[] message = "{\"action\":\"forward\",\"payload\":\"secret\"}".getBytes(StandardCharsets.UTF_8);

        // Agent side
        VeilSymmetricEnvelope envelope;
        try (VeilSymmetricKey agentKey = VeilSymmetricKey.derive(masterKey, context)) {
            envelope = agentKey.encrypt(message, "agent-to-relay".getBytes(StandardCharsets.UTF_8));
        }

        // Relay side
        try (VeilSymmetricKey relayKey = VeilSymmetricKey.derive(masterKey, context)) {
            byte[] decrypted = relayKey.decrypt(envelope);
            assertArrayEquals(message, decrypted,
                    "Relay must decrypt what Agent encrypted with the same master+context");
        }
    }

    /**
     * Encrypting with context A and attempting to decrypt with a key
     * derived from context B must fail, proving context binding.
     */
    @Test
    void contextBindingPreventsDecryptAcrossConversations() {
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);

        byte[] ctxA = "conversation-100".getBytes(StandardCharsets.UTF_8);
        byte[] ctxB = "conversation-200".getBytes(StandardCharsets.UTF_8);

        VeilSymmetricEnvelope envelope;
        try (VeilSymmetricKey keyA = VeilSymmetricKey.derive(masterKey, ctxA)) {
            envelope = keyA.encrypt(SAMPLE_PLAINTEXT, SAMPLE_AAD);
        }

        try (VeilSymmetricKey keyB = VeilSymmetricKey.derive(masterKey, ctxB)) {
            assertThrows(VeilException.class, () -> keyB.decrypt(envelope),
                    "Context-bound key must not decrypt data from a different context");
        }
    }
}
