package io.veil;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link VeilSymmetricEnvelope} covering serialization roundtrips,
 * map key presence, key version handling, getter correctness, and toString.
 *
 * <p>Requires the native library {@code libveil_jni} to be on the library path.
 * Build with: {@code cd crates/veil-jni && cargo build --release}
 * Run with: {@code mvn test -Djava.library.path=../../target/release}
 */
class VeilSymmetricEnvelopeTest {

    private static final byte[] PLAINTEXT = "envelope-test".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "envelope-aad".getBytes(StandardCharsets.UTF_8);

    /**
     * Encrypt, convert the envelope to a map, reconstruct from the map,
     * and verify that the reconstructed envelope decrypts to the original
     * plaintext.
     */
    @Test
    void toMapFromMapRoundtrip() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope original = key.encrypt(PLAINTEXT, AAD);

            Map<String, Object> map = original.toMap();
            VeilSymmetricEnvelope restored = VeilSymmetricEnvelope.fromMap(map);

            // Verify field equality
            assertEquals(original.getVersion(), restored.getVersion());
            assertEquals(original.getNonce(), restored.getNonce());
            assertEquals(original.getCiphertext(), restored.getCiphertext());
            assertEquals(original.getAad(), restored.getAad());
            assertEquals(original.getKeyVersion(), restored.getKeyVersion());

            // Verify the restored envelope still decrypts
            byte[] decrypted = key.decrypt(restored);
            assertArrayEquals(PLAINTEXT, decrypted,
                    "Envelope reconstructed from map must still decrypt correctly");
        }
    }

    /**
     * The map produced by {@link VeilSymmetricEnvelope#toMap()} must contain
     * the expected keys: version, nonce, ciphertext, and aad.
     */
    @Test
    void toMapContainsExpectedKeys() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(PLAINTEXT, AAD);
            Map<String, Object> map = envelope.toMap();

            assertTrue(map.containsKey("version"), "Map must contain 'version'");
            assertTrue(map.containsKey("nonce"), "Map must contain 'nonce'");
            assertTrue(map.containsKey("ciphertext"), "Map must contain 'ciphertext'");
            assertTrue(map.containsKey("aad"), "Map must contain 'aad'");
            assertEquals(1, map.get("version"), "Version must be 1");
        }
    }

    /**
     * A versioned envelope's map must include the "keyVersion" key with
     * the correct integer value.
     */
    @Test
    void toMapIncludesKeyVersionWhenPresent() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encryptVersioned(PLAINTEXT, AAD, 7);
            Map<String, Object> map = envelope.toMap();

            assertTrue(map.containsKey("keyVersion"), "Versioned map must contain 'keyVersion'");
            assertEquals(7, map.get("keyVersion"), "keyVersion must match");
        }
    }

    /**
     * An unversioned envelope's map must not contain the "keyVersion" key.
     */
    @Test
    void toMapOmitsKeyVersionWhenNull() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(PLAINTEXT, AAD);
            Map<String, Object> map = envelope.toMap();

            assertFalse(map.containsKey("keyVersion"),
                    "Unversioned map must not contain 'keyVersion'");
        }
    }

    /**
     * The nonce, ciphertext, and aad getters must return valid base64
     * strings that decode without error.
     */
    @Test
    void gettersReturnBase64Strings() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(PLAINTEXT, AAD);

            assertDoesNotThrow(() -> Base64.getDecoder().decode(envelope.getNonce()),
                    "getNonce() must return valid base64");
            assertDoesNotThrow(() -> Base64.getDecoder().decode(envelope.getCiphertext()),
                    "getCiphertext() must return valid base64");
            assertDoesNotThrow(() -> Base64.getDecoder().decode(envelope.getAad()),
                    "getAad() must return valid base64");
        }
    }

    /**
     * The {@link VeilSymmetricEnvelope#toString()} representation must
     * contain the version number for debugging.
     */
    @Test
    void toStringContainsVersion() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope envelope = key.encrypt(PLAINTEXT, AAD);
            String str = envelope.toString();

            assertTrue(str.contains("version=1"), "toString() must contain version info");
            assertTrue(str.contains("VeilSymmetricEnvelope"),
                    "toString() must contain class name");
        }
    }

    /**
     * Verify the versioned fromMap roundtrip preserves the keyVersion.
     */
    @Test
    void fromMapPreservesKeyVersion() {
        try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
            VeilSymmetricEnvelope original = key.encryptVersioned(PLAINTEXT, AAD, 5);
            Map<String, Object> map = original.toMap();
            VeilSymmetricEnvelope restored = VeilSymmetricEnvelope.fromMap(map);

            assertNotNull(restored.getKeyVersion());
            assertEquals(5, restored.getKeyVersion().intValue(),
                    "keyVersion must survive map roundtrip");
        }
    }
}
