package io.veil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Symmetric encryption envelope -- wire format for AES-256-GCM encrypted payloads.
 *
 * <p>An immutable value object that bundles everything needed to decrypt an
 * AES-256-GCM ciphertext: the random nonce, the ciphertext (which includes
 * the 16-byte GCM authentication tag), and the base64-encoded AAD. Optionally
 * carries a {@code keyVersion} integer for key-rotation tracking.
 *
 * <p>Produced by {@link VeilSymmetricKey#encrypt(byte[], byte[])} or
 * {@link VeilSymmetricKey#encryptVersioned(byte[], byte[], int)}, and consumed
 * by {@link VeilSymmetricKey#decrypt(VeilSymmetricEnvelope)}.
 *
 * <h3>Wire format (JSON):</h3>
 * <pre>{@code
 * {
 *   "version": 1,
 *   "nonce": "<base64-encoded 12-byte nonce>",
 *   "ciphertext": "<base64-encoded ciphertext + GCM tag>",
 *   "aad": "<base64-encoded additional authenticated data>",
 *   "keyVersion": 3   // present only for versioned envelopes
 * }
 * }</pre>
 *
 * <h3>Serialization example:</h3>
 * <pre>{@code
 * // Serialize for storage or transport
 * VeilSymmetricEnvelope envelope = key.encrypt(plaintext, aad);
 * Map<String, Object> map = envelope.toMap();
 * String json = new ObjectMapper().writeValueAsString(map);
 *
 * // Deserialize
 * Map<String, Object> parsed = new ObjectMapper().readValue(json, Map.class);
 * VeilSymmetricEnvelope restored = VeilSymmetricEnvelope.fromMap(parsed);
 * byte[] decrypted = key.decrypt(restored);
 * }</pre>
 *
 * <p>Field names use camelCase to match the Rust/Python implementations.
 *
 * @see VeilSymmetricKey
 */
public class VeilSymmetricEnvelope {

    private final int version;
    private final String nonce;         // base64
    private final String ciphertext;    // base64
    private final String aad;           // base64
    private final Integer keyVersion;   // nullable

    /**
     * Construct a symmetric envelope from its constituent fields.
     *
     * <p>Typically not called directly -- use {@link VeilSymmetricKey#encrypt}
     * or {@link VeilSymmetricEnvelope#fromMap(Map)} instead.
     *
     * @param version    Protocol version (currently always 1)
     * @param nonce      Base64-encoded 12-byte AES-GCM nonce
     * @param ciphertext Base64-encoded ciphertext with appended GCM tag
     * @param aad        Base64-encoded additional authenticated data
     * @param keyVersion Key version for rotation tracking, or {@code null}
     */
    public VeilSymmetricEnvelope(
            int version,
            String nonce,
            String ciphertext,
            String aad,
            Integer keyVersion
    ) {
        this.version = version;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
        this.aad = aad;
        this.keyVersion = keyVersion;
    }

    // -- Getters ----------------------------------------------------------------

    /** @return Protocol version (currently 1). */
    public int getVersion() { return version; }

    /** @return Base64-encoded 12-byte AES-GCM nonce. */
    public String getNonce() { return nonce; }

    /** @return Base64-encoded ciphertext with appended GCM authentication tag. */
    public String getCiphertext() { return ciphertext; }

    /** @return Base64-encoded additional authenticated data. */
    public String getAad() { return aad; }

    /** @return Key version for rotation tracking, or {@code null} if unversioned. */
    public Integer getKeyVersion() { return keyVersion; }

    // -- Serialization ----------------------------------------------------------

    /**
     * Convert this envelope to a {@link Map} matching the JSON wire format.
     *
     * <p>The map can be serialized to JSON with any library (Jackson, Gson,
     * etc.) for storage or transport. The "keyVersion" key is omitted when
     * {@link #getKeyVersion()} is {@code null}.
     *
     * <pre>{@code
     * {
     *   "version": 1,
     *   "nonce": "base64...",
     *   "ciphertext": "base64...",
     *   "aad": "base64...",
     *   "keyVersion": 3          // omitted if null
     * }
     * }</pre>
     *
     * @return A mutable {@link LinkedHashMap} with insertion-ordered keys
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", version);
        map.put("nonce", nonce);
        map.put("ciphertext", ciphertext);
        map.put("aad", aad);
        if (keyVersion != null) {
            map.put("keyVersion", keyVersion);
        }
        return map;
    }

    /**
     * Reconstruct an envelope from a {@link Map} (e.g., parsed from JSON).
     *
     * <p>This is the inverse of {@link #toMap()}. The map must contain
     * "version", "nonce", "ciphertext", and "aad" keys. The "keyVersion"
     * key is optional.
     *
     * @param map Map containing the envelope fields
     * @return A reconstructed {@link VeilSymmetricEnvelope}
     * @throws ClassCastException if the map values have unexpected types
     * @throws NullPointerException if required keys are missing
     */
    @SuppressWarnings("unchecked")
    public static VeilSymmetricEnvelope fromMap(Map<String, Object> map) {
        Integer kv = map.containsKey("keyVersion") && map.get("keyVersion") != null
                ? ((Number) map.get("keyVersion")).intValue()
                : null;
        return new VeilSymmetricEnvelope(
                ((Number) map.get("version")).intValue(),
                (String) map.get("nonce"),
                (String) map.get("ciphertext"),
                (String) map.get("aad"),
                kv
        );
    }

    @Override
    public String toString() {
        return "VeilSymmetricEnvelope{version=" + version +
                ", keyVersion=" + keyVersion +
                ", payloadSize=" + (ciphertext != null ? ciphertext.length() : 0) + "}";
    }
}
