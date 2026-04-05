package io.veil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Asymmetric encrypted envelope -- wire format for ECDH-encrypted payloads.
 *
 * <p>An immutable value object that combines the cryptographic envelope
 * (nonce, ciphertext, AAD) with transport metadata (ephemeral key, key ID,
 * timestamp, request ID) into a single JSON-serializable structure.
 *
 * <p>Produced by {@link VeilClientSession#encryptRequest} and
 * {@link VeilServerSession#encryptResponse}. Consumed by
 * {@link VeilServerSession#decryptRequest} and
 * {@link VeilClientSession#decryptResponse}.
 *
 * <h3>Wire format (JSON):</h3>
 * <pre>{@code
 * {
 *   "version": 1,
 *   "nonce": "<base64-encoded AES-GCM nonce>",
 *   "ciphertext": "<base64-encoded ciphertext + GCM tag>",
 *   "aad": "<base64-encoded additional authenticated data>",
 *   "ephemeralKey": "<base64-encoded client ephemeral X25519 public key>",
 *   "keyId": "shim-v1",
 *   "timestamp": "2026-03-25T10:24:00Z",
 *   "requestId": "uuid-v4"
 * }
 * }</pre>
 *
 * <h3>Serialization:</h3>
 * <pre>{@code
 * VeilEnvelope envelope = session.encryptRequest(payload, "chat");
 * Map<String, Object> map = envelope.toMap();
 * // Serialize map to JSON with Jackson, Gson, etc.
 *
 * // Deserialize
 * VeilEnvelope restored = VeilEnvelope.fromMap(parsedMap);
 * }</pre>
 *
 * <p>Field names use camelCase to match the Rust/Python implementations:
 * {@code ephemeralKey}, {@code keyId}, {@code requestId}.
 *
 * @see VeilClientSession
 * @see VeilServerSession
 * @see VeilSymmetricEnvelope
 */
public class VeilEnvelope {

    private final int version;
    private final String nonce;         // base64
    private final String ciphertext;    // base64
    private final String aad;           // base64
    private final String ephemeralKey;  // base64
    private final String keyId;
    private final String timestamp;
    private final String requestId;

    /**
     * Construct an envelope from its constituent fields.
     *
     * <p>Typically not called directly -- use {@link VeilClientSession#encryptRequest},
     * {@link VeilServerSession#encryptResponse}, or {@link VeilEnvelope#fromMap(Map)}.
     *
     * @param version      Protocol version (currently always 1)
     * @param nonce        Base64-encoded AES-GCM nonce
     * @param ciphertext   Base64-encoded ciphertext with appended GCM tag
     * @param aad          Base64-encoded additional authenticated data
     * @param ephemeralKey Base64-encoded client ephemeral X25519 public key
     * @param keyId        Server key identifier (e.g., "shim-v1")
     * @param timestamp    ISO 8601 timestamp of the request
     * @param requestId    UUID v4 request identifier
     */
    public VeilEnvelope(
            int version,
            String nonce,
            String ciphertext,
            String aad,
            String ephemeralKey,
            String keyId,
            String timestamp,
            String requestId
    ) {
        this.version = version;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
        this.aad = aad;
        this.ephemeralKey = ephemeralKey;
        this.keyId = keyId;
        this.timestamp = timestamp;
        this.requestId = requestId;
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    /** @return Protocol version (currently 1). */
    public int getVersion() { return version; }

    /** @return Base64-encoded AES-GCM nonce. */
    public String getNonce() { return nonce; }

    /** @return Base64-encoded ciphertext with appended GCM authentication tag. */
    public String getCiphertext() { return ciphertext; }

    /** @return Base64-encoded additional authenticated data. */
    public String getAad() { return aad; }

    /** @return Base64-encoded client ephemeral X25519 public key. */
    public String getEphemeralKey() { return ephemeralKey; }

    /** @return Server key identifier (e.g., "shim-v1"). */
    public String getKeyId() { return keyId; }

    /** @return ISO 8601 timestamp of the request. */
    public String getTimestamp() { return timestamp; }

    /** @return UUID v4 request identifier. */
    public String getRequestId() { return requestId; }

    // ── Serialization ────────────────────────────────────────────────────────

    /**
     * Convert this envelope to a {@link Map} matching the JSON wire format
     * expected by the Veil Shim/Agent.
     *
     * <p>The returned map can be serialized to JSON with any library
     * (Jackson, Gson, etc.) for HTTP transport.
     *
     * @return A mutable {@link LinkedHashMap} with insertion-ordered keys
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("version", version);
        map.put("nonce", nonce);
        map.put("ciphertext", ciphertext);
        map.put("aad", aad);
        map.put("ephemeralKey", ephemeralKey);
        map.put("keyId", keyId);
        map.put("timestamp", timestamp);
        map.put("requestId", requestId);
        return map;
    }

    /**
     * Reconstruct an envelope from a {@link Map} (e.g., parsed from a JSON response).
     *
     * <p>This is the inverse of {@link #toMap()}. The map must contain all
     * eight keys: version, nonce, ciphertext, aad, ephemeralKey, keyId,
     * timestamp, and requestId.
     *
     * @param map Map containing the envelope fields
     * @return A reconstructed {@link VeilEnvelope}
     * @throws ClassCastException if the map values have unexpected types
     * @throws NullPointerException if required keys are missing
     */
    @SuppressWarnings("unchecked")
    public static VeilEnvelope fromMap(Map<String, Object> map) {
        return new VeilEnvelope(
                ((Number) map.get("version")).intValue(),
                (String) map.get("nonce"),
                (String) map.get("ciphertext"),
                (String) map.get("aad"),
                (String) map.get("ephemeralKey"),
                (String) map.get("keyId"),
                (String) map.get("timestamp"),
                (String) map.get("requestId")
        );
    }

    @Override
    public String toString() {
        return "VeilEnvelope{version=" + version +
                ", keyId=" + keyId +
                ", requestId=" + requestId +
                ", payloadSize=" + (ciphertext != null ? ciphertext.length() : 0) + "}";
    }
}
