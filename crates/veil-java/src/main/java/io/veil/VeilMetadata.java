package io.veil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Request metadata carried as HTTP headers alongside the encrypted envelope.
 *
 * <p>Contains the key ID, ephemeral public key, model identifier, optional
 * token estimate, timestamp, and request ID. These fields are sent as
 * {@code X-Veil-*} HTTP headers so that the server (or intermediary proxy)
 * can route and validate requests before decrypting the payload.
 *
 * <p>Obtained from {@link VeilClientSession#getLastMetadata()} after an
 * {@link VeilClientSession#encryptRequest} call.
 *
 * <h3>Usage:</h3>
 * <pre>{@code
 * try (VeilClientSession session = new VeilClientSession(pubKeyB64, "shim-v1")) {
 *     VeilEnvelope envelope = session.encryptRequest(payload, "chat");
 *     VeilMetadata metadata = session.getLastMetadata();
 *
 *     // Add Veil headers to the HTTP request
 *     Map<String, String> headers = metadata.toHeaders();
 *     headers.forEach(httpRequest::addHeader);
 * }
 * }</pre>
 *
 * @see VeilClientSession#getLastMetadata()
 */
public class VeilMetadata {

    private final int version;
    private final String keyId;
    private final String ephemeralKey;
    private final String model;
    private final Integer tokenEstimate;
    private final String timestamp;
    private final String requestId;

    /**
     * Construct metadata from its constituent fields.
     *
     * @param version       Protocol version (currently always 1)
     * @param keyId         Server key identifier (e.g., "shim-v1")
     * @param ephemeralKey  Base64-encoded client ephemeral X25519 public key
     * @param model         Model/tool identifier (e.g., "chat", "embedding")
     * @param tokenEstimate Estimated token count, or {@code null} if unknown
     * @param timestamp     ISO 8601 timestamp of the request
     * @param requestId     UUID v4 request identifier
     */
    public VeilMetadata(
            int version,
            String keyId,
            String ephemeralKey,
            String model,
            Integer tokenEstimate,
            String timestamp,
            String requestId
    ) {
        this.version = version;
        this.keyId = keyId;
        this.ephemeralKey = ephemeralKey;
        this.model = model;
        this.tokenEstimate = tokenEstimate;
        this.timestamp = timestamp;
        this.requestId = requestId;
    }

    /** @return Protocol version (currently 1). */
    public int getVersion() { return version; }

    /** @return Server key identifier (e.g., "shim-v1"), or {@code null}. */
    public String getKeyId() { return keyId; }

    /** @return Base64-encoded client ephemeral X25519 public key. */
    public String getEphemeralKey() { return ephemeralKey; }

    /** @return Model/tool identifier (e.g., "chat"), or {@code null}. */
    public String getModel() { return model; }

    /** @return Estimated token count, or {@code null} if unknown. */
    public Integer getTokenEstimate() { return tokenEstimate; }

    /** @return ISO 8601 timestamp of the request. */
    public String getTimestamp() { return timestamp; }

    /** @return UUID v4 request identifier. */
    public String getRequestId() { return requestId; }

    /**
     * Convert this metadata to a map of HTTP headers in {@code X-Veil-*} format.
     *
     * <p>The returned map includes: X-Veil-Version, X-Veil-Key-Id,
     * X-Veil-Ephemeral-Key, X-Veil-Model, X-Veil-Timestamp, and
     * X-Veil-Request-Id. X-Veil-Token-Estimate is included only when
     * {@link #getTokenEstimate()} is non-null.
     *
     * @return A mutable {@link LinkedHashMap} of header name to header value
     */
    public Map<String, String> toHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Veil-Version", String.valueOf(version));
        headers.put("X-Veil-Key-Id", keyId);
        headers.put("X-Veil-Ephemeral-Key", ephemeralKey);
        headers.put("X-Veil-Model", model);
        if (tokenEstimate != null) {
            headers.put("X-Veil-Token-Estimate", tokenEstimate.toString());
        }
        headers.put("X-Veil-Timestamp", timestamp);
        headers.put("X-Veil-Request-Id", requestId);
        return headers;
    }

    @Override
    public String toString() {
        return "VeilMetadata{keyId=" + keyId + ", model=" + model +
                ", requestId=" + requestId + "}";
    }
}
