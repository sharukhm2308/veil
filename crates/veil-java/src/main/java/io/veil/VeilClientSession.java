package io.veil;

import java.util.Base64;

/**
 * Client-side Veil session for encrypting requests and decrypting responses.
 *
 * <p>Creates a fresh ephemeral X25519 keypair per session, performs ECDH with
 * the server's static public key, and derives two directional AES-256-GCM
 * keys via HKDF-SHA256: one for client-to-server (c2s) and one for
 * server-to-client (s2c). All cryptographic operations execute in the Rust
 * {@code veil-core} library via JNI.
 *
 * <p>Protocol-compatible with Rust {@code veil-core::ClientSession} and
 * Python {@code veil_sdk.VeilClientSession}.
 *
 * <h3>Encrypt a request:</h3>
 * <pre>{@code
 * try (VeilClientSession session = new VeilClientSession(serverPubKeyB64, "shim-v1")) {
 *     byte[] payload = "{\"query\": \"hello\"}".getBytes(StandardCharsets.UTF_8);
 *     VeilEnvelope envelope = session.encryptRequest(payload, "chat");
 *
 *     // Send envelope.toMap() as "_veil_envelope" in the HTTP request body
 *     Map<String, Object> body = new HashMap<>();
 *     body.put("_veil_envelope", envelope.toMap());
 *     httpClient.post("/api/chat", body);
 * }
 * }</pre>
 *
 * <h3>Full request-response roundtrip:</h3>
 * <pre>{@code
 * try (VeilClientSession session = new VeilClientSession(serverPubKeyB64, "shim-v1")) {
 *     VeilEnvelope reqEnvelope = session.encryptRequest(requestBytes, "chat");
 *     // ... send request, receive response ...
 *     VeilEnvelope respEnvelope = VeilEnvelope.fromMap(responseMap);
 *     byte[] plaintext = session.decryptResponse(respEnvelope);
 * }
 * }</pre>
 *
 * <h3>Thread safety:</h3>
 * <p>Instances are <strong>not</strong> thread-safe. Use one session per thread
 * or provide external synchronization.
 *
 * <h3>Lifecycle:</h3>
 * <p>Implements {@link AutoCloseable}. The native session handle and derived
 * key material are securely zeroized on {@link #close()}. Always use
 * try-with-resources.
 *
 * @see VeilServerSession
 * @see VeilEnvelope
 * @see VeilKeyPair
 */
public class VeilClientSession implements AutoCloseable {

    private long handle;

    private String requestId;
    private String timestamp;
    private String ephemeralPublicB64;

    /**
     * Create a new client session.
     *
     * @param serverPublicKeyB64 Server's X25519 public key (base64, 32 bytes)
     * @param keyId              Server's key identifier (e.g., "shim-v1")
     * @throws VeilException if session creation fails
     */
    public VeilClientSession(String serverPublicKeyB64, String keyId) {
        VeilNative.ensureLoaded();
        this.handle = nativeCreate(serverPublicKeyB64, keyId);
        if (this.handle == 0) {
            throw new VeilException("Failed to create ClientSession (null handle)");
        }
        this.ephemeralPublicB64 = nativeEphemeralPublicBase64(this.handle);
    }

    /**
     * Encrypt a request payload (client → server direction).
     *
     * <p>Generates a fresh requestId (UUID v4) and timestamp per call.
     * The AAD binds: protocol version, direction, keyId, ephemeral key,
     * requestId, and timestamp.
     *
     * @param plaintext The plaintext payload to encrypt (typically JSON bytes)
     * @param model     Model/tool identifier (included in metadata)
     * @return A VeilEnvelope ready for transport
     * @throws VeilException if encryption fails
     */
    public VeilEnvelope encryptRequest(byte[] plaintext, String model) {
        ensureOpen();
        String resultJson = nativeEncryptRequest(handle, plaintext, model);
        if (resultJson == null) {
            throw new VeilException("Encryption returned null");
        }

        // Parse the JSON result from Rust
        return parseEncryptResult(resultJson);
    }

    /**
     * Encrypt a request payload with default model name.
     *
     * @param plaintext The plaintext payload to encrypt
     * @return A VeilEnvelope ready for transport
     */
    public VeilEnvelope encryptRequest(byte[] plaintext) {
        return encryptRequest(plaintext, "default");
    }

    /**
     * Decrypt a response envelope (server → client direction).
     *
     * <p>Must be called on the same session that encrypted the request,
     * as it uses the s2c key derived from the same ECDH.
     *
     * @param envelope The encrypted response envelope from the server
     * @return Decrypted plaintext bytes
     * @throws VeilException if decryption fails (tampered data, wrong session, etc.)
     */
    public byte[] decryptResponse(VeilEnvelope envelope) {
        ensureOpen();
        byte[] result = nativeDecryptResponse(
                handle,
                envelope.getNonce(),
                envelope.getCiphertext(),
                envelope.getAad()
        );
        if (result == null) {
            throw new VeilException("Decryption returned null");
        }
        return result;
    }

    /**
     * Get the UUID v4 request identifier generated during the last
     * {@link #encryptRequest} call.
     *
     * @return Request ID string, or {@code null} if no request has been encrypted yet
     */
    public String getRequestId() { return requestId; }

    /**
     * Get the ISO 8601 timestamp generated during the last
     * {@link #encryptRequest} call.
     *
     * @return Timestamp string, or {@code null} if no request has been encrypted yet
     */
    public String getTimestamp() { return timestamp; }

    /**
     * Get this session's ephemeral public key as a base64 string.
     *
     * <p>This key is generated once at session construction and remains
     * constant for the session's lifetime.
     *
     * @return Base64-encoded 32-byte X25519 ephemeral public key
     */
    public String getEphemeralPublicB64() { return ephemeralPublicB64; }

    /**
     * Get the metadata from the last {@link #encryptRequest} call.
     *
     * <p>The metadata contains the key ID, ephemeral key, timestamp, and
     * request ID -- suitable for sending as X-Veil-* HTTP headers.
     *
     * @return Metadata from the last encrypt call, or {@code null} if no
     *         request has been encrypted yet
     */
    public VeilMetadata getLastMetadata() {
        if (requestId == null) return null;
        return new VeilMetadata(1, null, ephemeralPublicB64, null, null, timestamp, requestId);
    }

    /**
     * Release the native session handle and securely zeroize derived key material.
     *
     * <p>Safe to call multiple times; subsequent calls are no-ops. After
     * closing, any encrypt or decrypt call will throw {@link VeilException}.
     */
    @Override
    public void close() {
        if (handle != 0) {
            nativeDestroy(handle);
            handle = 0;
        }
    }

    private void ensureOpen() {
        if (handle == 0) {
            throw new VeilException("Session is closed");
        }
    }

    /**
     * Parse the JSON result from nativeEncryptRequest into a VeilEnvelope.
     * Also extracts metadata (requestId, timestamp) from the result.
     */
    private VeilEnvelope parseEncryptResult(String json) {
        // Minimal JSON parsing (avoid dependency on external JSON libs)
        // Format: {"envelope":{"version":1,"nonce":"...","ciphertext":"...","aad":"..."},
        //          "metadata":{"version":1,"key_id":"...","ephemeral_key":"...",...}}
        try {
            // Extract envelope fields
            String nonce = extractJsonString(json, "nonce");
            String ciphertext = extractJsonString(json, "ciphertext");
            String aad = extractJsonString(json, "aad");

            // Extract metadata fields
            String keyId = extractJsonString(json, "key_id");
            String ephKey = extractJsonString(json, "ephemeral_key");
            String model = extractJsonString(json, "model");
            this.timestamp = extractJsonString(json, "timestamp");
            this.requestId = extractJsonString(json, "request_id");

            return new VeilEnvelope(1, nonce, ciphertext, aad,
                    ephKey, keyId, this.timestamp, this.requestId);
        } catch (Exception e) {
            throw new VeilException("Failed to parse encrypt result: " + e.getMessage(), e);
        }
    }

    /**
     * Extract a string value from JSON by key name.
     * Simple implementation — works for flat or nested JSON with unique keys.
     */
    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    // -- Native methods (implemented in Rust veil-jni) --

    private static native long nativeCreate(String serverPublicKeyB64, String keyId);
    private static native String nativeEncryptRequest(long handle, byte[] plaintext, String model);
    private static native byte[] nativeDecryptResponse(long handle, String nonceB64, String ciphertextB64, String aadB64);
    private static native String nativeEphemeralPublicBase64(long handle);
    private static native void nativeDestroy(long handle);
}
