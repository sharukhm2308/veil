package io.veil;

/**
 * Server-side Veil session for decrypting requests and encrypting responses.
 *
 * <p>Created from the server's static X25519 secret key and the client's
 * ephemeral public key (extracted from the request envelope/metadata).
 * Performs the server half of the ECDH key agreement and derives
 * directional AES-256-GCM keys via HKDF-SHA256. All cryptographic
 * operations execute in the Rust {@code veil-core} library via JNI.
 *
 * <p>Protocol-compatible with Rust {@code veil-core::ServerSession} and
 * Python {@code veil_sdk.VeilServerSession}.
 *
 * <h3>Decrypt a request and encrypt a response:</h3>
 * <pre>{@code
 * VeilEnvelope envelope = VeilEnvelope.fromMap(requestBody.get("_veil_envelope"));
 *
 * try (VeilServerSession session = new VeilServerSession(
 *         secretKeyB64,
 *         envelope.getEphemeralKey(),
 *         envelope.getKeyId(),
 *         envelope.getRequestId(),
 *         envelope.getTimestamp())) {
 *
 *     byte[] plaintext = session.decryptRequest(envelope);
 *     // ... process plaintext, generate response ...
 *
 *     VeilEnvelope response = session.encryptResponse(responseBytes);
 *     return Map.of("_veil_envelope", response.toMap());
 * }
 * }</pre>
 *
 * <h3>Thread safety:</h3>
 * <p>Instances are <strong>not</strong> thread-safe. Use one session per
 * request or provide external synchronization.
 *
 * <h3>Lifecycle:</h3>
 * <p>Implements {@link AutoCloseable}. The native session handle and derived
 * key material are securely zeroized on {@link #close()}. Always use
 * try-with-resources.
 *
 * @see VeilClientSession
 * @see VeilEnvelope
 * @see VeilKeyPair
 */
public class VeilServerSession implements AutoCloseable {

    private long handle;

    /**
     * Create a new server session.
     *
     * @param secretKeyB64       Server's X25519 secret key (base64, 32 bytes)
     * @param clientEphemeralB64  Client's ephemeral public key (from request metadata)
     * @param keyId               Server's key identifier
     * @param requestId           Request UUID (from request metadata)
     * @param timestamp           Request timestamp (from request metadata)
     * @throws VeilException if session creation fails
     */
    public VeilServerSession(
            String secretKeyB64,
            String clientEphemeralB64,
            String keyId,
            String requestId,
            String timestamp
    ) {
        VeilNative.ensureLoaded();
        this.handle = nativeCreate(secretKeyB64, clientEphemeralB64, keyId, requestId, timestamp);
        if (this.handle == 0) {
            throw new VeilException("Failed to create ServerSession (null handle)");
        }
    }

    /**
     * Decrypt a request envelope.
     *
     * @param envelope The encrypted request from the client
     * @return Decrypted plaintext bytes
     * @throws VeilException if decryption fails
     */
    public byte[] decryptRequest(VeilEnvelope envelope) {
        ensureOpen();
        byte[] result = nativeDecryptRequest(
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
     * Encrypt a response payload (server → client direction).
     *
     * @param plaintext The plaintext response to encrypt
     * @return A VeilEnvelope containing the encrypted response
     * @throws VeilException if encryption fails
     */
    public VeilEnvelope encryptResponse(byte[] plaintext) {
        ensureOpen();
        String resultJson = nativeEncryptResponse(handle, plaintext);
        if (resultJson == null) {
            throw new VeilException("Encryption returned null");
        }
        return parseEnvelopeJson(resultJson);
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
     * Parse the JSON envelope returned from native encryptResponse.
     * Format: {"version":1,"nonce":"b64","ciphertext":"b64","aad":"b64"}
     */
    private VeilEnvelope parseEnvelopeJson(String json) {
        try {
            String nonce = extractJsonString(json, "nonce");
            String ciphertext = extractJsonString(json, "ciphertext");
            String aad = extractJsonString(json, "aad");

            return new VeilEnvelope(1, nonce, ciphertext, aad, "", "", "", "");
        } catch (Exception e) {
            throw new VeilException("Failed to parse envelope: " + e.getMessage(), e);
        }
    }

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

    private static native long nativeCreate(
            String secretKeyB64, String clientEphemeralB64,
            String keyId, String requestId, String timestamp);
    private static native byte[] nativeDecryptRequest(
            long handle, String nonceB64, String ciphertextB64, String aadB64);
    private static native String nativeEncryptResponse(long handle, byte[] plaintext);
    private static native void nativeDestroy(long handle);
}
