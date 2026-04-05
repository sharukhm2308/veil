package io.veil;

/**
 * X25519 static keypair for server identity in the Veil protocol.
 *
 * <p>Represents a Curve25519 keypair used for the asymmetric (ECDH) path of
 * the Veil protocol. The server holds the secret key; clients encrypt
 * requests to the corresponding public key. All cryptographic operations
 * are performed by the Rust {@code veil-core} library via JNI.
 *
 * <p>Instances are immutable. The secret key is stored as a base64 string
 * in Java (the raw key bytes live in Rust and are not exposed to the JVM
 * heap beyond the base64 encoding).
 *
 * <h3>Generate and persist:</h3>
 * <pre>{@code
 * VeilKeyPair kp = VeilKeyPair.generate();
 * String secretB64 = kp.secretBase64();   // store in a secrets manager
 * String publicB64 = kp.publicBase64();   // distribute to clients
 * }</pre>
 *
 * <h3>Reconstruct from stored secret:</h3>
 * <pre>{@code
 * String secretB64 = secretStore.load("veil/server-key");
 * VeilKeyPair kp = VeilKeyPair.fromSecretBase64(secretB64);
 * // kp.publicBase64() is deterministically derived from the secret
 * }</pre>
 *
 * <h3>Use with sessions:</h3>
 * <pre>{@code
 * // Client side
 * try (VeilClientSession client = new VeilClientSession(kp.publicBase64(), "shim-v1")) {
 *     VeilEnvelope envelope = client.encryptRequest(payload, "chat");
 * }
 *
 * // Server side
 * try (VeilServerSession server = new VeilServerSession(
 *         kp.secretBase64(), envelope.getEphemeralKey(),
 *         envelope.getKeyId(), envelope.getRequestId(), envelope.getTimestamp())) {
 *     byte[] plaintext = server.decryptRequest(envelope);
 * }
 * }</pre>
 *
 * @see VeilClientSession
 * @see VeilServerSession
 */
public class VeilKeyPair {

    private final String secretB64;
    private final String publicB64;

    private VeilKeyPair(String secretB64, String publicB64) {
        this.secretB64 = secretB64;
        this.publicB64 = publicB64;
    }

    /**
     * Generate a new random X25519 keypair.
     *
     * @return A new keypair with fresh random keys
     * @throws VeilException if key generation fails
     */
    public static VeilKeyPair generate() {
        VeilNative.ensureLoaded();
        String[] result = nativeGenerate();
        return new VeilKeyPair(result[0], result[1]);
    }

    /**
     * Reconstruct a keypair from a base64-encoded secret key.
     *
     * <p>The public key is derived from the secret key.
     *
     * @param secretB64 Base64-encoded 32-byte X25519 secret key
     * @return The reconstructed keypair
     * @throws VeilException if the secret key is invalid
     */
    public static VeilKeyPair fromSecretBase64(String secretB64) {
        VeilNative.ensureLoaded();
        String[] result = nativeFromSecretBase64(secretB64);
        return new VeilKeyPair(result[0], result[1]);
    }

    /**
     * Get the secret (private) key as a base64-encoded string.
     *
     * <p><strong>Security:</strong> This value must be stored securely in a
     * hardened secrets manager. Never log or expose it.
     *
     * @return Base64-encoded 32-byte X25519 secret key
     */
    public String secretBase64() { return secretB64; }

    /**
     * Get the public key as a base64-encoded string.
     *
     * <p>This value is safe to distribute to clients. Clients use it to
     * construct a {@link VeilClientSession}.
     *
     * @return Base64-encoded 32-byte X25519 public key
     */
    public String publicBase64() { return publicB64; }

    @Override
    public String toString() {
        return "VeilKeyPair(public='" + publicB64.substring(0, Math.min(8, publicB64.length())) + "...')";
    }

    // -- Native methods (implemented in Rust veil-jni) --

    private static native String[] nativeGenerate();
    private static native String[] nativeFromSecretBase64(String secretB64);
}
