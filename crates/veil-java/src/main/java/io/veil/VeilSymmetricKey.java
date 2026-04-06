package io.veil;

/**
 * Veil symmetric encryption key -- AES-256-GCM with HKDF-SHA256 key derivation.
 *
 * <p>Wraps a 256-bit AES key managed by the Rust {@code veil-core} library via
 * JNI. All cryptographic operations (key generation, derivation, encryption,
 * decryption) execute in native Rust code -- no Java-level crypto is used.
 *
 * <p>Use this class for message-at-rest encryption: database fields, config
 * values, message queues, or any scenario requiring authenticated symmetric
 * encryption. Each {@link #encrypt} call generates a fresh random nonce, so
 * repeated encryption of the same plaintext yields different ciphertexts.
 *
 * <h3>Basic usage -- generate, encrypt, decrypt:</h3>
 * <pre>{@code
 * try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
 *     byte[] plaintext = "sensitive data".getBytes(StandardCharsets.UTF_8);
 *     byte[] aad = "context-binding".getBytes(StandardCharsets.UTF_8);
 *
 *     VeilSymmetricEnvelope envelope = key.encrypt(plaintext, aad);
 *     byte[] decrypted = key.decrypt(envelope);
 *     // decrypted == plaintext
 * }
 * }</pre>
 *
 * <h3>Derive per-conversation keys from a master key:</h3>
 * <pre>{@code
 * byte[] masterKey = secretStore.load("veil/master-key");
 * byte[] context = ("cw-" + userId + "-" + conversationId).getBytes(StandardCharsets.UTF_8);
 *
 * try (VeilSymmetricKey key = VeilSymmetricKey.derive(masterKey, context)) {
 *     VeilSymmetricEnvelope envelope = key.encrypt(payload, aad);
 *     // Store envelope.toMap() in DB
 * }
 * }</pre>
 *
 * <h3>Versioned encryption for key rotation:</h3>
 * <pre>{@code
 * try (VeilSymmetricKey key = VeilSymmetricKey.generate()) {
 *     VeilSymmetricEnvelope envelope = key.encryptVersioned(plaintext, aad, 3);
 *     // envelope.getKeyVersion() == 3
 * }
 * }</pre>
 *
 * <h3>Thread safety:</h3>
 * <p>Instances are <strong>not</strong> thread-safe. Each thread should use its
 * own instance, or external synchronization must be provided.
 *
 * <h3>Security notes:</h3>
 * <ul>
 *   <li>The underlying native key material is securely zeroized when
 *       {@link #close()} is called. Always use try-with-resources.</li>
 *   <li>Each encryption generates a fresh random 96-bit nonce via the OS CSPRNG.</li>
 *   <li>The AAD (Additional Authenticated Data) is authenticated but not
 *       encrypted -- use it for context binding (user ID, conversation ID, etc.).</li>
 * </ul>
 *
 * @see VeilSymmetricEnvelope
 * @see #derive(byte[], byte[])
 */
public class VeilSymmetricKey implements AutoCloseable {

    private long handle;

    private VeilSymmetricKey(long handle) {
        this.handle = handle;
    }

    /**
     * Create a key from raw 32 bytes.
     *
     * @param raw 32-byte AES-256 key
     * @return A new VeilSymmetricKey
     * @throws VeilException if the key is not exactly 32 bytes
     */
    public static VeilSymmetricKey fromBytes(byte[] raw) {
        VeilNative.ensureLoaded();
        long h = nativeFromBytes(raw);
        if (h == 0) {
            throw new VeilException("Failed to create SymmetricKey from bytes (null handle)");
        }
        return new VeilSymmetricKey(h);
    }

    /**
     * Create a key from a base64-encoded string.
     *
     * @param b64 Base64-encoded 32-byte key
     * @return A new VeilSymmetricKey
     * @throws VeilException if the base64 is invalid or key is wrong size
     */
    public static VeilSymmetricKey fromBase64(String b64) {
        VeilNative.ensureLoaded();
        long h = nativeFromBase64(b64);
        if (h == 0) {
            throw new VeilException("Failed to create SymmetricKey from base64 (null handle)");
        }
        return new VeilSymmetricKey(h);
    }

    /**
     * Generate a new random 256-bit key.
     *
     * @return A new randomly generated VeilSymmetricKey
     */
    public static VeilSymmetricKey generate() {
        VeilNative.ensureLoaded();
        long h = nativeGenerate();
        if (h == 0) {
            throw new VeilException("Failed to generate SymmetricKey (null handle)");
        }
        return new VeilSymmetricKey(h);
    }

    /**
     * Derive a key from a master key and context via HKDF-SHA256.
     *
     * <p>Different contexts yield completely different keys from the same master.
     *
     * @param masterKey Master key bytes (typically 32 bytes, loaded from your secret store)
     * @param context   Binding context (e.g. "cw-{userId}-{conversationId}".getBytes())
     * @return A derived VeilSymmetricKey
     * @throws VeilException if key derivation fails
     */
    public static VeilSymmetricKey derive(byte[] masterKey, byte[] context) {
        VeilNative.ensureLoaded();
        long h = nativeDerive(masterKey, context);
        if (h == 0) {
            throw new VeilException("Failed to derive SymmetricKey (null handle)");
        }
        return new VeilSymmetricKey(h);
    }

    /**
     * Encrypt plaintext with AES-256-GCM.
     *
     * <p>A fresh random nonce is generated for each call. The AAD is
     * authenticated but not encrypted -- use it for context binding.
     *
     * @param plaintext Data to encrypt
     * @param aad       Additional Authenticated Data
     * @return A VeilSymmetricEnvelope containing nonce, ciphertext, and AAD
     * @throws VeilException if encryption fails
     */
    public VeilSymmetricEnvelope encrypt(byte[] plaintext, byte[] aad) {
        ensureOpen();
        String json = nativeEncrypt(handle, plaintext, aad);
        if (json == null) {
            throw new VeilException("Encryption returned null");
        }
        return parseEnvelopeJson(json, null);
    }

    /**
     * Encrypt plaintext with a key version tag for rotation support.
     *
     * @param plaintext  Data to encrypt
     * @param aad        Additional Authenticated Data
     * @param keyVersion Key version number (for tracking which key encrypted this)
     * @return A VeilSymmetricEnvelope with keyVersion set
     * @throws VeilException if encryption fails
     */
    public VeilSymmetricEnvelope encryptVersioned(byte[] plaintext, byte[] aad, int keyVersion) {
        ensureOpen();
        String json = nativeEncryptVersioned(handle, plaintext, aad, keyVersion);
        if (json == null) {
            throw new VeilException("Encryption returned null");
        }
        return parseEnvelopeJson(json, keyVersion);
    }

    /**
     * Decrypt a symmetric envelope.
     *
     * @param envelope The envelope produced by {@link #encrypt} or {@link #encryptVersioned}
     * @return Decrypted plaintext bytes
     * @throws VeilException if decryption fails (tampered data, wrong key, etc.)
     */
    public byte[] decrypt(VeilSymmetricEnvelope envelope) {
        ensureOpen();
        byte[] result = nativeDecrypt(
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
     * Export the key as a base64-encoded string.
     *
     * @return Base64-encoded 32-byte key
     */
    public String toBase64() {
        ensureOpen();
        return nativeToBase64(handle);
    }

    /**
     * Release the native key handle and securely zeroize the key material.
     *
     * <p>Safe to call multiple times; subsequent calls are no-ops. After
     * closing, any attempt to encrypt or decrypt with this key will throw
     * {@link VeilException}.
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
            throw new VeilException("SymmetricKey is closed");
        }
    }

    /**
     * Parse the JSON envelope string returned by native encrypt methods.
     *
     * Format: {"version":1,"nonce":"b64","ciphertext":"b64","aad":"b64"}
     * With versioned: adds "key_version":N
     */
    private static VeilSymmetricEnvelope parseEnvelopeJson(String json, Integer keyVersion) {
        try {
            String nonce = extractJsonString(json, "nonce");
            String ciphertext = extractJsonString(json, "ciphertext");
            String aad = extractJsonString(json, "aad");

            // If keyVersion was not passed, try to extract from JSON
            if (keyVersion == null) {
                String kvStr = extractJsonNumber(json, "key_version");
                if (kvStr != null) {
                    keyVersion = Integer.parseInt(kvStr);
                }
            }

            return new VeilSymmetricEnvelope(1, nonce, ciphertext, aad, keyVersion);
        } catch (Exception e) {
            throw new VeilException("Failed to parse encrypt result: " + e.getMessage(), e);
        }
    }

    /**
     * Extract a string value from JSON by key name.
     * Simple implementation -- works for flat JSON with unique keys.
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

    /**
     * Extract a numeric value from JSON by key name.
     */
    private static String extractJsonNumber(String json, String key) {
        String needle = "\"" + key + "\":";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        if (end == start) return null;
        return json.substring(start, end);
    }

    // -- Native methods (implemented in Rust veil-jni) --

    private static native long nativeFromBytes(byte[] raw);
    private static native long nativeFromBase64(String b64);
    private static native long nativeGenerate();
    private static native long nativeDerive(byte[] master, byte[] context);
    private static native String nativeEncrypt(long handle, byte[] plaintext, byte[] aad);
    private static native String nativeEncryptVersioned(long handle, byte[] plaintext, byte[] aad, int keyVersion);
    private static native byte[] nativeDecrypt(long handle, String nonceB64, String ciphertextB64, String aadB64);
    private static native String nativeToBase64(long handle);
    private static native void nativeDestroy(long handle);

    static { VeilNative.ensureLoaded(); }
}
