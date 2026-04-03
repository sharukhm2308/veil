package com.ninjacart.veil;

/**
 * Unchecked exception thrown by Veil SDK operations.
 *
 * <p>Wraps errors originating from the Rust {@code veil-core} library via
 * JNI. Common causes include:
 * <ul>
 *   <li>Key generation or derivation failures</li>
 *   <li>Encryption failures (e.g., null handle after close)</li>
 *   <li>Decryption failures (wrong key, tampered ciphertext, mismatched AAD)</li>
 *   <li>Invalid inputs (wrong key length, malformed base64)</li>
 *   <li>Use of a closed key or session</li>
 * </ul>
 *
 * <p>Extends {@link RuntimeException} so callers are not forced to declare
 * it, but should still handle it where appropriate (especially around
 * decryption, which can legitimately fail with untrusted input).
 *
 * @see VeilSymmetricKey
 * @see VeilClientSession
 * @see VeilServerSession
 */
public class VeilException extends RuntimeException {

    /**
     * Create a VeilException with a descriptive message.
     *
     * @param message Human-readable error description
     */
    public VeilException(String message) {
        super(message);
    }

    /**
     * Create a VeilException with a message and underlying cause.
     *
     * @param message Human-readable error description
     * @param cause   The underlying exception that triggered this error
     */
    public VeilException(String message, Throwable cause) {
        super(message, cause);
    }
}
