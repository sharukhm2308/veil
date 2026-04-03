//! JNI bindings for Veil E2E encrypted LLM inference.
//!
//! Wraps `veil-core` — all cryptographic operations (X25519, HKDF-SHA256,
//! AES-256-GCM) execute in Rust. Java classes are thin wrappers around
//! native method calls.
//!
//! # Architecture
//!
//! Rust objects (`ClientSession`, `ServerSession`) are heap-allocated and
//! stored as opaque `long` handles in Java. Java calls `nativeDestroy()`
//! to free them (called from `close()` or a weak ref / try-with-resources).
//!
//! ```text
//! Java VeilClientSession(pub_b64, key_id)
//!   → JNI nativeCreate(pub_b64, key_id) → Box<ClientSession> → handle
//!
//! Java encryptRequest(plaintext, model)
//!   → JNI nativeEncryptRequest(handle, plaintext, model) → JSON envelope+metadata
//!
//! Java close()
//!   → JNI nativeDestroy(handle) → drop(Box<ClientSession>)
//! ```

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use jni::objects::{JByteArray, JClass, JObject, JString};
use jni::sys::{jbyteArray, jlong, jobject, jstring};
use jni::JNIEnv;
use veil_core::symmetric::{SymmetricEnvelope, SymmetricKey};
use veil_core::{ClientSession, ServerSession, StaticKeyPair, VeilEnvelope};

// ---------------------------------------------------------------------------
// Handle helpers — Box Rust objects as opaque long pointers for Java
// ---------------------------------------------------------------------------

fn box_to_handle<T>(obj: T) -> jlong {
    Box::into_raw(Box::new(obj)) as jlong
}

/// # Safety
///
/// The handle must be a valid pointer to a `T` created by `box_to_handle`.
unsafe fn handle_to_ref<'a, T>(handle: jlong) -> &'a mut T {
    &mut *(handle as *mut T)
}

/// # Safety
///
/// The handle must be a valid pointer to a `T` created by `box_to_handle`.
/// After this call the handle is invalid.
unsafe fn handle_drop<T>(handle: jlong) {
    let _ = Box::from_raw(handle as *mut T);
}

// ---------------------------------------------------------------------------
// Helper: throw VeilException in Java
// ---------------------------------------------------------------------------

fn throw_veil_exception(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("com/ninjacart/veil/VeilException", msg);
}

fn get_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    env.get_string(s).ok().map(|s| s.into())
}

fn get_bytes(env: &mut JNIEnv, arr: &JByteArray) -> Option<Vec<u8>> {
    env.convert_byte_array(arr).ok()
}

// ---------------------------------------------------------------------------
// VeilKeyPair native methods
// ---------------------------------------------------------------------------

/// Generate a new X25519 keypair.
/// Returns a Java String[] with [secretB64, publicB64].
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilKeyPair_nativeGenerate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jobject {
    let kp = StaticKeyPair::generate();
    let secret = kp.secret_base64();
    let public = kp.public_base64();

    let arr = match env.new_object_array(2, "java/lang/String", JObject::null()) {
        Ok(a) => a,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Failed to create array: {e}"));
            return JObject::null().into_raw();
        }
    };

    let s = env.new_string(&secret).unwrap();
    let p = env.new_string(&public).unwrap();
    let _ = env.set_object_array_element(&arr, 0, s);
    let _ = env.set_object_array_element(&arr, 1, p);

    arr.into_raw()
}

/// Reconstruct a keypair from a base64-encoded secret key.
/// Returns a Java String[] with [secretB64, publicB64].
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilKeyPair_nativeFromSecretBase64<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    secret_b64: JString<'local>,
) -> jobject {
    let secret_str = match get_string(&mut env, &secret_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid secret key string");
            return JObject::null().into_raw();
        }
    };

    let kp = match StaticKeyPair::from_secret_base64(&secret_str) {
        Ok(k) => k,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid secret key: {e}"));
            return JObject::null().into_raw();
        }
    };

    let arr = match env.new_object_array(2, "java/lang/String", JObject::null()) {
        Ok(a) => a,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Failed to create array: {e}"));
            return JObject::null().into_raw();
        }
    };

    let s = env.new_string(kp.secret_base64()).unwrap();
    let p = env.new_string(kp.public_base64()).unwrap();
    let _ = env.set_object_array_element(&arr, 0, s);
    let _ = env.set_object_array_element(&arr, 1, p);

    arr.into_raw()
}

// ---------------------------------------------------------------------------
// VeilClientSession native methods
// ---------------------------------------------------------------------------

/// Create a new ClientSession. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilClientSession_nativeCreate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    server_pub_b64: JString<'local>,
    key_id: JString<'local>,
) -> jlong {
    let pub_str = match get_string(&mut env, &server_pub_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid server public key string");
            return 0;
        }
    };
    let kid_str = match get_string(&mut env, &key_id) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid key ID string");
            return 0;
        }
    };

    match ClientSession::new(&pub_str, &kid_str) {
        Ok(session) => box_to_handle(session),
        Err(e) => {
            throw_veil_exception(&mut env, &format!("ClientSession creation failed: {e}"));
            0
        }
    }
}

/// Encrypt a request. Returns JSON string with envelope + metadata.
///
/// The JSON format:
/// ```json
/// {
///   "envelope": { "version": 1, "nonce": "b64", "ciphertext": "b64", "aad": "b64" },
///   "metadata": { "version": 1, "key_id": "...", "ephemeral_key": "b64", ... }
/// }
/// ```
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilClientSession_nativeEncryptRequest<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    plaintext: JByteArray<'local>,
    model: JString<'local>,
) -> jstring {
    let pt = match get_bytes(&mut env, &plaintext) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid plaintext bytes");
            return JObject::null().into_raw();
        }
    };
    let model_str = match get_string(&mut env, &model) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid model string");
            return JObject::null().into_raw();
        }
    };

    let session = unsafe { handle_to_ref::<ClientSession>(handle) };

    match session.encrypt_request(&pt, &model_str, None) {
        Ok((envelope, metadata)) => {
            let result = serde_json::json!({
                "envelope": {
                    "version": envelope.version,
                    "nonce": B64.encode(&envelope.nonce),
                    "ciphertext": B64.encode(&envelope.ciphertext),
                    "aad": B64.encode(&envelope.aad),
                },
                "metadata": {
                    "version": metadata.version,
                    "key_id": metadata.key_id,
                    "ephemeral_key": metadata.ephemeral_key,
                    "model": metadata.model,
                    "token_estimate": metadata.token_estimate,
                    "timestamp": metadata.timestamp,
                    "request_id": metadata.request_id,
                }
            });

            match env.new_string(result.to_string()) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    throw_veil_exception(&mut env, &format!("JSON serialization failed: {e}"));
                    JObject::null().into_raw()
                }
            }
        }
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Encryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Decrypt a response envelope. Returns plaintext bytes.
///
/// Takes the envelope as 4 base64 strings: nonce, ciphertext, aad, version.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilClientSession_nativeDecryptResponse<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    nonce_b64: JString<'local>,
    ciphertext_b64: JString<'local>,
    aad_b64: JString<'local>,
) -> jbyteArray {
    let nonce_str = match get_string(&mut env, &nonce_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid nonce");
            return JObject::null().into_raw();
        }
    };
    let ct_str = match get_string(&mut env, &ciphertext_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid ciphertext");
            return JObject::null().into_raw();
        }
    };
    let aad_str = match get_string(&mut env, &aad_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid aad");
            return JObject::null().into_raw();
        }
    };

    let nonce = match B64.decode(&nonce_str) {
        Ok(b) => b,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid nonce base64: {e}"));
            return JObject::null().into_raw();
        }
    };
    let ciphertext = match B64.decode(&ct_str) {
        Ok(b) => b,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid ciphertext base64: {e}"));
            return JObject::null().into_raw();
        }
    };
    let aad = match B64.decode(&aad_str) {
        Ok(b) => b,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid aad base64: {e}"));
            return JObject::null().into_raw();
        }
    };

    let envelope = VeilEnvelope::new(nonce, ciphertext, aad);
    let session = unsafe { handle_to_ref::<ClientSession>(handle) };

    match session.decrypt_response(&envelope) {
        Ok(plaintext) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                throw_veil_exception(&mut env, &format!("Failed to create byte array: {e}"));
                JObject::null().into_raw()
            }
        },
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Decryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Get the ephemeral public key (base64).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilClientSession_nativeEphemeralPublicBase64<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let session = unsafe { handle_to_ref::<ClientSession>(handle) };
    let b64 = session.ephemeral_public_base64();
    match env.new_string(&b64) {
        Ok(s) => s.into_raw(),
        Err(_) => JObject::null().into_raw(),
    }
}

/// Destroy a ClientSession handle.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilClientSession_nativeDestroy<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe { handle_drop::<ClientSession>(handle) };
    }
}

// ---------------------------------------------------------------------------
// VeilServerSession native methods
// ---------------------------------------------------------------------------

/// Create a new ServerSession. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilServerSession_nativeCreate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    secret_key_b64: JString<'local>,
    client_eph_b64: JString<'local>,
    key_id: JString<'local>,
    request_id: JString<'local>,
    timestamp: JString<'local>,
) -> jlong {
    let secret = match get_string(&mut env, &secret_key_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid secret key");
            return 0;
        }
    };
    let eph = match get_string(&mut env, &client_eph_b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid ephemeral key");
            return 0;
        }
    };
    let kid = match get_string(&mut env, &key_id) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid key ID");
            return 0;
        }
    };
    let rid = match get_string(&mut env, &request_id) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid request ID");
            return 0;
        }
    };
    let ts = match get_string(&mut env, &timestamp) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid timestamp");
            return 0;
        }
    };

    let keypair = match StaticKeyPair::from_secret_base64(&secret) {
        Ok(kp) => kp,
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid keypair: {e}"));
            return 0;
        }
    };

    match ServerSession::new(&keypair, &eph, &kid, &rid, &ts) {
        Ok(session) => box_to_handle(session),
        Err(e) => {
            throw_veil_exception(&mut env, &format!("ServerSession creation failed: {e}"));
            0
        }
    }
}

/// Decrypt a request envelope. Returns plaintext bytes.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilServerSession_nativeDecryptRequest<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    nonce_b64: JString<'local>,
    ciphertext_b64: JString<'local>,
    aad_b64: JString<'local>,
) -> jbyteArray {
    let nonce = match get_string(&mut env, &nonce_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid nonce");
            return JObject::null().into_raw();
        }
    };
    let ct = match get_string(&mut env, &ciphertext_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid ciphertext");
            return JObject::null().into_raw();
        }
    };
    let aad = match get_string(&mut env, &aad_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid aad");
            return JObject::null().into_raw();
        }
    };

    let envelope = VeilEnvelope::new(nonce, ct, aad);
    let session = unsafe { handle_to_ref::<ServerSession>(handle) };

    match session.decrypt_request(&envelope) {
        Ok(plaintext) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                throw_veil_exception(&mut env, &format!("Failed to create byte array: {e}"));
                JObject::null().into_raw()
            }
        },
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Decryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Encrypt a response. Returns JSON string with envelope.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilServerSession_nativeEncryptResponse<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    plaintext: JByteArray<'local>,
) -> jstring {
    let pt = match get_bytes(&mut env, &plaintext) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid plaintext bytes");
            return JObject::null().into_raw();
        }
    };

    let session = unsafe { handle_to_ref::<ServerSession>(handle) };

    match session.encrypt_response(&pt) {
        Ok(envelope) => {
            let result = serde_json::json!({
                "version": envelope.version,
                "nonce": B64.encode(&envelope.nonce),
                "ciphertext": B64.encode(&envelope.ciphertext),
                "aad": B64.encode(&envelope.aad),
            });

            match env.new_string(result.to_string()) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    throw_veil_exception(&mut env, &format!("JSON serialization failed: {e}"));
                    JObject::null().into_raw()
                }
            }
        }
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Encryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Destroy a ServerSession handle.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilServerSession_nativeDestroy<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe { handle_drop::<ServerSession>(handle) };
    }
}

// ---------------------------------------------------------------------------
// VeilSymmetricKey native methods
// ---------------------------------------------------------------------------

/// Create a SymmetricKey from raw 32 bytes. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeFromBytes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    raw: JByteArray<'local>,
) -> jlong {
    let bytes = match get_bytes(&mut env, &raw) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid key bytes");
            return 0;
        }
    };
    if bytes.len() != 32 {
        throw_veil_exception(
            &mut env,
            &format!("Symmetric key must be 32 bytes, got {}", bytes.len()),
        );
        return 0;
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    let key = SymmetricKey::from_bytes(key_bytes);
    box_to_handle(key)
}

/// Create a SymmetricKey from a base64-encoded string. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeFromBase64<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    b64: JString<'local>,
) -> jlong {
    let b64_str = match get_string(&mut env, &b64) {
        Some(s) => s,
        None => {
            throw_veil_exception(&mut env, "Invalid base64 string");
            return 0;
        }
    };
    match SymmetricKey::from_base64(&b64_str) {
        Ok(key) => box_to_handle(key),
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Invalid symmetric key: {e}"));
            0
        }
    }
}

/// Generate a new random SymmetricKey. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeGenerate<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jlong {
    box_to_handle(SymmetricKey::generate())
}

/// Derive a SymmetricKey from master key + context via HKDF. Returns handle (long).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeDerive<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    master: JByteArray<'local>,
    context: JByteArray<'local>,
) -> jlong {
    let master_bytes = match get_bytes(&mut env, &master) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid master key bytes");
            return 0;
        }
    };
    let ctx_bytes = match get_bytes(&mut env, &context) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid context bytes");
            return 0;
        }
    };
    match SymmetricKey::derive(&master_bytes, &ctx_bytes) {
        Ok(key) => box_to_handle(key),
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Key derivation failed: {e}"));
            0
        }
    }
}

/// Encrypt plaintext. Returns JSON string with envelope fields.
///
/// JSON format:
/// ```json
/// {"version":1,"nonce":"b64","ciphertext":"b64","aad":"b64"}
/// ```
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeEncrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    plaintext: JByteArray<'local>,
    aad: JByteArray<'local>,
) -> jstring {
    let pt = match get_bytes(&mut env, &plaintext) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid plaintext bytes");
            return JObject::null().into_raw();
        }
    };
    let aad_bytes = match get_bytes(&mut env, &aad) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid AAD bytes");
            return JObject::null().into_raw();
        }
    };

    let key = unsafe { handle_to_ref::<SymmetricKey>(handle) };

    match key.encrypt(&pt, &aad_bytes) {
        Ok(envelope) => {
            let result = serde_json::json!({
                "version": envelope.version,
                "nonce": B64.encode(&envelope.nonce),
                "ciphertext": B64.encode(&envelope.ciphertext),
                "aad": B64.encode(&envelope.aad),
            });
            match env.new_string(result.to_string()) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    throw_veil_exception(&mut env, &format!("JSON serialization failed: {e}"));
                    JObject::null().into_raw()
                }
            }
        }
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Encryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Encrypt plaintext with a key version tag. Returns JSON string with envelope fields.
///
/// JSON format:
/// ```json
/// {"version":1,"nonce":"b64","ciphertext":"b64","aad":"b64","key_version":N}
/// ```
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeEncryptVersioned<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    plaintext: JByteArray<'local>,
    aad: JByteArray<'local>,
    key_version: jni::sys::jint,
) -> jstring {
    let pt = match get_bytes(&mut env, &plaintext) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid plaintext bytes");
            return JObject::null().into_raw();
        }
    };
    let aad_bytes = match get_bytes(&mut env, &aad) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid AAD bytes");
            return JObject::null().into_raw();
        }
    };

    let key = unsafe { handle_to_ref::<SymmetricKey>(handle) };

    match key.encrypt_versioned(&pt, &aad_bytes, key_version as u32) {
        Ok(envelope) => {
            let result = serde_json::json!({
                "version": envelope.version,
                "nonce": B64.encode(&envelope.nonce),
                "ciphertext": B64.encode(&envelope.ciphertext),
                "aad": B64.encode(&envelope.aad),
                "key_version": key_version,
            });
            match env.new_string(result.to_string()) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    throw_veil_exception(&mut env, &format!("JSON serialization failed: {e}"));
                    JObject::null().into_raw()
                }
            }
        }
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Encryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Decrypt a symmetric envelope. Returns plaintext bytes.
///
/// Takes nonce, ciphertext, and aad as base64 strings (from the Java envelope).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeDecrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    nonce_b64: JString<'local>,
    ciphertext_b64: JString<'local>,
    aad_b64: JString<'local>,
) -> jbyteArray {
    let nonce = match get_string(&mut env, &nonce_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid nonce");
            return JObject::null().into_raw();
        }
    };
    let ct = match get_string(&mut env, &ciphertext_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid ciphertext");
            return JObject::null().into_raw();
        }
    };
    let aad = match get_string(&mut env, &aad_b64).and_then(|s| B64.decode(&s).ok()) {
        Some(b) => b,
        None => {
            throw_veil_exception(&mut env, "Invalid aad");
            return JObject::null().into_raw();
        }
    };

    let envelope = SymmetricEnvelope {
        version: 1,
        nonce,
        ciphertext: ct,
        aad,
        key_version: None,
    };

    let key = unsafe { handle_to_ref::<SymmetricKey>(handle) };

    match key.decrypt(&envelope) {
        Ok(plaintext) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                throw_veil_exception(&mut env, &format!("Failed to create byte array: {e}"));
                JObject::null().into_raw()
            }
        },
        Err(e) => {
            throw_veil_exception(&mut env, &format!("Decryption failed: {e}"));
            JObject::null().into_raw()
        }
    }
}

/// Export the key as base64 string.
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeToBase64<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let key = unsafe { handle_to_ref::<SymmetricKey>(handle) };
    let b64 = key.to_base64();
    match env.new_string(&b64) {
        Ok(s) => s.into_raw(),
        Err(_) => JObject::null().into_raw(),
    }
}

/// Destroy a SymmetricKey handle (zeroize + free).
#[no_mangle]
pub extern "system" fn Java_com_ninjacart_veil_VeilSymmetricKey_nativeDestroy<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe { handle_drop::<SymmetricKey>(handle) };
    }
}
