//! HKDF-SHA256 key derivation for the Veil protocol.
//!
//! Derives separate encryption keys for each direction (client->server,
//! server->client) from the ECDH shared secret.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{VeilError, VeilResult};

/// The length of derived AES-256 keys.
const KEY_LEN: usize = 32;

/// Salt used for HKDF - standard single-DH sessions.
const PROTOCOL_SALT: &[u8] = b"veil-e2e-llm-v1";

/// Salt for prekey-enhanced sessions (dual-DH true forward secrecy).
const PROTOCOL_SALT_V2: &[u8] = b"veil-e2e-llm-v2-prekey";

/// Info strings for deriving directional keys.
const CLIENT_TO_SERVER_INFO: &[u8] = b"veil-c2s";
const SERVER_TO_CLIENT_INFO: &[u8] = b"veil-s2c";

/// A pair of derived session keys, one for each direction.
/// Both keys are securely zeroized from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for encrypting client->server traffic.
    pub client_to_server: [u8; KEY_LEN],
    /// Key for encrypting server->client traffic.
    pub server_to_client: [u8; KEY_LEN],
}

impl SessionKeys {
    /// Derive session keys from an ECDH shared secret (standard single-DH).
    pub fn derive(shared_secret: &SharedSecret) -> VeilResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT), shared_secret.as_bytes());

        let mut c2s = [0u8; KEY_LEN];
        hk.expand(CLIENT_TO_SERVER_INFO, &mut c2s)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand c2s: {e}")))?;

        let mut s2c = [0u8; KEY_LEN];
        hk.expand(SERVER_TO_CLIENT_INFO, &mut s2c)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand s2c: {e}")))?;

        Ok(Self {
            client_to_server: c2s,
            server_to_client: s2c,
        })
    }

    /// Derive from raw shared secret bytes (32 bytes).
    pub fn derive_from_bytes(shared_bytes: &[u8; 32]) -> VeilResult<Self> {
        let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT), shared_bytes);

        let mut c2s = [0u8; KEY_LEN];
        hk.expand(CLIENT_TO_SERVER_INFO, &mut c2s)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand c2s: {e}")))?;

        let mut s2c = [0u8; KEY_LEN];
        hk.expand(SERVER_TO_CLIENT_INFO, &mut s2c)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand s2c: {e}")))?;

        Ok(Self {
            client_to_server: c2s,
            server_to_client: s2c,
        })
    }

    /// Derive session keys from TWO ECDH shared secrets (true forward secrecy).
    ///
    /// Uses both a static DH and a one-time prekey DH as input keying material.
    /// An attacker who later compromises the server static key CANNOT derive
    /// session keys because the prekey secret has already been deleted.
    ///
    /// IKM = DH(client_eph, server_static) || DH(client_eph, server_prekey)
    pub fn derive_with_prekey(
        static_shared: &SharedSecret,
        prekey_shared: &SharedSecret,
    ) -> VeilResult<Self> {
        // Concatenate both DH outputs: attacker needs BOTH to derive keys
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(static_shared.as_bytes());
        ikm[32..].copy_from_slice(prekey_shared.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT_V2), &ikm);

        let mut c2s = [0u8; KEY_LEN];
        hk.expand(CLIENT_TO_SERVER_INFO, &mut c2s)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand c2s: {e}")))?;

        let mut s2c = [0u8; KEY_LEN];
        hk.expand(SERVER_TO_CLIENT_INFO, &mut s2c)
            .map_err(|e| VeilError::KeyDerivation(format!("HKDF expand s2c: {e}")))?;

        // Securely erase IKM from stack
        ikm.zeroize();

        Ok(Self {
            client_to_server: c2s,
            server_to_client: s2c,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EphemeralKeyPair, StaticKeyPair};

    #[test]
    fn test_derive_session_keys() {
        let server = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();
        let client_pub = *client.public_key();

        let client_shared = client.diffie_hellman(server.public_key()).unwrap();
        let server_shared = server.diffie_hellman(&client_pub);

        let client_keys = SessionKeys::derive(&client_shared).unwrap();
        let server_keys = SessionKeys::derive(&server_shared).unwrap();

        assert_eq!(client_keys.client_to_server, server_keys.client_to_server);
        assert_eq!(client_keys.server_to_client, server_keys.server_to_client);
        assert_ne!(client_keys.client_to_server, client_keys.server_to_client);
    }

    #[test]
    fn test_different_secrets_different_keys() {
        let server1 = StaticKeyPair::generate();
        let server2 = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();

        let shared1 = server1.diffie_hellman(client.public_key());
        let shared2 = server2.diffie_hellman(client.public_key());

        let keys1 = SessionKeys::derive(&shared1).unwrap();
        let keys2 = SessionKeys::derive(&shared2).unwrap();

        assert_ne!(keys1.client_to_server, keys2.client_to_server);
    }

    #[test]
    fn test_session_keys_zeroize() {
        use zeroize::Zeroize;
        let server = StaticKeyPair::generate();
        let client = EphemeralKeyPair::generate();
        let shared = client.diffie_hellman(server.public_key()).unwrap();
        let mut keys = SessionKeys::derive(&shared).unwrap();

        assert_ne!(keys.client_to_server, [0u8; 32]);
        assert_ne!(keys.server_to_client, [0u8; 32]);
        keys.zeroize();
        assert_eq!(keys.client_to_server, [0u8; 32], "c2s key not zeroized");
        assert_eq!(keys.server_to_client, [0u8; 32], "s2c key not zeroized");
    }

    #[test]
    fn test_derive_with_prekey_differs_from_standard() {
        use crate::keys::PreKeyPair;

        let server_static = StaticKeyPair::generate();
        let server_prekey = PreKeyPair::generate("prekey-001".into());
        let client = StaticKeyPair::generate();
        let client_pub = *client.public_key();

        let static_shared = server_static.diffie_hellman(&client_pub);
        let prekey_shared = server_prekey.diffie_hellman(&client_pub);

        let prekey_keys = SessionKeys::derive_with_prekey(&static_shared, &prekey_shared).unwrap();
        let standard_keys = SessionKeys::derive(&static_shared).unwrap();

        assert_ne!(
            prekey_keys.client_to_server, standard_keys.client_to_server,
            "Prekey session keys must differ from standard session keys"
        );
    }

    #[test]
    fn test_prekey_client_server_key_agreement() {
        use crate::keys::PreKeyPair;

        let server_static = StaticKeyPair::generate();
        let server_prekey = PreKeyPair::generate("pk-001".into());
        let client_sim = StaticKeyPair::generate();
        let client_pub = *client_sim.public_key();

        // Client side
        let c_static_shared = client_sim.diffie_hellman(server_static.public_key());
        let c_prekey_shared = client_sim.diffie_hellman(&server_prekey.public);
        let client_keys =
            SessionKeys::derive_with_prekey(&c_static_shared, &c_prekey_shared).unwrap();

        // Server side
        let s_static_shared = server_static.diffie_hellman(&client_pub);
        let s_prekey_shared = server_prekey.diffie_hellman(&client_pub);
        let server_keys =
            SessionKeys::derive_with_prekey(&s_static_shared, &s_prekey_shared).unwrap();

        assert_eq!(
            client_keys.client_to_server, server_keys.client_to_server,
            "Client and server must derive matching c2s keys with prekey"
        );
        assert_eq!(
            client_keys.server_to_client, server_keys.server_to_client,
            "Client and server must derive matching s2c keys with prekey"
        );
    }

    #[test]
    fn test_wrong_prekey_breaks_agreement() {
        use crate::keys::PreKeyPair;

        let server_static = StaticKeyPair::generate();
        let server_prekey = PreKeyPair::generate("pk-001".into());
        let wrong_prekey = PreKeyPair::generate("pk-wrong".into());
        let client = StaticKeyPair::generate();
        let client_pub = *client.public_key();

        let s_static_shared = server_static.diffie_hellman(&client_pub);
        let s_prekey_shared = server_prekey.diffie_hellman(&client_pub);
        let correct_keys =
            SessionKeys::derive_with_prekey(&s_static_shared, &s_prekey_shared).unwrap();

        let w_prekey_shared = wrong_prekey.diffie_hellman(&client_pub);
        let wrong_keys =
            SessionKeys::derive_with_prekey(&s_static_shared, &w_prekey_shared).unwrap();

        assert_ne!(
            correct_keys.client_to_server, wrong_keys.client_to_server,
            "Wrong prekey must yield different session keys"
        );
    }
}
