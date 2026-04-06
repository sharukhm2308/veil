"""Comprehensive test suite for the Veil Python SDK (``veil_sdk``).

Covers both asymmetric (X25519 + HKDF + AES-256-GCM) and symmetric
(AES-256-GCM with optional HKDF derivation) encryption paths exposed
by the PyO3 bindings.

Run with::

    pytest tests/test_veil_sdk.py -v
"""

import base64
import json
import os

import pytest

from veil_sdk import (
    VeilClientSession,
    VeilEnvelope,
    VeilKeyPair,
    VeilMetadata,
    VeilServerSession,
    VeilSymmetricEnvelope,
    VeilSymmetricKey,
    generate_keypair,
    keygen,
)


# =========================================================================
# VeilKeyPair
# =========================================================================


class TestVeilKeyPair:
    """Tests for X25519 static keypair generation and serialisation."""

    def test_generate_returns_keypair(self):
        """generate() produces a keypair with non-empty base64 keys."""
        kp = VeilKeyPair.generate()
        assert isinstance(kp.secret_base64(), str)
        assert isinstance(kp.public_base64(), str)
        assert len(kp.secret_base64()) > 0
        assert len(kp.public_base64()) > 0

    def test_generate_unique(self):
        """Two independently generated keypairs have different public keys."""
        kp1 = VeilKeyPair.generate()
        kp2 = VeilKeyPair.generate()
        assert kp1.public_base64() != kp2.public_base64()

    def test_from_secret_base64_roundtrip(self):
        """Exporting and reimporting a secret key preserves the public key."""
        kp = VeilKeyPair.generate()
        restored = VeilKeyPair.from_secret_base64(kp.secret_base64())
        assert restored.public_base64() == kp.public_base64()

    def test_from_secret_base64_invalid(self):
        """Invalid base64 raises ValueError."""
        with pytest.raises(ValueError):
            VeilKeyPair.from_secret_base64("not-valid-base64!!!")

    def test_repr(self):
        """repr includes the class name for debuggability."""
        kp = VeilKeyPair.generate()
        assert "VeilKeyPair" in repr(kp)


# =========================================================================
# Asymmetric Encryption (Client <-> Server)
# =========================================================================


class TestAsymmetricEncryption:
    """End-to-end tests for the asymmetric encrypt/decrypt protocol.

    Each test creates a fresh client session and, where needed, a
    corresponding server session to validate the full request/response
    lifecycle.
    """

    @staticmethod
    def _make_server_session(
        server_kp: VeilKeyPair, metadata: VeilMetadata
    ) -> VeilServerSession:
        """Helper: build a VeilServerSession from a keypair and metadata."""
        return VeilServerSession(
            server_kp.secret_base64(),
            metadata.ephemeral_key,
            metadata.key_id,
            metadata.request_id,
            metadata.timestamp,
        )

    def test_client_server_roundtrip(self, server_keypair, sample_plaintext):
        """Client encrypts a request; server decrypts it successfully."""
        client = VeilClientSession(server_keypair.public_base64(), "key-v1")
        envelope, metadata = client.encrypt_request(sample_plaintext, "gpt-4", 0)

        server = self._make_server_session(server_keypair, metadata)
        decrypted = server.decrypt_request(envelope)
        assert decrypted == sample_plaintext

    def test_server_response_roundtrip(self, server_keypair, sample_plaintext):
        """Server encrypts a response; client decrypts it successfully."""
        client = VeilClientSession(server_keypair.public_base64(), "key-v1")
        envelope, metadata = client.encrypt_request(b"request", "model", 0)

        server = self._make_server_session(server_keypair, metadata)
        server.decrypt_request(envelope)

        response_envelope = server.encrypt_response(sample_plaintext)
        decrypted = client.decrypt_response(response_envelope)
        assert decrypted == sample_plaintext

    def test_full_bidirectional(self, server_keypair):
        """Complete request + response lifecycle in a single test."""
        request_data = b"ping"
        response_data = b"pong"

        client = VeilClientSession(server_keypair.public_base64(), "k1")
        envelope, metadata = client.encrypt_request(request_data, "m", 0)

        server = self._make_server_session(server_keypair, metadata)
        assert server.decrypt_request(envelope) == request_data

        resp_env = server.encrypt_response(response_data)
        assert client.decrypt_response(resp_env) == response_data

    def test_different_sessions_different_ciphertexts(self, server_keypair):
        """Same plaintext encrypted in different sessions yields different envelopes."""
        plaintext = b"deterministic?"
        envelopes = []
        for _ in range(2):
            client = VeilClientSession(server_keypair.public_base64(), "k")
            env, _ = client.encrypt_request(plaintext, "m", 0)
            envelopes.append(env.to_json())
        assert envelopes[0] != envelopes[1]

    def test_wrong_server_key_fails(self, sample_plaintext):
        """Decryption with the wrong server key raises ValueError."""
        real_kp = VeilKeyPair.generate()
        wrong_kp = VeilKeyPair.generate()

        client = VeilClientSession(real_kp.public_base64(), "k")
        envelope, metadata = client.encrypt_request(sample_plaintext, "m", 0)

        wrong_server = VeilServerSession(
            wrong_kp.secret_base64(),
            metadata.ephemeral_key,
            metadata.key_id,
            metadata.request_id,
            metadata.timestamp,
        )
        with pytest.raises(ValueError):
            wrong_server.decrypt_request(envelope)

    def test_tampered_ciphertext_fails(self, server_keypair, sample_plaintext):
        """Flipping a byte in the ciphertext causes decryption to fail."""
        client = VeilClientSession(server_keypair.public_base64(), "k")
        envelope, metadata = client.encrypt_request(sample_plaintext, "m", 0)

        # Tamper: flip the first byte of the ciphertext
        json_str = envelope.to_json()
        d = json.loads(json_str)
        ct_bytes = bytearray(base64.b64decode(d["ciphertext"]))
        ct_bytes[0] ^= 0xFF
        d["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode()
        tampered = VeilEnvelope.from_json(json.dumps(d))

        server = VeilServerSession(
            server_keypair.secret_base64(),
            metadata.ephemeral_key,
            metadata.key_id,
            metadata.request_id,
            metadata.timestamp,
        )
        with pytest.raises(ValueError):
            server.decrypt_request(tampered)

    def test_large_payload(self, server_keypair):
        """1 MB payload survives the encrypt/decrypt roundtrip."""
        big = os.urandom(1024 * 1024)
        client = VeilClientSession(server_keypair.public_base64(), "k")
        envelope, metadata = client.encrypt_request(big, "m", 0)

        server = self._make_server_session(server_keypair, metadata)
        assert server.decrypt_request(envelope) == big

    def test_empty_payload(self, server_keypair):
        """Empty bytes roundtrip without error."""
        client = VeilClientSession(server_keypair.public_base64(), "k")
        envelope, metadata = client.encrypt_request(b"", "m", 0)

        server = self._make_server_session(server_keypair, metadata)
        assert server.decrypt_request(envelope) == b""

    def test_binary_payload(self, server_keypair):
        """Non-UTF-8 binary data roundtrips correctly."""
        binary = bytes(range(256))
        client = VeilClientSession(server_keypair.public_base64(), "k")
        envelope, metadata = client.encrypt_request(binary, "m", 0)

        server = self._make_server_session(server_keypair, metadata)
        assert server.decrypt_request(envelope) == binary


# =========================================================================
# VeilEnvelope
# =========================================================================


class TestVeilEnvelope:
    """Serialisation and introspection of asymmetric envelopes."""

    @pytest.fixture
    def _envelope(self, server_keypair, sample_plaintext):
        """Produce a VeilEnvelope for serialisation tests."""
        client = VeilClientSession(server_keypair.public_base64(), "k")
        env, _ = client.encrypt_request(sample_plaintext, "m", 0)
        return env

    def test_json_roundtrip(self, _envelope):
        """to_json -> from_json preserves all fields."""
        restored = VeilEnvelope.from_json(_envelope.to_json())
        assert restored.version == _envelope.version
        assert restored.nonce == _envelope.nonce
        assert restored.ciphertext == _envelope.ciphertext
        assert restored.aad == _envelope.aad

    def test_dict_roundtrip(self, _envelope):
        """to_dict -> from_dict preserves all fields."""
        d = _envelope.to_dict()
        restored = VeilEnvelope.from_dict(d)
        assert restored.version == _envelope.version
        assert restored.nonce == _envelope.nonce
        assert restored.ciphertext == _envelope.ciphertext

    def test_payload_size(self, _envelope):
        """payload_size matches the combined length of nonce + ciphertext + aad."""
        nonce_len = len(base64.b64decode(_envelope.nonce))
        ct_len = len(base64.b64decode(_envelope.ciphertext))
        aad_len = len(base64.b64decode(_envelope.aad))
        assert _envelope.payload_size() == nonce_len + ct_len + aad_len

    def test_from_json_invalid(self):
        """Malformed JSON raises ValueError."""
        with pytest.raises(ValueError):
            VeilEnvelope.from_json("{not json!}")

    def test_repr(self, _envelope):
        """repr contains the class name."""
        assert "VeilEnvelope" in repr(_envelope)


# =========================================================================
# VeilMetadata
# =========================================================================


class TestVeilMetadata:
    """Metadata extraction and HTTP header generation."""

    @pytest.fixture
    def _metadata(self, server_keypair):
        """Produce VeilMetadata for header tests."""
        client = VeilClientSession(server_keypair.public_base64(), "shim-v1")
        _, metadata = client.encrypt_request(b"x", "gpt-4o", 100)
        return metadata

    def test_to_headers(self, _metadata):
        """to_headers returns a dict with X-Veil-* keys."""
        headers = _metadata.to_headers()
        assert any(k.startswith("X-Veil") or k.startswith("x-veil") for k in headers)

    def test_headers_contain_key_id(self, _metadata):
        """The key_id is present in the metadata and headers."""
        assert _metadata.key_id == "shim-v1"
        headers = _metadata.to_headers()
        header_values = list(headers.values())
        assert "shim-v1" in header_values

    def test_headers_contain_model(self, _metadata):
        """The model name is accessible on the metadata object."""
        assert _metadata.model == "gpt-4o"

    def test_repr(self, _metadata):
        """repr contains the class name."""
        assert "VeilMetadata" in repr(_metadata)


# =========================================================================
# VeilSymmetricKey
# =========================================================================


class TestVeilSymmetricKey:
    """AES-256-GCM symmetric key: generation, derivation, encrypt/decrypt."""

    # -- Construction -------------------------------------------------------

    def test_generate_creates_key(self):
        """generate() produces a key whose base64 export is 44 characters.

        (32 raw bytes -> 44 base64 characters with padding.)
        """
        key = VeilSymmetricKey.generate()
        b64 = key.to_base64()
        assert len(b64) == 44

    def test_generate_unique(self):
        """Two generated keys differ."""
        k1 = VeilSymmetricKey.generate()
        k2 = VeilSymmetricKey.generate()
        assert k1.to_base64() != k2.to_base64()

    def test_from_bytes_roundtrip(self, sample_plaintext, sample_aad):
        """A key created via from_bytes can encrypt/decrypt successfully."""
        original = VeilSymmetricKey.generate()
        raw = base64.b64decode(original.to_base64())
        restored = VeilSymmetricKey.from_bytes(raw)

        envelope = original.encrypt(sample_plaintext, sample_aad)
        assert restored.decrypt(envelope) == sample_plaintext

    def test_from_bytes_wrong_length(self):
        """from_bytes rejects input that is not exactly 32 bytes."""
        with pytest.raises(ValueError):
            VeilSymmetricKey.from_bytes(b"\x00" * 16)

    def test_from_base64_roundtrip(self, sample_plaintext, sample_aad):
        """A key round-tripped through base64 still works for decryption."""
        original = VeilSymmetricKey.generate()
        restored = VeilSymmetricKey.from_base64(original.to_base64())

        envelope = original.encrypt(sample_plaintext, sample_aad)
        assert restored.decrypt(envelope) == sample_plaintext

    def test_from_base64_invalid(self):
        """Invalid base64 raises ValueError."""
        with pytest.raises(ValueError):
            VeilSymmetricKey.from_base64("not-valid-base64!!!")

    # -- Encrypt / Decrypt --------------------------------------------------

    def test_encrypt_decrypt_roundtrip(self, symmetric_key, sample_plaintext, sample_aad):
        """Basic encrypt then decrypt returns the original plaintext."""
        envelope = symmetric_key.encrypt(sample_plaintext, sample_aad)
        assert symmetric_key.decrypt(envelope) == sample_plaintext

    def test_encrypt_decrypt_utf8(self, symmetric_key):
        """Unicode text survives the encrypt/decrypt cycle."""
        text = "Hello \U0001f30d \u3053\u3093\u306b\u3061\u306f".encode("utf-8")
        envelope = symmetric_key.encrypt(text, b"utf8-test")
        assert symmetric_key.decrypt(envelope) == text

    def test_encrypt_decrypt_empty(self, symmetric_key):
        """Empty plaintext roundtrips without error."""
        envelope = symmetric_key.encrypt(b"", b"empty")
        assert symmetric_key.decrypt(envelope) == b""

    def test_encrypt_decrypt_large(self, symmetric_key):
        """1 MB random payload roundtrips correctly."""
        big = os.urandom(1024 * 1024)
        envelope = symmetric_key.encrypt(big, b"large")
        assert symmetric_key.decrypt(envelope) == big

    def test_encrypt_decrypt_binary(self, symmetric_key):
        """Arbitrary non-UTF-8 bytes roundtrip correctly."""
        binary = b"\x00\x01\xff\xfe"
        envelope = symmetric_key.encrypt(binary, b"bin")
        assert symmetric_key.decrypt(envelope) == binary

    def test_encrypt_produces_different_ciphertexts(self, symmetric_key, sample_plaintext):
        """Encrypting the same plaintext twice yields different envelopes (random nonce)."""
        env1 = symmetric_key.encrypt(sample_plaintext, b"aad")
        env2 = symmetric_key.encrypt(sample_plaintext, b"aad")
        assert env1.ciphertext != env2.ciphertext

    # -- Wrong key / tampering ----------------------------------------------

    def test_wrong_key_fails(self, sample_plaintext, sample_aad):
        """Decrypting with a different key raises ValueError."""
        key_a = VeilSymmetricKey.generate()
        key_b = VeilSymmetricKey.generate()
        envelope = key_a.encrypt(sample_plaintext, sample_aad)
        with pytest.raises(ValueError):
            key_b.decrypt(envelope)

    def test_tampered_ciphertext_fails(self, symmetric_key, sample_plaintext, sample_aad):
        """Flipping a byte in the ciphertext causes authentication failure."""
        envelope = symmetric_key.encrypt(sample_plaintext, sample_aad)
        d = json.loads(envelope.to_json())
        ct = bytearray(base64.b64decode(d["ciphertext"]))
        ct[0] ^= 0xFF
        d["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        tampered = VeilSymmetricEnvelope.from_json(json.dumps(d))
        with pytest.raises(ValueError):
            symmetric_key.decrypt(tampered)

    def test_tampered_nonce_fails(self, symmetric_key, sample_plaintext, sample_aad):
        """Changing the nonce causes authentication failure."""
        envelope = symmetric_key.encrypt(sample_plaintext, sample_aad)
        d = json.loads(envelope.to_json())
        nonce = bytearray(base64.b64decode(d["nonce"]))
        nonce[0] ^= 0xFF
        d["nonce"] = base64.b64encode(bytes(nonce)).decode()
        tampered = VeilSymmetricEnvelope.from_json(json.dumps(d))
        with pytest.raises(ValueError):
            symmetric_key.decrypt(tampered)

    # -- Key derivation -----------------------------------------------------

    def test_derive_deterministic(self, master_key_bytes, sample_plaintext, sample_aad):
        """Same master key + context -> same derived key (can cross-decrypt)."""
        ctx = b"conv-42"
        k1 = VeilSymmetricKey.derive(master_key_bytes, ctx)
        k2 = VeilSymmetricKey.derive(master_key_bytes, ctx)
        envelope = k1.encrypt(sample_plaintext, sample_aad)
        assert k2.decrypt(envelope) == sample_plaintext

    def test_derive_different_context(self, master_key_bytes, sample_plaintext, sample_aad):
        """Different context strings produce different keys that cannot cross-decrypt."""
        k_a = VeilSymmetricKey.derive(master_key_bytes, b"context-A")
        k_b = VeilSymmetricKey.derive(master_key_bytes, b"context-B")
        assert k_a.to_base64() != k_b.to_base64()

        envelope = k_a.encrypt(sample_plaintext, sample_aad)
        with pytest.raises(ValueError):
            k_b.decrypt(envelope)

    def test_derive_different_master(self, sample_plaintext, sample_aad):
        """Different master keys with the same context produce different derived keys."""
        ctx = b"shared-context"
        k1 = VeilSymmetricKey.derive(os.urandom(32), ctx)
        k2 = VeilSymmetricKey.derive(os.urandom(32), ctx)
        assert k1.to_base64() != k2.to_base64()

    def test_derive_empty_context(self, master_key_bytes, sample_plaintext, sample_aad):
        """Empty context bytes are accepted and produce a usable key."""
        key = VeilSymmetricKey.derive(master_key_bytes, b"")
        envelope = key.encrypt(sample_plaintext, sample_aad)
        assert key.decrypt(envelope) == sample_plaintext

    # -- Versioned encryption -----------------------------------------------

    def test_encrypt_versioned(self, symmetric_key, sample_plaintext, sample_aad):
        """encrypt_versioned stores the key_version on the envelope."""
        envelope = symmetric_key.encrypt_versioned(sample_plaintext, sample_aad, 3)
        assert envelope.key_version == 3
        assert symmetric_key.decrypt(envelope) == sample_plaintext

    def test_encrypt_versioned_zero(self, symmetric_key, sample_plaintext, sample_aad):
        """key_version=0 is a valid version number."""
        envelope = symmetric_key.encrypt_versioned(sample_plaintext, sample_aad, 0)
        assert envelope.key_version == 0

    def test_unversioned_has_none(self, symmetric_key, sample_plaintext, sample_aad):
        """encrypt() (no version) yields key_version == None."""
        envelope = symmetric_key.encrypt(sample_plaintext, sample_aad)
        assert envelope.key_version is None


# =========================================================================
# VeilSymmetricEnvelope
# =========================================================================


class TestVeilSymmetricEnvelope:
    """Serialisation, getters, and introspection of symmetric envelopes."""

    @pytest.fixture
    def _envelope(self, symmetric_key, sample_plaintext, sample_aad):
        """A symmetric envelope for serialisation tests."""
        return symmetric_key.encrypt(sample_plaintext, sample_aad)

    @pytest.fixture
    def _versioned_envelope(self, symmetric_key, sample_plaintext, sample_aad):
        """A versioned symmetric envelope."""
        return symmetric_key.encrypt_versioned(sample_plaintext, sample_aad, 7)

    def test_json_roundtrip(self, symmetric_key, _envelope, sample_plaintext):
        """to_json -> from_json preserves decryptability."""
        restored = VeilSymmetricEnvelope.from_json(_envelope.to_json())
        assert symmetric_key.decrypt(restored) == sample_plaintext

    def test_dict_roundtrip(self, symmetric_key, _envelope, sample_plaintext):
        """to_dict -> from_dict preserves decryptability."""
        d = _envelope.to_dict()
        restored = VeilSymmetricEnvelope.from_dict(d)
        assert symmetric_key.decrypt(restored) == sample_plaintext

    def test_dict_with_key_version(self, _versioned_envelope):
        """Versioned envelope exports key_version in the dict."""
        d = _versioned_envelope.to_dict()
        assert d["key_version"] == 7

    def test_dict_without_key_version(self, _envelope):
        """Unversioned envelope omits key_version from the dict."""
        d = _envelope.to_dict()
        assert "key_version" not in d

    def test_payload_size(self, _envelope):
        """payload_size matches the combined byte length of nonce + ciphertext + aad."""
        nonce_len = len(base64.b64decode(_envelope.nonce))
        ct_len = len(base64.b64decode(_envelope.ciphertext))
        aad_len = len(base64.b64decode(_envelope.aad))
        assert _envelope.payload_size() == nonce_len + ct_len + aad_len

    def test_from_json_invalid(self):
        """Malformed JSON raises ValueError."""
        with pytest.raises(ValueError):
            VeilSymmetricEnvelope.from_json("{bad json!")

    def test_repr(self, _envelope):
        """repr contains the class name."""
        assert "VeilSymmetricEnvelope" in repr(_envelope)

    def test_getters(self, _envelope):
        """version, nonce, ciphertext, and aad are non-empty base64 strings."""
        assert isinstance(_envelope.version, int)
        assert isinstance(_envelope.nonce, str) and len(_envelope.nonce) > 0
        assert isinstance(_envelope.ciphertext, str) and len(_envelope.ciphertext) > 0
        assert isinstance(_envelope.aad, str) and len(_envelope.aad) > 0
        # Verify they are valid base64
        base64.b64decode(_envelope.nonce)
        base64.b64decode(_envelope.ciphertext)
        base64.b64decode(_envelope.aad)


# =========================================================================
# Symmetric Interop (Agent <-> Relay)
# =========================================================================


class TestSymmetricInterop:
    """Cross-cutting tests verifying Agent <-> Relay interoperability.

    These simulate the real deployment pattern where the agent and relay
    independently derive the same symmetric key from a shared master
    secret and a conversation-specific context string.
    """

    def test_derive_encrypt_derive_decrypt(self, master_key_bytes, sample_plaintext):
        """Agent-side derive+encrypt, relay-side derive+decrypt with same params."""
        context = b"cw-user42-conv99"

        agent_key = VeilSymmetricKey.derive(master_key_bytes, context)
        envelope = agent_key.encrypt(sample_plaintext, context)

        relay_key = VeilSymmetricKey.derive(master_key_bytes, context)
        assert relay_key.decrypt(envelope) == sample_plaintext

    def test_message_at_rest_format(self, symmetric_key, sample_plaintext, sample_aad):
        """Serialised envelope has the expected JSON structure for storage.

        Validates that the wire format contains exactly the fields that
        downstream systems (e.g. Chatwoot message store) expect.
        """
        envelope = symmetric_key.encrypt(sample_plaintext, sample_aad)
        raw = json.loads(envelope.to_json())
        assert set(raw.keys()) >= {"version", "nonce", "ciphertext", "aad"}
        assert isinstance(raw["version"], int)
        # Verify all binary fields are valid base64
        for field in ("nonce", "ciphertext", "aad"):
            base64.b64decode(raw[field])

    def test_context_binding_prevents_cross_conversation(self, master_key_bytes):
        """Ciphertext bound to conversation A cannot be decrypted under conversation B."""
        plaintext = b"secret"
        ctx_a = b"cw-user1-conv-A"
        ctx_b = b"cw-user1-conv-B"

        key_a = VeilSymmetricKey.derive(master_key_bytes, ctx_a)
        envelope = key_a.encrypt(plaintext, ctx_a)

        key_b = VeilSymmetricKey.derive(master_key_bytes, ctx_b)
        with pytest.raises(ValueError):
            key_b.decrypt(envelope)

    def test_context_binding_prevents_cross_user(self, master_key_bytes):
        """Ciphertext bound to user A's context cannot be decrypted with user B's context."""
        plaintext = b"private"
        ctx_user_a = b"cw-userA-conv1"
        ctx_user_b = b"cw-userB-conv1"

        key_a = VeilSymmetricKey.derive(master_key_bytes, ctx_user_a)
        envelope = key_a.encrypt(plaintext, ctx_user_a)

        key_b = VeilSymmetricKey.derive(master_key_bytes, ctx_user_b)
        with pytest.raises(ValueError):
            key_b.decrypt(envelope)


# =========================================================================
# Module-level functions
# =========================================================================


class TestModuleFunctions:
    """Tests for the convenience functions at module scope."""

    def test_generate_keypair(self):
        """generate_keypair() returns a (secret_b64, public_b64) tuple."""
        secret, public = generate_keypair()
        assert isinstance(secret, str) and len(secret) > 0
        assert isinstance(public, str) and len(public) > 0
        # Verify they are valid base64
        base64.b64decode(secret)
        base64.b64decode(public)

    def test_keygen_alias(self):
        """keygen() behaves identically to generate_keypair()."""
        secret, public = keygen()
        assert isinstance(secret, str) and len(secret) > 0
        assert isinstance(public, str) and len(public) > 0
        # Verify the returned key can reconstruct the same public key
        kp = VeilKeyPair.from_secret_base64(secret)
        assert kp.public_base64() == public
