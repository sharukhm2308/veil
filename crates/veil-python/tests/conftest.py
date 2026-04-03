"""Shared pytest fixtures for the Veil Python SDK test suite.

Provides reusable cryptographic primitives (keypairs, symmetric keys,
sample data) so individual test modules stay focused on behaviour.
"""

import os

import pytest

from veil_sdk import VeilKeyPair, VeilSymmetricKey


# ---------------------------------------------------------------------------
# Asymmetric fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def server_keypair() -> VeilKeyPair:
    """A fresh X25519 keypair representing the server's static identity."""
    return VeilKeyPair.generate()


# ---------------------------------------------------------------------------
# Symmetric fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def symmetric_key() -> VeilSymmetricKey:
    """A randomly generated AES-256-GCM key."""
    return VeilSymmetricKey.generate()


@pytest.fixture
def master_key_bytes() -> bytes:
    """32 bytes of random key material for HKDF derivation tests."""
    return os.urandom(32)


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_plaintext() -> bytes:
    """A representative JSON payload used as plaintext in encrypt/decrypt tests."""
    return b'{"prompt": "Hello, world!"}'


@pytest.fixture
def sample_aad() -> bytes:
    """Context string used as Additional Authenticated Data (AAD).

    Mimics the Chatwoot binding pattern: ``cw-<user_id>-<conversation_id>``.
    """
    return b"cw-user123-conv456"
