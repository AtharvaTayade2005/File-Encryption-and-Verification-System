"""
Unit tests for the Asymmetric Cryptography & Digital Signature Module (src/crypto_asymmetric.py).
Tests RSA key generation, PEM serialization/loading, RSA-OAEP session key wrapping,
and RSA PKCS#1 v1.5 digital signature generation and verification.
"""

import os
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.crypto_asymmetric import (
    generate_rsa_keypair,
    export_key_to_pem,
    load_key_from_pem,
    wrap_session_key,
    unwrap_session_key,
    sign_payload,
    verify_signature,
)


@pytest.fixture(scope="module")
def rsa_keypair():
    """Module-scoped fixture to avoid redundant RSA key generation overhead."""
    return generate_rsa_keypair(key_size=2048)


@pytest.fixture(scope="module")
def second_keypair():
    """Secondary keypair representing an alternative user/recipient."""
    return generate_rsa_keypair(key_size=2048)


class TestRSAKeyManagement:
    """Test suite for RSA key generation and PEM serialization."""

    def test_generate_rsa_keypair_returns_valid_instances(self, rsa_keypair):
        priv, pub = rsa_keypair
        assert isinstance(priv, RSAPrivateKey)
        assert isinstance(pub, RSAPublicKey)
        assert priv.key_size == 2048
        assert pub.key_size == 2048

    def test_generate_keypair_insecure_size_raises_value_error(self):
        with pytest.raises(ValueError, match="minimum is 2048 bits"):
            generate_rsa_keypair(key_size=1024)

    def test_pem_export_and_load_unencrypted_private_key(self, rsa_keypair):
        priv, _ = rsa_keypair
        pem_bytes = export_key_to_pem(priv, is_private=True)
        assert pem_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert pem_bytes.strip().endswith(b"-----END PRIVATE KEY-----")

        loaded_priv = load_key_from_pem(pem_bytes, is_private=True)
        assert isinstance(loaded_priv, RSAPrivateKey)
        assert loaded_priv.key_size == priv.key_size

    def test_pem_export_and_load_encrypted_private_key(self, rsa_keypair):
        priv, _ = rsa_keypair
        passphrase = "UltraSecurePassword123!"
        pem_bytes = export_key_to_pem(priv, is_private=True, password=passphrase)
        assert pem_bytes.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

        # Loading with correct passphrase succeeds
        loaded_priv = load_key_from_pem(pem_bytes, is_private=True, password=passphrase)
        assert isinstance(loaded_priv, RSAPrivateKey)

        # Loading with wrong passphrase fails
        with pytest.raises(ValueError):
            load_key_from_pem(pem_bytes, is_private=True, password="WrongPassword!")

    def test_pem_export_and_load_public_key(self, rsa_keypair):
        _, pub = rsa_keypair
        pem_bytes = export_key_to_pem(pub, is_private=False)
        assert pem_bytes.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert pem_bytes.strip().endswith(b"-----END PUBLIC KEY-----")

        loaded_pub = load_key_from_pem(pem_bytes, is_private=False)
        assert isinstance(loaded_pub, RSAPublicKey)
        assert loaded_pub.key_size == pub.key_size

    def test_pem_export_mismatched_key_type_raises_error(self, rsa_keypair):
        priv, pub = rsa_keypair
        with pytest.raises(TypeError, match="Expected RSAPrivateKey"):
            export_key_to_pem(pub, is_private=True)  # type: ignore

        with pytest.raises(TypeError, match="Expected RSAPublicKey"):
            export_key_to_pem(priv, is_private=False)  # type: ignore


class TestSessionKeyWrapping:
    """Test suite for RSA-OAEP session key wrapping and unwrapping."""

    def test_wrap_and_unwrap_session_key_roundtrip(self, rsa_keypair):
        priv, pub = rsa_keypair
        session_keys = [
            os.urandom(16),  # 128-bit key
            os.urandom(24),  # 192-bit key
            os.urandom(32),  # 256-bit AES key
            b"arbitrary-symmetric-secret-token",
        ]
        for key in session_keys:
            wrapped = wrap_session_key(key, pub)
            assert isinstance(wrapped, bytes)
            assert len(wrapped) == 256  # 2048 bits / 8 = 256 bytes

            unwrapped = unwrap_session_key(wrapped, priv)
            assert unwrapped == key

    def test_unwrap_with_wrong_private_key_fails(self, rsa_keypair, second_keypair):
        _, pub_a = rsa_keypair
        priv_b, _ = second_keypair
        session_key = os.urandom(32)

        # Wrapped for A
        wrapped = wrap_session_key(session_key, pub_a)

        # Attempting unwrap with B's private key must fail
        with pytest.raises(ValueError):
            unwrap_session_key(wrapped, priv_b)

    def test_tampered_wrapped_key_fails_unwrapping(self, rsa_keypair):
        priv, pub = rsa_keypair
        session_key = os.urandom(32)
        wrapped = bytearray(wrap_session_key(session_key, pub))

        # Tamper with 1 byte of the ciphertext
        wrapped[10] ^= 0x01
        with pytest.raises(ValueError):
            unwrap_session_key(bytes(wrapped), priv)


class TestDigitalSignatures:
    """Test suite for RSA PKCS#1 v1.5 digital signatures and verification."""

    def test_signature_creation_and_successful_verification(self, rsa_keypair):
        priv, pub = rsa_keypair
        test_payloads = [
            b"Legal contract agreement plaintext.",
            "Unicode payload: \U0001f680 File integrity verified \u092d\u093e\u0930\u0924".encode("utf-8"),
            b"",  # Empty payload
            os.urandom(4096),  # Binary file payload
        ]
        for data in test_payloads:
            signature = sign_payload(data, priv)
            assert isinstance(signature, bytes)
            assert len(signature) == 256  # 2048-bit signature is 256 bytes

            # Verification succeeds with authentic public key
            is_valid = verify_signature(data, signature, pub)
            assert is_valid is True

    def test_signature_rejected_when_payload_modified_by_single_byte(self, rsa_keypair):
        priv, pub = rsa_keypair
        data = b"Critical financial transfer authorization: $500,000 to Account #12345"
        signature = sign_payload(data, priv)

        # Verify original passes
        assert verify_signature(data, signature, pub) is True

        # Modify exactly 1 byte at the start
        tampered_start = bytearray(data)
        tampered_start[0] ^= 0x01
        assert verify_signature(bytes(tampered_start), signature, pub) is False

        # Modify exactly 1 byte in the middle
        tampered_mid = bytearray(data)
        tampered_mid[len(data) // 2] ^= 0xFF
        assert verify_signature(bytes(tampered_mid), signature, pub) is False

        # Modify exactly 1 byte at the end
        tampered_end = bytearray(data)
        tampered_end[-1] ^= 0x80
        assert verify_signature(bytes(tampered_end), signature, pub) is False

    def test_signature_rejected_when_signature_bytes_tampered(self, rsa_keypair):
        priv, pub = rsa_keypair
        data = b"Untampered original data."
        signature = bytearray(sign_payload(data, priv))

        # Tamper 1 byte of the signature
        signature[0] ^= 0x01
        assert verify_signature(data, bytes(signature), pub) is False

    def test_signature_rejected_with_wrong_public_key(self, rsa_keypair, second_keypair):
        priv_a, _ = rsa_keypair
        _, pub_b = second_keypair
        data = b"Sender identity authentication test."

        signature_a = sign_payload(data, priv_a)
        # Verifying A's signature with B's public key must fail
        assert verify_signature(data, signature_a, pub_b) is False

    def test_signature_type_errors(self, rsa_keypair):
        priv, pub = rsa_keypair
        with pytest.raises(TypeError):
            sign_payload("string data", priv)  # type: ignore

        with pytest.raises(TypeError):
            verify_signature("string data", b"sig", pub)  # type: ignore
