"""
Unit tests for the File Vault & Binary Container Serialization Module (src/file_vault.py).
Tests HMAC-SHA256 generation/verification, .cns packing/unpacking,
magic byte validation, tamper detection, and secure file shredding.
"""

import os
import pytest

from src.crypto_symmetric import CIPHER_AES, CIPHER_DES
from src.file_vault import (
    MAGIC_BYTES,
    HMAC_TAG_SIZE,
    generate_hmac,
    verify_hmac,
    pack_cns_file,
    unpack_cns_file,
    shred_file,
)


class TestHMACIntegrity:
    """Test suite for HMAC-SHA256 authentication and verification."""

    def test_generate_and_verify_hmac_success(self):
        key = os.urandom(32)
        ciphertext = b"Confidential encrypted ciphertext blocks."

        tag = generate_hmac(key, ciphertext)
        assert isinstance(tag, bytes)
        assert len(tag) == HMAC_TAG_SIZE

        # Constant-time verification succeeds
        assert verify_hmac(key, ciphertext, tag) is True

    def test_verify_hmac_fails_when_ciphertext_modified(self):
        key = os.urandom(32)
        ciphertext = b"Encrypted financial audit data."
        tag = generate_hmac(key, ciphertext)

        # Tamper exactly 1 byte in the ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        assert verify_hmac(key, bytes(tampered), tag) is False

        tampered_end = bytearray(ciphertext)
        tampered_end[-1] ^= 0x80
        assert verify_hmac(key, bytes(tampered_end), tag) is False

    def test_verify_hmac_fails_with_wrong_key(self):
        key_a = os.urandom(32)
        key_b = os.urandom(32)
        ciphertext = b"Message authenticated with key A."
        tag = generate_hmac(key_a, ciphertext)

        assert verify_hmac(key_b, ciphertext, tag) is False

    def test_verify_hmac_fails_with_tampered_tag(self):
        key = os.urandom(32)
        ciphertext = b"Secret data payload."
        tag = bytearray(generate_hmac(key, ciphertext))

        tag[5] ^= 0xFF
        assert verify_hmac(key, ciphertext, bytes(tag)) is False

    def test_hmac_type_errors(self):
        with pytest.raises(TypeError):
            generate_hmac("string key", b"ciphertext")  # type: ignore

        with pytest.raises(TypeError):
            generate_hmac(b"key", "string ciphertext")  # type: ignore

        with pytest.raises(TypeError):
            verify_hmac(b"key", b"ct", "string tag")  # type: ignore


class TestCNSBinaryPackaging:
    """Test suite for .cns binary container packing and unpacking."""

    @pytest.mark.parametrize("cipher_type,iv_size", [
        (CIPHER_AES, 16),
        (CIPHER_DES, 8),
    ])
    def test_pack_and_unpack_roundtrip(self, cipher_type, iv_size):
        iv = os.urandom(iv_size)
        wrapped_key = os.urandom(256)
        ciphertext = b"Encrypted multi-block file payload with special characters: \x00\xFF\xAA\x55"
        hmac_key = os.urandom(32)
        hmac_tag = generate_hmac(hmac_key, ciphertext)
        signature = os.urandom(256)

        packed = pack_cns_file(
            cipher_type=cipher_type,
            iv=iv,
            wrapped_key=wrapped_key,
            hmac_tag=hmac_tag,
            signature=signature,
            ciphertext=ciphertext,
        )
        assert isinstance(packed, bytes)
        assert packed.startswith(MAGIC_BYTES)

        unpacked = unpack_cns_file(packed)
        assert unpacked["cipher_type"] == cipher_type
        assert unpacked["iv"] == iv
        assert unpacked["wrapped_key"] == wrapped_key
        assert unpacked["hmac_tag"] == hmac_tag
        assert unpacked["signature"] == signature
        assert unpacked["ciphertext"] == ciphertext

    def test_unpack_rejects_invalid_magic_bytes(self):
        iv = os.urandom(16)
        wrapped_key = os.urandom(256)
        hmac_tag = os.urandom(32)
        signature = os.urandom(256)
        ciphertext = b"payload"

        packed = pack_cns_file(CIPHER_AES, iv, wrapped_key, hmac_tag, signature, ciphertext)

        # Alter magic bytes from b"CNS1" to b"BAD!"
        corrupted_magic = b"BAD!" + packed[4:]
        with pytest.raises(ValueError, match="Invalid CNS file magic bytes"):
            unpack_cns_file(corrupted_magic)

    def test_unpack_truncated_data_raises_value_error(self):
        iv = os.urandom(16)
        wrapped_key = os.urandom(256)
        hmac_tag = os.urandom(32)
        signature = os.urandom(256)
        ciphertext = b"file content"

        packed = pack_cns_file(CIPHER_AES, iv, wrapped_key, hmac_tag, signature, ciphertext)

        # Truncate at various structural boundaries
        with pytest.raises(ValueError, match="too short"):
            unpack_cns_file(packed[:4])  # Shorter than 6-byte prefix

        with pytest.raises(ValueError, match="truncated IV"):
            unpack_cns_file(packed[:10])  # Partial IV

        with pytest.raises(ValueError, match="truncated wrapped key"):
            unpack_cns_file(packed[:50])  # Partial wrapped key

        with pytest.raises(ValueError, match="truncated HMAC"):
            unpack_cns_file(packed[:6 + 16 + 2 + 256 + 10])  # Partial HMAC tag

        with pytest.raises(ValueError, match="truncated signature"):
            unpack_cns_file(packed[:6 + 16 + 2 + 256 + 32 + 2 + 10])  # Partial signature

    def test_pack_invalid_hmac_length_raises_value_error(self):
        with pytest.raises(ValueError, match="HMAC tag must be exactly 32 bytes"):
            pack_cns_file(
                CIPHER_AES,
                os.urandom(16),
                os.urandom(256),
                os.urandom(16),  # Invalid tag length: 16 instead of 32
                os.urandom(256),
                b"ciphertext",
            )

    def test_pack_type_errors(self):
        with pytest.raises(TypeError):
            pack_cns_file("aes", os.urandom(16), os.urandom(256), os.urandom(32), os.urandom(256), b"ct")  # type: ignore

        with pytest.raises(TypeError):
            unpack_cns_file("not bytes string")  # type: ignore


class TestSecureShredding:
    """Test suite for file sanitization and shredding."""

    def test_shred_file_overwrites_and_removes_file(self, tmp_path):
        test_file = tmp_path / "secret_document.txt"
        original_content = b"Top secret operational keys and data" * 100
        test_file.write_bytes(original_content)
        assert test_file.exists()

        shred_file(str(test_file), passes=2)
        assert not test_file.exists()

    def test_shred_empty_file(self, tmp_path):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        assert empty_file.exists()

        shred_file(str(empty_file))
        assert not empty_file.exists()

    def test_shred_nonexistent_file_raises_not_found(self, tmp_path):
        fake_path = tmp_path / "nonexistent.bin"
        with pytest.raises(FileNotFoundError):
            shred_file(str(fake_path))
