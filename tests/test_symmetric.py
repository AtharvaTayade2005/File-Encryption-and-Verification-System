"""
Unit tests for the Symmetric Cryptography Engine (src/crypto_symmetric.py).
Tests PKCS#7 padding/unpadding, AES-256-CBC, and DES-CBC roundtrips,
tamper detection, and edge cases.
"""

import os
import pytest

from src.crypto_symmetric import (
    CIPHER_AES,
    CIPHER_DES,
    AES_BLOCK_SIZE_BITS,
    DES_BLOCK_SIZE_BITS,
    pad_data,
    unpad_data,
    encrypt_symmetric,
    decrypt_symmetric,
)


class TestPKCS7Padding:
    """Test suite for PKCS#7 padding and unpadding operations."""

    @pytest.mark.parametrize("block_size_bits,expected_block_bytes", [
        (AES_BLOCK_SIZE_BITS, 16),
        (DES_BLOCK_SIZE_BITS, 8),
    ])
    def test_padding_adds_correct_number_of_bytes(self, block_size_bits, expected_block_bytes):
        # 1 byte short of block
        data_short = b"A" * (expected_block_bytes - 1)
        padded_short = pad_data(data_short, block_size_bits)
        assert len(padded_short) == expected_block_bytes
        assert padded_short[-1:] == b"\x01"

        # Exact block boundary must append a full block of padding
        data_exact = b"A" * expected_block_bytes
        padded_exact = pad_data(data_exact, block_size_bits)
        assert len(padded_exact) == expected_block_bytes * 2
        assert padded_exact[-expected_block_bytes:] == bytes([expected_block_bytes]) * expected_block_bytes

        # Empty data must append a full block of padding
        padded_empty = pad_data(b"", block_size_bits)
        assert len(padded_empty) == expected_block_bytes
        assert padded_empty == bytes([expected_block_bytes]) * expected_block_bytes

    @pytest.mark.parametrize("block_size_bits", [AES_BLOCK_SIZE_BITS, DES_BLOCK_SIZE_BITS])
    @pytest.mark.parametrize("length", [0, 1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 100, 255])
    def test_padding_roundtrip_various_lengths(self, block_size_bits, length):
        data = os.urandom(length)
        padded = pad_data(data, block_size_bits)
        block_bytes = block_size_bits // 8
        assert len(padded) % block_bytes == 0
        assert len(padded) > len(data)

        unpadded = unpad_data(padded, block_size_bits)
        assert unpadded == data

    def test_unpad_invalid_padding_raises_value_error(self):
        # Corrupt last byte of valid padding
        data = b"Secret data"
        padded = bytearray(pad_data(data, AES_BLOCK_SIZE_BITS))
        padded[-1] = 0x00  # 0 is never a valid PKCS#7 padding value
        with pytest.raises(ValueError):
            unpad_data(bytes(padded), AES_BLOCK_SIZE_BITS)

    def test_padding_type_errors(self):
        with pytest.raises(TypeError):
            pad_data("string instead of bytes", AES_BLOCK_SIZE_BITS)  # type: ignore

        with pytest.raises(TypeError):
            pad_data(b"data", "128")  # type: ignore

        with pytest.raises(TypeError):
            unpad_data("string instead of bytes", AES_BLOCK_SIZE_BITS)  # type: ignore


class TestSymmetricAES:
    """Test suite for AES in CBC mode with PKCS#7 padding."""

    @pytest.fixture
    def aes_256_key(self) -> bytes:
        return os.urandom(32)  # 256 bits

    def test_aes_roundtrip_arbitrary_text(self, aes_256_key):
        text_samples = [
            b"Hello, Computer & Network Security!",
            "Secure File Vault with Unicode: \U0001f512\u26a1\u092d\u093e\u0930\u0924".encode("utf-8"),
            b"",  # Empty plaintext
            b"Short",
            b"Exact 16 bytes!!",
            b"Exact 32 bytes message for AES!!",
            b"A" * 1024,  # Larger payload
        ]
        for plaintext in text_samples:
            iv, ciphertext = encrypt_symmetric(plaintext, aes_256_key, CIPHER_AES)
            assert len(iv) == 16
            assert len(ciphertext) % 16 == 0
            assert ciphertext != plaintext

            decrypted = decrypt_symmetric(ciphertext, aes_256_key, iv, CIPHER_AES)
            assert decrypted == plaintext

    def test_aes_roundtrip_binary_data(self, aes_256_key):
        binary_samples = [
            bytes(range(256)),  # All byte values 0x00-0xFF
            os.urandom(1),
            os.urandom(15),
            os.urandom(16),
            os.urandom(33),
            os.urandom(4096),  # 4 KB binary file payload
            b"\x00" * 64,      # Null bytes
        ]
        for binary_payload in binary_samples:
            iv, ciphertext = encrypt_symmetric(binary_payload, aes_256_key, CIPHER_AES)
            decrypted = decrypt_symmetric(ciphertext, aes_256_key, iv, CIPHER_AES)
            assert decrypted == binary_payload

    def test_aes_supported_key_lengths(self):
        plaintext = b"Test multi key sizes for AES."
        for key_len in [16, 24, 32]:  # 128-bit, 192-bit, 256-bit keys
            key = os.urandom(key_len)
            iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_AES)
            decrypted = decrypt_symmetric(ciphertext, key, iv, CIPHER_AES)
            assert decrypted == plaintext

    def test_aes_invalid_key_length_raises_error(self):
        with pytest.raises(ValueError, match="Invalid AES key length"):
            encrypt_symmetric(b"data", os.urandom(10), CIPHER_AES)

        with pytest.raises(ValueError, match="Invalid AES key length"):
            decrypt_symmetric(b"0" * 16, os.urandom(10), os.urandom(16), CIPHER_AES)

    def test_aes_invalid_iv_length_raises_error(self, aes_256_key):
        with pytest.raises(ValueError, match="Invalid IV length for AES"):
            decrypt_symmetric(b"0" * 16, aes_256_key, os.urandom(8), CIPHER_AES)


class TestSymmetricDES:
    """Test suite for DES / TripleDES in CBC mode with PKCS#7 padding."""

    @pytest.fixture
    def des_key_8(self) -> bytes:
        return os.urandom(8)  # 64-bit DES (56-bit effective)

    @pytest.fixture
    def des_key_24(self) -> bytes:
        return os.urandom(24)  # 192-bit TripleDES

    def test_des_roundtrip_arbitrary_text(self, des_key_8, des_key_24):
        text_samples = [
            b"CNS DES CBC Test",
            "Symmetric encryption with UTF-8: \u0928\u092e\u0938\u094d\u0924\u0947".encode("utf-8"),
            b"",
            b"8 bytes!",
            b"16 bytes message!",
            b"A" * 512,
        ]
        for key in [des_key_8, des_key_24]:
            for plaintext in text_samples:
                iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_DES)
                assert len(iv) == 8
                assert len(ciphertext) % 8 == 0
                assert ciphertext != plaintext

                decrypted = decrypt_symmetric(ciphertext, key, iv, CIPHER_DES)
                assert decrypted == plaintext

    def test_des_roundtrip_binary_data(self, des_key_8):
        binary_samples = [
            bytes(range(256)),
            os.urandom(7),
            os.urandom(8),
            os.urandom(25),
            os.urandom(2048),
            b"\x00" * 32,
        ]
        for binary_payload in binary_samples:
            iv, ciphertext = encrypt_symmetric(binary_payload, des_key_8, CIPHER_DES)
            decrypted = decrypt_symmetric(ciphertext, des_key_8, iv, CIPHER_DES)
            assert decrypted == binary_payload

    def test_des_invalid_key_length_raises_error(self):
        with pytest.raises(ValueError, match="Invalid DES key length"):
            encrypt_symmetric(b"data", os.urandom(12), CIPHER_DES)

        with pytest.raises(ValueError, match="Invalid DES key length"):
            decrypt_symmetric(b"0" * 8, os.urandom(12), os.urandom(8), CIPHER_DES)

    def test_des_invalid_iv_length_raises_error(self, des_key_8):
        with pytest.raises(ValueError, match="Invalid IV length for DES"):
            decrypt_symmetric(b"0" * 8, des_key_8, os.urandom(16), CIPHER_DES)


class TestTamperingAndSecurityErrors:
    """Test suite ensuring tampering and corruption correctly trigger decryption/unpadding errors."""

    def test_tampered_aes_ciphertext_last_byte_fails_unpadding(self):
        plaintext = b"Sensitive classified document for FEVS project."
        key = os.urandom(32)
        iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_AES)

        # Corrupt the last byte of ciphertext (will corrupt decrypted padding)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01
        with pytest.raises(ValueError):
            decrypt_symmetric(bytes(tampered), key, iv, CIPHER_AES)

    def test_tampered_des_ciphertext_last_byte_fails_unpadding(self):
        plaintext = b"Sensitive DES payload content."
        key = os.urandom(8)
        iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_DES)

        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01
        with pytest.raises(ValueError):
            decrypt_symmetric(bytes(tampered), key, iv, CIPHER_DES)

    def test_truncated_ciphertext_causes_decryption_error(self):
        plaintext = b"A full block of confidential payload."
        key = os.urandom(32)
        iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_AES)

        # Truncate by 3 bytes -> length is no longer a multiple of block size
        truncated = ciphertext[:-3]
        with pytest.raises(ValueError):
            decrypt_symmetric(truncated, key, iv, CIPHER_AES)

    def test_tampered_ciphertext_middle_block_corrupts_data(self):
        plaintext = b"Block1Padding16!Block2Padding16!Block3Padding16!"
        key = os.urandom(32)
        iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_AES)

        # Alter a byte in the first block of ciphertext
        tampered = bytearray(ciphertext)
        tampered[2] ^= 0xFF
        # Decrypting might succeed in unpadding if the last block wasn't affected,
        # but the recovered plaintext must NOT match the original
        try:
            decrypted = decrypt_symmetric(bytes(tampered), key, iv, CIPHER_AES)
            assert decrypted != plaintext
        except ValueError:
            # If tampering also affected padding validation, that is valid behavior too
            pass

    def test_tampered_iv_corrupts_first_plaintext_block(self):
        plaintext = b"First block data!Second block data!"
        key = os.urandom(32)
        iv, ciphertext = encrypt_symmetric(plaintext, key, CIPHER_AES)

        # Tamper IV
        tampered_iv = bytearray(iv)
        tampered_iv[0] ^= 0xAA
        decrypted = decrypt_symmetric(ciphertext, key, bytes(tampered_iv), CIPHER_AES)
        assert decrypted != plaintext

    def test_unsupported_cipher_type_raises_value_error(self):
        with pytest.raises(ValueError, match="Unsupported cipher_type"):
            encrypt_symmetric(b"data", os.urandom(32), 999)

        with pytest.raises(ValueError, match="Unsupported cipher_type"):
            decrypt_symmetric(b"data", os.urandom(32), os.urandom(16), 999)

    def test_type_errors_on_invalid_inputs(self):
        key = os.urandom(32)
        with pytest.raises(TypeError):
            encrypt_symmetric("not bytes", key, CIPHER_AES)  # type: ignore

        with pytest.raises(TypeError):
            encrypt_symmetric(b"data", "not bytes key", CIPHER_AES)  # type: ignore

        with pytest.raises(TypeError):
            encrypt_symmetric(b"data", key, "not an int")  # type: ignore

        with pytest.raises(TypeError):
            decrypt_symmetric("not bytes", key, os.urandom(16), CIPHER_AES)  # type: ignore
