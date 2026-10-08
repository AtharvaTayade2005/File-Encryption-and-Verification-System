"""
Symmetric Cryptography Module for FEVS (File Encryption & Verification System).
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Implements AES-256 and DES/TripleDES in CBC mode with PKCS#7 padding using
the `cryptography` Python library.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Use modern decrepit module for TripleDES without deprecation warning,
# falling back to primitives if on an older cryptography release.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

# Cipher identification constants
CIPHER_AES = 1
CIPHER_DES = 2

# Standard algorithm block sizes in bits
AES_BLOCK_SIZE_BITS = 128
DES_BLOCK_SIZE_BITS = 64


def pad_data(data: bytes, block_size_bits: int) -> bytes:
    """
    Applies PKCS#7 padding to arbitrary binary data.

    :param data: Raw byte string to pad.
    :param block_size_bits: Block size in bits (128 for AES, 64 for DES).
    :return: Padded byte string.
    :raises TypeError: If data is not bytes-like or block_size_bits is not an integer.
    :raises ValueError: If block_size_bits is invalid.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray.")
    if not isinstance(block_size_bits, int):
        raise TypeError("block_size_bits must be an integer.")

    padder = padding.PKCS7(block_size_bits).padder()
    return padder.update(data) + padder.finalize()


def unpad_data(data: bytes, block_size_bits: int) -> bytes:
    """
    Removes PKCS#7 padding from padded binary data.

    :param data: Padded byte string.
    :param block_size_bits: Block size in bits (128 for AES, 64 for DES).
    :return: Original unpadded byte string.
    :raises TypeError: If data is not bytes-like or block_size_bits is not an integer.
    :raises ValueError: If padding is corrupted or invalid.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray.")
    if not isinstance(block_size_bits, int):
        raise TypeError("block_size_bits must be an integer.")

    unpadder = padding.PKCS7(block_size_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_symmetric(
    plaintext: bytes, key: bytes, cipher_type: int
) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext data using CBC mode with PKCS#7 padding.

    :param plaintext: Raw byte string to encrypt.
    :param key: Symmetric key (AES: 16, 24, or 32 bytes for 128, 192, or 256 bits;
                              DES: 8 bytes for DES, or 16/24 bytes for TripleDES).
    :param cipher_type: CIPHER_AES (1) or CIPHER_DES (2).
    :return: Tuple of (iv, ciphertext).
    :raises TypeError: If inputs are not of expected types.
    :raises ValueError: If cipher_type or key length is invalid.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes or bytearray.")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes or bytearray.")
    if not isinstance(cipher_type, int):
        raise TypeError("cipher_type must be an integer.")

    if cipher_type == CIPHER_AES:
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"Invalid AES key length: {len(key)} bytes. "
                "AES supports 16, 24, or 32 bytes (128, 192, or 256 bits)."
            )
        iv = os.urandom(AES_BLOCK_SIZE_BITS // 8)  # 16 bytes
        padded_data = pad_data(plaintext, AES_BLOCK_SIZE_BITS)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext

    elif cipher_type == CIPHER_DES:
        if len(key) not in (8, 16, 24):
            raise ValueError(
                f"Invalid DES key length: {len(key)} bytes. "
                "DES requires 8 bytes (single DES) or 16/24 bytes (TripleDES)."
            )
        iv = os.urandom(DES_BLOCK_SIZE_BITS // 8)  # 8 bytes
        padded_data = pad_data(plaintext, DES_BLOCK_SIZE_BITS)
        cipher = Cipher(TripleDES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv, ciphertext

    else:
        raise ValueError(
            f"Unsupported cipher_type: {cipher_type}. "
            f"Expected CIPHER_AES ({CIPHER_AES}) or CIPHER_DES ({CIPHER_DES})."
        )


def decrypt_symmetric(
    ciphertext: bytes, key: bytes, iv: bytes, cipher_type: int
) -> bytes:
    """
    Decrypts ciphertext data using CBC mode and removes PKCS#7 padding.

    :param ciphertext: Encrypted binary data.
    :param key: Symmetric key matching encryption.
    :param iv: Initialization Vector matching encryption (16 bytes for AES, 8 bytes for DES).
    :param cipher_type: CIPHER_AES (1) or CIPHER_DES (2).
    :return: Restored original plaintext bytes.
    :raises TypeError: If inputs are not of expected types.
    :raises ValueError: If key, IV, cipher_type, or padding is invalid / tampered with.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes or bytearray.")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("Key must be bytes or bytearray.")
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("IV must be bytes or bytearray.")
    if not isinstance(cipher_type, int):
        raise TypeError("cipher_type must be an integer.")

    if cipher_type == CIPHER_AES:
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"Invalid AES key length: {len(key)} bytes. "
                "AES supports 16, 24, or 32 bytes (128, 192, or 256 bits)."
            )
        if len(iv) != AES_BLOCK_SIZE_BITS // 8:
            raise ValueError(
                f"Invalid IV length for AES: expected {AES_BLOCK_SIZE_BITS // 8} bytes, got {len(iv)}."
            )
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad_data(padded_plaintext, AES_BLOCK_SIZE_BITS)

    elif cipher_type == CIPHER_DES:
        if len(key) not in (8, 16, 24):
            raise ValueError(
                f"Invalid DES key length: {len(key)} bytes. "
                "DES requires 8 bytes (single DES) or 16/24 bytes (TripleDES)."
            )
        if len(iv) != DES_BLOCK_SIZE_BITS // 8:
            raise ValueError(
                f"Invalid IV length for DES: expected {DES_BLOCK_SIZE_BITS // 8} bytes, got {len(iv)}."
            )
        cipher = Cipher(TripleDES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad_data(padded_plaintext, DES_BLOCK_SIZE_BITS)

    else:
        raise ValueError(
            f"Unsupported cipher_type: {cipher_type}. "
            f"Expected CIPHER_AES ({CIPHER_AES}) or CIPHER_DES ({CIPHER_DES})."
        )
