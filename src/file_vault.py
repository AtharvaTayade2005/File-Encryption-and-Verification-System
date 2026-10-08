"""
File Vault and Binary Container Serialization Module for FEVS.
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Implements HMAC-SHA256 integrity verification, .cns binary layout packing/unpacking,
and secure file wiping/shredding.
"""

import hashlib
import hmac
import os
import struct
from typing import Dict, Any

# Magic bytes identifying the CNS container format
MAGIC_BYTES = b"CNS1"

# Fixed size in bytes for HMAC-SHA256 authentication tag
HMAC_TAG_SIZE = 32


def generate_hmac(key: bytes, ciphertext: bytes) -> bytes:
    """
    Computes an HMAC-SHA256 authentication tag over ciphertext bytes.

    :param key: Symmetric authentication/HMAC key.
    :param ciphertext: Encrypted binary data to authenticate.
    :return: 32-byte HMAC-SHA256 digest tag.
    :raises TypeError: If key or ciphertext are not bytes-like.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes or bytearray.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes or bytearray.")

    return hmac.new(key, ciphertext, hashlib.sha256).digest()


def verify_hmac(key: bytes, ciphertext: bytes, expected_tag: bytes) -> bool:
    """
    Verifies an HMAC-SHA256 tag in constant time to prevent timing attacks.

    :param key: Symmetric authentication/HMAC key.
    :param ciphertext: Encrypted binary data.
    :param expected_tag: 32-byte expected HMAC-SHA256 tag.
    :return: True if tag matches exactly, False otherwise.
    :raises TypeError: If inputs are not bytes-like.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes or bytearray.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes or bytearray.")
    if not isinstance(expected_tag, (bytes, bytearray)):
        raise TypeError("expected_tag must be bytes or bytearray.")

    actual_tag = generate_hmac(key, ciphertext)
    return hmac.compare_digest(actual_tag, expected_tag)


def pack_cns_file(
    cipher_type: int,
    iv: bytes,
    wrapped_key: bytes,
    hmac_tag: bytes,
    signature: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Packs cryptographic envelope components into the standard .cns binary container.

    Binary Layout:
      - Magic Bytes (4B): b"CNS1"
      - Cipher Type (1B): uint8 (0x01 AES, 0x02 DES)
      - IV Length (1B): uint8
      - IV Data (variable bytes matching IV length)
      - Wrapped Key Length (2B): uint16 Big-Endian
      - Wrapped Key Data (variable bytes)
      - HMAC-SHA256 Tag (32B fixed)
      - Signature Length (2B): uint16 Big-Endian
      - Signature Data (variable bytes)
      - Ciphertext Data (remaining bytes)

    :param cipher_type: 1 for AES, 2 for DES.
    :param iv: Initialization Vector bytes.
    :param wrapped_key: Asymmetrically encrypted session key bytes.
    :param hmac_tag: 32-byte HMAC-SHA256 authentication tag.
    :param signature: Digital signature bytes.
    :param ciphertext: Encrypted file payload bytes.
    :return: Packed .cns binary byte string.
    :raises TypeError: If inputs are of invalid types.
    :raises ValueError: If field sizes exceed format limits or HMAC tag size is invalid.
    """
    if not isinstance(cipher_type, int):
        raise TypeError("cipher_type must be an integer.")
    if not isinstance(iv, (bytes, bytearray)):
        raise TypeError("iv must be bytes or bytearray.")
    if not isinstance(wrapped_key, (bytes, bytearray)):
        raise TypeError("wrapped_key must be bytes or bytearray.")
    if not isinstance(hmac_tag, (bytes, bytearray)):
        raise TypeError("hmac_tag must be bytes or bytearray.")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes or bytearray.")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes or bytearray.")

    if not (0 <= cipher_type <= 255):
        raise ValueError(f"cipher_type must fit in 1 byte (0-255), got {cipher_type}.")
    if len(iv) > 255:
        raise ValueError(f"IV length exceeds 255 bytes (got {len(iv)} bytes).")
    if len(wrapped_key) > 65535:
        raise ValueError(f"Wrapped key length exceeds 65535 bytes (got {len(wrapped_key)} bytes).")
    if len(hmac_tag) != HMAC_TAG_SIZE:
        raise ValueError(f"HMAC tag must be exactly {HMAC_TAG_SIZE} bytes (got {len(hmac_tag)} bytes).")
    if len(signature) > 65535:
        raise ValueError(f"Signature length exceeds 65535 bytes (got {len(signature)} bytes).")

    # Header Prefix: Magic (4B) + Cipher Type (1B) + IV Len (1B)
    header_prefix = struct.pack(">4sBB", MAGIC_BYTES, cipher_type, len(iv))
    wrapped_key_len_bytes = struct.pack(">H", len(wrapped_key))
    sig_len_bytes = struct.pack(">H", len(signature))

    return (
        header_prefix
        + bytes(iv)
        + wrapped_key_len_bytes
        + bytes(wrapped_key)
        + bytes(hmac_tag)
        + sig_len_bytes
        + bytes(signature)
        + bytes(ciphertext)
    )


def unpack_cns_file(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Unpacks and validates a .cns binary container into its constituent cryptographic components.

    :param raw_bytes: Raw bytes of the .cns file.
    :return: Dictionary containing cipher_type, iv, wrapped_key, hmac_tag, signature, and ciphertext.
    :raises TypeError: If raw_bytes is not bytes or bytearray.
    :raises ValueError: If magic bytes are invalid or file structure is truncated/corrupt.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise TypeError("raw_bytes must be bytes or bytearray.")

    prefix_size = struct.calcsize(">4sBB")
    if len(raw_bytes) < prefix_size:
        raise ValueError("Invalid CNS file: data is too short to contain a valid header prefix.")

    offset = 0
    magic, cipher_type, iv_len = struct.unpack_from(">4sBB", raw_bytes, offset)
    offset += prefix_size

    if magic != MAGIC_BYTES:
        raise ValueError(
            f"Invalid CNS file magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}."
        )

    # Read IV Data
    if len(raw_bytes) < offset + iv_len:
        raise ValueError("Invalid CNS file: truncated IV data.")
    iv = bytes(raw_bytes[offset : offset + iv_len])
    offset += iv_len

    # Read Wrapped Key Length & Data
    if len(raw_bytes) < offset + 2:
        raise ValueError("Invalid CNS file: truncated wrapped key length header.")
    wrapped_key_len = struct.unpack_from(">H", raw_bytes, offset)[0]
    offset += 2

    if len(raw_bytes) < offset + wrapped_key_len:
        raise ValueError("Invalid CNS file: truncated wrapped key data.")
    wrapped_key = bytes(raw_bytes[offset : offset + wrapped_key_len])
    offset += wrapped_key_len

    # Read Fixed HMAC Tag (32 Bytes)
    if len(raw_bytes) < offset + HMAC_TAG_SIZE:
        raise ValueError("Invalid CNS file: truncated HMAC authentication tag.")
    hmac_tag = bytes(raw_bytes[offset : offset + HMAC_TAG_SIZE])
    offset += HMAC_TAG_SIZE

    # Read Signature Length & Data
    if len(raw_bytes) < offset + 2:
        raise ValueError("Invalid CNS file: truncated signature length header.")
    sig_len = struct.unpack_from(">H", raw_bytes, offset)[0]
    offset += 2

    if len(raw_bytes) < offset + sig_len:
        raise ValueError("Invalid CNS file: truncated signature data.")
    signature = bytes(raw_bytes[offset : offset + sig_len])
    offset += sig_len

    # Remaining bytes are ciphertext
    ciphertext = bytes(raw_bytes[offset:])

    return {
        "cipher_type": cipher_type,
        "iv": iv,
        "wrapped_key": wrapped_key,
        "hmac_tag": hmac_tag,
        "signature": signature,
        "ciphertext": ciphertext,
    }


def shred_file(filepath: str, passes: int = 3) -> None:
    """
    Securely sanitizes and deletes a file from the storage medium.
    Performs multiple overwrite passes with cryptographically secure random bytes,
    followed by a zero-fill overwrite pass, flushing to physical disk before deletion.

    :param filepath: Path to the target file.
    :param passes: Number of random byte overwrite passes (default: 3).
    :raises FileNotFoundError: If the target file does not exist.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    file_size = os.path.getsize(filepath)
    if file_size > 0:
        chunk_size = 64 * 1024  # 64 KB buffers
        with open(filepath, "r+b") as f:
            # Overwrite with random bytes
            for _ in range(max(1, passes)):
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    write_size = min(remaining, chunk_size)
                    f.write(os.urandom(write_size))
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())

            # Final overwrite pass with all zeros
            f.seek(0)
            remaining = file_size
            zero_chunk = b"\x00" * min(file_size, chunk_size)
            while remaining > 0:
                write_size = min(remaining, len(zero_chunk))
                f.write(zero_chunk[:write_size])
                remaining -= write_size
            f.flush()
            os.fsync(f.fileno())

    os.remove(filepath)
