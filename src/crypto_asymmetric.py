"""
Asymmetric Key Management and Digital Signature Module for FEVS.
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Implements RSA key generation, PEM serialization/loading, RSA-OAEP session
key wrapping/unwrapping, and RSA-PKCS#1 v1.5 digital signatures using
the `cryptography` Python library.
"""

from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Standard RSA configuration per CNS syllabus
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_PUBLIC_EXPONENT = 65537


def generate_rsa_keypair(
    key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generates an RSA private and public key pair.

    :param key_size: Key size in bits (default: 2048, e=65537).
    :return: Tuple of (RSAPrivateKey, RSAPublicKey).
    :raises ValueError: If key_size is less than 2048 bits.
    """
    if not isinstance(key_size, int):
        raise TypeError("key_size must be an integer.")
    if key_size < 2048:
        raise ValueError(f"Key size {key_size} is insecure; minimum is 2048 bits.")

    private_key = rsa.generate_private_key(
        public_exponent=DEFAULT_PUBLIC_EXPONENT,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def export_key_to_pem(
    key: Union[RSAPrivateKey, RSAPublicKey],
    is_private: bool,
    password: Optional[str] = None,
) -> bytes:
    """
    Serializes an RSA key to PEM format.

    :param key: RSAPrivateKey or RSAPublicKey instance.
    :param is_private: True if key is private, False if public.
    :param password: Optional passphrase string for encrypting private keys.
    :return: PEM-encoded bytes.
    :raises TypeError: If key type does not match is_private.
    """
    if is_private:
        if not isinstance(key, RSAPrivateKey):
            raise TypeError("Expected RSAPrivateKey when is_private=True.")
        if password:
            pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
            encryption_algo = serialization.BestAvailableEncryption(pwd_bytes)
        else:
            encryption_algo = serialization.NoEncryption()

        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo,
        )
    else:
        if not isinstance(key, RSAPublicKey):
            raise TypeError("Expected RSAPublicKey when is_private=False.")
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def load_key_from_pem(
    pem_bytes: Union[bytes, str],
    is_private: bool,
    password: Optional[str] = None,
) -> Union[RSAPrivateKey, RSAPublicKey]:
    """
    Deserializes an RSA key from PEM format.

    :param pem_bytes: PEM-encoded bytes or string.
    :param is_private: True if key is private, False if public.
    :param password: Password string if the private key is encrypted.
    :return: RSAPrivateKey or RSAPublicKey.
    """
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode("utf-8")
    if not isinstance(pem_bytes, (bytes, bytearray)):
        raise TypeError("pem_bytes must be bytes or string.")

    if is_private:
        pwd_bytes = None
        if password is not None:
            pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
        return serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)
    else:
        return serialization.load_pem_public_key(pem_bytes)


def wrap_session_key(
    session_key: bytes, recipient_pubkey: RSAPublicKey
) -> bytes:
    """
    Wraps/encrypts a symmetric session key using RSA-OAEP with MGF1(SHA-256) and SHA-256 digest.

    :param session_key: Symmetric key bytes to wrap.
    :param recipient_pubkey: Recipient's RSA public key.
    :return: Encrypted session key bytes.
    :raises TypeError: If inputs are invalid.
    """
    if not isinstance(session_key, (bytes, bytearray)):
        raise TypeError("session_key must be bytes or bytearray.")
    if not isinstance(recipient_pubkey, RSAPublicKey):
        raise TypeError("recipient_pubkey must be an RSAPublicKey instance.")

    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    return recipient_pubkey.encrypt(session_key, oaep_padding)


def unwrap_session_key(
    wrapped_key: bytes, recipient_privkey: RSAPrivateKey
) -> bytes:
    """
    Unwraps/decrypts an RSA-OAEP wrapped symmetric session key.

    :param wrapped_key: Ciphertext bytes of the wrapped session key.
    :param recipient_privkey: Recipient's RSA private key.
    :return: Recovered symmetric session key bytes.
    :raises TypeError: If inputs are invalid.
    :raises ValueError: If unwrapping fails due to invalid key or tampered ciphertext.
    """
    if not isinstance(wrapped_key, (bytes, bytearray)):
        raise TypeError("wrapped_key must be bytes or bytearray.")
    if not isinstance(recipient_privkey, RSAPrivateKey):
        raise TypeError("recipient_privkey must be an RSAPrivateKey instance.")

    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    return recipient_privkey.decrypt(wrapped_key, oaep_padding)


def sign_payload(data: bytes, sender_privkey: RSAPrivateKey) -> bytes:
    """
    Signs data using RSA with PKCS#1 v1.5 padding and SHA-256 digest.

    :param data: Raw bytes of data to sign.
    :param sender_privkey: Sender's RSA private key.
    :return: Digital signature bytes.
    :raises TypeError: If inputs are invalid.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray.")
    if not isinstance(sender_privkey, RSAPrivateKey):
        raise TypeError("sender_privkey must be an RSAPrivateKey instance.")

    return sender_privkey.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def verify_signature(
    data: bytes, signature: bytes, sender_pubkey: RSAPublicKey
) -> bool:
    """
    Verifies an RSA PKCS#1 v1.5 signature with SHA-256 digest against payload data.

    :param data: Original payload bytes.
    :param signature: Digital signature bytes.
    :param sender_pubkey: Sender's RSA public key.
    :return: True if signature is valid, False otherwise.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray.")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes or bytearray.")
    if not isinstance(sender_pubkey, RSAPublicKey):
        raise TypeError("sender_pubkey must be an RSAPublicKey instance.")

    try:
        sender_pubkey.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False
