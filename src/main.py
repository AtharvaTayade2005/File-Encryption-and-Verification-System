"""
File Encryption & Verification System (FEVS) - Main CLI Entry Point.
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Provides command-line interface for:
  - keygen:  RSA-2048 keypair generation and PEM export
  - encrypt: End-to-end hybrid file encryption into .cns vault container
  - decrypt: End-to-end decryption, HMAC integrity check, and RSA signature verification
"""

import argparse
import os
import sys

# Ensure project root is present in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto_symmetric import (
    CIPHER_AES,
    CIPHER_DES,
    encrypt_symmetric,
    decrypt_symmetric,
)
from src.crypto_asymmetric import (
    generate_rsa_keypair,
    export_key_to_pem,
    load_key_from_pem,
    wrap_session_key,
    unwrap_session_key,
    sign_payload,
    verify_signature,
)
from src.file_vault import (
    generate_hmac,
    verify_hmac,
    pack_cns_file,
    unpack_cns_file,
    shred_file,
)


def handle_keygen(args: argparse.Namespace) -> int:
    """Handles the keygen subcommand: generates RSA keypair and exports to PEM."""
    os.makedirs(args.out_dir, exist_ok=True)
    priv_key, pub_key = generate_rsa_keypair(key_size=2048)

    prefix = (args.prefix or "").strip()
    if prefix:
        priv_filename = f"{prefix}_private.pem"
        pub_filename = f"{prefix}_public.pem"
    else:
        priv_filename = "private_key.pem"
        pub_filename = "public_key.pem"

    priv_path = os.path.join(args.out_dir, priv_filename)
    pub_path = os.path.join(args.out_dir, pub_filename)

    priv_pem = export_key_to_pem(priv_key, is_private=True, password=args.passphrase)
    pub_pem = export_key_to_pem(pub_key, is_private=False)

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    print(f"[+] RSA-2048 Keypair generated successfully:")
    print(f"    Private Key: {priv_path}")
    print(f"    Public Key:  {pub_path}")
    return 0


def handle_encrypt(args: argparse.Namespace) -> int:
    """Handles the encrypt subcommand: full hybrid encryption, HMAC, and packaging."""
    if not os.path.isfile(args.input):
        sys.stderr.write(f"Error: Input file '{args.input}' does not exist.\n")
        return 1
    if not os.path.isfile(args.recipient_pub):
        sys.stderr.write(f"Error: Recipient public key '{args.recipient_pub}' not found.\n")
        return 1
    if not os.path.isfile(args.sender_priv):
        sys.stderr.write(f"Error: Sender private key '{args.sender_priv}' not found.\n")
        return 1

    # 1. Read input plaintext
    with open(args.input, "rb") as f:
        plaintext = f.read()

    # 2. Generate symmetric session key
    cipher_choice = (args.cipher or "aes").lower()
    if cipher_choice == "aes":
        session_key = os.urandom(32)  # 256-bit AES
        cipher_type = CIPHER_AES
    elif cipher_choice == "des":
        session_key = os.urandom(24)  # 192-bit TripleDES (3-key DES)
        cipher_type = CIPHER_DES
    else:
        sys.stderr.write(f"Error: Unsupported cipher '{args.cipher}'. Choose 'aes' or 'des'.\n")
        return 1

    # 3. Encrypt plaintext using CBC mode with PKCS#7 padding
    try:
        iv, ciphertext = encrypt_symmetric(plaintext, session_key, cipher_type)
    except Exception as e:
        sys.stderr.write(f"Error: Symmetric encryption failed: {e}\n")
        return 1

    # 4. Sign the plaintext using sender's RSA private key (SHA-256 + PKCS#1 v1.5)
    with open(args.sender_priv, "rb") as f:
        sender_priv_pem = f.read()
    try:
        sender_privkey = load_key_from_pem(sender_priv_pem, is_private=True, password=args.passphrase)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to load sender private key: {e}\n")
        return 1

    try:
        signature = sign_payload(plaintext, sender_privkey)
    except Exception as e:
        sys.stderr.write(f"Error: Digital signature generation failed: {e}\n")
        return 1

    # 5. Compute HMAC-SHA256 over ciphertext using the symmetric session key
    hmac_tag = generate_hmac(session_key, ciphertext)

    # 6. Wrap symmetric key using recipient's RSA public key (OAEP)
    with open(args.recipient_pub, "rb") as f:
        recip_pub_pem = f.read()
    try:
        recip_pubkey = load_key_from_pem(recip_pub_pem, is_private=False)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to load recipient public key: {e}\n")
        return 1

    try:
        wrapped_key = wrap_session_key(session_key, recip_pubkey)
    except Exception as e:
        sys.stderr.write(f"Error: Session key wrapping failed: {e}\n")
        return 1

    # 7. Pack everything into .cns container and write to disk
    try:
        cns_bytes = pack_cns_file(cipher_type, iv, wrapped_key, hmac_tag, signature, ciphertext)
    except Exception as e:
        sys.stderr.write(f"Error: Packing .cns container failed: {e}\n")
        return 1

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "wb") as f:
        f.write(cns_bytes)

    print(f"[+] Successfully encrypted '{args.input}' -> '{args.output}'")
    print(f"    Cipher: {cipher_choice.upper()} | Container Size: {len(cns_bytes)} bytes")

    # 8. If --shred is set, securely wipe the original plaintext file
    if args.shred:
        try:
            shred_file(args.input)
            print(f"[+] Securely shredded original plaintext file: '{args.input}'")
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to shred '{args.input}': {e}\n")

    return 0


def handle_decrypt(args: argparse.Namespace) -> int:
    """Handles the decrypt subcommand: unpacking, unwrap, HMAC check, decrypt, and verify."""
    if not os.path.isfile(args.input):
        sys.stderr.write(f"Error: Input file '{args.input}' does not exist.\n")
        return 1
    if not os.path.isfile(args.recipient_priv):
        sys.stderr.write(f"Error: Recipient private key '{args.recipient_priv}' not found.\n")
        return 1
    if not os.path.isfile(args.sender_pub):
        sys.stderr.write(f"Error: Sender public key '{args.sender_pub}' not found.\n")
        return 1

    # 1. Read and parse .cns container
    with open(args.input, "rb") as f:
        cns_bytes = f.read()

    try:
        container = unpack_cns_file(cns_bytes)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to unpack .cns container: {e}\n")
        return 1

    cipher_type = container["cipher_type"]
    iv = container["iv"]
    wrapped_key = container["wrapped_key"]
    hmac_tag = container["hmac_tag"]
    signature = container["signature"]
    ciphertext = container["ciphertext"]

    # 2. Unwrap symmetric key using recipient's RSA private key
    with open(args.recipient_priv, "rb") as f:
        recip_priv_pem = f.read()
    try:
        recip_privkey = load_key_from_pem(recip_priv_pem, is_private=True, password=args.passphrase)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to load recipient private key: {e}\n")
        return 1

    try:
        session_key = unwrap_session_key(wrapped_key, recip_privkey)
    except Exception as e:
        sys.stderr.write(f"Error: Session key unwrapping failed: {e}\n")
        return 1

    # 3. Verify HMAC-SHA256 tag against ciphertext
    if not verify_hmac(session_key, ciphertext, hmac_tag):
        sys.stderr.write("Integrity violation: file has been tampered with!\n")
        return 1

    # 4. Decrypt ciphertext using recovered key and IV
    try:
        plaintext = decrypt_symmetric(ciphertext, session_key, iv, cipher_type)
    except Exception as e:
        sys.stderr.write(f"Error: Symmetric decryption failed: {e}\n")
        return 1

    # 5. Verify sender's RSA signature over decrypted plaintext
    with open(args.sender_pub, "rb") as f:
        sender_pub_pem = f.read()
    try:
        sender_pubkey = load_key_from_pem(sender_pub_pem, is_private=False)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to load sender public key: {e}\n")
        return 1

    if not verify_signature(plaintext, signature, sender_pubkey):
        sys.stderr.write("Authenticity violation: signature invalid!\n")
        return 1

    # 6. Write verified plaintext to disk
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "wb") as f:
        f.write(plaintext)

    print(f"[+] Successfully decrypted and verified '{args.input}' -> '{args.output}'")
    print(f"    Restored Size: {len(plaintext)} bytes | Integrity & Authenticity: VALID")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Builds and returns the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="fevs",
        description="FEVS: File Encryption & Verification System (PECE04T/PECE04P Module 2)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True, help="Available subcommands")

    # --- keygen ---
    keygen_parser = subparsers.add_parser("keygen", help="Generate an RSA-2048 keypair and export to PEM")
    keygen_parser.add_argument("--out-dir", "-o", default=".", help="Directory to save generated PEM keys (default: .)")
    keygen_parser.add_argument("--prefix", "-p", default="", help="Optional filename prefix for generated keys (e.g., 'alice')")
    keygen_parser.add_argument("--passphrase", help="Optional passphrase to protect the private key")

    # --- encrypt ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt and sign a file into .cns format")
    encrypt_parser.add_argument("--input", "-i", required=True, help="Path to input plaintext file")
    encrypt_parser.add_argument("--output", "-o", required=True, help="Path to output .cns container file")
    encrypt_parser.add_argument("--recipient-pub", required=True, help="Path to recipient's RSA public key PEM")
    encrypt_parser.add_argument("--sender-priv", required=True, help="Path to sender's RSA private key PEM")
    encrypt_parser.add_argument(
        "--cipher",
        choices=["aes", "des"],
        default="aes",
        help="Symmetric cipher algorithm: 'aes' (default) or 'des'",
    )
    encrypt_parser.add_argument("--shred", action="store_true", help="Securely wipe original input file after encryption")
    encrypt_parser.add_argument("--passphrase", help="Optional passphrase for sender's private key")

    # --- decrypt ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt and authenticate a .cns file")
    decrypt_parser.add_argument("--input", "-i", required=True, help="Path to input .cns container file")
    decrypt_parser.add_argument("--output", "-o", required=True, help="Path to output decrypted file")
    decrypt_parser.add_argument("--recipient-priv", required=True, help="Path to recipient's RSA private key PEM")
    decrypt_parser.add_argument("--sender-pub", required=True, help="Path to sender's RSA public key PEM")
    decrypt_parser.add_argument("--passphrase", help="Optional passphrase for recipient's private key")

    return parser


def main() -> None:
    """Main execution function."""
    parser = build_parser()
    args = parser.parse_args()

    if args.subcommand == "keygen":
        sys.exit(handle_keygen(args))
    elif args.subcommand == "encrypt":
        sys.exit(handle_encrypt(args))
    elif args.subcommand == "decrypt":
        sys.exit(handle_decrypt(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
