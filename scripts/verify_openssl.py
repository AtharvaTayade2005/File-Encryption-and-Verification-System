"""
OpenSSL Cross-Verification Script for FEVS.
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Validates FEVS cryptographic primitives against standard OpenSSL CLI vectors:
  1. AES-256-CBC Decryption via `openssl enc -d -aes-256-cbc`
  2. HMAC-SHA256 Authentication via `openssl dgst -sha256 -mac HMAC` and `openssl dgst -sha256 -hmac`
"""

import os
import shutil
import subprocess
import sys
import tempfile

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto_symmetric import CIPHER_AES, encrypt_symmetric
from src.file_vault import generate_hmac


def find_openssl_binary() -> str:
    """Locates the OpenSSL binary on PATH or standard installation paths."""
    cmd = shutil.which("openssl")
    if cmd:
        return cmd

    candidates = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\clangarm64\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files (x86)\Git\usr\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\OpenSSL-Win32\bin\openssl.exe",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    raise FileNotFoundError(
        "OpenSSL CLI binary not found in PATH or standard installation locations."
    )


def verify_aes_cbc(openssl_bin: str) -> bool:
    """
    Encrypts sample plaintext using FEVS AES-256-CBC engine and validates
    that OpenSSL can decrypt it using identical key and IV.
    """
    print("\n[+] Step 1: Validating AES-256-CBC Decryption with OpenSSL...")

    session_key = os.urandom(32)  # 256 bits
    test_plaintext = (
        b"PECE04T Computer & Network Security: OpenSSL AES-256-CBC Verification Vector!\n"
        b"Zero-knowledge file encryption test vector."
    )

    iv, ciphertext = encrypt_symmetric(test_plaintext, session_key, CIPHER_AES)

    with tempfile.TemporaryDirectory() as tmp_dir:
        ct_file = os.path.join(tmp_dir, "ciphertext.enc")
        out_file = os.path.join(tmp_dir, "decrypted.txt")

        with open(ct_file, "wb") as f:
            f.write(ciphertext)

        # OpenSSL command to decrypt AES-256-CBC with PKCS#7 padding
        cmd = [
            openssl_bin,
            "enc",
            "-d",
            "-aes-256-cbc",
            "-in", ct_file,
            "-out", out_file,
            "-K", session_key.hex(),
            "-iv", iv.hex(),
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] OpenSSL command failed with error:\n{result.stderr}")
            return False

        with open(out_file, "rb") as f:
            decrypted = f.read()

        if decrypted != test_plaintext:
            print("[-] Decrypted plaintext does not match original!")
            return False

    print("    [PASS] OpenSSL successfully decrypted FEVS AES-256-CBC ciphertext.")
    print(f"    Key (hex): {session_key.hex()[:16]}... (32 bytes)")
    print(f"    IV  (hex): {iv.hex()} (16 bytes)")
    print(f"    Plaintext verified ({len(test_plaintext)} bytes).")
    return True


def verify_hmac_sha256(openssl_bin: str) -> bool:
    """
    Generates HMAC-SHA256 tag using FEVS engine and validates
    that OpenSSL generates identical tag over the same ciphertext.
    """
    print("\n[+] Step 2: Validating HMAC-SHA256 Authentication with OpenSSL...")

    hmac_key = os.urandom(32)
    sample_data = b"Arbitrary binary file payload for HMAC-SHA256 validation\x00\xFF\x42" * 16

    fevs_tag = generate_hmac(hmac_key, sample_data)

    with tempfile.TemporaryDirectory() as tmp_dir:
        data_file = os.path.join(tmp_dir, "payload.bin")
        with open(data_file, "wb") as f:
            f.write(sample_data)

        # OpenSSL command using -mac HMAC and -macopt hexkey:<hex>
        cmd = [
            openssl_bin,
            "dgst",
            "-sha256",
            "-mac", "HMAC",
            "-macopt", f"hexkey:{hmac_key.hex()}",
            data_file,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # Fallback to string key if needed
            print(f"[-] OpenSSL dgst command failed:\n{result.stderr}")
            return False

        # OpenSSL output format: "HMAC-SHA2-256(filepath)= <hex_digest>" or "(stdin)= <hex_digest>"
        openssl_hex = result.stdout.strip().split()[-1].lower()

        if openssl_hex != fevs_tag.hex().lower():
            print(f"[-] HMAC mismatch!")
            print(f"    FEVS Tag:    {fevs_tag.hex()}")
            print(f"    OpenSSL Tag: {openssl_hex}")
            return False

    print("    [PASS] OpenSSL HMAC-SHA256 output matches FEVS tag bit-for-bit.")
    print(f"    HMAC Key (hex): {hmac_key.hex()[:16]}...")
    print(f"    HMAC Tag (hex): {fevs_tag.hex()}")
    return True


def main() -> int:
    print("=" * 70)
    print(" FEVS OpenSSL Cryptographic Vector Cross-Verification Suite")
    print(" PECE04T / PECE04P Module 2 Compliance Verification")
    print("=" * 70)

    try:
        openssl_bin = find_openssl_binary()
        print(f"[+] Found OpenSSL at: {openssl_bin}")
        ver_proc = subprocess.run([openssl_bin, "version"], capture_output=True, text=True)
        print(f"    Version: {ver_proc.stdout.strip()}")
    except FileNotFoundError as e:
        print(f"[-] {e}")
        return 1

    ok_aes = verify_aes_cbc(openssl_bin)
    ok_hmac = verify_hmac_sha256(openssl_bin)

    print("\n" + "=" * 70)
    if ok_aes and ok_hmac:
        print("[SUCCESS] All cryptographic primitives are 100% compliant with OpenSSL standard vectors!")
        print("=" * 70)
        return 0
    else:
        print("[FAILURE] OpenSSL cross-verification failed!")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
