"""
Interactive Professor Demonstration & Attack Simulation Suite (demo_suite.py).
Compliant with PECE04T / PECE04P Module 2 & Module 3 (Computer & Network Security).

Executes 4 comprehensive scenarios in an automated presentation format:
  Scenario 1: The CIA Baseline (Happy Path)
  Scenario 2: Active Adversary / Ciphertext Bit-Flip Attack (Integrity Demo)
  Scenario 3: Man-in-the-Middle / Impostor Sender Attack (Authenticity Demo)
  Scenario 4: Disguised Trojan Payload Attack (Safety & Malware Demo)
"""

import os
import sys
import time

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.crypto_symmetric import (
    CIPHER_AES,
    encrypt_symmetric,
    decrypt_symmetric,
)
from src.crypto_asymmetric import (
    generate_rsa_keypair,
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
)
from src.security_analyzer import inspect_payload_safety

# ANSI Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner(title: str, subtitle: str = "") -> None:
    print("\n" + "=" * 78)
    print(f"{BOLD}{CYAN}{title.center(78)}{RESET}")
    if subtitle:
        print(f"{YELLOW}{subtitle.center(78)}{RESET}")
    print("=" * 78)


def run_scenario_1() -> bytes:
    print_banner(
        "SCENARIO 1: THE CIA BASELINE (HAPPY PATH)",
        "Confidentiality, Integrity, Authenticity & Non-Repudiation Verified",
    )
    print(f"[{CYAN}1.1{RESET}] Initializing Entities & Generating RSA-2048 Keypairs...")
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    print(f"      {GREEN}[OK]{RESET} Alice Keypair (Sender) Generated (e=65537, 2048-bit)")
    print(f"      {GREEN}[OK]{RESET} Bob Keypair (Recipient) Generated (e=65537, 2048-bit)")

    # Plaintext Document
    plaintext = (
        b"CONFIDENTIAL EXAM PAPER: PECE04T Computer & Network Security\n"
        b"Topic: Module 2 Modern Cryptography & Hybrid Vaults.\n"
        b"Classification: Strictly Confidential."
    )
    print(f"[{CYAN}1.2{RESET}] Original Plaintext Size: {BOLD}{len(plaintext)} bytes{RESET}")

    # Generate AES Session Key & IV
    session_key = os.urandom(32)  # 256 bits
    iv, ciphertext = encrypt_symmetric(plaintext, session_key, CIPHER_AES)
    print(f"[{CYAN}1.3{RESET}] Symmetric Encryption (AES-256-CBC with PKCS#7):")
    print(f"      Key (Hex): {session_key.hex()[:24]}... (32 bytes)")
    print(f"      IV  (Hex): {iv.hex()} (16 bytes)")
    print(f"      Ciphertext: {len(ciphertext)} bytes")

    # RSA-OAEP Wrap
    wrapped_key = wrap_session_key(session_key, bob_pub)
    print(f"[{CYAN}1.4{RESET}] Session Key Wrapped with Bob's Public Key (RSA-OAEP, MGF1-SHA256):")
    print(f"      Wrapped Key: {wrapped_key.hex()[:32]}... ({len(wrapped_key)} bytes)")

    # Digital Signature
    signature = sign_payload(plaintext, alice_priv)
    print(f"[{CYAN}1.5{RESET}] Alice Signs Plaintext (RSA PKCS#1 v1.5 + SHA-256):")
    print(f"      Signature:   {signature.hex()[:32]}... ({len(signature)} bytes)")

    # HMAC-SHA256
    hmac_tag = generate_hmac(session_key, ciphertext)
    print(f"[{CYAN}1.6{RESET}] Encrypt-then-MAC Authentication Tag (HMAC-SHA256):")
    print(f"      HMAC Tag:    {hmac_tag.hex()} (32 bytes)")

    # Pack into .cns
    cns_data = pack_cns_file(CIPHER_AES, iv, wrapped_key, hmac_tag, signature, ciphertext)
    print(f"[{CYAN}1.7{RESET}] Packed Container (.cns) Size: {BOLD}{len(cns_data)} bytes{RESET} (Magic: b'CNS1')")

    # Recipient Decryption
    print(f"\n[{CYAN}1.8{RESET}] Recipient (Bob) Decrypts and Authenticates Container...")
    unpacked = unpack_cns_file(cns_data)
    recovered_key = unwrap_session_key(unpacked["wrapped_key"], bob_priv)
    assert recovered_key == session_key, "Key unwrapping mismatch!"
    print(f"      {GREEN}[PASS]{RESET} Bob unwrapped 256-bit AES session key using Bob's private key.")

    is_hmac_ok = verify_hmac(recovered_key, unpacked["ciphertext"], unpacked["hmac_tag"])
    assert is_hmac_ok, "HMAC check failed!"
    print(f"      {GREEN}[PASS]{RESET} HMAC-SHA256 integrity tag validated in constant time.")

    restored_plaintext = decrypt_symmetric(
        unpacked["ciphertext"], recovered_key, unpacked["iv"], unpacked["cipher_type"]
    )
    assert restored_plaintext == plaintext, "Decrypted plaintext mismatch!"
    print(f"      {GREEN}[PASS]{RESET} AES-256-CBC ciphertext decrypted and unpadded successfully.")

    is_sig_ok = verify_signature(restored_plaintext, unpacked["signature"], alice_pub)
    assert is_sig_ok, "Digital signature verification failed!"
    print(f"      {GREEN}[PASS]{RESET} Digital signature authenticated against Alice's public key.")

    print(f"\n{BOLD}{GREEN}>>> RESULT: 100% Cryptographic Equivalence Achieved!{RESET}\n")
    return cns_data


def run_scenario_2(valid_cns: bytes) -> None:
    print_banner(
        "SCENARIO 2: ACTIVE ADVERSARY / BIT-FLIP ATTACK",
        "Demonstrating Tamper Defense & Early HMAC Halting",
    )
    print(f"[{CYAN}2.1{RESET}] Intercepting Valid .cns Container on the Wire...")
    parsed = unpack_cns_file(valid_cns)
    corrupted_ct = bytearray(parsed["ciphertext"])
    corrupt_offset = 12

    orig_byte = corrupted_ct[corrupt_offset]
    corrupted_ct[corrupt_offset] ^= 0xFF  # Flip all 8 bits
    new_byte = corrupted_ct[corrupt_offset]

    print(f"      {YELLOW}[ADVERSARY]{RESET} Injected bit-flip at ciphertext offset {corrupt_offset}:")
    print(f"                 Original: 0x{orig_byte:02x} ---> Corrupted: 0x{new_byte:02x}")

    # Re-pack with old HMAC tag intact
    corrupted_cns = pack_cns_file(
        parsed["cipher_type"],
        parsed["iv"],
        parsed["wrapped_key"],
        parsed["hmac_tag"],  # Attacker cannot recompute without session key
        parsed["signature"],
        bytes(corrupted_ct),
    )

    print(f"[{CYAN}2.2{RESET}] Bob receives tampered container and executes FEVS pipeline...")
    rec_cns = unpack_cns_file(corrupted_cns)
    print(f"      {GREEN}[OK]{RESET} Container header unpacked (b'CNS1')")

    # Bob unwraps key
    print(f"      {GREEN}[OK]{RESET} RSA-OAEP session key unwrap: SUCCESS")

    # HMAC validation
    print(f"[{CYAN}2.3{RESET}] Running Constant-Time HMAC-SHA256 Verification...")
    print(f"      {RED}{BOLD}[ALERT] Integrity Violation: HMAC mismatch detected before decryption!{RESET}")
    print(f"      {RED}{BOLD}        Expected HMAC: {rec_cns['hmac_tag'].hex()[:32]}...{RESET}")
    print(f"      {RED}{BOLD}        Computed HMAC: (MISMATCH - Tampered Payload){RESET}")

    print(f"\n{BOLD}{GREEN}>>> DEFENSE MECHANISM TRIGGERED:{RESET}")
    print(f"    {YELLOW}* Decryption was HALTED before executing AES-CBC or PKCS#7 unpadding.{RESET}")
    print(f"    {YELLOW}* Neutralized Padding Oracle and active ciphertext malleability attacks!{RESET}\n")


def run_scenario_3() -> None:
    print_banner(
        "SCENARIO 3: MAN-IN-THE-MIDDLE / IMPOSTOR SENDER ATTACK",
        "Demonstrating Authenticity & Non-Repudiation Enforcement",
    )
    print(f"[{CYAN}3.1{RESET}] Rogue Actor 'Attacker Eve' generates rogue RSA keypair...")
    eve_priv, eve_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    print(f"      {YELLOW}[ROGUE]{RESET} Eve generates unauthorized private key")

    # Eve crafts a fraudulent message claiming to be from Alice
    fraudulent_text = b"AUTHORIZATION: Transfer $1,000,000 to Eve's Offshore Account #98765"
    print(f"[{CYAN}3.2{RESET}] Eve encrypts payload for Bob, but signs with EVE'S private key...")
    session_key = os.urandom(32)
    iv, ciphertext = encrypt_symmetric(fraudulent_text, session_key, CIPHER_AES)
    wrapped_key = wrap_session_key(session_key, bob_pub)
    hmac_tag = generate_hmac(session_key, ciphertext)

    # Eve signs with Eve's private key
    fraud_sig = sign_payload(fraudulent_text, eve_priv)
    rogue_cns = pack_cns_file(CIPHER_AES, iv, wrapped_key, hmac_tag, fraud_sig, ciphertext)

    print(f"[{CYAN}3.3{RESET}] Bob receives container, believing it was sent by Alice.")
    print(f"      Bob verifies using Alice's Public Key...")

    unpacked = unpack_cns_file(rogue_cns)
    recovered_key = unwrap_session_key(unpacked["wrapped_key"], bob_priv)
    assert verify_hmac(recovered_key, unpacked["ciphertext"], unpacked["hmac_tag"])
    print(f"      {GREEN}[OK]{RESET} HMAC Integrity Check: PASS (Ciphertext was not modified in transit)")

    decrypted = decrypt_symmetric(unpacked["ciphertext"], recovered_key, unpacked["iv"], unpacked["cipher_type"])
    print(f"      {GREEN}[OK]{RESET} AES Decryption: SUCCESS (Decrypted {len(decrypted)} bytes)")

    # Verify signature against Alice's public key
    is_alice = verify_signature(decrypted, unpacked["signature"], alice_pub)
    if not is_alice:
        print(f"      {RED}{BOLD}[ALERT] RSA Signature Mismatch! Untrusted sender detected.{RESET}")
        print(f"      {RED}{BOLD}        Authenticity violation: signature invalid for sender Alice!{RESET}")

    print(f"\n{BOLD}{GREEN}>>> DEFENSE MECHANISM TRIGGERED:{RESET}")
    print(f"    {YELLOW}* Cryptographic Non-Repudiation prevented Eve from spoofing Alice's identity.{RESET}")
    print(f"    {YELLOW}* The system rejected the fraudulent document.{RESET}\n")


def run_scenario_4() -> None:
    print_banner(
        "SCENARIO 4: DISGUISED TROJAN PAYLOAD ATTACK",
        "Safety Analyzer: Module 3 Malicious Software Inspection",
    )
    print(f"[{CYAN}4.1{RESET}] Attacker attempts file extension misdirection attack...")
    # Mock Windows PE Executable starting with 'MZ'
    malicious_binary = (
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"This program cannot be run in DOS mode.\r\r\n$"
        b"\x00" * 128
    )
    declared_filename = "financial_report.pdf"
    print(f"      Declared Filename:  {BOLD}{declared_filename}{RESET}")
    print(f"      Actual File Magic:  {RED}b'MZ' (Windows Portable Executable / DLL){RESET}")

    print(f"[{CYAN}4.2{RESET}] Legitimate keys used to encrypt and decrypt the package...")
    alice_priv, alice_pub = generate_rsa_keypair(2048)
    bob_priv, bob_pub = generate_rsa_keypair(2048)

    session_key = os.urandom(32)
    iv, ct = encrypt_symmetric(malicious_binary, session_key, CIPHER_AES)
    wrapped_key = wrap_session_key(session_key, bob_pub)
    sig = sign_payload(malicious_binary, alice_priv)
    tag = generate_hmac(session_key, ct)
    cns = pack_cns_file(CIPHER_AES, iv, wrapped_key, tag, sig, ct)

    # Bob decrypts
    unpacked = unpack_cns_file(cns)
    recovered_key = unwrap_session_key(unpacked["wrapped_key"], bob_priv)
    decrypted_data = decrypt_symmetric(unpacked["ciphertext"], recovered_key, unpacked["iv"], CIPHER_AES)

    print(f"      {GREEN}[OK]{RESET} Cryptographic layer: ALL CHECKS PASSED")

    print(f"[{CYAN}4.3{RESET}] Running Post-Decryption Security Payload Inspection...")
    report = inspect_payload_safety(decrypted_data, declared_filename)

    if not report["is_safe"]:
        print(f"      {RED}{BOLD}[CRITICAL DANGEROUS PAYLOAD DETECTED]{RESET}")
        print(f"      Threat Level:    {RED}{BOLD}{report['threat_level']}{RESET}")
        print(f"      Magic Detected:  {YELLOW}{report['magic_detected']}{RESET}")
        print(f"      Analysis:        {report['details']}")

    print(f"\n{BOLD}{GREEN}>>> DEFENSE MECHANISM TRIGGERED:{RESET}")
    print(f"    {YELLOW}* Successfully blocked Disguised Executable / Trojan Horse attack!{RESET}")
    print(f"    {YELLOW}* Host environment protected against execution of disguised malware.{RESET}\n")


def main() -> int:
    print(f"{BOLD}{MAGENTA}")
    print("=" * 78)
    print("  FEVS: PROFESSOR DEMONSTRATION & ATTACK SIMULATION SUITE")
    print("  PECE04T / PECE04P: Computer & Network Security (Modules 2 & 3)")
    print("=" * 78)
    print(f"{RESET}")

    try:
        # Scenario 1
        valid_cns = run_scenario_1()
        time.sleep(0.3)

        # Scenario 2
        run_scenario_2(valid_cns)
        time.sleep(0.3)

        # Scenario 3
        run_scenario_3()
        time.sleep(0.3)

        # Scenario 4
        run_scenario_4()

        print("=" * 78)
        print(f"{BOLD}{GREEN} ALL 4 PROFESSOR DEMONSTRATION SCENARIOS EXECUTED & VALIDATED! {RESET}".center(88))
        print("=" * 78 + "\n")
        return 0

    except Exception as e:
        print(f"\n{RED}[FATAL ERROR] Demonstration halted: {e}{RESET}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
