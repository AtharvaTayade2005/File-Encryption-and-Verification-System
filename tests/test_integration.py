"""
End-to-End Integration and Cryptographic Vector Validation Suite (tests/test_integration.py).
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Tests:
  - Full cryptographic lifecycle (Keygen -> Encrypt -> Decrypt -> Hash Verification)
  - 1-byte ciphertext tamper detection stopping specifically at HMAC check
  - Access control: unauthorized recipient private key fails session key unwrapping
  - Authenticity: impostor sender public key fails digital signature verification
  - Cross-validation against OpenSSL CLI vectors
"""

import hashlib
import os
import subprocess
import sys
import pytest

from src.file_vault import pack_cns_file, unpack_cns_file, verify_hmac
from src.crypto_asymmetric import unwrap_session_key, verify_signature
from scripts.verify_openssl import find_openssl_binary, verify_aes_cbc, verify_hmac_sha256


@pytest.fixture
def run_fevs_cli():
    """Helper to execute FEVS CLI commands."""
    def _run(*args):
        cmd = [sys.executable, os.path.abspath("src/main.py")] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)
    return _run


@pytest.fixture(scope="module")
def integration_identities(tmp_path_factory):
    """Generates RSA keypairs for Alice (sender), Bob (recipient), Charlie, and Mallory."""
    keys_dir = tmp_path_factory.mktemp("integration_identities")

    identities = ["alice", "bob", "charlie", "mallory"]
    paths = {}
    for name in identities:
        cmd = [sys.executable, os.path.abspath("src/main.py"), "keygen", "--out-dir", str(keys_dir), "--prefix", name]
        subprocess.run(cmd, check=True)
        paths[f"{name}_priv"] = keys_dir / f"{name}_private.pem"
        paths[f"{name}_pub"] = keys_dir / f"{name}_public.pem"

    return paths


class TestCryptographicIntegrationLifecycle:
    """Integration test suite verifying full multi-party workflow."""

    @pytest.mark.parametrize("cipher", ["aes", "des"])
    def test_full_lifecycle_sha256_hash_verification(self, run_fevs_cli, integration_identities, tmp_path, cipher):
        """
        Lifecycle:
          Alice signs & encrypts for Bob -> Bob decrypts & verifies.
          Verifies identical SHA-256 digests between original and restored files.
        """
        # 1. Create original payload
        original_file = tmp_path / f"payload_{cipher}.dat"
        payload_data = os.urandom(8192) + b"FEVS CNS PECE04T Integration Test Data"
        original_file.write_bytes(payload_data)
        original_sha256 = hashlib.sha256(payload_data).hexdigest()

        vault_file = tmp_path / f"vault_{cipher}.cns"
        restored_file = tmp_path / f"restored_{cipher}.dat"

        # 2. Encrypt
        enc_res = run_fevs_cli(
            "encrypt",
            "--input", str(original_file),
            "--output", str(vault_file),
            "--recipient-pub", str(integration_identities["bob_pub"]),
            "--sender-priv", str(integration_identities["alice_priv"]),
            "--cipher", cipher,
        )
        assert enc_res.returncode == 0, enc_res.stderr
        assert vault_file.exists()

        # 3. Decrypt
        dec_res = run_fevs_cli(
            "decrypt",
            "--input", str(vault_file),
            "--output", str(restored_file),
            "--recipient-priv", str(integration_identities["bob_priv"]),
            "--sender-pub", str(integration_identities["alice_pub"]),
        )
        assert dec_res.returncode == 0, dec_res.stderr
        assert restored_file.exists()

        # 4. Verify identical hashes
        restored_data = restored_file.read_bytes()
        restored_sha256 = hashlib.sha256(restored_data).hexdigest()

        assert restored_sha256 == original_sha256
        assert restored_data == payload_data

    def test_tampering_1_byte_ciphertext_stops_at_hmac_check(self, run_fevs_cli, integration_identities, tmp_path):
        """
        Tampering test:
          Modifying 1 byte of ciphertext inside .cns must cause decryption to abort
          strictly at the HMAC check before any attempt to decrypt or verify signature.
        """
        plain_file = tmp_path / "financial_record.csv"
        plain_file.write_bytes(b"id,user,balance\n1,alice,50000\n2,bob,75000\n")
        vault_file = tmp_path / "record.cns"
        restored_file = tmp_path / "restored_record.csv"

        # Encrypt
        run_fevs_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(vault_file),
            "--recipient-pub", str(integration_identities["bob_pub"]),
            "--sender-priv", str(integration_identities["alice_priv"]),
        )

        # Unpack and tamper exactly 1 byte in the ciphertext
        raw_cns = vault_file.read_bytes()
        container = unpack_cns_file(raw_cns)
        tampered_ct = bytearray(container["ciphertext"])
        tampered_ct[0] ^= 0x01  # Flip 1 bit

        corrupted_cns = pack_cns_file(
            container["cipher_type"],
            container["iv"],
            container["wrapped_key"],
            container["hmac_tag"],  # Retains original HMAC tag
            container["signature"],
            bytes(tampered_ct),
        )
        vault_file.write_bytes(corrupted_cns)

        # Decrypt must fail at the HMAC integrity check
        dec_res = run_fevs_cli(
            "decrypt",
            "--input", str(vault_file),
            "--output", str(restored_file),
            "--recipient-priv", str(integration_identities["bob_priv"]),
            "--sender-pub", str(integration_identities["alice_pub"]),
        )
        assert dec_res.returncode == 1
        assert "Integrity violation: file has been tampered with!" in dec_res.stderr
        assert not restored_file.exists(), "Decrypted file must NOT be written when integrity check fails"

    def test_wrong_recipient_private_key_fails_unwrapping(self, run_fevs_cli, integration_identities, tmp_path):
        """
        Confidentiality / Access Control:
          Alice encrypts for Bob. Charlie attempts to decrypt with Charlie's private key.
          Session key unwrapping must fail.
        """
        plain_file = tmp_path / "classified.txt"
        plain_file.write_bytes(b"Confidential communication strictly for Bob.")
        vault_file = tmp_path / "classified.cns"
        restored_file = tmp_path / "restored_classified.txt"

        # Encrypt for Bob
        run_fevs_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(vault_file),
            "--recipient-pub", str(integration_identities["bob_pub"]),
            "--sender-priv", str(integration_identities["alice_priv"]),
        )

        # Charlie attempts decryption with Charlie's private key
        dec_res = run_fevs_cli(
            "decrypt",
            "--input", str(vault_file),
            "--output", str(restored_file),
            "--recipient-priv", str(integration_identities["charlie_priv"]),
            "--sender-pub", str(integration_identities["alice_pub"]),
        )
        assert dec_res.returncode == 1
        assert "Session key unwrapping failed" in dec_res.stderr
        assert not restored_file.exists()

    def test_impostor_sender_public_key_fails_signature_verification(self, run_fevs_cli, integration_identities, tmp_path):
        """
        Authenticity / Non-Repudiation:
          Alice encrypts and signs for Bob.
          Bob attempts verification using Mallory's public key (impostor sender).
          Decryption succeeds in key unwrap and HMAC, but signature verification fails.
        """
        plain_file = tmp_path / "contract.txt"
        plain_file.write_bytes(b"Legal agreement signed by Alice.")
        vault_file = tmp_path / "contract.cns"
        restored_file = tmp_path / "restored_contract.txt"

        # Alice signs and encrypts for Bob
        run_fevs_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(vault_file),
            "--recipient-pub", str(integration_identities["bob_pub"]),
            "--sender-priv", str(integration_identities["alice_priv"]),
        )

        # Bob decrypts with Bob's private key, but checks signature against Mallory's public key
        dec_res = run_fevs_cli(
            "decrypt",
            "--input", str(vault_file),
            "--output", str(restored_file),
            "--recipient-priv", str(integration_identities["bob_priv"]),
            "--sender-pub", str(integration_identities["mallory_pub"]),
        )
        assert dec_res.returncode == 1
        assert "Authenticity violation: signature invalid!" in dec_res.stderr
        assert not restored_file.exists(), "File must NOT be written when signature authenticity fails"


class TestOpenSSLVectorCompliance:
    """Validates FEVS against standard OpenSSL CLI vectors."""

    def test_openssl_cross_verification_suite(self):
        try:
            openssl_bin = find_openssl_binary()
        except FileNotFoundError:
            pytest.skip("OpenSSL CLI not installed on this system.")

        # Test AES-256-CBC decryption vector with OpenSSL
        assert verify_aes_cbc(openssl_bin) is True

        # Test HMAC-SHA256 authentication vector with OpenSSL
        assert verify_hmac_sha256(openssl_bin) is True
