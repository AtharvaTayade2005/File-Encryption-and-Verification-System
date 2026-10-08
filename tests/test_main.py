"""
Unit and integration tests for the CLI Entry Point (src/main.py).
Tests end-to-end command line execution for keygen, encrypt, decrypt,
HMAC integrity violation detection, and RSA signature authenticity failure.
"""

import os
import subprocess
import sys
import pytest

from src.file_vault import unpack_cns_file, pack_cns_file


@pytest.fixture
def run_cli():
    """Helper to execute src/main.py via subprocess."""
    def _run(*args):
        cmd = [sys.executable, os.path.abspath("src/main.py")] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)
    return _run


@pytest.fixture(scope="module")
def cli_test_keys(tmp_path_factory):
    """Generates Alice (sender) and Bob (recipient) keys for testing."""
    keys_dir = tmp_path_factory.mktemp("cli_keys")
    cmd_alice = [sys.executable, os.path.abspath("src/main.py"), "keygen", "--out-dir", str(keys_dir), "--prefix", "alice"]
    cmd_bob = [sys.executable, os.path.abspath("src/main.py"), "keygen", "--out-dir", str(keys_dir), "--prefix", "bob"]
    subprocess.run(cmd_alice, check=True)
    subprocess.run(cmd_bob, check=True)

    return {
        "alice_priv": keys_dir / "alice_private.pem",
        "alice_pub": keys_dir / "alice_public.pem",
        "bob_priv": keys_dir / "bob_private.pem",
        "bob_pub": keys_dir / "bob_public.pem",
    }


class TestCLIE2EPipeline:
    """End-to-end CLI workflow tests."""

    def test_cli_keygen_command(self, run_cli, tmp_path):
        out_dir = tmp_path / "keygen_test"
        res = run_cli("keygen", "--out-dir", str(out_dir), "--prefix", "charlie")
        assert res.returncode == 0
        assert (out_dir / "charlie_private.pem").exists()
        assert (out_dir / "charlie_public.pem").exists()

    @pytest.mark.parametrize("cipher", ["aes", "des"])
    def test_cli_encrypt_and_decrypt_roundtrip(self, run_cli, cli_test_keys, tmp_path, cipher):
        plain_file = tmp_path / f"test_{cipher}.txt"
        secret_content = b"CNS PECE04T Course Project: End-to-End CLI Pipeline Test!"
        plain_file.write_bytes(secret_content)

        cns_file = tmp_path / f"vault_{cipher}.cns"
        restored_file = tmp_path / f"restored_{cipher}.txt"

        # 1. Encrypt
        enc_res = run_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(cns_file),
            "--recipient-pub", str(cli_test_keys["bob_pub"]),
            "--sender-priv", str(cli_test_keys["alice_priv"]),
            "--cipher", cipher,
        )
        assert enc_res.returncode == 0, enc_res.stderr
        assert cns_file.exists()

        # 2. Decrypt
        dec_res = run_cli(
            "decrypt",
            "--input", str(cns_file),
            "--output", str(restored_file),
            "--recipient-priv", str(cli_test_keys["bob_priv"]),
            "--sender-pub", str(cli_test_keys["alice_pub"]),
        )
        assert dec_res.returncode == 0, dec_res.stderr
        assert restored_file.exists()
        assert restored_file.read_bytes() == secret_content

    def test_cli_encrypt_with_shred(self, run_cli, cli_test_keys, tmp_path):
        sensitive_file = tmp_path / "burn_after_reading.txt"
        sensitive_file.write_bytes(b"Top secret document to shred.")
        cns_file = tmp_path / "burned.cns"

        res = run_cli(
            "encrypt",
            "--input", str(sensitive_file),
            "--output", str(cns_file),
            "--recipient-pub", str(cli_test_keys["bob_pub"]),
            "--sender-priv", str(cli_test_keys["alice_priv"]),
            "--shred",
        )
        assert res.returncode == 0
        assert cns_file.exists()
        assert not sensitive_file.exists(), "Original file should be shredded and removed"

    def test_cli_tampered_ciphertext_aborts_with_integrity_error(self, run_cli, cli_test_keys, tmp_path):
        plain_file = tmp_path / "integrity_test.txt"
        plain_file.write_bytes(b"Data before tampering.")
        cns_file = tmp_path / "integrity_vault.cns"
        restored_file = tmp_path / "restored_tampered.txt"

        # Encrypt
        run_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(cns_file),
            "--recipient-pub", str(cli_test_keys["bob_pub"]),
            "--sender-priv", str(cli_test_keys["alice_priv"]),
        )

        # Tamper ciphertext in the .cns container
        raw_cns = cns_file.read_bytes()
        container = unpack_cns_file(raw_cns)
        tampered_ct = bytearray(container["ciphertext"])
        tampered_ct[0] ^= 0x01
        corrupted_cns = pack_cns_file(
            container["cipher_type"],
            container["iv"],
            container["wrapped_key"],
            container["hmac_tag"],  # Original HMAC tag, won't match tampered_ct
            container["signature"],
            bytes(tampered_ct),
        )
        cns_file.write_bytes(corrupted_cns)

        # Decrypt must abort with exact error message
        dec_res = run_cli(
            "decrypt",
            "--input", str(cns_file),
            "--output", str(restored_file),
            "--recipient-priv", str(cli_test_keys["bob_priv"]),
            "--sender-pub", str(cli_test_keys["alice_pub"]),
        )
        assert dec_res.returncode == 1
        assert "Integrity violation: file has been tampered with!" in dec_res.stderr

    def test_cli_tampered_signature_aborts_with_authenticity_error(self, run_cli, cli_test_keys, tmp_path):
        plain_file = tmp_path / "authenticity_test.txt"
        plain_file.write_bytes(b"Data for authenticity test.")
        cns_file = tmp_path / "authenticity_vault.cns"
        restored_file = tmp_path / "restored_invalid_sig.txt"

        # Encrypt
        run_cli(
            "encrypt",
            "--input", str(plain_file),
            "--output", str(cns_file),
            "--recipient-pub", str(cli_test_keys["bob_pub"]),
            "--sender-priv", str(cli_test_keys["alice_priv"]),
        )

        # Alter the signature in the .cns container (retaining valid HMAC tag so it passes step c)
        raw_cns = cns_file.read_bytes()
        container = unpack_cns_file(raw_cns)
        tampered_sig = bytearray(container["signature"])
        tampered_sig[0] ^= 0x01
        corrupted_cns = pack_cns_file(
            container["cipher_type"],
            container["iv"],
            container["wrapped_key"],
            container["hmac_tag"],
            bytes(tampered_sig),
            container["ciphertext"],
        )
        cns_file.write_bytes(corrupted_cns)

        # Decrypt must pass HMAC but abort at signature verification
        dec_res = run_cli(
            "decrypt",
            "--input", str(cns_file),
            "--output", str(restored_file),
            "--recipient-priv", str(cli_test_keys["bob_priv"]),
            "--sender-pub", str(cli_test_keys["alice_pub"]),
        )
        assert dec_res.returncode == 1
        assert "Authenticity violation: signature invalid!" in dec_res.stderr
