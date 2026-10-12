# FEVS Codebase Line-by-Line & Function Walkthrough

> **Purpose**: A comprehensive developer walkthrough detailing the implementation mechanics, exact functions, algorithms, and security reasoning behind every module in the FEVS codebase.

---

## Table of Contents
1. [src/crypto_symmetric.py (Symmetric Cryptography Engine)](#1-srccrypto_symmetricpy)
2. [src/crypto_asymmetric.py (Asymmetric Key Management & Signatures)](#2-srccrypto_asymmetricpy)
3. [src/file_vault.py (Binary Packaging, HMAC & File Shredding)](#3-srcfile_vaultpy)
4. [src/security_analyzer.py (Post-Decryption Threat Scanner)](#4-srcsecurity_analyzerpy)
5. [src/main.py (CLI Orchestrator)](#5-srcmainpy)
6. [app.py (Streamlit Web GUI Dashboard)](#6-apppy)
7. [demo_suite.py (Automated 4-Scenario Professor Testbed)](#7-demo_suitepy)
8. [scripts/verify_openssl.py (OpenSSL Cross-Verification)](#8-scriptsverify_opensslpy)

---

## 1. `src/crypto_symmetric.py`

This module provides symmetric encryption and decryption primitives, block padding, and unpadding using the `cryptography` library.

### Constants & Imports (Lines 9–29)
- **`from cryptography.hazmat.primitives import padding`**: Supplies the PKCS#7 padding standard.
- **`from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes`**: High-level cryptographic primitives interface.
- **`CIPHER_AES = 1` & `CIPHER_DES = 2`**: Integer constants identifying cipher algorithms in binary container headers.
- **`AES_BLOCK_SIZE_BITS = 128`**: Block size for AES in bits (16 bytes).
- **`DES_BLOCK_SIZE_BITS = 64`**: Block size for DES / TripleDES in bits (8 bytes).

### `pad_data(data: bytes, block_size_bits: int) -> bytes` (Lines 31–47)
- **Lines 41–44**: Enforces strict runtime type validation: ensures `data` is bytes-like and `block_size_bits` is an integer.
- **Line 46**: `padder = padding.PKCS7(block_size_bits).padder()` creates a PKCS#7 padder configured for the given block size.
- **Line 47**: `return padder.update(data) + padder.finalize()` appends the PKCS#7 padding bytes. If data ends exactly on a block boundary, a full padding block (16 bytes of `\x10` for AES, or 8 bytes of `\x08` for DES) is appended.

### `unpad_data(data: bytes, block_size_bits: int) -> bytes` (Lines 50–67)
- **Lines 60–63**: Runtime type verification.
- **Line 65**: `unpadder = padding.PKCS7(block_size_bits).unpadder()`.
- **Line 66**: `return unpadder.update(data) + unpadder.finalize()`. Inspects the last byte of data; if the padding sequence is malformed or corrupted, raises `ValueError`.

### `encrypt_symmetric(plaintext: bytes, key: bytes, cipher_type: int) -> Tuple[bytes, bytes]` (Lines 69–131)
- **Lines 83–88**: Type checks on plaintext, key, and cipher type.
- **Lines 90–101 (AES Branch)**:
  - Validates key length (`16`, `24`, or `32` bytes for 128, 192, or 256 bits).
  - `iv = os.urandom(16)`: Generates a cryptographically strong 16-byte IV.
  - `padded_data = pad_data(plaintext, AES_BLOCK_SIZE_BITS)`: Pads plaintext to 16-byte boundary.
  - `cipher = Cipher(algorithms.AES(key), modes.CBC(iv))`: Initializes the AES cipher in CBC mode.
  - `encryptor = cipher.encryptor()`: Creates the encryptor context.
  - `ciphertext = encryptor.update(padded_data) + encryptor.finalize()`: Encrypts the padded data.
  - Returns `(iv, ciphertext)`.
- **Lines 103–125 (DES / TripleDES Branch)**:
  - Validates key length (`8`, `16`, or `24` bytes).
  - Key normalization:
    - If `len(key) == 8`, expands key to `key * 3` (mathematically identical 3-key TripleDES with $K_1=K_2=K_3$).
    - If `len(key) == 16`, expands key to `key + key[:8]` ($K_1, K_2, K_1$).
    - This eliminates deprecated single/two-key warnings while guaranteeing 100% standard compatibility.
  - `iv = os.urandom(8)`: Generates an 8-byte IV.
  - `padded_data = pad_data(plaintext, DES_BLOCK_SIZE_BITS)`: Pads plaintext to 8-byte boundary.
  - `cipher = Cipher(TripleDES(des_key), modes.CBC(iv))`: Encrypts in CBC mode.
  - Returns `(iv, ciphertext)`.

### `decrypt_symmetric(ciphertext: bytes, key: bytes, iv: bytes, cipher_type: int) -> bytes` (Lines 133–193)
- Validates inputs, lengths of key and IV for the selected cipher.
- Initializes `Cipher.decryptor()` in CBC mode with the provided IV.
- Decrypts the raw ciphertext blocks to padded plaintext.
- Invokes `unpad_data(...)` to strip and validate PKCS#7 padding bytes.
- Returns the exact original plaintext bytes.

---

## 2. `src/crypto_asymmetric.py`

This module manages RSA-2048 key generation, PEM serialization/deserialization, RSA-OAEP session key wrapping, and RSA digital signatures.

### Constants (Lines 18–19)
- **`DEFAULT_RSA_KEY_SIZE = 2048`**: Compliant with NIST SP 800-57 recommended minimum key length.
- **`DEFAULT_PUBLIC_EXPONENT = 65537`**: Standard Fermat prime $F_4$ preventing low-exponent attacks while providing efficient public operations.

### `generate_rsa_keypair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]` (Lines 22–42)
- **Lines 32–35**: Validates integer type and ensures `key_size >= 2048`.
- **Lines 37–41**: `rsa.generate_private_key(public_exponent=65537, key_size=key_size)` generates a fresh RSA private key. Returns `(private_key, private_key.public_key())`.

### `export_key_to_pem(key, is_private: bool, password: Optional[str] = None) -> bytes` (Lines 44–80)
- **Lines 58–71 (Private Key Export)**:
  - Formats as standard **PKCS#8** (`serialization.PrivateFormat.PKCS8`).
  - If `password` is supplied, wraps with `serialization.BestAvailableEncryption(pwd_bytes)` (AES-256-CBC with scrypt/PBKDF2).
  - If no password, uses `serialization.NoEncryption()`.
- **Lines 72–79 (Public Key Export)**:
  - Formats as standard **SubjectPublicKeyInfo (X.509)** (`serialization.PublicFormat.SubjectPublicKeyInfo`).

### `load_key_from_pem(pem_bytes, is_private: bool, password: Optional[str] = None)` (Lines 81–106)
- **Lines 94–97**: Accepts strings or bytes; converts strings to UTF-8 encoded bytes.
- **Lines 99–103**: Calls `serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)`.
- **Lines 104–105**: Calls `serialization.load_pem_public_key(pem_bytes)`.

### `wrap_session_key(session_key: bytes, recipient_pubkey: RSAPublicKey) -> bytes` (Lines 108–130)
- Encapsulates the symmetric session key using **RSA-OAEP**:
  - `mgf = padding.MGF1(algorithm=hashes.SHA256())`
  - `algorithm = hashes.SHA256()`
  - `label = None`
- Prevents Bleichenbacher's chosen-ciphertext attacks on RSA PKCS#1 v1.5 encryption.
- Returns 256 bytes of encrypted key data.

### `unwrap_session_key(wrapped_key: bytes, recipient_privkey: RSAPrivateKey) -> bytes` (Lines 132–155)
- Uses recipient's private key with identical OAEP parameters to decrypt the session key.
- Throws `ValueError` if the key is tampered with or decrypted with an incorrect private key.

### `sign_payload(data: bytes, sender_privkey: RSAPrivateKey) -> bytes` (Lines 157–176)
- Signs the raw data bytes using **RSA PKCS#1 v1.5** padding with **SHA-256** digest:
  - `sender_privkey.sign(data, padding.PKCS1v15(), hashes.SHA256())`
- Guarantees origin authenticity and non-repudiation.
- Returns 256 bytes of signature data.

### `verify_signature(data: bytes, signature: bytes, sender_pubkey: RSAPublicKey) -> bool` (Lines 178–206)
- Verifies the signature using sender's public key:
  - `sender_pubkey.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())`
- Catches `InvalidSignature` and returns `False` safely without crashing. Returns `True` if valid.

---

## 3. `src/file_vault.py`

This module manages the binary layout of the `.cns` container, HMAC-SHA256 authentication, and secure file wiping.

### Constants (Lines 16–19)
- **`MAGIC_BYTES = b"CNS1"`**: Fixed 4-byte signature prefix.
- **`HMAC_TAG_SIZE = 32`**: 32-byte digest length for SHA-256 (256 bits).

### `generate_hmac(key: bytes, ciphertext: bytes) -> bytes` (Lines 22–37)
- Computes $HMAC(K, C) = H((K \oplus opad) \parallel H((K \oplus ipad) \parallel C))$ using `hashlib.sha256`.
- Returns the 32-byte binary digest.

### `verify_hmac(key: bytes, ciphertext: bytes, expected_tag: bytes) -> bool` (Lines 39–58)
- Recomputes HMAC over ciphertext.
- Compares actual tag against expected tag using **`hmac.compare_digest(...)`**.
- This constant-time string comparison protects against side-channel **timing attacks**.

### `pack_cns_file(...) -> bytes` (Lines 60–132)
- Formats and packs container fields using Python's `struct` module:
  - `header_prefix = struct.pack(">4sBB", MAGIC_BYTES, cipher_type, len(iv))`
  - Big-endian lengths for wrapped key (`>H`) and signature (`>H`).
  - Concatenates header, IV, wrapped key, 32-byte HMAC tag, signature, and ciphertext.

### `unpack_cns_file(raw_bytes: bytes) -> Dict[str, Any]` (Lines 134–204)
- Parses the container byte-by-byte:
  - Validates minimum header size.
  - Checks `magic == b"CNS1"`.
  - Reads IV according to `iv_len`.
  - Reads wrapped key according to `wrapped_key_len`.
  - Reads fixed 32-byte HMAC tag.
  - Reads signature according to `sig_len`.
  - Remaining bytes are assigned as `ciphertext`.
- Returns a structured dictionary containing all 6 components.

### `shred_file(filepath: str, passes: int = 3) -> None` (Lines 206–252)
- Multi-pass sanitization:
  - Reads file size.
  - Executes `passes` overwrites with random bytes (`os.urandom(chunk_size)`).
  - Executes 1 final overwrite pass with all zero bytes (`b"\x00"`).
  - Calls `f.flush()` and `os.fsync(f.fileno())` after each pass to force disk write.
  - Closes file and unlinks it with `os.remove(filepath)`.
  - Catches `PermissionError` on Windows (e.g. read-only files), adjusts permissions with `os.chmod`, and retries deletion.

---

## 4. `src/security_analyzer.py`

Inspects post-decryption payloads for malicious executable signatures and Trojan horse disguises (Module 3 curriculum compliance).

### Magic Byte Identification (Lines 53–76)
- **Windows PE Executable**: `data.startswith(b"MZ")` (DOS / PE header).
- **Linux ELF Executable**: `data.startswith(b"\x7fELF")`.
- **Shell Script**: `data.startswith(b"#!/bin/") or data.startswith(b"#!/usr/")`.
- **ZIP Archive**: `data.startswith(b"PK\x03\x04")`.
- **PDF Document**: `data.startswith(b"%PDF")`.
- **JPEG Image**: `data.startswith(b"\xff\xd8\xff")`.
- **PNG Image**: `data.startswith(b"\x89PNG\r\n\x1a\n")`.

### Safe Text Detection (Lines 77–92)
- Slices sample of up to 1024 bytes.
- Trims trailing split UTF-8 bytes to prevent slice-boundary decoding errors.
- Checks `b"\x00" not in sample` to distinguish text from binary null-byte streams.

### Threat Detection Rules (Lines 94–122)
- **Scenario A (Trojan Horse / Disguised Executable)**:
  - If magic matches `MZ`, `ELF`, or Shell Script, but declared extension is benign (`.txt`, `.pdf`, `.jpg`, `.png`, etc.), marks **`threat_level = "CRITICAL DANGEROUS"`**.
- **Scenario B (Raw Executable)**:
  - If magic is an executable without disguise, marks **`threat_level = "HIGH"`**.
- **Scenario C (Archive Misdirection)**:
  - If file has ZIP header but is named `.txt` or `.pdf`, marks **`threat_level = "HIGH"`**.
- **Scenario D (Valid Document)**:
  - Extension matches magic bytes; marks **`threat_level = "SAFE"`**.

---

## 5. `src/main.py`

Command-Line Interface (CLI) entry point providing `keygen`, `encrypt`, and `decrypt` subcommands.

### Subcommand: `handle_keygen(args)` (Lines 42–70)
- Generates 2048-bit RSA keypair.
- Serializes keys to `<prefix>_private.pem` and `<prefix>_public.pem`.
- Supports optional passphrase protection for the private key.

### Subcommand: `handle_encrypt(args)` (Lines 72–167)
- Reads plaintext file.
- Generates 256-bit AES key (or 192-bit TripleDES key) and random IV.
- Encrypts plaintext via `encrypt_symmetric`.
- Signs plaintext via `sign_payload`.
- Computes HMAC tag over ciphertext via `generate_hmac`.
- Wraps session key with recipient's public key via `wrap_session_key`.
- Serializes container via `pack_cns_file` and writes to disk.
- If `--shred` is set, securely overwrites and deletes the input file.

### Subcommand: `handle_decrypt(args)` (Lines 169–262)
- Unpacks `.cns` container via `unpack_cns_file`.
- Unwraps session key via `unwrap_session_key`.
- Verifies HMAC tag via `verify_hmac`. **Halts if mismatch detected.**
- Decrypts ciphertext via `decrypt_symmetric`.
- Verifies sender signature via `verify_signature`. **Halts if signature invalid.**
- Writes verified plaintext to disk.
- Runs `inspect_payload_safety(...)` and prints security status.

---

## 6. `app.py`

Interactive Streamlit Web Dashboard:
- **Sidebar**: Symmetric cipher selector (AES-256 vs DES), RSA keypair generator, PEM file download/upload widgets.
- **Tab 1 (Encrypt & Package)**: File uploader, full cryptographic step breakdown (Hex previews of session key, IV, ciphertext, signature, HMAC, wrapped key), `.cns` download button.
- **Tab 2 (Decrypt & Authenticate)**: Live security checklist with green/red status badges for Magic bytes, RSA-OAEP unwrap, HMAC integrity, symmetric unpadding, and signature verification.
- **Tab 3 (Attack Simulation Lab)**:
  - *Subsection A*: Inverts 1 bit in ciphertext; demonstrates early HMAC halt preventing padding oracle attacks.
  - *Subsection B*: Eve encrypts and signs with her key; demonstrates authenticity failure on Bob's end.
  - *Subsection C*: Tests disguised Windows executable (`MZ`) named `report.pdf`; triggers Trojan alarm.

---

## 7. `demo_suite.py`

Automated, color-coded interactive presentation suite:
- **Scenario 1 (The CIA Baseline)**: Executes complete happy path; asserts 100% cryptographic equivalence.
- **Scenario 2 (Active Adversary Bit-Flip)**: Flips 8 bits at ciphertext byte 12; demonstrates HMAC rejection before decryption.
- **Scenario 3 (Impostor Sender Attack)**: Eve attempts identity spoofing; digital signature check rejects the transaction.
- **Scenario 4 (Disguised Trojan Attack)**: Flags embedded Windows PE executable disguised as `.pdf`.

---

## 8. `scripts/verify_openssl.py`

Cross-verification engine testing interoperability with OpenSSL CLI:
- **`verify_aes_cbc`**: Encrypts test vector with FEVS AES-256-CBC, calls `openssl enc -d -aes-256-cbc -K ... -iv ...`, and confirms identical plaintext output.
- **`verify_hmac_sha256`**: Computes HMAC with FEVS, calls `openssl dgst -sha256 -mac HMAC -macopt hexkey:...`, and confirms bit-for-bit tag equivalence.
