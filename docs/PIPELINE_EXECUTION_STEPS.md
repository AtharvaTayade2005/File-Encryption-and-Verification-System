# Pipeline Execution Steps: Encrypt & Decrypt

Direct mapping of user interface actions to code execution, source files, functions, and cryptographic operations.

---

## Part 1: Encryption & Packaging Pipeline (Tab 1)

### Execution Flow in `app.py`:

```
User uploads file & clicks "Encrypt & Build .cns Container"
  │
  ├──► 0. Key Loading (src/crypto_asymmetric.py)
  ├──► 1. Session Key & IV Generation (os.urandom)
  ├──► 2. PKCS#7 Padding & Symmetric CBC Encryption (src/crypto_symmetric.py)
  ├──► 3. Sender Digital Signature (src/crypto_asymmetric.py)
  ├──► 4. Encrypt-then-MAC Authentication Tag (src/file_vault.py)
  ├──► 5. RSA-OAEP Key Wrapping (src/crypto_asymmetric.py)
  └──► 6. Pack Binary Container (src/file_vault.py)
```

---

### Step 0: Ingest Keys from PEM
- **File**: [`src/crypto_asymmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_asymmetric.py)
- **Function**: `load_key_from_pem(pem_bytes, password=None, is_private=True)`
- **Code**:
  ```python
  sender_priv = load_key_from_pem(st.session_state.sender_priv_pem, is_private=True)
  recip_pub = load_key_from_pem(st.session_state.recip_pub_pem, is_private=False)
  ```
- **Action**: Deserializes Alice's private key (PKCS#8) and Bob's public key (SubjectPublicKeyInfo).

---

### Step 1: Generate Symmetric Session Key & IV
- **File**: `os` (Python Standard Library CSPRNG)
- **Code**:
  ```python
  if cipher_type == CIPHER_AES:
      session_key = os.urandom(32)  # 256-bit AES key
  else:
      session_key = os.urandom(24)  # 192-bit TripleDES key
  ```
- **Action**: Generates a volatile, single-use Data Encryption Key (DEK) in memory.

---

### Step 2: PKCS#7 Padding & Symmetric CBC Encryption
- **File**: [`src/crypto_symmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_symmetric.py)
- **Functions**: `encrypt_symmetric(plaintext, key, cipher_type)` → `pad_pkcs7(data, block_size)`
- **Code**:
  ```python
  iv, ciphertext = encrypt_symmetric(plaintext, session_key, cipher_type)
  ```
- **Action**:
  1. Pads raw file bytes to block boundary (16 bytes for AES, 8 bytes for DES) using RFC 5652 PKCS#7.
  2. Generates random IV (`os.urandom(block_size)`).
  3. Encrypts padded bytes using AES-256-CBC (or 3DES-CBC).

---

### Step 3: Sender Digital Signature
- **File**: [`src/crypto_asymmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_asymmetric.py)
- **Function**: `sign_payload(data, private_key)`
- **Code**:
  ```python
  signature = sign_payload(plaintext, sender_priv)
  ```
- **Action**: Signs the original plaintext bytes using Alice's RSA-2048 private key with PKCS#1 v1.5 padding and SHA-256 digest (produces 256 bytes).

---

### Step 4: Encrypt-then-MAC Authentication Tag
- **File**: [`src/file_vault.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/file_vault.py)
- **Function**: `generate_hmac(key, data)`
- **Code**:
  ```python
  hmac_tag = generate_hmac(session_key, ciphertext)
  ```
- **Action**: Computes an HMAC-SHA256 authentication tag across the ciphertext using the symmetric session key (produces 32 bytes).

---

### Step 5: RSA-OAEP Session Key Wrapping
- **File**: [`src/crypto_asymmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_asymmetric.py)
- **Function**: `wrap_session_key(session_key, public_key)`
- **Code**:
  ```python
  wrapped_key = wrap_session_key(session_key, recip_pub)
  ```
- **Action**: Encapsulates the symmetric session key using Bob's RSA-2048 public key with OAEP padding (`MGF1(SHA-256)` + `SHA-256`, produces 256 bytes).

---

### Step 6: Binary Container Assembly (`.cns`)
- **File**: [`src/file_vault.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/file_vault.py)
- **Function**: `pack_cns_file(cipher_type, iv, wrapped_key, hmac_tag, signature, ciphertext)`
- **Code**:
  ```python
  cns_container = pack_cns_file(
      cipher_type=cipher_type,
      iv=iv,
      wrapped_key=wrapped_key,
      hmac_tag=hmac_tag,
      signature=signature,
      ciphertext=ciphertext,
  )
  ```
- **Action**: Serializes all fields using network big-endian struct format (`!4sBB`, `!H`):
  - Magic bytes: `b"CNS1"` (4B)
  - Cipher type: `0x01` (AES) or `0x02` (DES) (1B)
  - IV Length + IV bytes (1B + 16B/8B)
  - Wrapped Key Length + Wrapped Key (2B + 256B)
  - HMAC Tag (32B)
  - Signature Length + Signature bytes (2B + 256B)
  - Ciphertext (remaining bytes)

---
---

## Part 2: Decryption & Verification Pipeline (Tab 2)

### Execution Flow in `app.py`:

```
User uploads .cns container & clicks "Decrypt & Authenticate"
  │
  ├──► 1. Unpack & Validate Magic Bytes (src/file_vault.py)
  ├──► 2. RSA-OAEP Key Unwrapping (src/crypto_asymmetric.py)
  ├──► 3. Constant-Time HMAC-SHA256 Check (src/file_vault.py) [HALT IF TAMPERED]
  ├──► 4. Symmetric CBC Decryption & PKCS#7 Unpadding (src/crypto_symmetric.py)
  ├──► 5. Sender Digital Signature Verification (src/crypto_asymmetric.py) [HALT IF FORGED]
  └──► 6. Post-Decryption Threat & Trojan Scanner (src/security_analyzer.py)
```

---

### Step 1: Unpack Binary Container & Validate Magic Bytes
- **File**: [`src/file_vault.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/file_vault.py)
- **Function**: `unpack_cns_file(packed_bytes)`
- **Code**:
  ```python
  container = unpack_cns_file(raw_cns)
  ```
- **Action**: Unpacks the binary layout with struct offsets and validates that `magic == b"CNS1"`. If invalid, aborts immediately.

---

### Step 2: Unwrap Session Key (RSA-OAEP Decryption)
- **File**: [`src/crypto_asymmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_asymmetric.py)
- **Function**: `unwrap_session_key(wrapped_key, private_key)`
- **Code**:
  ```python
  recip_priv = load_key_from_pem(st.session_state.recip_priv_pem, is_private=True)
  session_key = unwrap_session_key(container["wrapped_key"], recip_priv)
  ```
- **Action**: Decrypts the 256-byte wrapped key using Bob's RSA-2048 private key with OAEP padding, recovering the symmetric DEK.

---

### Step 3: Constant-Time HMAC-SHA256 Integrity Check
- **File**: [`src/file_vault.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/file_vault.py)
- **Function**: `verify_hmac(key, data, expected_hmac)`
- **Code**:
  ```python
  hmac_valid = verify_hmac(session_key, container["ciphertext"], container["hmac_tag"])
  if not hmac_valid:
      st.error("🚨 Decryption aborted to prevent padding oracle or ciphertext manipulation attacks!")
      st.stop()
  ```
- **Action**: Recomputes HMAC over ciphertext and performs constant-time comparison via `hmac.compare_digest`. **If invalid, execution stops immediately without invoking cipher decryption.**

---

### Step 4: Symmetric Decryption & PKCS#7 Unpadding
- **File**: [`src/crypto_symmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_symmetric.py)
- **Functions**: `decrypt_symmetric(ciphertext, key, iv, cipher_type)` → `unpad_pkcs7(padded_data, block_size)`
- **Code**:
  ```python
  plaintext = decrypt_symmetric(
      container["ciphertext"],
      session_key,
      container["iv"],
      container["cipher_type"]
  )
  ```
- **Action**: Decrypts ciphertext blocks using AES-256-CBC (or 3DES-CBC), validates PKCS#7 padding bytes, and strips padding to recover original plaintext bytes.

---

### Step 5: Sender RSA Digital Signature Verification
- **File**: [`src/crypto_asymmetric.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/crypto_asymmetric.py)
- **Function**: `verify_signature(data, signature, public_key)`
- **Code**:
  ```python
  sender_pub = load_key_from_pem(st.session_state.sender_pub_pem, is_private=False)
  sig_valid = verify_signature(plaintext, container["signature"], sender_pub)
  if not sig_valid:
      st.error("🚨 The signature does not correspond to the sender's public key.")
      st.stop()
  ```
- **Action**: Verifies signature against recovered plaintext using Alice's RSA public key (PKCS#1 v1.5 + SHA-256). Proves sender identity and non-repudiation.

---

### Step 6: Post-Decryption Threat & Trojan Scanner
- **File**: [`src/security_analyzer.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/security_analyzer.py)
- **Function**: `inspect_payload_safety(data, declared_filename)`
- **Code**:
  ```python
  safety_report = inspect_payload_safety(plaintext, restored_filename)
  ```
- **Action**: Scans magic bytes of the decrypted file (`b"MZ"`, `b"\x7fELF"`, `b"#!/bin/"`, `b"PK\x03\x04"`) against the declared extension to detect disguised executable trojans before offering file download.
