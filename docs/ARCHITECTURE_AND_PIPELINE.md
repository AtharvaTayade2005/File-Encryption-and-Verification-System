# FEVS Architecture & End-to-End Cryptographic Pipeline Guide

> **Course Alignment**: PECE04T / PECE04P — Computer & Network Security  
> **Module 2**: Cryptographic Techniques | **Module 3**: Malicious Software & Defensive Analysis  
> **Container Specification**: `.cns` (Cryptographic Network Security) Binary Format (`b"CNS1"`)

---

## 1. Executive Summary

The **File Encryption & Verification System (FEVS)** is a production-grade cryptographic toolkit that implements a **hybrid cryptographic architecture**. It resolves the fundamental trade-off between symmetric and asymmetric cryptography:

- **Symmetric Block Ciphers (AES-256 / 3DES)**: Fast, computationally lightweight, capable of encrypting multi-gigabyte files with negligible overhead. However, both parties must share a secret key beforehand.
- **Asymmetric Cryptography (RSA-2048)**: Solves key distribution and provides non-repudiation (digital signatures), but is computationally slow and mathematically restricted to encrypting data smaller than the key modulus minus padding.
- **Hybrid Cryptography**: Combines both. For every file, a fresh, single-use symmetric **Data Encryption Key (DEK)** is generated. The file payload is encrypted with this fast DEK, while the DEK itself is encrypted (wrapped) using the recipient's RSA public key.

FEVS simultaneously satisfies all **four fundamental goals of information security**:

```
+---------------------------------------------------------------------------------+
|  1. CONFIDENTIALITY   -> Payload encrypted via AES-256-CBC / TripleDES          |
|  2. INTEGRITY         -> Encrypt-then-MAC via HMAC-SHA256                       |
|  3. AUTHENTICITY      -> Digital Signatures via RSA PKCS#1 v1.5 + SHA-256       |
|  4. NON-REPUDIATION   -> Sender's private key signature verified by public key  |
+---------------------------------------------------------------------------------+
|  + MALWARE DEFENSE    -> Post-decryption magic byte payload threat analysis     |
+---------------------------------------------------------------------------------+
```

---

## 2. High-Level System Architecture Diagram

```mermaid
flowchart TD
    subgraph PHASE 1: SENDER (Alice) - Encryption & Signing
        InFile[Original File] --> SymEnc[AES-256-CBC or DES-CBC Engine]
        RandKey[Fresh 256-bit Session Key DEK] --> SymEnc
        SymEnc --> CipherPayload[Padded Ciphertext]

        RandKey --> OAEPWrap[RSA-OAEP Key Wrapper]
        BobPub[Bob Public Key PEM] --> OAEPWrap
        OAEPWrap --> WrappedDEK[Wrapped Session Key 256B]

        InFile --> SignEngine[RSA PKCS#1 v1.5 Sign Engine]
        AlicePriv[Alice Private Key PEM] --> SignEngine
        SignEngine --> SigData[Digital Signature 256B]

        CipherPayload --> HMACGen[HMAC-SHA256 Engine]
        RandKey --> HMACGen
        HMACGen --> HMACTag[32-Byte HMAC Tag]
    end

    subgraph PHASE 2: PACKAGING
        CipherPayload --> PackCNS[CNS Binary Pack Engine]
        WrappedDEK --> PackCNS
        SigData --> PackCNS
        HMACTag --> PackCNS
        PackCNS --> CNSVault[Vault Container: filename.cns]
    end

    subgraph PHASE 3: TRANSMISSION / STORAGE
        CNSVault -. In-Flight Network Transmission or Disk Storage .-> RecvVault[Received .cns File]
    end

    subgraph PHASE 4: RECIPIENT (Bob) - Decryption & Verification
        RecvVault --> UnpackCNS[CNS Binary Unpack Engine]
        UnpackCNS --> ExtractFields[Header, IV, Wrapped Key, HMAC, Sig, Ciphertext]

        ExtractFields --> KeyUnwrap[RSA-OAEP Key Unwrapper]
        BobPriv[Bob Private Key PEM] --> KeyUnwrap
        KeyUnwrap --> RecovDEK[Recovered Symmetric Key]

        ExtractFields --> HMACCheck{Constant-Time HMAC Match?}
        RecovDEK --> HMACCheck
        HMACCheck -- NO: Tampered! --> AbortTamper[HALT: Integrity Violation!]

        HMACCheck -- YES: Intact --> SymDec[AES/DES CBC Decrypt & Unpad]
        RecovDEK --> SymDec
        SymDec --> DecryptedData[Decrypted Plaintext]

        DecryptedData --> SigCheck{Sender Signature Valid?}
        AlicePub[Alice Public Key PEM] --> SigCheck
        SigCheck -- NO: Forgery! --> AbortSig[HALT: Authenticity Violation!]

        SigCheck -- YES: Valid --> ThreatScan[Module 3 Threat Inspector]
        ThreatScan --> SafeFile[Verified Clean Restored File]
    end
```

---

## 3. Step-by-Step Encryption & Packaging Pipeline (Sender)

When a sender (Alice) encrypts a file for a recipient (Bob), the system executes a sequence of 8 distinct phases:

### Phase 1: Input Validation & Entity Identity Ingestion
1. The plaintext file is read from disk as a sequence of raw bytes `P`.
2. Bob's RSA-2048 public key is loaded from PEM format (`SubjectPublicKeyInfo`).
3. Alice's RSA-2048 private key is loaded from PEM format (`PKCS#8`), decrypting with passphrase if protected.

### Phase 2: Volatile Session Key (DEK) & IV Generation
1. A fresh, cryptographically secure pseudo-random symmetric key is generated directly in volatile memory using OS entropy (`os.urandom`):
   - **AES-256**: 32 random bytes (256 bits).
   - **DES (TripleDES)**: 24 random bytes (192 bits).
2. A random Initialization Vector (IV) is generated:
   - **AES**: 16 random bytes (128 bits, matching AES block size).
   - **DES**: 8 random bytes (64 bits, matching DES block size).

### Phase 3: PKCS#7 Padding & Symmetric CBC Encryption
1. The raw plaintext `P` is padded according to RFC 5652 PKCS#7 standards:
   - $PadLength = BlockSize - (len(P) \pmod{BlockSize})$
   - If payload length is already an exact multiple of the block size, a full block of padding is appended to avoid ambiguity upon removal.
2. The padded byte sequence is encrypted using **CBC (Cipher Block Chaining)** mode:
   - $C_0 = E_K(P_0 \oplus IV)$
   - $C_i = E_K(P_i \oplus C_{i-1})$
3. Output: Raw ciphertext bytes `C`.

### Phase 4: Sender Digital Signature Generation (Non-Repudiation)
1. Alice signs the original plaintext `P` using her RSA-2048 private key.
2. The signature algorithm uses **RSA PKCS#1 v1.5 with SHA-256 digest**:
   - $Digest = SHA256(P)$
   - $Signature = (EM)^d \pmod n$
3. Output: Exactly 256 bytes of digital signature data.

### Phase 5: Encrypt-then-MAC Authentication Tag Generation (Integrity)
1. Using the symmetric session key `DEK`, the system computes an HMAC-SHA256 authentication tag across the ciphertext `C`:
   - $Tag = HMAC_{SHA256}(DEK, C)$
2. Output: Exactly 32 bytes (256 bits) of authentication digest.
3. *Security Note*: FEVS follows the provably secure **Encrypt-then-MAC** paradigm. Computing HMAC over ciphertext ensures any modification in transit is detected before decryption is attempted.

### Phase 6: Asymmetric Session Key Wrapping (Key Encapsulation)
1. The symmetric session key `DEK` is encrypted using Bob's RSA-2048 public key.
2. Padding scheme used: **RSA-OAEP (Optimal Asymmetric Encryption Padding)** with:
   - Mask Generation Function: `MGF1(algorithm=hashes.SHA256())`
   - Hash digest: `SHA-256`
   - Label: `None`
3. Output: Exactly 256 bytes of wrapped key ciphertext.

### Phase 7: Binary Container Assembly (`.cns` Packaging)
1. All components are serialized into a single binary stream using big-endian byte order:
   - `Magic Bytes`: 4 bytes (`b"CNS1"`)
   - `Cipher Type`: 1 byte (`0x01` for AES, `0x02` for DES)
   - `IV Length`: 1 byte (16 or 8)
   - `IV Bytes`: 16 or 8 bytes
   - `Wrapped Key Length`: 2 bytes (`uint16` = 256)
   - `Wrapped Key Bytes`: 256 bytes
   - `HMAC Tag`: 32 bytes
   - `Signature Length`: 2 bytes (`uint16` = 256)
   - `Signature Bytes`: 256 bytes
   - `Ciphertext`: Variable length (remaining bytes)
2. The packed container is written to `<filename>.cns`.

### Phase 8: Secure File Sanitization (`--shred`) [Optional]
1. If the `--shred` flag is passed, the original plaintext file is overwritten with:
   - 3 passes of cryptographically secure random bytes (`os.urandom`).
   - 1 final pass of all zero bytes (`0x00`).
2. After each pass, file buffers are flushed and forced to physical disk via `os.fsync`.
3. The original file is then unlinked from the filesystem (`os.remove`).

---

## 4. Step-by-Step Decryption & Verification Pipeline (Recipient)

When the recipient (Bob) receives a `.cns` container, the pipeline executes in strict defensive order:

```
[Received .cns] 
      │
      ▼
1. Unpack & Verify Magic Bytes (`b"CNS1"`)
      │ (Fails? -> Abort with Invalid Magic)
      ▼
2. Unwrap Session Key with Bob's Private Key (RSA-OAEP)
      │ (Fails? -> Abort: Unauthorized Recipient)
      ▼
3. Constant-Time HMAC-SHA256 Verification
      │ (Fails? -> HALT IMMEDIATELY! Zero decryption performed)
      ▼
4. Symmetric CBC Decryption & PKCS#7 Unpadding
      │ (Fails? -> Abort: Corrupt Ciphertext)
      ▼
5. Sender RSA Digital Signature Verification (Alice's Public Key)
      │ (Fails? -> Abort: Sender Identity Mismatch / Forgery)
      ▼
6. Post-Decryption Threat & Trojan Inspection (Module 3)
      │ (Detects disguised executables, shell scripts, or archive misdirection)
      ▼
[Restored Verified Plaintext File]
```

### Detailed Execution Stages:

1. **Unpacking & Header Validation**:
   - Reads `.cns` container.
   - Extracts the 4-byte magic header and validates that it equals `b"CNS1"`.
   - Parses field lengths and slices all constituent cryptographic blocks.

2. **Session Key Unwrapping**:
   - Bob uses his RSA-2048 private key to decrypt the 256-byte wrapped key using RSA-OAEP.
   - Only the legitimate recipient possessing the matching private key can recover the symmetric `DEK`.

3. **Integrity Enforcement (HMAC-SHA256)**:
   - The system computes $ActualHMAC = HMAC_{SHA256}(DEK, Ciphertext)$.
   - Compares $ActualHMAC$ with the container's stored tag using constant-time comparison `hmac.compare_digest`.
   - **DEFENSE RULE**: If the tags do not match, execution halts instantly. Decryption is never invoked, completely eliminating **Padding Oracle Attacks**.

4. **Payload Decryption & PKCS#7 Removal**:
   - The ciphertext is decrypted using the recovered `DEK`, the extracted `IV`, and the cipher algorithm (AES-256 or TripleDES).
   - The PKCS#7 unpadder validates the trailing padding bytes and strips them, restoring original plaintext bytes.

5. **Authenticity & Non-Repudiation Check**:
   - Sender's public key (Alice) is used to verify the digital signature over the decrypted plaintext.
   - If Alice denies sending the file or an impostor (Eve) substituted the message, verification fails.

6. **Post-Decryption Threat Analysis (Module 3)**:
   - Magic byte analyzer checks the restored byte stream against the declared filename extension.
   - If an attacker disguised a Windows PE (`MZ`), Linux ELF, or Shell script as a `.pdf` or `.txt`, the threat scanner flags a **CRITICAL DANGEROUS** alert.

---

## 5. Summary Table: Cryptographic Primitives & Specifications

| Component | Primitive / Algorithm | Standard / Parameters | Purpose |
| :--- | :--- | :--- | :--- |
| **Symmetric Bulk Encryption** | AES-256-CBC | 256-bit key, 128-bit block, PKCS#7 | High-throughput confidentiality |
| **Legacy Symmetric Cipher** | TripleDES-CBC | 192-bit key, 64-bit block, PKCS#7 | Backward compatibility & benchmarking |
| **Asymmetric Key Exchange** | RSA-OAEP | 2048-bit RSA, MGF1(SHA-256), SHA-256 | Secure session key encapsulation |
| **Origin Authenticity** | RSA PKCS#1 v1.5 | 2048-bit RSA, SHA-256 digest | Digital signatures & non-repudiation |
| **Message Integrity** | HMAC-SHA256 | 256-bit digest, Encrypt-then-MAC | Tamper detection & oracle neutralization |
| **Entropy Generation** | CSPRNG | Python `os.urandom` (OS entropy pool) | Nonce and key unpredictability |
| **Secure Erasure** | Multi-Pass Shredder | 3 random passes + 1 zero-fill + fsync | Anti-forensic data sanitization |
| **Malware Inspection** | Magic Byte Scanner | PE (MZ), ELF, Script, ZIP, PDF signatures | Post-decryption Trojan detection |
