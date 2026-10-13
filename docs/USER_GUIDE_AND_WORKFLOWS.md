# FEVS User Guide & Practical Workflows

> **Goal**: Step-by-step instructions on how to install, run, test, and demonstrate the File Encryption & Verification System (FEVS) using both the Command-Line Interface (CLI) and the Interactive Web Dashboard.

---

## 1. Installation & Environment Setup

### Prerequisites
- **Python**: Version 3.10 or higher.
- **Git** (recommended for cloning and OpenSSL access on Windows).
- **OpenSSL** (optional, for vector cross-verification).

### Step 1: Clone Repository & Enter Directory
```bash
git clone https://github.com/AtharvaTayade2005/File-Encryption-and-Verification-System.git
cd File-Encryption-and-Verification-System
```

### Step 2: Create and Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```
- **Windows (Command Prompt)**:
  ```cmd
  python -m venv .venv
  .\.venv\Scripts\activate.bat
  ```
- **Linux / macOS**:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```
This installs:
- `cryptography>=42.0.0`
- `pytest>=8.0.0`
- `streamlit>=1.30.0`

---

## 2. Command-Line Interface (CLI) Workflows

The main CLI entry point is [`src/main.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/main.py).

```bash
python src/main.py --help
```

---

### Workflow A: Key Generation (`keygen`)

Generate RSA-2048 keypairs for two communicating parties, **Alice (Sender)** and **Bob (Recipient)**.

#### 1. Generate Alice's Keypair:
```bash
python src/main.py keygen --out-dir ./keys --prefix alice
```
*Generated files*:
- `./keys/alice_private.pem`: Alice's private key (used to sign files).
- `./keys/alice_public.pem`: Alice's public key (shared with Bob to verify signatures).

#### 2. Generate Bob's Keypair (with passphrase protection):
```bash
python src/main.py keygen --out-dir ./keys --prefix bob --passphrase "BobSecret123!"
```
*Generated files*:
- `./keys/bob_private.pem`: Bob's encrypted private key.
- `./keys/bob_public.pem`: Bob's public key (shared with Alice to wrap session keys).

---

### Workflow B: End-to-End Encryption (`encrypt`)

Alice encrypts a confidential file for Bob.

```bash
# Create a sample document
echo "Strictly confidential PECE04T exam paper content." > exam_paper.txt

# Encrypt using default AES-256-CBC
python src/main.py encrypt \
  --input exam_paper.txt \
  --output exam_paper.cns \
  --recipient-pub ./keys/bob_public.pem \
  --sender-priv ./keys/alice_private.pem
```

#### Advanced Encryption Options:

1. **Using TripleDES instead of AES**:
   ```bash
   python src/main.py encrypt \
     --input exam_paper.txt \
     --output exam_paper.cns \
     --recipient-pub ./keys/bob_public.pem \
     --sender-priv ./keys/alice_private.pem \
     --cipher des
   ```

2. **Securely Shredding the Original Plaintext (`--shred`)**:
   ```bash
   python src/main.py encrypt \
     --input exam_paper.txt \
     --output exam_paper.cns \
     --recipient-pub ./keys/bob_public.pem \
     --sender-priv ./keys/alice_private.pem \
     --shred
   ```
   *Behavior*: Overwrites `exam_paper.txt` with 3 passes of random bytes, 1 pass of zero-fill, forces disk flush via `fsync`, and permanently unlinks the file.

---

### Workflow C: End-to-End Decryption & Verification (`decrypt`)

Bob receives `exam_paper.cns` and executes the verification pipeline.

```bash
python src/main.py decrypt \
  --input exam_paper.cns \
  --output restored_exam_paper.txt \
  --recipient-priv ./keys/bob_private.pem \
  --sender-pub ./keys/alice_public.pem \
  --passphrase "BobSecret123!"
```

*Expected Terminal Output*:
```text
[+] Successfully decrypted and verified 'exam_paper.cns' -> 'restored_exam_paper.txt'
    Restored Size: 52 bytes | Integrity & Authenticity: VALID
    Payload Safety: SAFE (Plain Text (UTF-8 / ASCII))
```

#### Error Defenses in Action:

1. **Tampered File**:
   If an in-transit attacker modifies even 1 bit of the `.cns` container:
   ```text
   Integrity violation: file has been tampered with!
   ```
   *The system terminates immediately without writing any output file.*

2. **Impostor / Signature Forgery**:
   If an untrusted sender forged the file or Alice's signature does not match:
   ```text
   Authenticity violation: signature invalid!
   ```

3. **Wrong Recipient Key**:
   If an unauthorized user attempts decryption using their own private key:
   ```text
   Error: Session key unwrapping failed: ...
   ```

---

## 3. Interactive Web GUI (Streamlit Dashboard)

To launch the web interface:

```bash
streamlit run app.py
```

The browser will open to `http://localhost:8501`.

```
+----------------------------------------------------------------------------------+
|                   FEVS: Interactive Web Dashboard Layout                         |
+----------------------------------------------------------------------------------+
|  SIDEBAR               |  MAIN PANEL                                             |
|  - Symmetric Algorithm |  Tab 1: 🔐 Encrypt & Package File                       |
|    (AES-256 vs DES)    |    - Drag-and-drop file upload                          |
|  - RSA Key Manager     |    - Step-by-step cryptographic decomposition            |
|    - Regenerate Alice  |    - Download resulting .cns container                  |
|    - Regenerate Bob    |                                                         |
|    - Download PEM keys |  Tab 2: 🔓 Decrypt & Authenticate Container             |
|  - Custom PEM Upload   |    - Live cryptographic validation checklist            |
|                        |    - Post-decryption Trojan scanner                     |
|                        |    - Restored file preview & download                   |
+----------------------------------------------------------------------------------+
```

### Demonstration Guide for Professors in Web GUI:

1. **Step 1: Encrypt in Tab 1**:
   - Upload any document or image.
   - Click **"🚀 Encrypt & Build .cns Container"**.
   - Show the professor the **Hex breakdowns**: Session Key, IV, Ciphertext, Digital Signature, HMAC-SHA256 tag, and Wrapped Session Key.
2. **Step 2: Decrypt in Tab 2**:
   - Switch to **Tab 2**.
   - Click **"🔓 Decrypt & Authenticate"**.
   - Point out the **all-green checklist**:
     - Magic Bytes (`b"CNS1"`): Valid
     - RSA-OAEP Key Unwrap: Valid
     - HMAC-SHA256: Match in constant time
     - PKCS#7 Unpadding: Valid
     - RSA Signature: Verified against Alice
     - Post-decryption Payload Safety: Clean

*(To demonstrate adversarial attacks like bit-flip wire corruption, impostor sender forgery, and disguised trojans to your professor, run the automated CLI demonstration suite: `python demo_suite.py`)*

---

## 4. Automated Professor Demonstration Suite (`demo_suite.py`)

Run the automated, color-coded presentation:

```bash
python demo_suite.py
```

This runs 4 back-to-back scenarios:
1. **Scenario 1**: The CIA Baseline (Happy Path)
2. **Scenario 2**: In-flight Bit-Flip Tampering (Integrity Rejection)
3. **Scenario 3**: Man-in-the-Middle Identity Forgery (Authenticity Rejection)
4. **Scenario 4**: Trojan Horse Disguise Attack (Malware Defense)

---

## 5. Automated Unit & Integration Testing (`pytest`)

Execute the complete 97-test suite:

```bash
# Run all tests
pytest

# Verbose output showing each test name
pytest -v

# Run specific functional areas
pytest tests/test_symmetric.py         # AES, DES, PKCS#7 padding
pytest tests/test_asymmetric.py        # RSA, OAEP, Signatures
pytest tests/test_vault.py             # HMAC, Binary packing, Shredding
pytest tests/test_security_analyzer.py # Trojan detection
pytest tests/test_main.py              # CLI commands
pytest tests/test_integration.py       # Full lifecycles & OpenSSL
```

---

## 6. OpenSSL Cross-Verification

Validate that FEVS primitives match official OpenSSL CLI outputs bit-for-bit:

```bash
python scripts/verify_openssl.py
```

*Expected Output*:
```text
======================================================================
 FEVS OpenSSL Cryptographic Vector Cross-Verification Suite
 PECE04T / PECE04P Module 2 Compliance Verification
======================================================================
[+] Found OpenSSL at: C:\Program Files\Git\usr\bin\openssl.exe
    Version: OpenSSL 3.x
[+] Step 1: Validating AES-256-CBC Decryption with OpenSSL...
    [PASS] OpenSSL successfully decrypted FEVS AES-256-CBC ciphertext.
[+] Step 2: Validating HMAC-SHA256 Authentication with OpenSSL...
    [PASS] OpenSSL HMAC-SHA256 output matches FEVS tag bit-for-bit.
======================================================================
[SUCCESS] All cryptographic primitives are 100% compliant with OpenSSL standard vectors!
======================================================================
```
