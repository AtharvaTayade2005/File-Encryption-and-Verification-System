# FEVS Attack Defense & Cryptographic Security Model

> **Course Alignment**: PECE04T / PECE04P — Computer & Network Security  
> **Module 2**: Cryptographic Techniques | **Module 3**: Malicious Software & Defensive Analysis

---

## 1. Threat Model & Adversary Capabilities

In the design of FEVS, we assume a standard Dolev-Yao network adversary model combined with host-level threat analysis:

```
[Sender: Alice] ───( Insecure Channel / Storage Medium )───> [Recipient: Bob]
                               ▲
                               │ Intercepts, modifies, drops, injects
                     [Adversary: Mallory / Eve]
```

| Threat Vector | Adversary Objective | Potential Attack Type | FEVS Defensive Countermeasure |
| :--- | :--- | :--- | :--- |
| **Passive Wire Eavesdropping** | Read confidential contents in transit | Plaintext sniffing | AES-256-CBC / TripleDES with random IV and RSA-OAEP key wrapping |
| **Active Ciphertext Tampering** | Manipulate data or trigger padding errors | Bit-flipping / Padding Oracle | Encrypt-then-MAC (HMAC-SHA256) evaluated before invoking decryption |
| **Side-Channel Timing Attacks** | Recover MAC bytes via timing variations | Timing measurement | Constant-time tag comparison via `hmac.compare_digest` |
| **Sender Identity Spoofing** | Frame legitimate user or forge orders | Man-in-the-Middle / Impostor | RSA PKCS#1 v1.5 digital signatures over original plaintext |
| **Chosen-Ciphertext Key Attack** | Exploit RSA mathematical structure | Bleichenbacher attack | RSA-OAEP with MGF1(SHA-256) for session key wrapping |
| **Post-Deletion Data Recovery** | Recover sensitive plaintext from disk | Unallocated cluster carving | Multi-pass CSPRNG overwrite + zero-fill + `os.fsync` (`shred_file`) |
| **Trojan Horse Disguise** | Execute malware disguised as benign document | File extension misdirection | Post-decryption magic byte inspector (`inspect_payload_safety`) |

---

## 2. In-Depth Cryptographic Design Rationale

### A. Why Encrypt-then-MAC (and Not MAC-then-Encrypt)?

Historical protocols (such as SSL 3.0 and early TLS) employed **MAC-then-Encrypt**:
$$\text{Payload} = \text{Encrypt}(P \parallel MAC(P))$$

In 2002, Serge Vaudenay published the **Padding Oracle Attack**. When a recipient receives a tampered ciphertext:
1. The recipient decrypts the ciphertext.
2. The recipient checks PKCS#7 padding.
3. If padding is invalid, an error is returned before checking the MAC.
4. By sending crafted ciphertexts and observing whether a padding error occurred, the attacker can decrypt the entire message without knowing the key!

#### FEVS Solution: Encrypt-then-MAC
$$\text{Ciphertext } C = \text{Encrypt}(P)$$
$$\text{Tag } T = HMAC(K, C)$$

In FEVS, the HMAC tag is calculated over the *ciphertext*:
1. Upon receipt, Bob unwraps the session key.
2. Bob verifies $T = HMAC(K, C)$.
3. If $T$ does not match, **execution halts immediately**.
4. The AES decryptor and PKCS#7 unpadder are **never invoked**.
5. Zero side-channel signals or padding exceptions are ever leaked to an adversary.

---

### B. Why Constant-Time HMAC Verification (`hmac.compare_digest`)?

Standard string equality comparison (`a == b`) in most programming languages short-circuits:
```python
# INSECURE NAIVE COMPARISON:
def naive_compare(a, b):
    if len(a) != len(b): return False
    for i in range(len(a)):
        if a[i] != b[i]:   # Exits immediately on first mismatched byte!
            return False
    return True
```

An attacker can measure the execution time of verification:
- If byte 0 matches, verification takes 1 CPU cycle longer.
- If bytes 0 and 1 match, verification takes 2 CPU cycles longer.
- By repeatedly guessing each byte and measuring response latency, an attacker can forge an HMAC tag byte-by-byte.

#### FEVS Solution:
FEVS strictly uses `hmac.compare_digest(actual_tag, expected_tag)`. This executes in fixed time independent of where differences occur, eliminating timing side-channels.

---

### C. Why RSA-OAEP for Key Wrapping?

Traditional RSA PKCS#1 v1.5 encryption wraps data as:
$$EM = 0x00 \parallel 0x02 \parallel PS \parallel 0x00 \parallel M$$

In 1998, Daniel Bleichenbacher demonstrated that if a server reveals whether a decrypted ciphertext begins with `0x00 0x02`, an attacker can decrypt any RSA ciphertext using approximately 1 million queries (Million-Message Attack).

#### FEVS Solution:
FEVS uses **RSA-OAEP (Optimal Asymmetric Encryption Padding)** with MGF1-SHA256:
- OAEP is an all-or-nothing two-round Feistel transform.
- It is provably secure in the Random Oracle Model against **Adaptive Chosen Ciphertext Attacks (IND-CCA2)**.

---

### D. Why Random IV in CBC Mode?

In Cipher Block Chaining (CBC):
$$C_0 = E_K(P_0 \oplus IV)$$

If an implementation uses a static or predictable IV (such as all zeros, a counter, or timestamp):
- An attacker can determine whether the first block of two files is identical.
- In 2011, this vulnerability was exploited in the **BEAST attack** (Browser Exploit Against SSL/TLS).

#### FEVS Solution:
FEVS generates a fresh, cryptographically secure 16-byte random IV (`os.urandom(16)`) for every encryption operation.

---

### E. Why Multi-Pass Cryptographic Shredding (`shred_file`)?

Standard file deletion (`rm` or `os.remove`) merely removes the directory entry and pointer in the filesystem FAT/MFT/inode table. The raw data blocks remain intact on the physical storage medium until overwritten. Forensic recovery tools can easily carve the original file.

#### FEVS Solution:
1. **Passes 1–3**: Overwrites the physical file bytes with random data from `os.urandom(chunk_size)`.
2. **Pass 4**: Overwrites all file bytes with zeroes (`b"\x00"`).
3. **Hardware Flushing**: Calls `f.flush()` followed by `os.fsync(f.fileno())` after each pass to force the operating system and storage controller to flush volatile disk write caches to physical platters/cells.
4. **Unlink**: Removes the file node only after physical overwriting completes.

---

### F. Post-Decryption Threat Analysis (Module 3 Compliance)

Even when all cryptographic checks pass, cryptography alone cannot guarantee that the *contents* of a file are benign.

#### Attack Scenario: The Disguised Trojan Horse
An attacker with legitimate credentials signs and encrypts a file named `quarterly_budget.pdf`. However, the contents are actually a compiled Windows executable binary (`malware.exe`) or a shell script. When an unsuspecting user decrypts the file and double-clicks it, malicious code executes.

#### FEVS Solution:
FEVS includes [`src/security_analyzer.py`](file:///d:/Coding/GitHub/File-Encryption-and-Verification-System/src/security_analyzer.py):
1. Analyzes the file's **magic bytes**:
   - `b"MZ"` -> Windows PE Executable
   - `b"\x7fELF"` -> Linux ELF Binary
   - `b"#!/bin/"` -> Shell Script
   - `b"PK\x03\x04"` -> ZIP Container
2. Compares identified magic bytes against the declared file extension.
3. If an executable is hidden behind a benign extension (`.pdf`, `.txt`, `.jpg`), a **`CRITICAL DANGEROUS`** warning is raised, advising the user not to open or execute the file.
