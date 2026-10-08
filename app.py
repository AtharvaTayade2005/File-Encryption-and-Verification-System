"""
File Encryption & Verification System (FEVS) - Interactive Web GUI.
Compliant with PECE04T / PECE04P Module 2 (Computer & Network Security).

Built with Streamlit to demonstrate step-by-step cryptographic operations,
hybrid encryption, digital signatures, and security defenses.
"""

import os
import sys
import streamlit as st

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.crypto_symmetric import (
    CIPHER_AES,
    CIPHER_DES,
    AES_BLOCK_SIZE_BITS,
    DES_BLOCK_SIZE_BITS,
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
    MAGIC_BYTES,
    HMAC_TAG_SIZE,
    generate_hmac,
    verify_hmac,
    pack_cns_file,
    unpack_cns_file,
)

# --- Page Configuration ---
st.set_page_config(
    page_title="FEVS — File Encryption & Verification System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom Styling ---
st.markdown("""
<style>
    .reportview-container {
        font-family: 'Inter', sans-serif;
    }
    .main-header {
        font-size: 2.1rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .step-box {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #3B82F6;
        padding: 1rem 1.25rem;
        border-radius: 0.375rem;
        margin-bottom: 1rem;
    }
    .step-title {
        font-weight: 600;
        color: #1E293B;
        font-size: 1.05rem;
        margin-bottom: 0.35rem;
    }
    .badge-pass {
        display: inline-block;
        background-color: #DCFCE7;
        color: #15803D;
        font-weight: 600;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        border: 1px solid #86EFAC;
    }
    .badge-fail {
        display: inline-block;
        background-color: #FEE2E2;
        color: #B91C1C;
        font-weight: 600;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        border: 1px solid #FCA5A5;
    }
    .hex-box {
        font-family: 'Courier New', Courier, monospace;
        background-color: #0F172A;
        color: #38BDF8;
        padding: 0.75rem 1rem;
        border-radius: 0.375rem;
        font-size: 0.85rem;
        word-break: break-all;
        max-height: 140px;
        overflow-y: auto;
    }
</style>
""", unsafe_allow_html=True)


# --- Session State Initialization for Keys ---
def init_default_keys():
    if "sender_priv_pem" not in st.session_state:
        # Generate Alice (Sender)
        alice_priv, alice_pub = generate_rsa_keypair(2048)
        st.session_state.sender_priv_pem = export_key_to_pem(alice_priv, is_private=True)
        st.session_state.sender_pub_pem = export_key_to_pem(alice_pub, is_private=False)

    if "recip_priv_pem" not in st.session_state:
        # Generate Bob (Recipient)
        bob_priv, bob_pub = generate_rsa_keypair(2048)
        st.session_state.recip_priv_pem = export_key_to_pem(bob_priv, is_private=True)
        st.session_state.recip_pub_pem = export_key_to_pem(bob_pub, is_private=False)

init_default_keys()


# --- SIDEBAR ---
with st.sidebar:
    st.markdown("### 🎓 PECE04T / PECE04P")
    st.markdown("**Computer & Network Security**")
    st.markdown("`Module 2: Cryptographic Techniques`")
    st.divider()

    st.markdown("### ⚙️ Symmetric Algorithm")
    cipher_choice = st.radio(
        "Select Cipher Mode",
        options=["AES-256-CBC (Default)", "DES-CBC (TripleDES)"],
        index=0,
        help="AES-256 uses 128-bit block size and 256-bit key. DES uses 64-bit block size and 192-bit TripleDES key."
    )
    cipher_type = CIPHER_AES if "AES" in cipher_choice else CIPHER_DES
    cipher_name = "AES-256-CBC" if cipher_type == CIPHER_AES else "DES-CBC"

    st.divider()
    st.markdown("### 🔑 RSA-2048 Key Manager")
    
    col_k1, col_k2 = st.columns(2)
    with col_k1:
        if st.button("🔄 Regen Sender", help="Generate fresh keypair for Sender (Alice)"):
            priv, pub = generate_rsa_keypair(2048)
            st.session_state.sender_priv_pem = export_key_to_pem(priv, is_private=True)
            st.session_state.sender_pub_pem = export_key_to_pem(pub, is_private=False)
            st.success("Sender keys regenerated!")
            st.rerun()

    with col_k2:
        if st.button("🔄 Regen Recipient", help="Generate fresh keypair for Recipient (Bob)"):
            priv, pub = generate_rsa_keypair(2048)
            st.session_state.recip_priv_pem = export_key_to_pem(priv, is_private=True)
            st.session_state.recip_pub_pem = export_key_to_pem(pub, is_private=False)
            st.success("Recipient keys regenerated!")
            st.rerun()

    with st.expander("👤 Sender Keypair (Alice)"):
        st.caption("Public Key (used by Recipient to verify signatures):")
        st.code(st.session_state.sender_pub_pem.decode("utf-8")[:160] + "\n...[TRUNCATED]...", language="text")
        st.caption("Private Key (used by Sender to create signatures):")
        st.code(st.session_state.sender_priv_pem.decode("utf-8")[:160] + "\n...[TRUNCATED]...", language="text")
        st.download_button("💾 Download Alice Public Key", st.session_state.sender_pub_pem, "alice_public.pem")

    with st.expander("🎯 Recipient Keypair (Bob)"):
        st.caption("Public Key (used by Sender to wrap session key):")
        st.code(st.session_state.recip_pub_pem.decode("utf-8")[:160] + "\n...[TRUNCATED]...", language="text")
        st.caption("Private Key (used by Recipient to unwrap session key):")
        st.code(st.session_state.recip_priv_pem.decode("utf-8")[:160] + "\n...[TRUNCATED]...", language="text")
        st.download_button("💾 Download Bob Private Key", st.session_state.recip_priv_pem, "bob_private.pem")

    st.divider()
    st.markdown("### 📂 Upload Custom PEM Keys")
    uploaded_sender_pub = st.file_uploader("Upload Sender Public Key (.pem)", type=["pem"], key="up_s_pub")
    if uploaded_sender_pub:
        st.session_state.sender_pub_pem = uploaded_sender_pub.read()
    uploaded_recip_priv = st.file_uploader("Upload Recipient Private Key (.pem)", type=["pem"], key="up_r_priv")
    if uploaded_recip_priv:
        st.session_state.recip_priv_pem = uploaded_recip_priv.read()


# --- MAIN HEADER ---
st.markdown('<div class="main-header">🛡️ File Encryption & Verification System (FEVS)</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Interactive Cryptographic Pipeline & Security Evaluation Dashboard</div>', unsafe_allow_html=True)


# --- TABS ---
tab1, tab2, tab3 = st.tabs([
    "🔐 1. Encrypt & Package File",
    "🔓 2. Decrypt & Authenticate Container",
    "🧪 3. Security Defense & Tamper Lab (Evaluator)"
])


# ==============================================================================
# TAB 1: ENCRYPT & PACKAGE FILE
# ==============================================================================
with tab1:
    st.markdown("### Hybrid Encryption Pipeline")
    st.write(
        "Upload any file (text, document, PDF, image) to execute the complete hybrid cryptographic workflow: "
        "Symmetric payload encryption, RSA digital signature, HMAC-SHA256 integrity tag, and RSA-OAEP session key wrapping."
    )

    uploaded_file = st.file_uploader("Select a file to encrypt & package:", type=None, key="encrypt_uploader")

    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        encrypt_btn = st.button("🚀 Encrypt & Build .cns Container", type="primary", use_container_width=True)

    if uploaded_file is not None and encrypt_btn:
        plaintext = uploaded_file.read()
        file_name = uploaded_file.name
        file_size = len(plaintext)

        with st.spinner("Executing cryptographic pipeline..."):
            # Load keys
            sender_priv = load_key_from_pem(st.session_state.sender_priv_pem, is_private=True)
            recip_pub = load_key_from_pem(st.session_state.recip_pub_pem, is_private=False)

            # Step 1: Session Key & IV
            if cipher_type == CIPHER_AES:
                session_key = os.urandom(32)  # 256 bits
            else:
                session_key = os.urandom(24)  # 192 bits 3DES
            
            iv, ciphertext = encrypt_symmetric(plaintext, session_key, cipher_type)

            # Step 2: Digital Signature over Plaintext
            signature = sign_payload(plaintext, sender_priv)

            # Step 3: HMAC-SHA256 over Ciphertext
            hmac_tag = generate_hmac(session_key, ciphertext)

            # Step 4: Wrap Session Key via RSA-OAEP
            wrapped_key = wrap_session_key(session_key, recip_pub)

            # Step 5: Pack .cns binary container
            cns_container = pack_cns_file(
                cipher_type=cipher_type,
                iv=iv,
                wrapped_key=wrapped_key,
                hmac_tag=hmac_tag,
                signature=signature,
                ciphertext=ciphertext,
            )

            # Store in session state for tabs 2 and 3
            st.session_state["latest_cns"] = cns_container
            st.session_state["latest_filename"] = file_name
            st.session_state["latest_plaintext"] = plaintext

        st.success(f"✅ Container successfully generated for **{file_name}** ({file_size} bytes -> {len(cns_container)} bytes)!")

        st.markdown("#### 🔍 Step-by-Step Cryptographic Breakdown")

        # Step 1 Display
        with st.container():
            st.markdown(f"""
            <div class="step-box">
                <div class="step-title">Step 1: Symmetric Session Key & IV Generation ({cipher_name})</div>
                <div>A cryptographically secure pseudo-random key and initialization vector were generated strictly in volatile memory.</div>
            </div>
            """, unsafe_allow_html=True)
            col_s1_a, col_s1_b = st.columns(2)
            with col_s1_a:
                st.caption(f"Session Key ({len(session_key) * 8} bits):")
                st.markdown(f'<div class="hex-box">{session_key.hex()}</div>', unsafe_allow_html=True)
            with col_s1_b:
                st.caption(f"Initialization Vector (IV) ({len(iv) * 8} bits):")
                st.markdown(f'<div class="hex-box">{iv.hex()}</div>', unsafe_allow_html=True)

        # Step 2 Display
        with st.container():
            st.markdown(f"""
            <div class="step-box">
                <div class="step-title">Step 2: PKCS#7 Padding & CBC Ciphertext Generation</div>
                <div>Plaintext ({file_size} bytes) was padded to block boundary and encrypted using {cipher_name}. Padded Ciphertext: {len(ciphertext)} bytes.</div>
            </div>
            """, unsafe_allow_html=True)
            st.caption("Ciphertext Preview (first 128 bytes):")
            st.markdown(f'<div class="hex-box">{ciphertext[:128].hex()}...</div>', unsafe_allow_html=True)

        # Step 3 Display
        with st.container():
            st.markdown("""
            <div class="step-box">
                <div class="step-title">Step 3: Plaintext RSA Digital Signature (RSA PKCS#1 v1.5 + SHA-256)</div>
                <div>Sender (Alice) signs the plaintext to guarantee origin authenticity and non-repudiation. (256 bytes)</div>
            </div>
            """, unsafe_allow_html=True)
            st.caption("Digital Signature (Hex):")
            st.markdown(f'<div class="hex-box">{signature.hex()}</div>', unsafe_allow_html=True)

        # Step 4 Display
        with st.container():
            st.markdown("""
            <div class="step-box">
                <div class="step-title">Step 4: HMAC-SHA256 Authentication Tag</div>
                <div>Encrypt-then-MAC: Message authentication code computed over the ciphertext using the session key to detect tampering prior to decryption. (32 bytes)</div>
            </div>
            """, unsafe_allow_html=True)
            st.caption("HMAC-SHA256 Tag (256 bits):")
            st.markdown(f'<div class="hex-box">{hmac_tag.hex()}</div>', unsafe_allow_html=True)

        # Step 5 Display
        with st.container():
            st.markdown("""
            <div class="step-box">
                <div class="step-title">Step 5: RSA-OAEP Key Encapsulation (Key Wrapping)</div>
                <div>The symmetric session key was wrapped using Recipient\'s (Bob) RSA-2048 public key with OAEP padding (MGF1-SHA256). (256 bytes)</div>
            </div>
            """, unsafe_allow_html=True)
            st.caption("Wrapped Key (Hex):")
            st.markdown(f'<div class="hex-box">{wrapped_key.hex()}</div>', unsafe_allow_html=True)

        # Step 6 Download
        st.divider()
        out_cns_name = f"{file_name}.cns"
        st.download_button(
            label=f"💾 Download Secure Vault Container ({out_cns_name})",
            data=cns_container,
            file_name=out_cns_name,
            mime="application/octet-stream",
            type="primary"
        )
    elif uploaded_file is None:
        st.info("👆 Please upload a file to begin the encryption demonstration.")


# ==============================================================================
# TAB 2: DECRYPT & AUTHENTICATE CONTAINER
# ==============================================================================
with tab2:
    st.markdown("### Decryption & Cryptographic Verification")
    st.write(
        "Upload a `.cns` vault container to unpack, unwrap the session key, "
        "verify the HMAC-SHA256 tag in constant time, decrypt the payload, and validate the sender's digital signature."
    )

    cns_file = st.file_uploader("Upload .cns container to decrypt:", type=["cns"], key="decrypt_uploader")

    # Convenience button if user encrypted in Tab 1
    if "latest_cns" in st.session_state and cns_file is None:
        if st.button("📋 Load latest container from Tab 1"):
            cns_file = st.session_state["latest_cns"]

    col_dec_btn, _ = st.columns([1, 3])
    with col_dec_btn:
        decrypt_action = st.button("🔓 Decrypt & Authenticate", type="primary", use_container_width=True)

    if (cns_file is not None or "latest_cns" in st.session_state) and decrypt_action:
        # Determine raw bytes
        if hasattr(cns_file, "read"):
            raw_cns = cns_file.read()
            container_name = getattr(cns_file, "name", "vault.cns")
        else:
            raw_cns = st.session_state["latest_cns"]
            container_name = st.session_state.get("latest_filename", "restored_file") + ".cns"

        st.markdown("#### 🛡️ Live Cryptographic Inspection Checklist")

        # 1. Unpack & Magic bytes check
        try:
            container = unpack_cns_file(raw_cns)
            st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>Container Header Magic Bytes Validated (b"CNS1")</b></p>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<p><span class="badge-fail">✖ FAIL</span> <b>Invalid Magic Bytes:</b> {e}</p>', unsafe_allow_html=True)
            st.stop()

        # 2. Key unwrapping
        try:
            recip_priv = load_key_from_pem(st.session_state.recip_priv_pem, is_private=True)
            session_key = unwrap_session_key(container["wrapped_key"], recip_priv)
            st.markdown(f'<p><span class="badge-pass">✔ PASS</span> <b>RSA-OAEP Session Key Unwrapped:</b> <code>{session_key.hex()[:16]}...</code> ({len(session_key) * 8} bits)</p>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<p><span class="badge-fail">✖ FAIL</span> <b>Session Key Unwrapping Failed:</b> {e}</p>', unsafe_allow_html=True)
            st.stop()

        # 3. HMAC Verification
        hmac_valid = verify_hmac(session_key, container["ciphertext"], container["hmac_tag"])
        if hmac_valid:
            st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>HMAC-SHA256 Integrity Check:</b> Authentication tag matched in constant time.</p>', unsafe_allow_html=True)
        else:
            st.markdown('<p><span class="badge-fail">✖ FAIL</span> <b>Integrity Violation:</b> HMAC-SHA256 mismatch! Payload has been altered in transit.</p>', unsafe_allow_html=True)
            st.error("🚨 Decryption aborted to prevent padding oracle or ciphertext manipulation attacks!")
            st.stop()

        # 4. Symmetric Decryption
        try:
            plaintext = decrypt_symmetric(
                container["ciphertext"],
                session_key,
                container["iv"],
                container["cipher_type"]
            )
            c_name = "AES-256-CBC" if container["cipher_type"] == CIPHER_AES else "DES-CBC"
            st.markdown(f'<p><span class="badge-pass">✔ PASS</span> <b>Symmetric Decryption & PKCS#7 Unpadding ({c_name}):</b> Restored {len(plaintext)} plaintext bytes.</p>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<p><span class="badge-fail">✖ FAIL</span> <b>Decryption Failed:</b> {e}</p>', unsafe_allow_html=True)
            st.stop()

        # 5. Digital Signature Verification
        try:
            sender_pub = load_key_from_pem(st.session_state.sender_pub_pem, is_private=False)
            sig_valid = verify_signature(plaintext, container["signature"], sender_pub)
            if sig_valid:
                st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>Sender RSA-2048 Digital Signature:</b> Validated! Identity & non-repudiation confirmed.</p>', unsafe_allow_html=True)
            else:
                st.markdown('<p><span class="badge-fail">✖ FAIL</span> <b>Authenticity Violation:</b> Digital signature is invalid!</p>', unsafe_allow_html=True)
                st.error("🚨 The signature does not correspond to the sender's public key.")
                st.stop()
        except Exception as e:
            st.markdown(f'<p><span class="badge-fail">✖ FAIL</span> <b>Signature Verification Error:</b> {e}</p>', unsafe_allow_html=True)
            st.stop()

        # Success Presentation
        st.divider()
        st.success("🎉 All 4 Cryptographic Guarantees (Confidentiality, Integrity, Authenticity, Non-Repudiation) SATISFIED!")

        # Preview if possible
        try:
            text_preview = plaintext.decode("utf-8")
            st.caption("Plaintext Preview (UTF-8):")
            st.text_area("Decrypted Content", text_preview[:2000], height=150)
        except UnicodeDecodeError:
            st.info("Binary payload restored (non-text format).")

        # Download button
        restored_filename = container_name.replace(".cns", "") if container_name.endswith(".cns") else "restored_payload.bin"
        st.download_button(
            label=f"💾 Download Verified Plaintext ({restored_filename})",
            data=plaintext,
            file_name=restored_filename,
            mime="application/octet-stream",
            type="primary"
        )
    elif cns_file is None and "latest_cns" not in st.session_state:
        st.info("👆 Please upload a .cns file or generate one in Tab 1 to run decryption.")


# ==============================================================================
# TAB 3: SECURITY DEFENSE & TAMPER LAB
# ==============================================================================
with tab3:
    st.markdown("### 🧪 Security Defense & Tamper Lab (Evaluator Demo)")
    st.write(
        "Demonstrates active defensive behavior against ciphertext tampering and active bit-flipping attacks. "
        "Evaluators can simulate an adversary intercepting the `.cns` container and flipping a single bit/byte in transit."
    )

    tamper_cns_file = st.file_uploader("Upload .cns file for tampering test:", type=["cns"], key="tamper_uploader")
    if tamper_cns_file is None and "latest_cns" in st.session_state:
        st.info("💡 Using the latest generated container from Tab 1.")
        raw_tamper_cns = st.session_state["latest_cns"]
    elif tamper_cns_file is not None:
        raw_tamper_cns = tamper_cns_file.read()
    else:
        raw_tamper_cns = None

    if raw_tamper_cns:
        try:
            parsed = unpack_cns_file(raw_tamper_cns)
        except Exception as e:
            st.error(f"Failed to unpack container: {e}")
            st.stop()

        st.markdown("#### 📦 Original Container Inspection")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Cipher Mode", "AES-256-CBC" if parsed["cipher_type"] == CIPHER_AES else "DES-CBC")
        c2.metric("IV Length", f"{len(parsed['iv'])} Bytes")
        c3.metric("Ciphertext Size", f"{len(parsed['ciphertext'])} Bytes")
        c4.metric("HMAC Tag Size", f"{len(parsed['hmac_tag'])} Bytes")

        st.caption("Original HMAC-SHA256 Tag (stored in header):")
        st.markdown(f'<div class="hex-box">{parsed["hmac_tag"].hex()}</div>', unsafe_allow_html=True)

        st.divider()
        st.markdown("#### 💥 Adversary Simulation: Active Bit-Flip Attack")
        st.write(
            "An active attacker flips 1 byte inside the ciphertext on the wire while leaving the original HMAC tag intact in the container header."
        )

        offset = st.slider("Select Byte Offset in Ciphertext to Corrupt:", min_value=0, max_value=max(0, len(parsed["ciphertext"]) - 1), value=0)

        if st.button("🚨 Simulate Adversary Attack & Attempt Decryption", type="primary"):
            # Corrupt exactly 1 byte
            corrupted_ct = bytearray(parsed["ciphertext"])
            orig_val = corrupted_ct[offset]
            corrupted_ct[offset] ^= 0x01  # Flip 1 bit
            new_val = corrupted_ct[offset]

            # Re-pack with original HMAC tag
            corrupted_cns = pack_cns_file(
                cipher_type=parsed["cipher_type"],
                iv=parsed["iv"],
                wrapped_key=parsed["wrapped_key"],
                hmac_tag=parsed["hmac_tag"],  # attacker does not have session key to recompute HMAC!
                signature=parsed["signature"],
                ciphertext=bytes(corrupted_ct),
            )

            st.warning(f"Attacker flipped byte at offset `{offset}`: `0x{orig_val:02x}` ➡️ `0x{new_val:02x}`")

            st.markdown("#### 🛡️ Execution of FEVS Defense Mechanism")

            # 1. Unpack
            st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>Container Structure Unpacked</b></p>', unsafe_allow_html=True)

            # 2. Key unwrap
            recip_priv = load_key_from_pem(st.session_state.recip_priv_pem, is_private=True)
            recovered_key = unwrap_session_key(parsed["wrapped_key"], recip_priv)
            st.markdown(f'<p><span class="badge-pass">✔ PASS</span> <b>Session Key Unwrapped:</b> <code>{recovered_key.hex()[:16]}...</code></p>', unsafe_allow_html=True)

            # 3. HMAC Constant-Time Check
            computed_hmac = generate_hmac(recovered_key, bytes(corrupted_ct))
            is_valid = verify_hmac(recovered_key, bytes(corrupted_ct), parsed["hmac_tag"])

            col_h1, col_h2 = st.columns(2)
            with col_h1:
                st.caption("Expected Tag (Container Header):")
                st.markdown(f'<div class="hex-box">{parsed["hmac_tag"].hex()}</div>', unsafe_allow_html=True)
            with col_h2:
                st.caption("Computed Tag (Tampered Ciphertext):")
                st.markdown(f'<div class="hex-box">{computed_hmac.hex()}</div>', unsafe_allow_html=True)

            if not is_valid:
                st.markdown('<p><span class="badge-fail">✖ DETECTED & HALTED</span> <b>Integrity Violation: HMAC mismatch detected before decryption.</b></p>', unsafe_allow_html=True)
                st.error("🛑 DEFENSE TRIGGERED: Decryption immediately aborted. System refused to invoke AES-CBC decryptor or PKCS#7 unpadder.")
                
                with st.expander("🎓 CNS Evaluation Explanation (Why this matters)", expanded=True):
                    st.markdown("""
                    - **Encrypt-then-MAC Security Guarantee**: Because the HMAC authentication tag is computed over the ciphertext and verified *before* decryption, any tampering in transit is caught immediately.
                    - **Padding Oracle Defense**: If decryption were attempted on manipulated CBC ciphertext, unpadding errors would leak side-channel timing information to an attacker. By rejecting invalid HMACs first, padding oracle attacks are completely neutralized.
                    - **Non-Repudiation Preserved**: The integrity check prevents corrupt payloads from reaching signature verification.
                    """)
    else:
        st.info("👆 Please encrypt a file in Tab 1 or upload a .cns container above to test the Tamper Lab.")
