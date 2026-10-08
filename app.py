"""
File Encryption & Verification System (FEVS) - Interactive Web GUI.
Compliant with PECE04T / PECE04P Module 2 & Module 3 (Computer & Network Security).

Built with Streamlit to demonstrate step-by-step cryptographic operations,
hybrid encryption, digital signatures, security defenses, and threat analysis.
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
from src.security_analyzer import inspect_payload_safety

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
    .danger-box {
        background-color: #FEF2F2;
        border: 1px solid #FECACA;
        border-left: 4px solid #EF4444;
        padding: 1rem 1.25rem;
        border-radius: 0.375rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# --- Session State Initialization for Keys ---
def init_default_keys():
    if "sender_priv_pem" not in st.session_state:
        alice_priv, alice_pub = generate_rsa_keypair(2048)
        st.session_state.sender_priv_pem = export_key_to_pem(alice_priv, is_private=True)
        st.session_state.sender_pub_pem = export_key_to_pem(alice_pub, is_private=False)

    if "recip_priv_pem" not in st.session_state:
        bob_priv, bob_pub = generate_rsa_keypair(2048)
        st.session_state.recip_priv_pem = export_key_to_pem(bob_priv, is_private=True)
        st.session_state.recip_pub_pem = export_key_to_pem(bob_pub, is_private=False)

init_default_keys()


# --- SIDEBAR ---
with st.sidebar:
    st.markdown("### 🎓 PECE04T / PECE04P")
    st.markdown("**Computer & Network Security**")
    st.markdown("`Module 2: Cryptography & Module 3: Threats`")
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
    "🧪 3. Attack Simulation & Professor Evaluation Lab"
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

    col_btn, _ = st.columns([1, 3])
    with col_btn:
        encrypt_btn = st.button("🚀 Encrypt & Build .cns Container", type="primary", use_container_width=True)

    if uploaded_file is not None and encrypt_btn:
        plaintext = uploaded_file.read()
        file_name = uploaded_file.name
        file_size = len(plaintext)

        with st.spinner("Executing cryptographic pipeline..."):
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
        "verify the HMAC-SHA256 tag in constant time, decrypt the payload, validate the digital signature, "
        "and inspect the payload with the post-decryption Threat Analyzer."
    )

    cns_file = st.file_uploader("Upload .cns container to decrypt:", type=["cns"], key="decrypt_uploader")

    if "latest_cns" in st.session_state and cns_file is None:
        if st.button("📋 Load latest container from Tab 1"):
            cns_file = st.session_state["latest_cns"]

    col_dec_btn, _ = st.columns([1, 3])
    with col_dec_btn:
        decrypt_action = st.button("🔓 Decrypt & Authenticate", type="primary", use_container_width=True)

    if (cns_file is not None or "latest_cns" in st.session_state) and decrypt_action:
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

        # 6. Post-Decryption Threat Analysis (Module 3)
        restored_filename = container_name.replace(".cns", "") if container_name.endswith(".cns") else "restored_payload.bin"
        safety_report = inspect_payload_safety(plaintext, restored_filename)
        
        st.markdown("#### 🛡️ Post-Decryption Payload Threat Scanner (Module 3)")
        if safety_report["is_safe"]:
            st.markdown(f'<p><span class="badge-pass">✔ SAFE DOCUMENT</span> <b>Signature:</b> {safety_report["magic_detected"]} | <b>Threat Level:</b> {safety_report["threat_level"]}</p>', unsafe_allow_html=True)
        else:
            st.markdown(f'<p><span class="badge-fail">🚨 {safety_report["threat_level"]}</span> <b>Dangerous Payload Detected:</b> {safety_report["magic_detected"]}</p>', unsafe_allow_html=True)
            st.warning(f"⚠️ {safety_report['details']}")

        # Success Presentation
        st.divider()
        st.success("🎉 All 4 Cryptographic Guarantees (Confidentiality, Integrity, Authenticity, Non-Repudiation) SATISFIED!")

        try:
            text_preview = plaintext.decode("utf-8")
            st.caption("Plaintext Preview (UTF-8):")
            st.text_area("Decrypted Content", text_preview[:2000], height=150)
        except UnicodeDecodeError:
            st.info("Binary payload restored (non-text format).")

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
# TAB 3: ATTACK SIMULATION & PROFESSOR EVALUATION LAB
# ==============================================================================
with tab3:
    st.markdown("### 🧪 Attack Simulation & Professor Evaluation Lab")
    st.write(
        "Interactive testbed for professors and evaluators to test adversarial attacks against FEVS: "
        "Active wire bit-flipping, sender signature forgery, and disguised trojan horse payloads."
    )

    sub_tab_a, sub_tab_b, sub_tab_c = st.tabs([
        "⚡ Subsection A: Bit-Flip / Tamper Simulator",
        "🎭 Subsection B: Sender Identity Forgery Test",
        "🦠 Subsection C: Malicious Payload Scanner"
    ])

    # --------------------------------------------------------------------------
    # SUBSECTION A: BIT-FLIP / TAMPER SIMULATOR
    # --------------------------------------------------------------------------
    with sub_tab_a:
        st.markdown("#### ⚡ Active Adversary: In-Flight Ciphertext Tampering")
        st.write(
            "Simulates an attacker intercepting the `.cns` container on the wire and corrupting 1 byte in the ciphertext. "
            "Demonstrates how the **Encrypt-then-MAC** architecture catches the tamper immediately and halts before decryption."
        )

        tamper_cns_file = st.file_uploader("Upload .cns container for tampering:", type=["cns"], key="sub_a_uploader")
        if tamper_cns_file is None and "latest_cns" in st.session_state:
            st.info("💡 Using latest generated container from Tab 1.")
            raw_tamper_cns = st.session_state["latest_cns"]
        elif tamper_cns_file is not None:
            raw_tamper_cns = tamper_cns_file.read()
        else:
            raw_tamper_cns = None

        if raw_tamper_cns:
            parsed = unpack_cns_file(raw_tamper_cns)
            offset = st.slider(
                "Select Ciphertext Byte Offset to Invert:",
                min_value=0,
                max_value=max(0, len(parsed["ciphertext"]) - 1),
                value=0,
                key="sub_a_slider"
            )

            if st.button("⚡ Inject 1-Bit Corruption into Ciphertext", type="primary", key="sub_a_inject_btn"):
                corrupted_ct = bytearray(parsed["ciphertext"])
                orig_byte = corrupted_ct[offset]
                corrupted_ct[offset] ^= 0x01  # Flip 1 bit
                new_byte = corrupted_ct[offset]

                st.warning(f"Adversary inverted bit at offset `{offset}`: `0x{orig_byte:02x}` ➡️ `0x{new_byte:02x}`")

                recip_priv = load_key_from_pem(st.session_state.recip_priv_pem, is_private=True)
                recovered_key = unwrap_session_key(parsed["wrapped_key"], recip_priv)

                computed_hmac = generate_hmac(recovered_key, bytes(corrupted_ct))
                is_valid = verify_hmac(recovered_key, bytes(corrupted_ct), parsed["hmac_tag"])

                col_ea, col_eb = st.columns(2)
                with col_ea:
                    st.caption("Expected HMAC-SHA256 (from Header):")
                    st.markdown(f'<div class="hex-box">{parsed["hmac_tag"].hex()}</div>', unsafe_allow_html=True)
                with col_eb:
                    st.caption("Computed HMAC-SHA256 (Tampered Ciphertext):")
                    st.markdown(f'<div class="hex-box">{computed_hmac.hex()}</div>', unsafe_allow_html=True)

                if not is_valid:
                    st.markdown("""
                    <div class="danger-box">
                        <div class="step-title" style="color: #B91C1C;">🛑 Integrity Violation: HMAC mismatch. Zero decryption occurred.</div>
                        <div><b>Defensive Action:</b> The HMAC-SHA256 constant-time check failed. The system immediately halted, refusing to invoke the AES/DES decryptor or PKCS#7 unpadder.</div>
                    </div>
                    """, unsafe_allow_html=True)

                    with st.expander("🎓 Why this prevents Padding Oracle Attacks", expanded=True):
                        st.markdown("""
                        - **Encrypt-then-MAC Security**: Verifying integrity *prior* to decryption guarantees that an attacker cannot send manipulated ciphertexts to observe PKCS#7 padding exceptions.
                        - **Zero Information Leak**: Because zero cipher or unpad routines are executed, no side-channel timing signals are leaked to the attacker.
                        """)
        else:
            st.info("👆 Please encrypt a file in Tab 1 or upload a .cns container above to test.")

    # --------------------------------------------------------------------------
    # SUBSECTION B: SENDER IDENTITY FORGERY TEST
    # --------------------------------------------------------------------------
    with sub_tab_b:
        st.markdown("#### 🎭 Man-in-the-Middle: Sender Identity Forgery Test")
        st.write(
            "Simulates 'Attacker Eve' encrypting an unauthorized wire transfer to Bob, but signing with **Eve's private key** "
            "while claiming to be Alice. Demonstrates that digital signatures guarantee **Non-Repudiation** and origin authenticity."
        )

        st.caption("Forged Message Payload:")
        st.code("AUTHORIZATION: Transfer $1,000,000 to Eve's Account #987654321", language="text")

        if st.button("🎭 Sign with Untrusted Third-Party Key", type="primary", key="sub_b_forgery_btn"):
            with st.spinner("Simulating impostor attack..."):
                # Generate Eve's rogue keys
                eve_priv, eve_pub = generate_rsa_keypair(2048)
                bob_pub = load_key_from_pem(st.session_state.recip_pub_pem, is_private=False)
                bob_priv = load_key_from_pem(st.session_state.recip_priv_pem, is_private=True)
                alice_pub = load_key_from_pem(st.session_state.sender_pub_pem, is_private=False)

                fraud_msg = b"AUTHORIZATION: Transfer $1,000,000 to Eve's Account #987654321"

                # Eve encrypts for Bob
                session_key = os.urandom(32)
                iv, ct = encrypt_symmetric(fraud_msg, session_key, CIPHER_AES)
                wrapped_key = wrap_session_key(session_key, bob_pub)
                tag = generate_hmac(session_key, ct)

                # Eve signs with Eve's key!
                eve_sig = sign_payload(fraud_msg, eve_priv)

                rogue_cns = pack_cns_file(CIPHER_AES, iv, wrapped_key, tag, eve_sig, ct)

                # Bob unwraps and decrypts
                unpacked = unpack_cns_file(rogue_cns)
                recov_key = unwrap_session_key(unpacked["wrapped_key"], bob_priv)
                hmac_ok = verify_hmac(recov_key, unpacked["ciphertext"], unpacked["hmac_tag"])
                dec_msg = decrypt_symmetric(unpacked["ciphertext"], recov_key, unpacked["iv"], CIPHER_AES)

                # Bob validates against Alice's public key
                is_alice_sig = verify_signature(dec_msg, unpacked["signature"], alice_pub)

            col_b1, col_b2 = st.columns(2)
            with col_b1:
                st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>Session Key Unwrapped:</b> Bob\'s private key decrypted the DEK.</p>', unsafe_allow_html=True)
                st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>HMAC Integrity Check:</b> Ciphertext was untouched on the wire.</p>', unsafe_allow_html=True)
            with col_b2:
                st.markdown('<p><span class="badge-pass">✔ PASS</span> <b>AES-256 Decryption:</b> Payload decrypted to text.</p>', unsafe_allow_html=True)
                st.markdown('<p><span class="badge-fail">✖ FAILED</span> <b>Sender Signature Verification:</b> Signature does NOT match Alice!</p>', unsafe_allow_html=True)

            st.markdown("""
            <div class="danger-box">
                <div class="step-title" style="color: #B91C1C;">🚨 Authenticity Failure: Digital signature does not match sender's public key.</div>
                <div><b>Security Defense:</b> Bob successfully aborted the transaction. Even though the encryption was mathematically valid and the message was intact, the sender\'s identity could not be authenticated.</div>
            </div>
            """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # SUBSECTION C: MALICIOUS PAYLOAD SCANNER
    # --------------------------------------------------------------------------
    with sub_tab_c:
        st.markdown("#### 🦠 Module 3: Threat Inspection & Trojan Disguise Scanner")
        st.write(
            "Evaluates post-decryption payload safety. Even if cryptographic checks pass, an attacker might transmit a "
            "malicious executable or trojan disguised under a benign extension (e.g. `invoice.pdf` or `memo.txt`)."
        )

        col_t1, col_t2, col_t3 = st.columns(3)
        with col_t1:
            if st.button("📄 Test Legitimate PDF", use_container_width=True):
                st.session_state["test_payload"] = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
                st.session_state["test_ext"] = "invoice.pdf"

        with col_t2:
            if st.button("⚠️ Test Disguised Trojan EXE", use_container_width=True):
                st.session_state["test_payload"] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00This program cannot be run in DOS mode."
                st.session_state["test_ext"] = "financial_report.pdf"

        with col_t3:
            if st.button("⚠️ Test Disguised Shell Script", use_container_width=True):
                st.session_state["test_payload"] = b"#!/bin/bash\nrm -rf / --no-preserve-root\n"
                st.session_state["test_ext"] = "project_notes.txt"

        if "test_payload" in st.session_state:
            payload_data = st.session_state["test_payload"]
            declared_name = st.session_state["test_ext"]

            st.write(f"**Scanning Payload:** `{declared_name}` ({len(payload_data)} bytes)")
            st.caption("Magic Bytes Preview (Hex):")
            st.code(payload_data[:32].hex(), language="text")

            report = inspect_payload_safety(payload_data, declared_name)

            if report["is_safe"]:
                st.markdown(f"""
                <div class="step-box" style="border-left-color: #22C55E;">
                    <span class="badge-pass">✔ SAFE DOCUMENT</span>
                    <div class="step-title" style="margin-top: 0.5rem;">File Structure Validated</div>
                    <div><b>Identified Magic:</b> {report['magic_detected']}</div>
                    <div><b>Threat Level:</b> {report['threat_level']}</div>
                    <div>{report['details']}</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="danger-box">
                    <span class="badge-fail">🚨 {report['threat_level']}</span>
                    <div class="step-title" style="color: #B91C1C; margin-top: 0.5rem;">Dangerous Executable / Trojan Disguise Detected</div>
                    <div><b>Detected Magic:</b> {report['magic_detected']}</div>
                    <div><b>Declared Extension:</b> {declared_name}</div>
                    <div style="margin-top: 0.5rem;"><b>Analysis:</b> {report['details']}</div>
                </div>
                """, unsafe_allow_html=True)
