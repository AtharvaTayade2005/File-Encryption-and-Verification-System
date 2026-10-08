"""
Security Payload Analyzer Module for FEVS.
Compliant with PECE04T / PECE04P Module 2 & Module 3 (Malicious Software).

Inspects post-decryption payloads for malicious executable vectors,
trojan disguises, and file type misdirection attacks.
"""

import os
from typing import Dict, Any


def inspect_payload_safety(data: bytes, declared_extension: str) -> Dict[str, Any]:
    """
    Inspects decrypted payload bytes for dangerous executable signatures,
    magic byte mismatches, and Trojan horse misdirection attacks.

    :param data: Decrypted raw byte sequence.
    :param declared_extension: The filename or extension declared by sender (e.g., 'doc.pdf' or '.pdf').
    :return: Dictionary containing:
        - is_safe (bool): True if no threat detected, False if threat identified.
        - threat_level (str): 'CRITICAL DANGEROUS', 'HIGH', 'WARNING', or 'SAFE'.
        - details (str): Descriptive explanation of threat detection.
        - magic_detected (str): Identified file signature type.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Payload data must be bytes or bytearray.")
    if not isinstance(declared_extension, str):
        raise TypeError("declared_extension must be a string.")

    # Normalize extension: extract extension if a full filename was passed
    raw_str = declared_extension.strip()
    extracted_ext = os.path.splitext(raw_str)[1].lower()
    if extracted_ext:
        ext = extracted_ext
    else:
        ext = f".{raw_str.lower().lstrip('.')}" if raw_str else ""

    # Default baseline
    magic_detected = "Unknown / Binary"
    is_safe = True
    threat_level = "SAFE"
    details = f"No obvious executable threat detected for declared format '{ext or 'unspecified'}."

    if len(data) == 0:
        return {
            "is_safe": True,
            "threat_level": "SAFE",
            "details": "Payload is empty (0 bytes).",
            "magic_detected": "Empty Payload",
        }

    # 1. Magic byte identification
    is_windows_pe = data.startswith(b"MZ")
    is_linux_elf = data.startswith(b"\x7fELF")
    is_shell_script = data.startswith(b"#!/bin/") or data.startswith(b"#!/usr/")
    is_zip_archive = data.startswith(b"PK\x03\x04")
    is_pdf = data.startswith(b"%PDF")
    is_jpeg = data.startswith(b"\xff\xd8\xff")
    is_png = data.startswith(b"\x89PNG\r\n\x1a\n")

    if is_windows_pe:
        magic_detected = "Windows PE Executable / DLL (MZ)"
    elif is_linux_elf:
        magic_detected = "Linux ELF Executable binary"
    elif is_shell_script:
        magic_detected = "Executable Shell Script"
    elif is_zip_archive:
        magic_detected = "ZIP Container / Compressed Archive"
    elif is_pdf:
        magic_detected = "Adobe PDF Document"
    elif is_jpeg:
        magic_detected = "JPEG Image"
    elif is_png:
        magic_detected = "PNG Image"
    else:
        # Check if valid printable UTF-8 / ASCII text
        try:
            data[:1024].decode("utf-8")
            magic_detected = "Plain Text (UTF-8 / ASCII)"
        except UnicodeDecodeError:
            magic_detected = "Generic Binary Stream"

    # 2. Threat & Misdirection Detection
    benign_document_extensions = {".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".csv", ".doc", ".docx"}

    # Threat Scenario A: Disguised Executable / Trojan Horse
    if (is_windows_pe or is_linux_elf or is_shell_script) and (ext in benign_document_extensions):
        is_safe = False
        threat_level = "CRITICAL DANGEROUS"
        details = (
            f"Disguised Executable / Trojan Horse: The file is declared as '{ext}', "
            f"but contains a native executable binary ({magic_detected}). "
            "Execution could compromise the host operating system."
        )

    # Threat Scenario B: Raw executable payload
    elif is_windows_pe or is_linux_elf or is_shell_script:
        is_safe = False
        threat_level = "HIGH"
        details = f"Active executable binary detected ({magic_detected}). Execution restricted."

    # Threat Scenario C: Disguised ZIP / Archive evasion
    elif is_zip_archive and ext in {".txt", ".pdf", ".jpg", ".png"}:
        is_safe = False
        threat_level = "HIGH"
        details = (
            f"Archive Misdirection: File is named '{ext}', but header reveals a ZIP container. "
            "Potential polyglot or archive evasion vector."
        )

    # Valid matching formats
    elif (ext == ".pdf" and is_pdf) or (ext in {".jpg", ".jpeg"} and is_jpeg) or (ext == ".png" and is_png):
        is_safe = True
        threat_level = "SAFE"
        details = f"File signature matches declared format '{ext}'."

    elif ext == ".txt" and magic_detected.startswith("Plain Text"):
        is_safe = True
        threat_level = "SAFE"
        details = "File content is verified plain text."

    return {
        "is_safe": is_safe,
        "threat_level": threat_level,
        "details": details,
        "magic_detected": magic_detected,
    }
