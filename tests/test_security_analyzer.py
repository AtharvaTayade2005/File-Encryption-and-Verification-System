"""
Unit tests for the Security Payload Analyzer (src/security_analyzer.py).
Tests Trojan detection, magic byte analysis, and file misdirection protection.
"""

import pytest
from src.security_analyzer import inspect_payload_safety


class TestSecurityPayloadAnalyzer:
    """Test suite for post-decryption threat inspection."""

    def test_windows_pe_disguised_as_pdf(self):
        # Starts with 'MZ' (DOS/PE header)
        fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"This program cannot be run in DOS mode."
        report = inspect_payload_safety(fake_pdf, ".pdf")
        assert report["is_safe"] is False
        assert report["threat_level"] == "CRITICAL DANGEROUS"
        assert "MZ" in report["magic_detected"]
        assert "Disguised Executable" in report["details"]

    def test_linux_elf_disguised_as_txt(self):
        fake_txt = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
        report = inspect_payload_safety(fake_txt, ".txt")
        assert report["is_safe"] is False
        assert report["threat_level"] == "CRITICAL DANGEROUS"
        assert "ELF" in report["magic_detected"]

    def test_shell_script_disguised_as_jpg(self):
        script_payload = b"#!/bin/bash\nrm -rf / --no-preserve-root\n"
        report = inspect_payload_safety(script_payload, ".jpg")
        assert report["is_safe"] is False
        assert report["threat_level"] == "CRITICAL DANGEROUS"
        assert "Shell Script" in report["magic_detected"]

    def test_zip_disguised_as_txt(self):
        zip_payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"file.dat"
        report = inspect_payload_safety(zip_payload, ".txt")
        assert report["is_safe"] is False
        assert report["threat_level"] == "HIGH"
        assert "ZIP" in report["magic_detected"]

    def test_genuine_pdf_is_safe(self):
        pdf_payload = b"%PDF-1.4\n1 0 obj<<>>endobj\nxref\ntrailer<<>>\n%%EOF"
        report = inspect_payload_safety(pdf_payload, ".pdf")
        assert report["is_safe"] is True
        assert report["threat_level"] == "SAFE"
        assert "PDF" in report["magic_detected"]

    def test_genuine_jpeg_is_safe(self):
        jpeg_payload = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
        report = inspect_payload_safety(jpeg_payload, ".jpg")
        assert report["is_safe"] is True
        assert report["threat_level"] == "SAFE"

    def test_genuine_plain_text_is_safe(self):
        text_payload = b"Hello, this is legitimate academic plain text."
        report = inspect_payload_safety(text_payload, ".txt")
        assert report["is_safe"] is True
        assert report["threat_level"] == "SAFE"

    def test_empty_payload_is_safe(self):
        report = inspect_payload_safety(b"", ".txt")
        assert report["is_safe"] is True
        assert report["threat_level"] == "SAFE"

    def test_input_type_errors(self):
        with pytest.raises(TypeError):
            inspect_payload_safety("not bytes", ".pdf")  # type: ignore

        with pytest.raises(TypeError):
            inspect_payload_safety(b"data", 123)  # type: ignore
