#!/usr/bin/env bash
# OpenSSL Cross-Verification Script for FEVS (PECE04T/PECE04P Module 2)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON:-python}"

echo "======================================================================"
echo " Running FEVS OpenSSL Vector Cross-Verification"
echo "======================================================================"

"$PYTHON_BIN" "$SCRIPT_DIR/verify_openssl.py"
