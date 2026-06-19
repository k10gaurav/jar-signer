#!/usr/bin/env bash
# =============================================================================
# setup_credentials.sh
# -----------------------------------------------------------------------------
# Run ONCE to encrypt and store your JKS keystore password securely.
# The encrypted credential is machine-bound and stored in .cred_store.
#
# Usage:
#   chmod +x setup_credentials.sh
#   ./setup_credentials.sh
#
# Requirements: openssl, base64  (present on all standard Linux distros)
# =============================================================================

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRED_FILE="${SCRIPT_DIR}/.cred_store"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# ── Dependency check ──────────────────────────────────────────────────────────
for cmd in openssl base64; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo -e "${RED}[ERROR]${NC} Required command not found: $cmd"
        exit 1
    }
done

# ── Abort if credential already exists ───────────────────────────────────────
if [[ -f "$CRED_FILE" ]]; then
    echo -e "${YELLOW}[WARN]${NC}  A credential file already exists at:"
    echo "       $CRED_FILE"
    echo ""
    read -r -p "       Overwrite it? (yes/no): " confirm
    [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
fi

# ── Machine identity ──────────────────────────────────────────────────────────
# /etc/machine-id is a stable, system-unique 128-bit ID (Linux/systemd).
# If absent (containers, macOS), fall back to a locally generated token.
_get_machine_id() {
    local mid=""

    # Linux / systemd
    if [[ -r /etc/machine-id ]]; then
        mid=$(tr -d '[:space:]' < /etc/machine-id)
        [[ -n "$mid" ]] && { echo "$mid"; return; }
    fi

    # macOS
    if command -v ioreg >/dev/null 2>&1; then
        mid=$(ioreg -rd1 -c IOPlatformExpertDevice \
              | awk -F'"' '/IOPlatformUUID/{print $4}')
        [[ -n "$mid" ]] && { echo "$mid"; return; }
    fi

    # Fallback: create a local machine token (persisted in the script dir)
    local fallback="${SCRIPT_DIR}/.machine_id"
    if [[ -f "$fallback" ]]; then
        cat "$fallback"
    else
        openssl rand -hex 32 | tee "$fallback"
        chmod 600 "$fallback"
        echo -e "${YELLOW}[INFO]${NC}  Created local machine-id at $fallback" >&2
    fi
}

MACHINE_ID=$(_get_machine_id)

# ── Prompt for password (no echo) ─────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  JAR-Signer  —  Credential Setup"
echo "============================================================"
echo ""
echo "  Encrypts your keystore password with AES-256-CBC + PBKDF2."
echo "  The result is machine-bound: the file is useless elsewhere."
echo ""

read -r -s -p "  Enter keystore password       : " PWD1; echo ""
read -r -s -p "  Re-enter keystore password    : " PWD2; echo ""

if [[ "$PWD1" != "$PWD2" ]]; then
    echo -e "\n${RED}[ERROR]${NC} Passwords do not match. Run setup again."
    # wipe
    PWD1=$(head -c 64 /dev/urandom | base64); PWD2="$PWD1"
    unset PWD1 PWD2
    exit 1
fi

if [[ -z "$PWD1" ]]; then
    echo -e "\n${RED}[ERROR]${NC} Password cannot be empty."
    unset PWD1 PWD2
    exit 1
fi

# ── Encrypt ───────────────────────────────────────────────────────────────────
# Passphrase for openssl = MACHINE_ID + a random 256-bit salt stored alongside.
# This means:
#   - The .cred_store blob needs the salt to decrypt (stored in the file).
#   - Without the machine's ID (which is NOT in the file), decryption fails.
#
# openssl enc -aes-256-cbc -pbkdf2 -iter 600000:
#   - AES-256-CBC with PBKDF2-SHA256 key derivation
#   - 600 000 iterations (OWASP 2023 recommendation)
#   - -a  : base64 output (safe to store in a text file)
#   - -salt: openssl prepends its own random 8-byte salt to the ciphertext
#            (independent of our MACHINE_ID salt — gives double salting)

EXTRA_SALT=$(openssl rand -hex 32)          # 256 bits
OPENSSL_PASS="${MACHINE_ID}${EXTRA_SALT}"   # never stored on disk

ENCRYPTED=$(printf '%s' "$PWD1" \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -a -salt \
        -pass "pass:${OPENSSL_PASS}" 2>/dev/null)

# Wipe password variables immediately
PWD1=$(head -c 64 /dev/urandom | base64 2>/dev/null || echo "xxxxxxxx")
PWD2="$PWD1"
OPENSSL_PASS="$PWD1"
unset PWD1 PWD2 OPENSSL_PASS

# ── Write credential file ─────────────────────────────────────────────────────
# Format (plain text, each field on its own line):
#   Line 1: VERSION=1
#   Line 2: EXTRA_SALT=<hex>
#   Line 3: CIPHERTEXT=<base64, may span multiple lines — stored URL-safe>
#
# We collapse the multi-line base64 to a single line for easy parsing.
CIPHERTEXT_ONELINE=$(echo "$ENCRYPTED" | tr -d '\n')

{
    echo "VERSION=1"
    echo "KDF=PBKDF2-HMAC-SHA256"
    echo "ITERATIONS=600000"
    echo "EXTRA_SALT=${EXTRA_SALT}"
    echo "CIPHERTEXT=${CIPHERTEXT_ONELINE}"
} > "$CRED_FILE"

chmod 600 "$CRED_FILE"

echo ""
echo -e "${GREEN}[OK]${NC}   Encrypted credential saved to:"
echo "       $CRED_FILE"
echo "       (permissions: 600 — owner read/write only)"
echo ""
echo "  The plaintext password is NOT stored anywhere."
echo "  Run ./sign_jar.sh to sign a JAR."
echo ""
