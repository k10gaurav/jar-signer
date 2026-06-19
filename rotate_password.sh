#!/usr/bin/env bash
# =============================================================================
# rotate_password.sh
# -----------------------------------------------------------------------------
# Use when the keystore password changes.
# Verifies the OLD password before accepting and re-encrypting the NEW one.
# No stale credential can be left behind.
#
# Usage:
#   chmod +x rotate_password.sh
#   ./rotate_password.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRED_FILE="${SCRIPT_DIR}/.cred_store"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for cmd in openssl base64; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo -e "${RED}[ERROR]${NC} Required command not found: $cmd"; exit 1
    }
done

# ── Machine identity ──────────────────────────────────────────────────────────
_get_machine_id() {
    local mid=""
    if [[ -r /etc/machine-id ]]; then
        mid=$(tr -d '[:space:]' < /etc/machine-id)
        [[ -n "$mid" ]] && { echo "$mid"; return; }
    fi
    if command -v ioreg >/dev/null 2>&1; then
        mid=$(ioreg -rd1 -c IOPlatformExpertDevice \
              | awk -F'"' '/IOPlatformUUID/{print $4}')
        [[ -n "$mid" ]] && { echo "$mid"; return; }
    fi
    local fallback="${SCRIPT_DIR}/.machine_id"
    [[ -f "$fallback" ]] && { cat "$fallback"; return; }
    echo -e "${RED}[ERROR]${NC} Machine-ID not found." >&2; exit 1
}

# ── Decrypt current credential ────────────────────────────────────────────────
_decrypt() {
    local extra_salt="" ciphertext=""
    while IFS= read -r line; do
        local pkey="${line%%=*}"
        local pval="${line#*=}"
        case "$pkey" in
            EXTRA_SALT)  extra_salt="$pval"  ;;
            CIPHERTEXT)  ciphertext="$pval"  ;;
        esac
    done < "$CRED_FILE"

    local machine_id; machine_id=$(_get_machine_id)
    local openssl_pass="${machine_id}${extra_salt}"

    local result
    result=$(echo "$ciphertext" \
        | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -a \
            -pass "pass:${openssl_pass}" 2>/dev/null) || {
        echo -e "${RED}[ERROR]${NC} Decryption of current credential failed." >&2
        echo "        Are you on the same machine where setup was run?" >&2
        exit 1
    }
    openssl_pass="x"; unset openssl_pass
    printf '%s' "$result"
}

# ── Encrypt new credential ────────────────────────────────────────────────────
_encrypt_and_save() {
    local plaintext="$1"
    local machine_id; machine_id=$(_get_machine_id)
    local extra_salt; extra_salt=$(openssl rand -hex 32)
    local openssl_pass="${machine_id}${extra_salt}"

    local encrypted
    encrypted=$(printf '%s' "$plaintext" \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -a -salt \
            -pass "pass:${openssl_pass}" 2>/dev/null)

    openssl_pass="x"; unset openssl_pass

    local ciphertext_oneline
    ciphertext_oneline=$(echo "$encrypted" | tr -d '\n')

    # Write to a temp file first, then atomic rename — avoids partial writes
    local tmp="${CRED_FILE}.tmp"
    {
        echo "VERSION=1"
        echo "KDF=PBKDF2-HMAC-SHA256"
        echo "ITERATIONS=600000"
        echo "EXTRA_SALT=${extra_salt}"
        echo "CIPHERTEXT=${ciphertext_oneline}"
    } > "$tmp"

    chmod 600 "$tmp"
    mv "$tmp" "$CRED_FILE"
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  JAR-Signer  —  Password Rotation"
echo "============================================================"
echo ""

if [[ ! -f "$CRED_FILE" ]]; then
    echo -e "${RED}[ERROR]${NC} No credential file found. Run ./setup_credentials.sh first."
    exit 1
fi

# Verify old password
STORED_PWD=$(_decrypt)

read -r -s -p "  Enter CURRENT keystore password (to verify) : " INPUT_OLD; echo ""

if [[ "$INPUT_OLD" != "$STORED_PWD" ]]; then
    echo -e "\n${RED}[ERROR]${NC} Current password does not match. Rotation aborted."
    STORED_PWD="x"; INPUT_OLD="x"; unset STORED_PWD INPUT_OLD
    exit 1
fi

echo -e "${GREEN}[OK]${NC}   Current password verified."
echo ""

STORED_PWD="x"; unset STORED_PWD
INPUT_OLD="x"; unset INPUT_OLD

# Collect new password
read -r -s -p "  Enter NEW keystore password : " NEW1; echo ""
read -r -s -p "  Re-enter NEW password       : " NEW2; echo ""

if [[ "$NEW1" != "$NEW2" ]]; then
    echo -e "\n${RED}[ERROR]${NC} New passwords do not match. Rotation aborted."
    NEW1="x"; NEW2="x"; unset NEW1 NEW2
    exit 1
fi

if [[ -z "$NEW1" ]]; then
    echo -e "\n${RED}[ERROR]${NC} Password cannot be empty."
    unset NEW1 NEW2
    exit 1
fi

_encrypt_and_save "$NEW1"

NEW1="x"; NEW2="x"; unset NEW1 NEW2

echo ""
echo -e "${GREEN}[OK]${NC}   Credential rotated successfully."
echo "       $CRED_FILE updated with the new encrypted password."
echo ""
