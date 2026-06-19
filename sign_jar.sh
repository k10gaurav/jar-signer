#!/usr/bin/env bash
# =============================================================================
# sign_jar.sh
# -----------------------------------------------------------------------------
# Signs a JAR file using the securely stored keystore password.
# Prompts for: JAVA_HOME (optional)  +  JAR file path  +  alias name.
# The keystore password is NEVER visible — not in ps, not in history, not
# on the terminal.
#
# Usage:
#   ./sign_jar.sh                            # interactive prompts
#   ./sign_jar.sh /path/to/app.jar alias1   # positional arguments
#
# Prerequisites:
#   1. Run ./setup_credentials.sh once first
#   2. Place signing.jks in this directory (or edit KEYSTORE below)
#   3. jarsigner must be reachable — either via JAVA_HOME prompt or PATH
# =============================================================================

set -euo pipefail

# ── Configuration  ← edit KEYSTORE if your JKS lives elsewhere ───────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYSTORE="${SCRIPT_DIR}/signing.jks"
CRED_FILE="${SCRIPT_DIR}/.cred_store"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# ── Dependency check (openssl + base64 always required) ───────────────────────
for cmd in openssl base64; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo -e "${RED}[ERROR]${NC} Required command not found: $cmd"
        exit 1
    }
done

# ── Machine identity (must match setup_credentials.sh) ───────────────────────
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
    if [[ -f "$fallback" ]]; then
        cat "$fallback"
    else
        echo -e "${RED}[ERROR]${NC} Machine-ID not found. Run setup_credentials.sh first." >&2
        exit 1
    fi
}

# ── Decrypt stored credential ─────────────────────────────────────────────────
_load_password() {
    if [[ ! -f "$CRED_FILE" ]]; then
        echo -e "${RED}[ERROR]${NC} Credential file not found: $CRED_FILE" >&2
        echo "        Run ./setup_credentials.sh first." >&2
        exit 1
    fi

    # Warn if permissions are too open
    local perms
    perms=$(stat -c '%a' "$CRED_FILE" 2>/dev/null \
            || stat -f '%OLp' "$CRED_FILE" 2>/dev/null \
            || echo "???")
    if [[ "$perms" != "600" && "$perms" != "400" ]]; then
        echo -e "${YELLOW}[WARN]${NC}  $CRED_FILE has permissions $perms (expected 600)." >&2
        echo "        Fix with: chmod 600 $CRED_FILE" >&2
    fi

    # Parse the credential file.
    # Use line%%=* / line#*= to split on the FIRST '=' only, so that
    # base64 padding characters ('=') inside the ciphertext are preserved.
    local extra_salt="" ciphertext=""
    while IFS= read -r line; do
        local pkey="${line%%=*}"
        local pval="${line#*=}"
        case "$pkey" in
            EXTRA_SALT)  extra_salt="$pval"  ;;
            CIPHERTEXT)  ciphertext="$pval"  ;;
        esac
    done < "$CRED_FILE"

    if [[ -z "$extra_salt" || -z "$ciphertext" ]]; then
        echo -e "${RED}[ERROR]${NC} Credential file is malformed or corrupted." >&2
        exit 1
    fi

    local machine_id
    machine_id=$(_get_machine_id)
    local openssl_pass="${machine_id}${extra_salt}"

    local plaintext
    plaintext=$(echo "$ciphertext" \
        | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -a \
            -pass "pass:${openssl_pass}" 2>/dev/null) || {
        echo -e "${RED}[ERROR]${NC} Decryption failed." >&2
        echo "        Possible causes:" >&2
        echo "          • You are on a different machine from where setup was run" >&2
        echo "          • The credential file has been tampered with" >&2
        exit 1
    }

    # Wipe the openssl passphrase variable immediately
    openssl_pass="$(head -c 64 /dev/urandom | base64 2>/dev/null || echo 'x')"
    unset openssl_pass

    printf '%s' "$plaintext"
}

# ── Resolve jarsigner binary ──────────────────────────────────────────────────
# Accepts a JAVA_HOME path from the user.
# If provided   → uses $JAVA_HOME/bin/jarsigner (validated to exist).
# If left blank → falls back to whatever jarsigner is on PATH.
_resolve_jarsigner() {
    local java_home="$1"

    if [[ -n "$java_home" ]]; then
        # Strip any trailing slash for clean path construction
        java_home="${java_home%/}"
        local candidate="${java_home}/bin/jarsigner"

        if [[ ! -f "$candidate" ]]; then
            echo -e "${RED}[ERROR]${NC} jarsigner not found at: $candidate" >&2
            echo "        Check that the JAVA_HOME path points to a valid JDK." >&2
            exit 1
        fi

        if [[ ! -x "$candidate" ]]; then
            echo -e "${RED}[ERROR]${NC} jarsigner exists but is not executable: $candidate" >&2
            exit 1
        fi

        echo "$candidate"
    else
        # Fall back to PATH
        local default_bin
        default_bin=$(command -v jarsigner 2>/dev/null) || {
            echo -e "${RED}[ERROR]${NC} jarsigner not found on PATH and no JAVA_HOME was provided." >&2
            echo "        Either enter a JAVA_HOME path, or install the JDK and add it to PATH." >&2
            exit 1
        }
        echo "$default_bin"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  JAR Signer  (secure credential mode)"
echo "============================================================"
echo ""

# ── Prompt 1: JAVA_HOME (optional) ───────────────────────────────────────────
echo -e "  ${CYAN}JAVA_HOME${NC} (press Enter to use system default):"
read -r -p "  > " USER_JAVA_HOME
# Trim surrounding whitespace
USER_JAVA_HOME="${USER_JAVA_HOME#"${USER_JAVA_HOME%%[![:space:]]*}"}"
USER_JAVA_HOME="${USER_JAVA_HOME%"${USER_JAVA_HOME##*[![:space:]]}"}"

JARSIGNER_BIN=$(_resolve_jarsigner "$USER_JAVA_HOME")

if [[ -n "$USER_JAVA_HOME" ]]; then
    echo -e "  ${GREEN}[OK]${NC}   Using JAVA_HOME : $USER_JAVA_HOME"
else
    echo -e "  ${YELLOW}[INFO]${NC} Using system default : $JARSIGNER_BIN"
fi
echo ""

# ── Prompt 2: JAR path ────────────────────────────────────────────────────────
JAR_PATH="${1:-}"
ALIAS="${2:-}"

if [[ -z "$JAR_PATH" ]]; then
    read -r -p "  JAR file path : " JAR_PATH
fi

if [[ -z "$ALIAS" ]]; then
    read -r -p "  Alias name    : " ALIAS
fi

echo ""

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if [[ -z "$JAR_PATH" ]]; then
    echo -e "${RED}[ERROR]${NC} JAR file path is required."
    exit 1
fi

if [[ -z "$ALIAS" ]]; then
    echo -e "${RED}[ERROR]${NC} Alias name is required."
    exit 1
fi

# Resolve to absolute path
JAR_PATH="$(realpath "$JAR_PATH" 2>/dev/null || readlink -f "$JAR_PATH")"

if [[ ! -f "$JAR_PATH" ]]; then
    echo -e "${RED}[ERROR]${NC} JAR file not found: $JAR_PATH"
    exit 1
fi

if [[ ! -f "$KEYSTORE" ]]; then
    echo -e "${RED}[ERROR]${NC} Keystore not found: $KEYSTORE"
    echo "        Edit the KEYSTORE variable in this script if it lives elsewhere."
    exit 1
fi

echo "  JAR        : $JAR_PATH"
echo "  Alias      : $ALIAS"
echo "  Keystore   : $KEYSTORE"
echo "  jarsigner  : $JARSIGNER_BIN"
echo ""

# ── Decrypt at the last possible moment ──────────────────────────────────────
KS_PASSWORD=$(_load_password)

# ── Sign the JAR ─────────────────────────────────────────────────────────────
# Security: the password is passed via -storepass:env so it NEVER appears
# in the process argument list (invisible to `ps aux`).
# env -i launches jarsigner with a fresh, minimal environment — the variable
# never leaks into the parent shell.

export _JARSIGN_PWD="$KS_PASSWORD"

# Wipe our local copy before exec
KS_PASSWORD="$(head -c 64 /dev/urandom | base64 2>/dev/null || echo 'x')"
unset KS_PASSWORD

env -i \
    PATH="$PATH" \
    HOME="${HOME:-/root}" \
    _JARSIGN_PWD="$_JARSIGN_PWD" \
    "$JARSIGNER_BIN" \
        -keystore "$KEYSTORE" \
        -storepass:env _JARSIGN_PWD \
        "$JAR_PATH" \
        "$ALIAS"

EXIT_CODE=$?

# Wipe immediately after jarsigner exits
_JARSIGN_PWD="$(head -c 64 /dev/urandom | base64 2>/dev/null || echo 'x')"
unset _JARSIGN_PWD

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}[SUCCESS]${NC} JAR signed successfully: $JAR_PATH"
else
    echo -e "${RED}[FAILURE]${NC} jarsigner exited with code $EXIT_CODE"
    exit $EXIT_CODE
fi
echo ""