# JAR Signer — Secure Credential Utility (Shell Scripts)

Signs JAR files without ever exposing the keystore password in plaintext —
not on the terminal, not in `ps`/`top` output, not in shell history.

**Requirements:** `openssl`, `base64` — both present on all standard Linux
distros. No third-party packages needed.

---

## Files

| File | Purpose |
|---|---|
| `setup_credentials.sh` | **Run once** — encrypts and stores the keystore password |
| `sign_jar.sh` | **Run every time** — prompts only for JAR path + alias |
| `rotate_password.sh` | Run when the keystore password changes |
| `.cred_store` | Auto-created — encrypted credential (permissions: 600) |
| `.machine_id` | Auto-created on non-Linux systems — machine fingerprint |

---

## Quick Start

### 1. Make scripts executable

```bash
chmod +x setup_credentials.sh sign_jar.sh rotate_password.sh
```

### 2. Place your keystore

Put `signing.jks` in the same directory, **or** edit the `KEYSTORE` variable
at the top of `sign_jar.sh`.

### 3. Store the password (once)

```bash
./setup_credentials.sh
```

You will be prompted to enter the keystore password **twice** (confirmation).
The password is encrypted and saved to `.cred_store`. It is never written to
disk in plaintext.

### 4. Sign JARs (every 10 days, or whenever needed)

```bash
# Interactive
./sign_jar.sh

# Positional arguments (for scripting / cron)
./sign_jar.sh /path/to/app.jar alias1
```

The only prompts are:
```
  JAVA_HOME (press Enter to use system default): 
  JAR file path : /path/to/app.jar
  Alias name    : alias1
```

### 5. When the keystore password changes

```bash
./rotate_password.sh
```

Verifies the old password before accepting the new one.

---

## Security Design

### Encryption

| Property | Value |
|---|---|
| Algorithm | AES-256-CBC |
| Key derivation | PBKDF2-HMAC-SHA256, 600 000 iterations (OWASP 2023) |
| KDF input | Machine-ID + random 256-bit extra salt |
| Salt (openssl) | 64-bit random salt, prepended by openssl to the ciphertext |
| Extra salt | 256-bit random hex, stored in `.cred_store` |
| Machine binding | Key = PBKDF2(machine-id + extra-salt); machine-id is NOT stored |

The effective passphrase fed into PBKDF2 is `MACHINE_ID + EXTRA_SALT`.
Because `MACHINE_ID` is never written to `.cred_store`, the file is useless
on any other machine — even with the correct `EXTRA_SALT`.

### Why the password is never visible

**1. Not a CLI argument.**
`jarsigner -storepass mypassword` would expose the password in `ps aux`
output, visible to every user on the machine.
This utility uses:
```bash
jarsigner -storepass:env _JARSIGN_PWD ...
```
jarsigner reads the password from an environment variable, not from argv.

**2. Isolated subprocess environment.**
The signing command is launched with `env -i`, which creates a fresh,
minimal environment containing only `PATH`, `HOME`, and `_JARSIGN_PWD`.
The variable is never added to the parent shell's environment.

**3. Not in shell history.**
You never type the password when signing. It was entered once during setup
via `read -s`, which disables terminal echo and is not recorded by the shell.

**4. Machine-bound.**
Copying `.cred_store` to another host produces only garbage — the other
machine's ID produces a different AES key.

**5. Post-use wipe.**
After `jarsigner` exits, `_JARSIGN_PWD` is overwritten with random bytes and
`unset` immediately.

**6. Secure file permissions.**
`.cred_store` is created with `chmod 600` — no other OS user can read it.

**7. Atomic credential rotation.**
`rotate_password.sh` writes to a `.tmp` file, sets permissions, then does an
atomic `mv` — so the credential file is never in a partially-written state.

### What this does NOT protect against

- A `root` attacker who can read your process memory or files.
- Malware running as your own user account.
- Physical access combined with a readable machine ID source.

For higher assurance, integrate with a hardware security module (HSM) or the
OS keystore (Linux GNOME Keyring / `secret-tool`, or a Vault agent).

---

## Troubleshooting

| Error | Cause / Fix |
|---|---|
| `Credential file not found` | Run `./setup_credentials.sh` first |
| `Decryption failed` | File tampered with, or you are on a different machine |
| `jarsigner: command not found` | JDK not installed or not in PATH |
| `JAR file not found` | Check path; use absolute paths to be safe |
| `Keystore not found` | Edit `KEYSTORE` variable in `sign_jar.sh` |
| `Permission denied` | Run `chmod +x *.sh` |
