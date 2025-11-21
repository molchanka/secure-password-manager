# secure-password-manager

Secure password manager for personal use, written using C++ and secured using various practices learned thoughout the TalTech's Secure Programming course.

## Current features

- Argon2id key derivation for master passwords
- XChaCha20-Poly1305 authenticated encryption for all vault data
- AEAD authentication (via Poly1305) provides integrity for all vault data.


### Workflow

- Input Master Password -> derive encryption key -> unlock vault
- If incorrect -> failed attempt logged
- After several failed attempts -> session locks
- Vault automatically encrypted on every modification

### Credential operations

| Action | Behavior |
| -------- | ------- |
| +New | Adds a new credential, validates input, creates a log entry |
| Update | Requires old password, validates, securely overwrites, creates a log entry |
| Delete | Requires master password, removes the credential, creates a log entry |
| Reveal | Displays credential, creates a log entry |
| Copy | Copies credential into a secure buffer (not system clipboard), buffer is locked in RAM and wiped on demand |

### Future roadmap

- SHA-256 for log integrity checks
- Cross-platform clipboard integration (timed clear)
- Session timeout auto-lock
- Multi-vault support

## Dependencies

- **C++17 or newer**
- **libsodium** for cryptographic operations

### Install dependencies

Ubuntu / Debian / WSL
```bash
sudo apt update
sudo apt install g++ libsodium-dev
```

Fedora
```bash
sudo dnf install g++ libsodium-devel
```

## Security notes

This is a learning-based implementation, not a production password manager. It demonstrates principles from the Secure Programming and Cryptography courses.

### Secure Programming principles

| Principle | Implementation |
| -------- | ------- |
| Input validation | Max length, empty and malformation checks, no unsafe string functions (gets, strcpy, etc.), avoiding undefined behavior in escaping logic |
| Logging and auditability | All sensitive actions recorded in audit.log with a timestamp, write failures handled, no sensitive data included |
| Secure deletion (file) | Overwrite with zeroes before unlink(), atomic rename to avoid partial deletion, metadata clear |
| Secure deletion (memory) | All sensitive strings wiped with `sodium_memzero`, secure buffers mlocked where supported |
| Least privilege | Files created with 0600 permissions only |
| TOCTOU avoidance | Atomic file writes via `mkostemp()`, `fsync()` and `rename()` |
| Fail-secure | Locked on failed password attempts, memory wiped on any operation fail, no partial writes |
| Integer Overflow Protection | Overflow guards, file size validation before allocation or vectors resizing |
| Silent Error Messaging | No sensitive error messages (e.g., not “Argon2 failed at step X” but instead “An unexpected error occurred”) |
| Cryptographic Correctness | Argon2id with user-configured parameters, salts always random, new nonce for every save, AEAD XChaCha20-Poly1305 auth checks verified |
| Replay and Corruption Detection | AEAD authentication ensures tampering causes clean failure, vault won't load if ciphertext or metadata mismatched |
| Controlled Resource Usage | Hard limits on vault size (10MB), password, username, label lengths, avoiding unbounded growth, fail safely on giant or corrupted files |

## Build instructions

### Using g++

```
g++ -std=c++17 -O2 -Wall passman.cpp -lsodium -o passman
```

### Run

```
./passman
```