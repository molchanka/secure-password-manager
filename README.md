# secure-password-manager

Secure password manager for personal use, written using C++ and secured using various practices learned thoughout the TalTech's Secure Programming course.

## Current features

- Argon2id key derivation for master passwords
- XChaCha20-Poly1305 authenticated encryption for all vault data
- SHA-256 used for logging and internal integrity checks

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
| Input validation | Max length checks, no unsafe string functions (gets, strcpy, etc.) |
| Logging and auditability | All sensitive actions recorded in audit.log with a timestamp |
| Secure deletion | Overwrite before unlink(), in-memory wipe on vault delete |
| Least privilege | Files created with 0600 permissions only |
| TOCTOU avoidance | Atomic file writes via mkstemp and rename() |
| Fail-secure | Locked on failed password attempts, memory wiped on any operation fail, no partial writes |
| Integer Overflow Protection | Overflow guards, file size validation before allocation or vectors resizing |


## Build instructions

### Using g++

```
g++ -std=c++17 -O2 -Wall passman.cpp -lsodium -o passman
```

### Run

```
./passman
```

## Credits

Author of the ICS0022 Secure Programming course is Ali Ghasempour. The project and its requirements are based on 2025 autumn version of the course materials.
This project's documentation and code comments were partially written with assistance from OpenAI's ChatGPT (GPT-5).
All source logic, review, and testing were performed by the author.