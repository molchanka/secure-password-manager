#pragma once

#include <sodium.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/wait.h>
#include <spawn.h>
extern char** environ;
#include <pwd.h>
#include <dirent.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <cerrno>
#include <limits>
#include <algorithm>
#include <thread>
#include <chrono>
#include <atomic>
#include <cctype>
#include <random>

// -------- Configuration constants --------
inline constexpr const char* VAULT_FILENAME = "vault.bin";
inline constexpr const char* META_FILENAME = "vault.meta"; // stores salt & nonce info securely
inline constexpr const char* AUDIT_LOG = "audit.log";
inline constexpr size_t SALT_LEN = crypto_pwhash_SALTBYTES; // Argon2 salt
inline constexpr size_t KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
inline constexpr size_t NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
inline constexpr size_t ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;

// Argon2 parameters
inline constexpr unsigned long OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
inline constexpr size_t MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

// limits for username/password lengths
inline constexpr size_t MAX_USER_LEN = 256;
inline constexpr size_t MAX_PASS_LEN = 1024;
inline constexpr size_t MAX_LABEL_LEN = 256;
inline constexpr size_t MAX_VAULT_NAME_LEN = 64;
inline constexpr size_t MAX_NOTES_LEN = 4096;
inline constexpr size_t MAX_VAULT_SIZE = 10 * 1024 * 1024; // 10 MB hard cap

using byte = unsigned char;

struct Cred {
    std::string label;   // e.g. "gmail"
    std::string username;
    std::string password;
    std::string notes;
};

using Vault = std::map<std::string, Cred>; // key by label
