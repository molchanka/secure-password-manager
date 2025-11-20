// passman.cpp
// Build: g++ -std=c++17 -O2 -Wall passman.cpp -lsodium -o passman

#include <sodium.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

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

// -------- Configuration constants --------
static constexpr const char* VAULT_FILENAME = "vault.bin";
static constexpr const char* META_FILENAME = "vault.meta"; // stores salt & nonce info securely
static constexpr const char* AUDIT_LOG = "audit.log";
static constexpr size_t SALT_LEN = crypto_pwhash_SALTBYTES; // Argon2 salt
static constexpr size_t KEY_LEN = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
static constexpr size_t NONCE_LEN = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
static constexpr size_t ABYTES = crypto_aead_xchacha20poly1305_ietf_ABYTES;

// Argon2 parameters
static constexpr unsigned long OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
static constexpr size_t MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

// limits for username/password lengths
static constexpr size_t MAX_USER_LEN = 256;
static constexpr size_t MAX_PASS_LEN = 1024;
static constexpr size_t MAX_LABEL_LEN = 256;
static constexpr size_t MAX_VAULT_SIZE = 10 * 1024 * 1024; // 10 MB hard cap

using byte = unsigned char;

struct Cred {
    std::string label;   // e.g. "gmail"
    std::string username;
    std::string password;
    std::string notes;
};

using Vault = std::map<std::string, Cred>; // key by label

// -------- Utility helpers --------

// Logging
enum class LogLevel { INFO, WARN, ERROR, ALERT }; // levels

static void audit_log_level(LogLevel lvl, const std::string& entry) {
    // append entry to audit log with 0600 perms
    int fd = open(AUDIT_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        std::cerr << "open audit log failed" << strerror(errno) << "\n";
        return;
    }
    time_t t = time(nullptr);
    char buf[64];
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    const char* lname = "INFO";
    switch (lvl) {
        case LogLevel::INFO:  lname = "INFO"; break;
        case LogLevel::WARN:  lname = "WARN"; break;
        case LogLevel::ERROR: lname = "ERROR"; break;
        case LogLevel::ALERT: lname = "ALERT"; break;
    }
    std::string line = std::string(buf) + " [" + lname + "] " + entry + "\n";
    if (write(fd, line.c_str(), line.size()) < 0) {
        std::cerr << "write audit log failed" << strerror(errno) << "\n";
    }
    if (close(fd) != 0) {
        std::cerr << "close audit log failed" << strerror(errno) << "\n";
    }
}

static void audit_log(const std::string& entry) { audit_log_level(LogLevel::INFO, entry); }

// zero and unlock memory safely
static void secure_free(unsigned char* buf, size_t len) {
    if (!buf || len == 0) return;
    sodium_memzero(buf, len);
    // attempt to munlock if possible
#if defined(MADV_DONTNEED)
    munlock(buf, len);
#endif
    free(buf);
}

// get password (no echo) - simple, portable-ish
static std::string get_password(const char* prompt) {
    std::string pw;
    std::cout << prompt;
    std::fflush(stdout);
    // turn off echo on POSIX
    struct termios oldt, newt;
    if (!isatty(STDIN_FILENO)) {
        std::getline(std::cin, pw);
        return pw;
    }
    if (tcgetattr(STDIN_FILENO, &oldt) == -1) {
        std::getline(std::cin, pw);
        return pw;
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return pw;
}

// simple base64 - using libsodium helper
static std::string to_base64(const byte* bin, size_t len) {
    if (!bin) return "";
    size_t out_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    if (out_len == 0) return "";
    std::string out;
    out.resize(out_len);
    sodium_bin2base64(reinterpret_cast<char*>(&out[0]), out_len, bin, len, sodium_base64_VARIANT_ORIGINAL);
    // trim at first null
    size_t pos = out.find('\0');
    if (pos != std::string::npos) out.resize(pos);
    return out;
}

static std::vector<byte> from_base64(const std::string& b64) {
    size_t max_out = b64.size();
    std::vector<byte> out(max_out);
    size_t out_len = 0;
    if (b64.empty()) return {};
    if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(), NULL, &out_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        return {};
    }
    if (out_len > out.size()) return {}; // sanity guard (no malformed base64 strings)
    out.resize(out_len);
    return out;
}

static int cleanup_and_exit(int code, Vault& vault, unsigned char key[KEY_LEN], unsigned char salt[SALT_LEN], unsigned char nonce[NONCE_LEN]) {
    // wipe vault entries
    for (auto& p : vault) {
        if (!p.second.username.empty()) sodium_memzero(&p.second.username[0], p.second.username.size());
        if (!p.second.password.empty()) sodium_memzero(&p.second.password[0], p.second.password.size());
        if (!p.second.notes.empty()) sodium_memzero(&p.second.notes[0], p.second.notes.size());
    }
    vault.clear();

    sodium_memzero(key, KEY_LEN);
    sodium_memzero(salt, SALT_LEN);
    sodium_memzero(nonce, NONCE_LEN);

    audit_log_level(LogLevel::INFO, std::string("Session closed with code ") + std::to_string(code));
    if (code != 0) std::cerr << "An unexpected error occurred. Check audit log for details.\n";
    return code;
}

// -------- Vault layout (high-level) --------
// vault.bin: contains ciphertext (encrypted blob of serialized entries) produced by AEAD.
// vault.meta: stores base64(salt) and base64(nonce) and base64(header H) as needed.
// The encryption key is derived with Argon2id from master password + salt.


// Serialize/deserialize vault to a simple newline-separated format with escaping.
static std::string serialize_vault(const Vault& v) {
    std::ostringstream oss;
    for (const auto& p : v) {
        // escape newlines by \\n
        auto esc = [](const std::string& s)->std::string {
            std::string r; r.reserve(s.size());
            for (char c : s) {
                if (c == '\n') { r += "\\n"; }
                else if (c == '\\') { r += "\\\\"; }
                else r.push_back(c);
            }
            return r;
            };
        oss << p.first << '\t' << esc(p.second.username) << '\t' << esc(p.second.password) << '\t' << esc(p.second.notes) << '\n';
    }
    return oss.str();
}
static Vault deserialize_vault(const std::string& s) {
    Vault v;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        std::vector<std::string> toks;
        size_t pos = 0, start = 0;
        while (pos <= line.size()) {
            if (pos == line.size() || line[pos] == '\t') {
                toks.push_back(line.substr(start, pos - start));
                start = pos + 1;
            }
            pos++;
        }
        auto unesc = [](const std::string& x)->std::string {
            std::string r; r.reserve(x.size());
            for (size_t i = 0; i < x.size(); ++i) {
                if (x[i] == '\\' && i + 1 < x.size()) {
                    if (x[i + 1] == 'n') { r.push_back('\n'); ++i; }
                    else if (x[i + 1] == '\\') { r.push_back('\\'); ++i; }
                    else r.push_back(x[i]);
                }
                else r.push_back(x[i]);
            }
            return r;
            };
        if (toks.size() >= 4) {
            Cred c{ toks[0], unesc(toks[1]), unesc(toks[2]), unesc(toks[3]) };
            v[toks[0]] = c;
        }
    }
    return v;
}

// -------- Core crypto operations --------
static bool derive_key_from_password(const std::string& pw, const byte salt[SALT_LEN], byte key[KEY_LEN]) {
    if (pw.empty()) return false;
    if (crypto_pwhash(key, KEY_LEN,
        pw.c_str(), pw.size(),
        salt,
        OPSLIMIT, MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        audit_log_level(LogLevel::ERROR, "crypto_pwhash failed");
        return false; // out of memory
    }
    return true;
}

static bool encrypt_vault_blob(const byte key[KEY_LEN], const byte *plaintext, size_t plen,
    byte **out_ct, size_t *out_ct_len, byte nonce[NONCE_LEN]) {
    if (!plaintext) return false;
    if (plen > MAX_VAULT_SIZE) { audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: plaintext too large"); return false; }
    if (plen > SIZE_MAX - ABYTES) { audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: size overflow guard"); return false; }
    // generate nonce
    randombytes_buf(nonce, NONCE_LEN);
    unsigned long long ct_len64 = 0;
    size_t alloc_len = plen + ABYTES;
    *out_ct = (byte*)malloc(alloc_len);
    if (!*out_ct) {
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: malloc failed");
        return false;
    }
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(*out_ct, &ct_len64, plaintext, plen, NULL, 0, NULL, nonce, key) != 0) {
        sodium_memzero(*out_ct, alloc_len);
        free(*out_ct);
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: encrypt failed");
        return false;
    }
    *out_ct_len = (size_t)ct_len64;
    return true;
}

static bool decrypt_vault_blob(const unsigned char key[KEY_LEN], const unsigned char* ct, size_t ct_len,
    const unsigned char nonce[NONCE_LEN],
    unsigned char** out_plain, size_t* out_plain_len) {
    unsigned long long mlen = 0;
    *out_plain = (unsigned char*)malloc(ct_len); // ciphertext len is >= plaintext
    if (!*out_plain) return false;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(*out_plain, &mlen,
        NULL,
        ct, ct_len,
        NULL, 0,
        nonce, key) != 0) {
        sodium_memzero(*out_plain, ct_len);
        free(*out_plain);
        return false;
    }
    *out_plain_len = (size_t)mlen;
    return true;
}

// Atomic file write helper (mkstemp + rename)
static bool atomic_write_file(const std::string& path, const byte* buf, size_t len) {
    if (!buf) return false;
    if (len > MAX_VAULT_SIZE) {
        audit_log_level(LogLevel::ERROR, "atomic_write_file: attempt to write huge file");
        return false;
    }
    std::string tmpl = path + ".tmpXXXXXX";
    std::vector<char> temp(tmpl.begin(), tmpl.end());
    temp.push_back('\0');
    int fd = mkostemp(temp.data(), O_CLOEXEC);
    if (fd < 0) {
        std::cerr << "mkostemp failed: " << strerror(errno) << "\n";
        return false;
    }
    // set perms to 0600
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "fchmod failed: " << strerror(errno) << "\n";
        close(fd);
        unlink(temp.data());
        return false;
    }
    ssize_t w = write(fd, buf, len);
    if (w < 0 || (size_t)w != len) {
        std::cerr << "audit log write failed: " << strerror(errno) << "\n";
        close(fd);
        unlink(temp.data());
        return false;
    }
    if (fsync(fd) != 0) {
        std::cerr << "fsync failed: " << strerror(errno) << "\n";
    }
    if (close(fd) != 0) {
        std::cerr << "audit log close failed: " << strerror(errno) << "\n";
    }
    if (rename(temp.data(), path.c_str()) != 0) {
        std::cerr << "rename failed: " << strerror(errno) << "\n";
        unlink(temp.data());
        return false;
    }
    return true;
}

// load meta (salt & nonce) (meta file format: base64(salt)\nbase64(nonce)\n)
static bool load_meta(unsigned char salt[SALT_LEN], unsigned char nonce[NONCE_LEN]) {
    FILE* f = fopen(META_FILENAME, "r");
    if (!f) return false;
    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return false; }
    std::string s_salt(buf);
    s_salt.erase(s_salt.find_last_not_of("\r\n") + 1);
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return false; }
    std::string s_nonce(buf);
    s_nonce.erase(s_nonce.find_last_not_of("\r\n") + 1);
    fclose(f);
    auto vb = from_base64(s_salt);
    if (vb.size() != SALT_LEN) return false;
    memcpy(salt, vb.data(), SALT_LEN);
    auto vn = from_base64(s_nonce);
    if (vn.size() != NONCE_LEN) return false;
    memcpy(nonce, vn.data(), NONCE_LEN);
    return true;
}

static bool save_meta(const unsigned char salt[SALT_LEN], const unsigned char nonce[NONCE_LEN]) {
    std::string b64salt = to_base64(salt, SALT_LEN);
    std::string b64nonce = to_base64(nonce, NONCE_LEN);
    std::string content = b64salt + "\n" + b64nonce + "\n";
    // atomic write
    return atomic_write_file(META_FILENAME, (const unsigned char*)content.c_str(), content.size());
}

// load vault ciphertext
static bool load_vault_ciphertext(std::vector<unsigned char>& ct) {
    FILE* f = fopen(VAULT_FILENAME, "rb");
    if (!f) return false;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return false; }
    if ((unsigned long)sz > MAX_VAULT_SIZE) {  // Prevent integer overflow & large files
        std::cerr << "Vault file too large or corrupt.\n";
        fclose(f);
        return false;
    }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return false; }
    size_t size = static_cast<size_t>(sz);
    ct.resize(size);
    if (size > 0) {
        size_t r = fread(ct.data(), 1, size, f);
        if (r != size) { fclose(f); ct.clear(); return false; }
    }
    fclose(f);
    return true;
}


// Vault clear utility
static void secure_clear_vault(Vault& v) {
    for (auto& p : v) {
        sodium_memzero((void*)p.second.username.data(), p.second.username.size());
        sodium_memzero((void*)p.second.password.data(), p.second.password.size());
        sodium_memzero((void*)p.second.notes.data(), p.second.notes.size());
    }
    v.clear();
}


// ---------- CLI / Workflow ----------

static Vault load_vault_with_key(const unsigned char key[KEY_LEN]) {
    Vault v;
    std::vector<unsigned char> ct;
    if (!load_vault_ciphertext(ct)) return v; // empty vault if none
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    if (!load_meta(salt, nonce)) return v;
    unsigned char* plain = nullptr;
    size_t plain_len = 0;
    if (!decrypt_vault_blob(key, ct.data(), ct.size(), nonce, &plain, &plain_len)) return v;
    std::string txt((char*)plain, plain_len);
    // zero out plain after deserialize
    v = deserialize_vault(txt);
    sodium_memzero(plain, plain_len);
    free(plain);
    return v;
}

// ---------- Program flow helpers ----------

static void print_menu() {
    std::cout << "SecurePass CLI - Menu:\n";
    std::cout << "1) List credentials\n";
    std::cout << "2) Add credential (+New)\n";
    std::cout << "3) Update credential\n";
    std::cout << "4) Delete credential\n";
    std::cout << "5) Reveal credential (logs action)\n";
    std::cout << "6) Copy credential to secure buffer\n";
    std::cout << "7) Quit\n";
    std::cout << "8) Delete entire vault / Create new vault\n";
}

int main() {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "An unexpected error occurred. Check audit log for details.\n");
        audit_log_level(LogLevel::ERROR, "libsodium init failed");
        return 1;
    }

    
    Vault vault;
    byte salt[SALT_LEN];
    byte key[KEY_LEN];
    sodium_memzero(key, KEY_LEN);
    byte nonce[NONCE_LEN];
    sodium_memzero(nonce, NONCE_LEN);

    // Check if vault exists; if not, run init
    bool vault_exists = (access(VAULT_FILENAME, F_OK) == 0 && access(META_FILENAME, F_OK) == 0);

    if (!vault_exists) {
        std::cout << "No vault found. Initialize new vault.\n";
        // generate salt and ask master password twice
        randombytes_buf(salt, SALT_LEN);
        std::string pw1 = get_password("Create master password: ");
        std::string pw2 = get_password("Confirm master password: ");
        if (pw1 != pw2) {
            audit_log_level(LogLevel::WARN, "Vault init: passwords did not match");
            std::cerr << "Passwords do not match. Exiting.\n";
            sodium_memzero((void*)pw1.data(), pw1.size());
            sodium_memzero((void*)pw2.data(), pw2.size());
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        if (!derive_key_from_password(pw1, salt, key)) {
            audit_log_level(LogLevel::ERROR, "Vault init: key derivation failed");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        // empty vault encrypt
        Vault v;
        std::string ser = serialize_vault(v);
        byte* ct = nullptr;
        size_t ct_len = 0;
        byte new_nonce[NONCE_LEN];
        if (!encrypt_vault_blob(key, (const byte*)ser.data(), ser.size(), &ct, &ct_len, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: encrypt_vault_blob failed");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(new_nonce, NONCE_LEN);
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        // atomic write vault
        if (ct_len > MAX_VAULT_SIZE) {
            audit_log_level(LogLevel::ERROR, "Vault init: ciphertext too large");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        if (!atomic_write_file(VAULT_FILENAME, ct, ct_len) || !save_meta(salt, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: saving vault/meta failed");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            sodium_memzero(new_nonce, NONCE_LEN);
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        sodium_memzero(ct, ct_len);
        free(ct);
        sodium_memzero((void*)pw1.data(), pw1.size());
        sodium_memzero((void*)pw2.data(), pw2.size());
        sodium_memzero(key, KEY_LEN);
        std::cout << "Vault initialized. Restart to open.\n";
        audit_log_level(LogLevel::INFO, "New vault initialized");
        return 0;
    }

    // Vault exists -> prompt for master password
    if (!load_meta(salt, nonce)) {
        audit_log_level(LogLevel::ERROR, "Failed to load vault metadata");
        std::cerr << "An unexpected error occurred. Check audit log.\n";
        return cleanup_and_exit(2, vault, key, salt, nonce);
    }

    unsigned attempts = 0;
    const unsigned MAX_ATTEMPTS = 5;
    bool authenticated = false;

    while (attempts < MAX_ATTEMPTS) {
        std::string master = get_password("Master password: ");
        if (!derive_key_from_password(master, salt, key)) {
            attempts++;
            audit_log_level(LogLevel::WARN, "Empty master password input");
                sodium_memzero((void*)master.data(), master.size());
            continue;
        }
        // try decrypting
        std::vector<unsigned char> ct;
        if (!load_vault_ciphertext(ct)) {
            audit_log_level(LogLevel::ERROR, "Unable to read vault ciphertext");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(key, KEY_LEN);
            sodium_memzero((void*)master.data(), master.size());
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        unsigned char* plain = nullptr; size_t plain_len = 0;
        if (decrypt_vault_blob(key, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
            // success
            std::string txt((char*)plain, plain_len);
            vault = deserialize_vault(txt);
            sodium_memzero(plain, plain_len);
            free(plain);
            authenticated = true;
            audit_log_level(LogLevel::INFO, "Master password accepted - session opened");
            sodium_memzero((void*)master.data(), master.size());
            break;
        }
        else {
            attempts++;
            audit_log_level(LogLevel::WARN, "Failed master password attempt");
            sodium_memzero((void*)master.data(), master.size());
            sodium_memzero(key, KEY_LEN);
        }
    }
    if (!authenticated) {
        audit_log_level(LogLevel::ALERT, "Too many failed master attempts - lockout");
        std::cerr << "Too many failed attempts; exiting.\n";
        return cleanup_and_exit(3, vault, key, salt, nonce);
    }
    audit_log("Master password accepted - session opened");

    // Main CLI loop
    bool running = true;
    while (running) {
        print_menu();
        std::cout << "> ";
        std::string choice;
        if (!std::getline(std::cin, choice)) break;

        if (choice == "1") {
            std::cout << "Stored credentials:\n";
            for (auto& p : vault) {
                std::cout << " - " << p.first << " (user: " << p.second.username << ")\n";
            }
        }
        else if (choice == "2") {
            std::string label, user, pass, notes;
            std::cout << "+New - Label: ";
            std::getline(std::cin, label);
            if (label.empty() || label.size() > MAX_LABEL_LEN) { std::cout << "Invalid label\n"; continue; }
            std::cout << " Username: "; std::getline(std::cin, user);
            std::cout << " Password (leave empty to prompt hidden): ";
            std::string tmp;
            std::getline(std::cin, tmp);
            if (tmp.empty()) tmp = get_password("Password: ");
            pass = tmp;
            std::cout << " Notes: "; std::getline(std::cin, notes);

            // validation
            if (user.size() > MAX_USER_LEN || pass.size() > MAX_PASS_LEN) { std::cout << "Input too long\n"; continue; }
            Cred c{ label, user, pass, notes };
            vault[label] = c;
            audit_log("Add credential: " + label);

            // save immediately (re-encrypt)
            unsigned char new_nonce[NONCE_LEN];
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR, "serialize_vault produced excessively large output");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }
            unsigned char* ct = nullptr; size_t ct_len = 0;
            if (!encrypt_vault_blob(key, (const unsigned char*)ser.data(), ser.size(), &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR, "Encryption failed on save (add credential)");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(VAULT_FILENAME, ct, ct_len) || !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Failed to persist vault (add credential)");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                sodium_memzero(ct, ct_len);
                free(ct);
            }
            sodium_memzero((void*)pass.data(), pass.size());
        }
        else if (choice == "3") {
            std::string label;
            std::cout << "Update - Label: ";
            std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) { std::cout << "Not found\n"; continue; }

            // ask old password for that entry
            std::string oldpw = get_password("Old password for this entry: ");
            if (oldpw != it->second.password) {
                audit_log_level(LogLevel::WARN, "Failed update attempt for " + label);
                std::cout << "Old password mismatch\n";
                sodium_memzero((void*)oldpw.data(), oldpw.size());
                continue;
            }
            audit_log_level(LogLevel::INFO, "Update attempt for " + label);
            std::string newpw = get_password("New password: ");
            if (newpw.empty() || newpw.size() > MAX_PASS_LEN) {
                std::cout << "Invalid new password\n";
                sodium_memzero((void*)newpw.data(), newpw.size());
                sodium_memzero((void*)oldpw.data(), oldpw.size());
                continue;
            }
            it->second.password = newpw;
            audit_log_level(LogLevel::INFO, "Update success for " + label);

            // save
            unsigned char new_nonce[NONCE_LEN];
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR, "serialize_vault too large on update");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }
            unsigned char* ct = nullptr; size_t ct_len = 0;
            if (!encrypt_vault_blob(key, (const unsigned char*)ser.data(), ser.size(), &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR, "Encryption failed on save (update)");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(VAULT_FILENAME, ct, ct_len) || !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Failed to persist vault (update)");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                sodium_memzero(ct, ct_len);
                free(ct);
            }
            sodium_memzero((void*)oldpw.data(), oldpw.size());
            sodium_memzero((void*)newpw.data(), newpw.size());
        }
        else if (choice == "4") {
            std::string label;
            std::cout << "Delete - Label: "; std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) { std::cout << "Not found\n"; continue; }
            std::string confirm = get_password("Type MASTER password to confirm deletion: ");

            if (!load_meta(salt, nonce)) {
                audit_log_level(LogLevel::WARN, "Failed to reload meta before credential deletion");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            unsigned char testkey[KEY_LEN];
            if (!derive_key_from_password(confirm, salt, testkey)) {
                audit_log_level(LogLevel::WARN, "Deletion: key derivation failed while verifying master");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                sodium_memzero((void*)confirm.data(), confirm.size());
                continue;
            }
            // attempt to re-decrypt to verify correct master
            std::vector<unsigned char> ct;
            if (!load_vault_ciphertext(ct)) {
                audit_log_level(LogLevel::ERROR, "Deletion: cannot read vault ciphertext");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                sodium_memzero((void*)confirm.data(), confirm.size());
                sodium_memzero(testkey, KEY_LEN);
                continue;
            }
            unsigned char* plain = nullptr;
            size_t plain_len = 0;
            if (decrypt_vault_blob(testkey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                // good master
                sodium_memzero(plain, plain_len);
                free(plain);
                plain = nullptr;
                vault.erase(it);
                audit_log_level(LogLevel::INFO, "Deletion success for " + label);
                // save
                unsigned char new_nonce[NONCE_LEN];
                std::string ser = serialize_vault(vault);
                if (ser.size() > MAX_VAULT_SIZE / 2) {
                    audit_log_level(LogLevel::ERROR, "serialize_vault too large during deletion save");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                    continue;
                }
                unsigned char* ct2 = nullptr; size_t ct2_len = 0;
                if (!encrypt_vault_blob(key, (const unsigned char*)ser.data(), ser.size(), &ct2, &ct2_len, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Encryption failed on save (delete credential)");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    if (!atomic_write_file(VAULT_FILENAME, ct2, ct2_len) || !save_meta(salt, new_nonce)) {
                        audit_log_level(LogLevel::ERROR, "Failed to persist vault (delete credential)");
                        std::cerr << "An unexpected error occurred. Check audit log.\n";
                    }
                    sodium_memzero(ct2, ct2_len);
                    free(ct2);
                }
            }
            else {
                audit_log_level(LogLevel::WARN, "Deletion attempt failed (wrong master) for " + label);
                std::cout << "Master password check failed. Not deleted.\n";
            }
            sodium_memzero((void*)confirm.data(), confirm.size());
            sodium_memzero(testkey, KEY_LEN);
        }
        else if (choice == "5") {
            std::string label;
            std::cout << "Reveal - Label: "; std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) { std::cout << "Not found\n"; continue; }
            audit_log_level(LogLevel::INFO, "Reveal password requested for " + label);
            std::cout << "Username: " << it->second.username << "\n";
            std::cout << "Password: " << it->second.password << "\n";
            std::cout << "(action logged)\n";
        }
        else if (choice == "6") {
            std::string label;
            std::cout << "Copy - Label: "; std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) { std::cout << "Not found\n"; continue; }
            audit_log_level(LogLevel::INFO, "Copy requested for " + label);

            // Secure buffer allocation (mlock)
            size_t len = it->second.password.size();
            unsigned char* buf = (unsigned char*)malloc(len + 1);
            if (!buf) { std::cout << "Alloc fail\n"; continue; }
            memcpy(buf, it->second.password.data(), len);
            buf[len] = 0;

#if defined(MADV_DONTNEED)
            if (mlock(buf, len + 1) != 0) {
                audit_log_level(LogLevel::WARN, "mlock failed for secure buffer");
            }
#endif

            std::cout << "Password copied to secure buffer (NOT system clipboard). Press Enter to clear it now.\n";
            audit_log_level(LogLevel::INFO, "Credential copied to secure buffer for " + label);
            std::string dummy;
            std::getline(std::cin, dummy);
            // clear buffer
            sodium_memzero(buf, len + 1);
#if defined(MADV_DONTNEED)
            munlock(buf, len + 1);
#endif
            free(buf);
            audit_log_level(LogLevel::INFO, "Secure buffer cleared for " + label);
        }
        else if (choice == "7") {
            running = false;
        }
        else if (choice == "8") {
            std::cout << "WARNING: This will permanently delete your entire vault!\n";
            std::cout << "Type DELETE to confirm: ";
            std::string confirmWord;
            std::getline(std::cin, confirmWord);

            if (confirmWord != "DELETE") {
                std::cout << "Aborted.\n";
                continue;
            }

            std::string masterCheck = get_password("Enter master password to confirm: ");
            unsigned char verifyKey[KEY_LEN];

            if (!load_meta(salt, nonce)) {
                audit_log_level(LogLevel::WARN, "Failed to reload meta before deletion");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            if (!derive_key_from_password(masterCheck, salt, verifyKey)) {
                sodium_memzero((void*)masterCheck.data(), masterCheck.size());
                audit_log_level(LogLevel::WARN, "Vault delete: key derivation failed during verification");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            // Verify correctness of master password by trying a decrypt
            std::vector<unsigned char> ct;
            if (!load_vault_ciphertext(ct)) {
                audit_log_level(LogLevel::ERROR, "Vault delete: no vault found (load failed)");
                std::cout << "No vault file found.\n";
                sodium_memzero((void*)masterCheck.data(), masterCheck.size());
                sodium_memzero(verifyKey, KEY_LEN);
                continue;
            }
            unsigned char* plain = nullptr;
            size_t plain_len = 0;
            if (!decrypt_vault_blob(verifyKey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                audit_log_level(LogLevel::WARN, "Vault delete: incorrect master password");
                std::cout << "Incorrect master password. Aborted.\n";
                sodium_memzero((void*)masterCheck.data(), masterCheck.size());
                sodium_memzero(verifyKey, KEY_LEN);
                continue;
            }
            sodium_memzero(plain, plain_len);
            free(plain);
            sodium_memzero((void*)masterCheck.data(), masterCheck.size());
            sodium_memzero(verifyKey, KEY_LEN);

            // Overwrite vault and meta before deletion
            auto secure_delete_file = [](const char* path) {
                FILE* f = fopen(path, "r+");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long sz = ftell(f);
                    rewind(f);
                    if (sz <= 0 || (unsigned long)sz > MAX_VAULT_SIZE) {
                        fclose(f);
                        unlink(path);
                        return;
                    } // prevents an attacker from replacing vault.bin with a giant file
                    std::vector<unsigned char> zeros(sz, 0);
                    fwrite(zeros.data(), 1, sz, f);
                    fflush(f);
                    fsync(fileno(f));
                    fclose(f);
                }
                unlink(path);
                };

            secure_delete_file(VAULT_FILENAME);
            secure_delete_file(META_FILENAME);

            secure_clear_vault(vault);

            audit_log_level(LogLevel::ALERT, "Vault deleted by user request and memory cleared");

            std::cout << "Vault deleted.\n";
            std::cout << "Do you want to create a new empty vault now? (y/n): ";
            std::string ans;
            std::getline(std::cin, ans);
            if (ans == "y" || ans == "Y") {
                randombytes_buf(salt, SALT_LEN);
                std::string pw1 = get_password("Create new master password: ");
                std::string pw2 = get_password("Confirm new master password: ");
                if (pw1 != pw2) {
                    audit_log_level(LogLevel::WARN, "Vault reinit: passwords did not match");
                    std::cerr << "Passwords do not match. No vault created.\n";
                    sodium_memzero((void*)pw1.data(), pw1.size());
                    sodium_memzero((void*)pw2.data(), pw2.size());
                    continue;
                }
                if (!derive_key_from_password(pw1, salt, key)) {
                    audit_log_level(LogLevel::ERROR, "Vault reinit: key derivation failed");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                    continue;
                }
                Vault newVault;
                std::string ser = serialize_vault(newVault);
                if (ser.size() > MAX_VAULT_SIZE / 2) {
                    audit_log_level(LogLevel::ERROR, "Vault reinit: serialized size too large");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                    continue;
                }
                unsigned char* ct2 = nullptr; size_t ct2_len = 0; unsigned char newNonce[NONCE_LEN];
                if (!encrypt_vault_blob(key, (const unsigned char*)ser.data(), ser.size(), &ct2, &ct2_len, newNonce)) {
                    audit_log_level(LogLevel::ERROR, "Vault reinit: encryption failed");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                    continue;
                }
                if (!atomic_write_file(VAULT_FILENAME, ct2, ct2_len) || !save_meta(salt, newNonce)) {
                    audit_log_level(LogLevel::ERROR, "Vault reinit: failed to save new vault/meta");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    audit_log_level(LogLevel::INFO, "New vault created after deletion");
                    std::cout << "New vault created successfully.\n";
                }
                sodium_memzero(ct2, ct2_len);
                free(ct2);
                sodium_memzero((void*)pw1.data(), pw1.size());
                sodium_memzero((void*)pw2.data(), pw2.size());
                sodium_memzero(key, KEY_LEN);
            }
            else if (ans == "n" || ans == "N") {
                running = false;
            }
        }
        else {
            std::cout << "Unknown choice\n";
        }
    }

    audit_log_level(LogLevel::INFO, "Session closed");
    std::cout << "Goodbye.\n";
    return cleanup_and_exit(0, vault, key, salt, nonce);
}
