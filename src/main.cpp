#include "clipboard.hpp"
#include "passman_common.hpp"
#include "logging.hpp"
#include "util.hpp"
#include "vault.hpp"
#include "crypto.hpp"
#include "io.hpp"
#include "secure_key.hpp"
#include "secure_buffer.hpp"
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <algorithm>
#include <cctype>

// ---------------- Decrypt + deserialize vault ----------------
bool load_vault_decrypted(const byte key[KEY_LEN],
    const byte nonce[NONCE_LEN],
    Vault& out)
{
    out.clear();
    std::vector<byte> ct;
    if (!load_vault_ciphertext(ct)) {
        audit_log_level(LogLevel::ERROR,
            "load_vault_decrypted: cannot read ciphertext",
            "load_vault",
            "failure");
        return false;
    }
    if (ct.empty()) {
        // empty vault - not an error, just no entries
        return true;
    }
    byte* plain = nullptr;
    size_t plain_len = 0;
    if (!decrypt_vault_blob(key,
        ct.data(),
        ct.size(),
        nonce,
        &plain,
        &plain_len)) {
        audit_log_level(LogLevel::ERROR,
            "load_vault_decrypted: decrypt failed",
            "load_vault",
            "failure");
        if (plain) {
            sodium_memzero(plain, plain_len);
            free(plain);
        }
        return false;
    }
    std::string txt;
    if (plain_len > 0) {
        try {
            txt.assign(reinterpret_cast<char*>(plain), plain_len);
        }
        catch (...) {
            audit_log_level(LogLevel::ERROR,
                "load_vault_decrypted: std::string allocation failed",
                "load_vault",
                "failure");
            sodium_memzero(plain, plain_len);
            free(plain);
            return false;
        }
    }
    // wipe and free raw plaintext buffer
    sodium_memzero(plain, plain_len);
    free(plain);
    if (!txt.empty()) {
        out = deserialize_vault(txt);
        sodium_memzero(&txt[0], txt.size());
    }
    else {
        // empty plaintext => empty vault
        out.clear();
    }
    return true;
}

// ---------------- Serialize + encrypt vault ----------------
bool save_vault_encrypted(const byte key[KEY_LEN],
    byte salt[SALT_LEN],
    byte nonce_out[NONCE_LEN],
    const Vault& v)
{
    std::string ser = serialize_vault(v);
    if (ser.size() > MAX_VAULT_SIZE / 2) {
        audit_log_level(LogLevel::ERROR,
            "serialize_vault exceeded safe size",
            "save_vault",
            "failure");
        return false;
    }
    byte* ct = nullptr;
    size_t ct_len = 0;
    byte new_nonce[NONCE_LEN];
    if (!encrypt_vault_blob(key,
        reinterpret_cast<const byte*>(ser.data()),
        ser.size(),
        &ct,
        &ct_len,
        new_nonce)) {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob failed",
            "save_vault",
            "failure");
        return false;
    }
    bool ok = atomic_write_file(g_vault_filename, ct, ct_len) &&
        save_meta(salt, new_nonce);
    if (ok) {
        memcpy(nonce_out, new_nonce, NONCE_LEN);
    }
    // wipe memory
    if (ct && ct_len) {
        sodium_memzero(ct, ct_len);
    }
    free(ct);
    if (!ser.empty()) {
        sodium_memzero(&ser[0], ser.size());
    }
    return ok;
}

// ---------------- helper: check whitespace-only secrets ----------------
static bool is_all_space(const SecureBuffer& b) {
    if (b.size() == 0) return true;
    const byte* p = b.data();
    for (size_t i = 0; i < b.size(); ++i) {
        if (std::isspace(static_cast<unsigned char>(p[i])) == 0) {
            return false;
        }
    }
    return true;
}

// ---------------- input normalization helpers ----------------
static inline void strip_cr(std::string& s) {
    if (!s.empty() && s.back() == '\r') s.pop_back();
}

static inline void trim_spaces(std::string& s) {
    auto first = s.find_first_not_of(" \t");
    auto last = s.find_last_not_of(" \t");
    if (first == std::string::npos) { s.clear(); return; }
    s = s.substr(first, last - first + 1);
}

static inline int parse_choice(const std::string& s) {
    try {
        return std::stoi(s);
    }
    catch (...) {
        return -1;
    }
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
int main() {
    init_log_context();
    audit_log_level(LogLevel::INFO,
        "Password manager starting",
        "session",
        "notify");
    if (!init_vault_paths()) {
        std::fprintf(stderr, "Failed to initialize vault paths.\n");
        audit_log_level(LogLevel::ERROR,
            "Vault path initialization failed",
            "session",
            "failure");
        return 1;
    }
    if (sodium_init() < 0) {
        std::fprintf(stderr, "An unexpected error occurred. Check audit log.\n");
        audit_log_level(LogLevel::ERROR,
            "libsodium initialization failed",
            "session",
            "failure");
        return 1;
    }
    byte salt[SALT_LEN];
    byte nonce[NONCE_LEN];
    SecureKey key(KEY_LEN);

    // ---------------- Vault initialization ----------------
    bool vault_exists =
        (access(g_vault_filename.c_str(), F_OK) == 0 &&
            access(g_meta_filename.c_str(), F_OK) == 0);
    if (!vault_exists) {
        std::cout << "No vault found. Initialize new vault.\n";
        audit_log_level(LogLevel::INFO,
            "No vault detected, starting initialization",
            "vault_init",
            "notify");
        randombytes_buf(salt, SALT_LEN);
        SecureBuffer pw1 = get_password_secure("Create master password: ");
        SecureBuffer pw2 = get_password_secure("Confirm master password: ");
        // disallow empty / whitespace-only
        if (pw1.size() == 0 || is_all_space(pw1) ||
            pw2.size() == 0 || is_all_space(pw2)) {
            audit_log_level(LogLevel::WARN,
                "Vault init failed: empty/whitespace master password",
                "vault_init",
                "failure");
            std::cerr << "Master password cannot be empty or whitespace.\n";
            return cleanup_and_exit(2, salt, nonce);
        }
        if (pw1.size() != pw2.size() ||
            sodium_memcmp(pw1.data(), pw2.data(), pw1.size()) != 0)
        {
            audit_log_level(LogLevel::WARN,
                "Vault init failed: passwords did not match",
                "vault_init",
                "failure");
            std::cerr << "Passwords do not match. Exiting.\n";
            return cleanup_and_exit(2, salt, nonce);
        }
        if (!derive_key_from_password(pw1.data(), pw1.size(), salt, key.data())) {
            audit_log_level(LogLevel::ERROR,
                "Key derivation failed during vault init",
                "vault_init",
                "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            if (pw1.size() != 0) sodium_memzero(pw1.data(), pw1.size());
            if (pw2.size() != 0) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, salt, nonce);
        }
        Vault empty_vault;
        if (!save_vault_encrypted(key.data(), salt, nonce, empty_vault)) {
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            if (pw1.size() != 0) sodium_memzero(pw1.data(), pw1.size());
            if (pw2.size() != 0) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, salt, nonce);
        }
        if (pw1.size() != 0) sodium_memzero(pw1.data(), pw1.size());
        if (pw2.size() != 0) sodium_memzero(pw2.data(), pw2.size());
        sodium_memzero(key.data(), KEY_LEN);
        audit_log_level(LogLevel::INFO,
            "New vault initialized successfully",
            "vault_init",
            "success");
        std::cout << "Vault initialized. Restart to open.\n";
        return cleanup_and_exit(0, salt, nonce);
    }

    // ---------------- Existing vault: ownership & metadata ----------------
    if (!check_file_ownership_and_perms(g_vault_filename, false) ||
        !check_file_ownership_and_perms(g_meta_filename, false)) {
        std::cerr << "Vault files do not meet security requirements.\n";
        audit_log_level(LogLevel::ERROR,
            "Vault file permissions/ownership invalid",
            "session",
            "failure");
        return cleanup_and_exit(2, salt, nonce);
    }
    if (!load_meta(salt, nonce)) {
        std::cerr << "An unexpected error occurred. Check audit log.\n";
        audit_log_level(LogLevel::ERROR,
            "Failed to load vault metadata",
            "load_metadata",
            "failure");
        return cleanup_and_exit(2, salt, nonce);
    }

    // ---------------- Master password unlock ----------------
    const unsigned MAX_ATTEMPTS = 5;
    unsigned attempts = 0;
    bool authenticated = false;
    while (attempts < MAX_ATTEMPTS) {
        SecureBuffer master = get_password_secure("Master password: ");
        if (master.size() == 0 || is_all_space(master) ||
            master.size() > MAX_PASS_LEN) {
            attempts++;
            audit_log_level(LogLevel::WARN,
                "Empty/invalid master password during unlock",
                "load_vault",
                "failure");
            if (master.size() != 0) {
                sodium_memzero(master.data(), master.size());
            }
            if (attempts >= MAX_ATTEMPTS) break;
            std::cout << "Invalid master password.\n";
            continue;
        }
        if (!derive_key_from_password(master.data(), master.size(), salt, key.data())) {
            attempts++;
            audit_log_level(LogLevel::WARN,
                "Key derivation failed during unlock",
                "load_vault",
                "failure");
            sodium_memzero(key.data(), KEY_LEN);
            if (attempts >= MAX_ATTEMPTS) break;
            std::cout << "Master password incorrect.\n";
            continue;
        }
        Vault tmp;
        if (load_vault_decrypted(key.data(), nonce, tmp)) {
            secure_clear_vault(tmp);
            authenticated = true;
            audit_log_level(LogLevel::INFO,
                "Master password accepted - session opened",
                "session",
                "success");
            break;
        }
        else {
            attempts++;
            audit_log_level(LogLevel::WARN,
                "Failed master password attempt",
                "load_vault",
                "failure");
            sodium_memzero(master.data(), master.size());
            sodium_memzero(key.data(), KEY_LEN);
        }
    }
    if (!authenticated) {
        std::cerr << "Too many failed attempts; exiting.\n";
        audit_log_level(LogLevel::ALERT,
            "Too many failed master password attempts - lockout",
            "load_vault",
            "failure");
        return cleanup_and_exit(3, salt, nonce);
    }

    // ---------------- Start inactivity timer ----------------
    g_timer_running = true;
    g_reset_timer = true;
    start_inactivity_timer([&]() {
        std::cout << "\n[!] Logged out due to inactivity.\n";
        audit_log_level(LogLevel::INFO,
            "Session closed due to inactivity timeout",
            "session_timeout",
            "success");
#if defined(_WIN32)
        CloseHandle(GetStdHandle(STD_INPUT_HANDLE));
#else
        close(STDIN_FILENO); // break getline()
#endif
        g_timer_running = false;
        cleanup_and_exit(0, salt, nonce);
        });

    // ---------------- Main CLI loop ----------------
    bool running = true;
    while (running) {
        print_menu();
        std::cout << "> ";
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            break; // EOF or stdin closed
        }
        strip_cr(choice);
        trim_spaces(choice);
        g_reset_timer = true;

        int opt = parse_choice(choice);
        switch (opt) {
        case 1: {
            audit_log_level(LogLevel::INFO,
                "Listing credential labels",
                "list_creds",
                "notify");
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::cout << "Stored credentials:\n";
            for (auto& p : v) {
                std::cout << " - " << p.first << "\n";
            }
            secure_clear_vault(v);
            break;
        }
        case 2: {
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::string label, user, notes;
            std::cout << "+New - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            if (!valid_label_or_username(label)) {
                std::cout << "Invalid label\n";
                audit_log_level(LogLevel::WARN,
                    "Invalid label during add_cred",
                    "add_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            std::cout << " Username: ";
            if (!std::getline(std::cin, user)) break;
            g_reset_timer = true;
            if (!valid_label_or_username(user)) {
                std::cout << "Invalid username\n";
                audit_log_level(LogLevel::WARN,
                    "Invalid username during add_cred",
                    "add_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            SecureBuffer pw_vec = get_password_secure(" Password: ");
            g_reset_timer = true;
            if (pw_vec.size() == 0 || pw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid password\n";
                audit_log_level(LogLevel::WARN,
                    "Invalid password during add_cred",
                    "add_cred",
                    "failure");
                if (pw_vec.size() != 0) {
                    sodium_memzero(pw_vec.data(), pw_vec.size());
                }
                secure_clear_vault(v);
                break;
            }
            std::cout << " Notes (optional): ";
            if (!std::getline(std::cin, notes)) break;
            g_reset_timer = true;
            if (notes.size() > MAX_NOTES_LEN) {
                std::cout << "Notes too long\n";
                audit_log_level(LogLevel::WARN,
                    "Notes too long during add_cred",
                    "add_cred",
                    "failure");
                if (pw_vec.size() != 0) {
                    sodium_memzero(pw_vec.data(), pw_vec.size());
                }
                secure_clear_vault(v);
                break;
            }
            std::string pw(reinterpret_cast<char*>(pw_vec.data()), pw_vec.size());
            sodium_memzero(pw_vec.data(), pw_vec.size());
            Cred c;
            c.label = label;
            c.username = user;
            c.password = pw;
            c.notes = notes;
            v[label] = std::move(c);
            if (!save_vault_encrypted(key.data(), salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    std::string("Credential added: ") + label,
                    "add_cred",
                    "success");
            }
            if (!pw.empty()) sodium_memzero(&pw[0], pw.size());
            secure_clear_vault(v);
            break;
        }
        case 3: {
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::string label;
            std::cout << "Update - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Update requested for non-existent label: ") + label,
                    "upd_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            SecureBuffer oldpw_vec = get_password_secure("Old password: ");
            g_reset_timer = true;
            if (oldpw_vec.size() == 0 || oldpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid old password\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Invalid old password during update for: ") + label,
                    "upd_cred",
                    "failure");
                if (oldpw_vec.size() != 0) {
                    sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
                }
                secure_clear_vault(v);
                break;
            }
            bool match = false;
            if (oldpw_vec.size() == it->second.password.size()) {
                match = (sodium_memcmp(
                    oldpw_vec.data(),
                    reinterpret_cast<const byte*>(it->second.password.data()),
                    oldpw_vec.size()) == 0);
            }
            sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
            if (!match) {
                audit_log_level(LogLevel::WARN,
                    std::string("Old password mismatch on update for: ") + label,
                    "upd_cred",
                    "failure");
                std::cout << "Old password mismatch\n";
                secure_clear_vault(v);
                break;
            }
            SecureBuffer newpw_vec = get_password_secure("New password: ");
            g_reset_timer = true;
            if (newpw_vec.size() == 0 || newpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid new password\n";
                audit_log_level(LogLevel::WARN,
                    std::string("New password invalid on update for: ") + label,
                    "upd_cred",
                    "failure");
                if (newpw_vec.size() != 0) {
                    sodium_memzero(newpw_vec.data(), newpw_vec.size());
                }
                secure_clear_vault(v);
                break;
            }
            std::string newpw(reinterpret_cast<char*>(newpw_vec.data()), newpw_vec.size());
            sodium_memzero(newpw_vec.data(), newpw_vec.size());
            it->second.password = newpw;
            if (!save_vault_encrypted(key.data(), salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    std::string("Update success for: ") + label,
                    "upd_cred",
                    "success");
            }
            if (!newpw.empty()) sodium_memzero(&newpw[0], newpw.size());
            secure_clear_vault(v);
            break;
        }
        case 4: {
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::string label;
            std::cout << "Delete - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Deletion requested for non-existent label: ") + label,
                    "del_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            audit_log_level(LogLevel::INFO,
                std::string("Deletion attempt for: ") + label,
                "del_cred",
                "notify");
            SecureBuffer confirm = get_password_secure("Type MASTER password to confirm deletion: ");
            g_reset_timer = true;
            if (confirm.size() == 0 || is_all_space(confirm)) {
                std::cout << "Invalid input\n";
                secure_clear_vault(v);
                if (confirm.size() != 0) {
                    sodium_memzero(confirm.data(), confirm.size());
                }
                break;
            }
            SecureKey verifyKey(KEY_LEN);
            if (!derive_key_from_password(confirm.data(), confirm.size(),
                salt, verifyKey.data())) {
                audit_log_level(LogLevel::WARN,
                    "Key derivation failed while verifying master for deletion",
                    "del_cred",
                    "failure");
                sodium_memzero(confirm.data(), confirm.size());
                std::cout << "Master password check failed.\n";
                secure_clear_vault(v);
                break;
            }
            Vault validate_vault;
            if (!load_vault_decrypted(verifyKey.data(), nonce, validate_vault)) {
                audit_log_level(LogLevel::WARN,
                    "Incorrect master password for deletion check",
                    "del_cred",
                    "failure");
                sodium_memzero(confirm.data(), confirm.size());
                std::cout << "Master password check failed.\n";
                secure_clear_vault(v);
                secure_clear_vault(validate_vault);
                break;
            }
            secure_clear_vault(validate_vault);
            sodium_memzero(confirm.data(), confirm.size());
            v.erase(it);
            if (!save_vault_encrypted(key.data(), salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    std::string("Deletion success for: ") + label,
                    "del_cred",
                    "success");
            }
            secure_clear_vault(v);
            break;
        }
        case 5: {
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::string label;
            std::cout << "Reveal - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Reveal requested for non-existent label: ") + label,
                    "reveal_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            audit_log_level(LogLevel::INFO,
                std::string("Revealed credential for: ") + label,
                "reveal_cred",
                "success");
            std::cout << "Username: " << it->second.username << "\n";
            std::cout << "Password: " << it->second.password << "\n";
            std::cout << "Notes: " << it->second.notes << "\n";
            secure_clear_vault(v);
            break;
        }
        case 6: {
            Vault v;
            if (!load_vault_decrypted(key.data(), nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                break;
            }
            std::string label;
            std::cout << "Copy - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Clipboard copy requested for non-existent label: ") + label,
                    "clip_cred",
                    "failure");
                secure_clear_vault(v);
                break;
            }
            if (windows_clipboard_history_enabled()) {
                std::cout << "Caution: you have Clipboard History enabled! (Win + V)\n";
                std::cout << "Any secret you copy will remain in there. We advise you to disable it to avoid leaking sensitive info.\n";
            }
            if (clipboard_set(it->second.password)) {
                std::cout << "Password copied to clipboard for 15 seconds.\n";
                copy_with_timed_clear(it->second.password, 15);
                audit_log_level(LogLevel::INFO,
                    std::string("Clipboard copy success for: ") + label,
                    "clip_cred",
                    "success");
            }
            else {
                std::cout << "Failed to copy to clipboard.\n";
                audit_log_level(LogLevel::WARN,
                    std::string("Clipboard copy failed for: ") + label,
                    "clip_cred",
                    "failure");
            }
            secure_clear_vault(v);
            break;
        }
        case 7: {
            running = false;
            break;
        }
        case 8: {
            std::cout << "This will delete the entire vault, audit log and metadata.\n";
            SecureBuffer masterCheck =
                get_password_secure("Type MASTER password to confirm vault delete: ");
            g_reset_timer = true;
            if (masterCheck.size() == 0 || is_all_space(masterCheck)) {
                std::cout << "Invalid master password.\n";
                audit_log_level(LogLevel::WARN,
                    "Empty master password during vault delete confirmation",
                    "del_vault",
                    "failure");
                if (masterCheck.size() != 0) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                }
                break;
            }
            SecureKey verifyKey(KEY_LEN);
            if (!derive_key_from_password(masterCheck.data(), masterCheck.size(),
                salt, verifyKey.data())) {
                audit_log_level(LogLevel::WARN,
                    "Key derivation failed during vault delete verification",
                    "del_vault",
                    "failure");
                if (masterCheck.size() != 0) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                }
                std::cout << "Key derivation failed.\n";
                break;
            }
            Vault test;
            if (!load_vault_decrypted(verifyKey.data(), nonce, test)) {
                audit_log_level(LogLevel::WARN,
                    "Incorrect master password for vault delete",
                    "del_vault",
                    "failure");
                if (masterCheck.size() != 0) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                }
                std::cout << "Incorrect master password. Aborted.\n";
                secure_clear_vault(test);
                break;
            }
            if (masterCheck.size() != 0) {
                sodium_memzero(masterCheck.data(), masterCheck.size());
            }
            secure_clear_vault(test);
            secure_delete_file(g_vault_filename.c_str());
            secure_delete_file(g_meta_filename.c_str());
            secure_delete_file(g_audit_log_path.c_str());
            audit_log_level(LogLevel::ALERT,
                "Vault deleted by user",
                "del_vault",
                "success");
            std::cout << "Vault deleted\n";
            running = false;
            break;
        }
        default:
            std::cout << "Unknown option\n";
            break;
        }
    }

    g_timer_running = false;
    clear_screen();
    std::cout << "Goodbye.\n";
    audit_log_level(LogLevel::INFO,
        "Session ended normally",
        "session",
        "success");
    return cleanup_and_exit(0, salt, nonce);
}
