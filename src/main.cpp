#include "clipboard.hpp"
#include "passman_common.hpp"
#include "logging.hpp"
#include "util.hpp"
#include "vault.hpp"
#include "crypto.hpp"
#include "io.hpp"

#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <algorithm>


// -------- Decrypt + deserialize vault --------
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


// -------- Serialize + encrypt vault --------
bool save_vault_encrypted(const byte key[KEY_LEN],
    byte        salt[SALT_LEN],
    byte        nonce_out[NONCE_LEN],
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


// -------- Small helper: check whitespace-only secrets --------
static bool is_all_space(const std::vector<byte>& v) {
    if (v.empty()) return true;
    return std::all_of(v.begin(), v.end(), [](byte c) {
        return std::isspace(static_cast<unsigned char>(c)) != 0;
        });
}



// --------------------------------------------------------
//                             main
// --------------------------------------------------------
int main() {
    init_log_context();
    audit_log_level(LogLevel::INFO,
        "Password manager starting",
        "session",
        "notify");

    if (!init_vault_paths_interactive()) {
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
    byte key[KEY_LEN];      sodium_memzero(key, KEY_LEN);
    byte nonce[NONCE_LEN];  sodium_memzero(nonce, NONCE_LEN);

    // ---------------- Vault initialization (first run) ----------------
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

        std::vector<byte> pw1 = get_password_bytes("Create master password: ");
        std::vector<byte> pw2 = get_password_bytes("Confirm master password: ");

        // disallow empty / whitespace-only
        if (pw1.empty() || is_all_space(pw1) ||
            pw2.empty() || is_all_space(pw2)) {
            audit_log_level(LogLevel::WARN,
                "Vault init failed: empty/whitespace master password",
                "vault_init",
                "failure");
            std::cerr << "Master password cannot be empty or whitespace.\n";
            if (!pw1.empty()) sodium_memzero(pw1.data(), pw1.size());
            if (!pw2.empty()) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, key, salt, nonce);
        }

        if (pw1 != pw2) {
            audit_log_level(LogLevel::WARN,
                "Vault init failed: passwords did not match",
                "vault_init",
                "failure");
            std::cerr << "Passwords do not match. Exiting.\n";
            if (!pw1.empty()) sodium_memzero(pw1.data(), pw1.size());
            if (!pw2.empty()) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, key, salt, nonce);
        }

        if (!derive_key_from_password(pw1.data(), pw1.size(), salt, key)) {
            audit_log_level(LogLevel::ERROR,
                "Key derivation failed during vault init",
                "vault_init",
                "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            if (!pw1.empty()) sodium_memzero(pw1.data(), pw1.size());
            if (!pw2.empty()) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, key, salt, nonce);
        }

        Vault empty_vault;
        if (!save_vault_encrypted(key, salt, nonce, empty_vault)) {
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            if (!pw1.empty()) sodium_memzero(pw1.data(), pw1.size());
            if (!pw2.empty()) sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, key, salt, nonce);
        }

        if (!pw1.empty()) sodium_memzero(pw1.data(), pw1.size());
        if (!pw2.empty()) sodium_memzero(pw2.data(), pw2.size());
        sodium_memzero(key, KEY_LEN);

        audit_log_level(LogLevel::INFO,
            "New vault initialized successfully",
            "vault_init",
            "success");

        std::cout << "Vault initialized. Restart to open.\n";
        return cleanup_and_exit(0, key, salt, nonce);
    }

    // ---------------- Existing vault: ownership & metadata ----------------
    if (!check_file_ownership_and_perms(g_vault_filename, false) ||
        !check_file_ownership_and_perms(g_meta_filename, false)) {
        std::cerr << "Vault files do not meet security requirements.\n";
        audit_log_level(LogLevel::ERROR,
            "Vault file permissions/ownership invalid",
            "session",
            "failure");
        return cleanup_and_exit(2, key, salt, nonce);
    }

    if (!load_meta(salt, nonce)) {
        std::cerr << "An unexpected error occurred. Check audit log.\n";
        audit_log_level(LogLevel::ERROR,
            "Failed to load vault metadata",
            "load_metadata",
            "failure");
        return cleanup_and_exit(2, key, salt, nonce);
    }

    // ---------------- Master password unlock ----------------
    const unsigned MAX_ATTEMPTS = 5;
    unsigned attempts = 0;
    bool authenticated = false;

    while (attempts < MAX_ATTEMPTS) {
        std::vector<byte> master = get_password_bytes("Master password: ");
        if (master.empty() || is_all_space(master) ||
            master.size() > MAX_PASS_LEN) {
            attempts++;
            audit_log_level(LogLevel::WARN,
                "Empty/invalid master password during unlock",
                "load_vault",
                "failure");
            if (!master.empty()) {
                sodium_memzero(master.data(), master.size());
            }
            if (attempts >= MAX_ATTEMPTS) break;
            std::cout << "Invalid master password.\n";
            continue;
        }

        if (!derive_key_from_password(master.data(), master.size(), salt, key)) {
            attempts++;
            audit_log_level(LogLevel::WARN,
                "Key derivation failed during unlock",
                "load_vault",
                "failure");
            sodium_memzero(master.data(), master.size());
            sodium_memzero(key, KEY_LEN);
            if (attempts >= MAX_ATTEMPTS) break;
            std::cout << "Master password incorrect.\n";
            continue;
        }

        Vault tmp;
        if (load_vault_decrypted(key, nonce, tmp)) {
            secure_clear_vault(tmp);
            sodium_memzero(master.data(), master.size());
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
            sodium_memzero(key, KEY_LEN);
        }
    }

    if (!authenticated) {
        std::cerr << "Too many failed attempts; exiting.\n";
        audit_log_level(LogLevel::ALERT,
            "Too many failed master password attempts - lockout",
            "load_vault",
            "failure");
        return cleanup_and_exit(3, key, salt, nonce);
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
        return cleanup_and_exit(0, key, salt, nonce);
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

        // hard length limit for menu choice
        if (choice.size() > 3) {
            std::cout << "Invalid choice.\n";
            continue;
        }

        g_reset_timer = true;

        // -------- 1) List credentials --------
        if (choice == "1") {
            audit_log_level(LogLevel::INFO,
                "Listing credential labels",
                "list_creds",
                "notify");

            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
            }

            std::cout << "Stored credentials:\n";
            for (auto& p : v) {
                std::cout << " - " << p.first << "\n";
            }
            secure_clear_vault(v);
        }

        // -------- 2) Add credential --------
        else if (choice == "2") {
            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
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
                continue;
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
                continue;
            }

            std::vector<byte> pw_vec = get_password_bytes(" Password: ");
            g_reset_timer = true;
            if (pw_vec.empty() || pw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid password\n";
                audit_log_level(LogLevel::WARN,
                    "Invalid password during add_cred",
                    "add_cred",
                    "failure");
                if (!pw_vec.empty()) {
                    sodium_memzero(pw_vec.data(), pw_vec.size());
                    pw_vec.clear();
                }
                secure_clear_vault(v);
                continue;
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
                if (!pw_vec.empty()) {
                    sodium_memzero(pw_vec.data(), pw_vec.size());
                    pw_vec.clear();
                }
                secure_clear_vault(v);
                continue;
            }

            std::string pw(pw_vec.begin(), pw_vec.end());
            sodium_memzero(pw_vec.data(), pw_vec.size());
            pw_vec.clear();

            Cred c;
            c.label = label;
            c.username = user;
            c.password = pw;
            c.notes = notes;
            v[label] = std::move(c);

            if (!save_vault_encrypted(key, salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    "Credential added: " + label,
                    "add_cred",
                    "success");
            }

            if (!pw.empty()) sodium_memzero(&pw[0], pw.size());
            secure_clear_vault(v);
        }

        // -------- 3) Update credential --------
        else if (choice == "3") {
            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
            }

            std::string label;
            std::cout << "Update - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    "Update requested for non-existent label: " + label,
                    "upd_cred",
                    "failure");
                secure_clear_vault(v);
                continue;
            }

            std::vector<byte> oldpw_vec = get_password_bytes("Old password: ");
            g_reset_timer = true;
            if (oldpw_vec.empty() || oldpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid old password\n";
                audit_log_level(LogLevel::WARN,
                    "Invalid old password during update for: " + label,
                    "upd_cred",
                    "failure");
                if (!oldpw_vec.empty()) {
                    sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
                    oldpw_vec.clear();
                }
                secure_clear_vault(v);
                continue;
            }

            bool match = false;
            if (oldpw_vec.size() == it->second.password.size()) {
                match = (sodium_memcmp(
                    oldpw_vec.data(),
                    reinterpret_cast<const byte*>(it->second.password.data()),
                    oldpw_vec.size()) == 0);
            }

            sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
            oldpw_vec.clear();

            if (!match) {
                audit_log_level(LogLevel::WARN,
                    "Old password mismatch on update for: " + label,
                    "upd_cred",
                    "failure");
                std::cout << "Old password mismatch\n";
                secure_clear_vault(v);
                continue;
            }

            std::vector<byte> newpw_vec = get_password_bytes("New password: ");
            g_reset_timer = true;
            if (newpw_vec.empty() || newpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid new password\n";
                audit_log_level(LogLevel::WARN,
                    "New password invalid on update for: " + label,
                    "upd_cred",
                    "failure");
                if (!newpw_vec.empty()) {
                    sodium_memzero(newpw_vec.data(), newpw_vec.size());
                    newpw_vec.clear();
                }
                secure_clear_vault(v);
                continue;
            }

            std::string newpw(newpw_vec.begin(), newpw_vec.end());
            sodium_memzero(newpw_vec.data(), newpw_vec.size());
            newpw_vec.clear();

            it->second.password = newpw;

            if (!save_vault_encrypted(key, salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    "Update success for: " + label,
                    "upd_cred",
                    "success");
            }

            if (!newpw.empty()) sodium_memzero(&newpw[0], newpw.size());
            secure_clear_vault(v);
        }

        // -------- 4) Delete credential --------
        else if (choice == "4") {
            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
            }

            std::string label;
            std::cout << "Delete - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    "Deletion requested for non-existent label: " + label,
                    "del_cred",
                    "failure");
                secure_clear_vault(v);
                continue;
            }

            audit_log_level(LogLevel::INFO,
                "Deletion attempt for: " + label,
                "del_cred",
                "notify");

            std::vector<byte> confirm =
                get_password_bytes("Type MASTER password to confirm deletion: ");
            g_reset_timer = true;
            if (confirm.empty() || is_all_space(confirm)) {
                std::cout << "Invalid input\n";
                secure_clear_vault(v);
                if (!confirm.empty()) {
                    sodium_memzero(confirm.data(), confirm.size());
                    confirm.clear();
                }
                continue;
            }

            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);

            if (!derive_key_from_password(confirm.data(), confirm.size(),
                salt, verifyKey)) {
                audit_log_level(LogLevel::WARN,
                    "Key derivation failed while verifying master for deletion",
                    "del_cred",
                    "failure");
                sodium_memzero(confirm.data(), confirm.size());
                confirm.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Master password check failed.\n";
                secure_clear_vault(v);
                continue;
            }

            Vault validate_vault;
            if (!load_vault_decrypted(verifyKey, nonce, validate_vault)) {
                audit_log_level(LogLevel::WARN,
                    "Incorrect master password for deletion check",
                    "del_cred",
                    "failure");
                sodium_memzero(confirm.data(), confirm.size());
                confirm.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Master password check failed.\n";
                secure_clear_vault(v);
                secure_clear_vault(validate_vault);
                continue;
            }

            secure_clear_vault(validate_vault);
            sodium_memzero(confirm.data(), confirm.size());
            confirm.clear();
            sodium_memzero(verifyKey, KEY_LEN);

            v.erase(it);

            if (!save_vault_encrypted(key, salt, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                audit_log_level(LogLevel::INFO,
                    "Deletion success for: " + label,
                    "del_cred",
                    "success");
            }

            secure_clear_vault(v);
        }

        // -------- 5) Reveal credential (logs action) --------
        else if (choice == "5") {
            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
            }

            std::string label;
            std::cout << "Reveal - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    "Reveal requested for non-existent label: " + label,
                    "reveal_cred",
                    "failure");
                secure_clear_vault(v);
                continue;
            }

            audit_log_level(LogLevel::INFO,
                "Revealed credential for: " + label,
                "reveal_cred",
                "success");

            std::cout << "Username: " << it->second.username << "\n";
            std::cout << "Password: " << it->second.password << "\n";
            std::cout << "Notes: " << it->second.notes << "\n";

            secure_clear_vault(v);
        }

        // -------- 6) Copy credential to secure buffer --------
        else if (choice == "6") {
            Vault v;
            if (!load_vault_decrypted(key, nonce, v)) {
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                secure_clear_vault(v);
                continue;
            }

            std::string label;
            std::cout << "Copy - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = v.find(label);
            if (it == v.end()) {
                std::cout << "Not found\n";
                audit_log_level(LogLevel::WARN,
                    "Clipboard copy requested for non-existent label: " + label,
                    "clip_cred",
                    "failure");
                secure_clear_vault(v);
                continue;
            }

            copy_with_timed_clear(it->second.password, 15);

            std::cout << "Password copied to clipboard for 15 seconds.\n";

            audit_log_level(LogLevel::INFO,
                "Clipboard copy success for: " + label,
                "clip_cred",
                "success");

            secure_clear_vault(v);
        }

        // -------- 7) Quit --------
        else if (choice == "7") {
            running = false;
        }

        // -------- 8) Delete current vault --------
        else if (choice == "8") {
            std::cout << "This will delete the entire vault, audit log and metadata.\n";

            std::vector<byte> masterCheck =
                get_password_bytes("Type MASTER password to confirm vault delete: ");
            g_reset_timer = true;
            if (masterCheck.empty() || is_all_space(masterCheck)) {
                std::cout << "Invalid master password.\n";
                audit_log_level(LogLevel::WARN,
                    "Empty master password during vault delete confirmation",
                    "del_vault",
                    "failure");
                if (!masterCheck.empty()) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                    masterCheck.clear();
                }
                continue;
            }

            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);
            if (!derive_key_from_password(masterCheck.data(), masterCheck.size(),
                salt, verifyKey)) {
                audit_log_level(LogLevel::WARN,
                    "Key derivation failed during vault delete verification",
                    "del_vault",
                    "failure");
                if (!masterCheck.empty()) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                    masterCheck.clear();
                }
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Key derivation failed.\n";
                continue;
            }

            Vault test;
            if (!load_vault_decrypted(verifyKey, nonce, test)) {
                audit_log_level(LogLevel::WARN,
                    "Incorrect master password for vault delete",
                    "del_vault",
                    "failure");
                if (!masterCheck.empty()) {
                    sodium_memzero(masterCheck.data(), masterCheck.size());
                    masterCheck.clear();
                }
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Incorrect master password. Aborted.\n";
                secure_clear_vault(test);
                continue;
            }

            if (!masterCheck.empty()) {
                sodium_memzero(masterCheck.data(), masterCheck.size());
                masterCheck.clear();
            }
            sodium_memzero(verifyKey, KEY_LEN);
            secure_clear_vault(test);

            secure_delete_file(g_vault_filename.c_str());
            secure_delete_file(g_meta_filename.c_str());
            secure_delete_file(g_audit_log_path.c_str());

            audit_log_level(LogLevel::ALERT,
                "Vault deleted by user",
                "del_vault",
                "success");

            std::cout << "Vault deleted.\n";
            running = false;
        }

        else {
            std::cout << "Unknown option\n";
        }
    }

    g_timer_running = false;
    clear_screen();
    std::cout << "Goodbye.\n";
    audit_log_level(LogLevel::INFO,
        "Session ended normally",
        "session",
        "success");

    return cleanup_and_exit(2, key, salt, nonce);
}
