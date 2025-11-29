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

// ---------------- Inactivity timer implementation ----------------
static std::atomic<bool> g_reset_timer{ false };
static std::atomic<bool> g_timer_running{ true };
constexpr int INACTIVITY_LIMIT = 15; // seconds

static void start_inactivity_timer(std::function<void()> on_timeout) {
    std::thread([on_timeout]() {
        int remaining = INACTIVITY_LIMIT;
        while (g_timer_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (g_reset_timer.exchange(false)) {
                remaining = INACTIVITY_LIMIT;
            }
            else {
                remaining--;
                if (remaining <= 0) {
                    on_timeout();
                    return;
                }
            }
        }
        }).detach();
}

int main() {
    init_log_context();

    if (!init_vault_paths_interactive()) {
        std::fprintf(stderr, "Failed to initialize vault paths.\n");
        return 1;
    }

    if (sodium_init() < 0) {
        std::fprintf(stderr, "An unexpected error occurred. Check audit log for details.\n");
        audit_log_level(LogLevel::ERROR, "libsodium init failed", "sodium_init", "failure");
        return 1;
    }

    Vault vault;
    byte salt[SALT_LEN];
    byte key[KEY_LEN];
    sodium_memzero(key, KEY_LEN);
    byte nonce[NONCE_LEN];
    sodium_memzero(nonce, NONCE_LEN);

    // Check if vault exists; if not, run init
    bool vault_exists = (access(g_vault_filename.c_str(), F_OK) == 0 &&
        access(g_meta_filename.c_str(), F_OK) == 0);
    if (!vault_exists) {
        std::cout << "No vault found. Initialize new vault.\n";
        // generate salt and ask master password twice
        randombytes_buf(salt, SALT_LEN);
        std::vector<byte> pw1 = get_password_bytes("Create master password: ");
        std::vector<byte> pw2 = get_password_bytes("Confirm master password: ");
        if (pw1 != pw2) {
            audit_log_level(LogLevel::WARN, "Vault init: passwords did not match", "vault_init", "failure");
            std::cerr << "Passwords do not match. Exiting.\n";
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        if (!derive_key_from_password(pw1.data(), pw1.size(), salt, key)) {
            audit_log_level(LogLevel::ERROR, "Vault init: key derivation failed", "vault_init", "failure");
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        // empty vault encrypt
        std::string ser = serialize_vault(vault);
        byte* ct = nullptr;
        size_t ct_len = 0;
        byte new_nonce[NONCE_LEN];
        if (!encrypt_vault_blob(key,
            reinterpret_cast<const byte*>(ser.data()),
            ser.size(),
            &ct, &ct_len, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: encrypt_vault_blob failed", "vault_init", "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        // atomic write vault
        if (ct_len > MAX_VAULT_SIZE) {
            audit_log_level(LogLevel::ERROR, "Vault init: ciphertext too large", "vault_init", "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        if (!atomic_write_file(g_vault_filename, ct, ct_len) || !save_meta(salt, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: saving vault/meta failed", "vault_init", "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        sodium_memzero(ct, ct_len);
        free(ct);
        sodium_memzero(pw1.data(), pw1.size());
        sodium_memzero(pw2.data(), pw2.size());
        sodium_memzero(key, KEY_LEN);
        std::cout << "Vault initialized. Restart to open.\n";
        audit_log_level(LogLevel::INFO, "New vault initialized", "vault_init", "success");
        return 0;
    }

    // For existing vaults, re-check per-user ownership on files
    if (!check_file_ownership_and_perms(g_vault_filename, false) ||
        !check_file_ownership_and_perms(g_meta_filename, false)) {
        std::cerr << "Vault files do not meet security requirements.\n";
        return cleanup_and_exit(2, vault, key, salt, nonce);
    }

    // Loading metadata
    if (!load_meta(salt, nonce)) {
        audit_log_level(LogLevel::ERROR, "Failed to load vault metadata", "load_metadata", "failure");
        std::cerr << "An unexpected error occurred. Check audit log.\n";
        return cleanup_and_exit(2, vault, key, salt, nonce);
    }

    unsigned attempts = 0;
    const unsigned MAX_ATTEMPTS = 5;
    bool authenticated = false;

    // Vault exists -> prompt for master password
    while (attempts < MAX_ATTEMPTS) {
        std::vector<byte> master = get_password_bytes("Master password: ");
        if (master.empty()) {
            attempts++;
            audit_log_level(LogLevel::WARN, "Empty master password input");
            continue;
        }
        if (!derive_key_from_password(master.data(), master.size(), salt, key)) {
            attempts++;
            audit_log_level(LogLevel::WARN, "derive_key_from_password failed during unlock", "load_vault", "failure");
            sodium_memzero(master.data(), master.size());
            continue;
        }
        // try decrypting
        std::vector<byte> ct;
        if (!load_vault_ciphertext(ct)) {
            audit_log_level(LogLevel::ERROR, "Unable to read vault ciphertext", "load_vault", "failure");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(master.data(), master.size());
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        byte* plain = nullptr;
        size_t plain_len = 0;
        if (decrypt_vault_blob(key, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
            // success
            std::string txt(reinterpret_cast<char*>(plain), plain_len);
            vault = deserialize_vault(txt);
            sodium_memzero(plain, plain_len);
            free(plain);
            sodium_memzero(master.data(), master.size());
            authenticated = true;
            audit_log_level(LogLevel::INFO, "Master password accepted - session opened", "load_vault", "success");
            break;
        }
        else {
            attempts++;
            audit_log_level(LogLevel::WARN, "Failed master password attempt", "load_vault", "failure");
            sodium_memzero(master.data(), master.size());
            sodium_memzero(key, KEY_LEN);
        }
    }

    if (!authenticated) {
        audit_log_level(LogLevel::ALERT, "Too many failed master attempts - lockout", "load_vault", "failure");
        std::cerr << "Too many failed attempts; exiting.\n";
        return cleanup_and_exit(3, vault, key, salt, nonce);
    }

    audit_log_level(LogLevel::INFO, "Master password accepted - session opened", "load_vault", "success");

    // Start inactivity timer ONCE after successful authentication
    g_reset_timer = true;
    g_timer_running = true;
    start_inactivity_timer([]() {
        std::cout << "\n[!] Logged out due to inactivity.\n";
#if defined(_WIN32)
        CloseHandle(GetStdHandle(STD_INPUT_HANDLE));
#else
        close(STDIN_FILENO); // break blocking getline()
#endif
        g_timer_running = false;
        });

    // Main CLI loop
    bool running = true;
    while (running) {
        print_menu();
        std::cout << "> ";
        std::string choice;
        if (!std::getline(std::cin, choice)) {
            break; // EOF or stdin closed (e.g., timeout)
        }
        g_reset_timer = true;

        if (choice == "1") { // ------ List credentials ------
            std::cout << "Stored credentials:\n";
            for (auto& p : vault) {
                std::cout << " - " << p.first << "\n";
            }
        }
        else if (choice == "2") { // ------ Add new credentials ------
            std::string label, user, notes;

            std::cout << "+New - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;
            if (!valid_label_or_username(label)) {
                std::cout << "Invalid label\n";
                continue;
            }

            std::cout << " Username: ";
            if (!std::getline(std::cin, user)) break;
            g_reset_timer = true;
            if (!valid_label_or_username(user)) {
                std::cout << "Invalid username\n";
                continue;
            }

            std::cout << " Password (leave empty to prompt hidden): ";
            std::string tmp;
            if (!std::getline(std::cin, tmp)) break;
            g_reset_timer = true;

            std::vector<byte> pwvec;
            if (tmp.empty()) {
                pwvec = get_password_bytes("Password: ");
                g_reset_timer = true;
            }
            else {
                pwvec.assign(tmp.begin(), tmp.end());
            }

            if (pwvec.empty()) {
                std::cout << "Password empty\n";
                continue;
            }

            std::string pass(pwvec.begin(), pwvec.end());
            sodium_memzero(pwvec.data(), pwvec.size());
            pwvec.clear();

            if (!valid_password(pass)) {
                std::cout << "Invalid password\n";
                sodium_memzero((void*)pass.data(), pass.size());
                continue;
            }

            std::cout << " Notes: ";
            if (!std::getline(std::cin, notes)) break;
            g_reset_timer = true;
            if (notes.size() > 4096) notes.resize(4096);

            Cred c{ label, user, pass, notes };
            vault[label] = c;
            audit_log_level(LogLevel::INFO, "Added credential: " + label, "add_cred", "success");

            // persist
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR,
                    "serialize_vault produced excessively large output",
                    "add_cred", "failure");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            byte* ct = nullptr;
            size_t ct_len = 0;
            byte new_nonce[NONCE_LEN];
            if (!encrypt_vault_blob(key,
                reinterpret_cast<const byte*>(ser.data()),
                ser.size(),
                &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR,
                    "Encryption failed on save (add credential)",
                    "add_cred", "failure");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(g_vault_filename, ct, ct_len) ||
                    !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR,
                        "Failed to persist vault (add credential)",
                        "add_cred", "failure");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    memcpy(nonce, new_nonce, NONCE_LEN);
                }
                sodium_memzero(ct, ct_len);
                free(ct);
            }

            // wipe local pass variable
            sodium_memzero((void*)pass.data(), pass.size());
        }
        else if (choice == "3") { // ------ Update existing credentials ------
            std::string label;
            std::cout << "Update - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            audit_log_level(LogLevel::INFO, "Update attempt for " + label, "notify");

            // ask old password for that entry
            std::vector<byte> oldpw_vec = get_password_bytes("Old password for this entry: ");
            g_reset_timer = true;
            if (oldpw_vec.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }

            bool match = false;
            if (oldpw_vec.size() == it->second.password.size()) {
                match = (sodium_memcmp(
                    oldpw_vec.data(),
                    reinterpret_cast<const byte*>(it->second.password.data()),
                    oldpw_vec.size()) == 0);
            }
            else {
                match = false;
            }

            if (!match) {
                audit_log_level(LogLevel::WARN,
                    "Failed update attempt for " + label,
                    "upd_cred", "failure");
                std::cout << "Old password mismatch\n";
                sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
                oldpw_vec.clear();
                continue;
            }

            std::vector<byte> newpw_vec = get_password_bytes("New password: ");
            g_reset_timer = true;
            if (newpw_vec.empty() || newpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid new password\n";
                sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
                oldpw_vec.clear();
                sodium_memzero(newpw_vec.data(), newpw_vec.size());
                newpw_vec.clear();
                continue;
            }

            std::string newpw(newpw_vec.begin(), newpw_vec.end());
            sodium_memzero(newpw_vec.data(), newpw_vec.size());
            newpw_vec.clear();

            it->second.password = newpw;
            audit_log_level(LogLevel::INFO, "Update success for " + label, "upd_cred", "success");

            // persist
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR,
                    "serialize_vault too large on update",
                    "upd_cred", "failure");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            byte* ct = nullptr;
            size_t ct_len = 0;
            byte new_nonce[NONCE_LEN];
            if (!encrypt_vault_blob(key,
                reinterpret_cast<const byte*>(ser.data()),
                ser.size(),
                &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR,
                    "Encryption failed on save (update)",
                    "upd_cred", "failure");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(g_vault_filename, ct, ct_len) ||
                    !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR,
                        "Failed to persist vault (update)",
                        "upd_cred", "failure");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    memcpy(nonce, new_nonce, NONCE_LEN);
                }
                sodium_memzero(ct, ct_len);
                free(ct);
            }

            sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
            oldpw_vec.clear();
            sodium_memzero((void*)newpw.data(), newpw.size());
        }
        else if (choice == "4") { // ------ Delete existing credentials ------
            std::string label;
            std::cout << "Delete - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            audit_log_level(LogLevel::INFO, "Deletion attempt for " + label, "notify");

            std::vector<byte> confirm =
                get_password_bytes("Type MASTER password to confirm deletion: ");
            g_reset_timer = true;
            if (confirm.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }

            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);
            if (!derive_key_from_password(confirm.data(), confirm.size(), salt, verifyKey)) {
                audit_log_level(LogLevel::WARN,
                    "Deletion: key derivation failed while verifying master",
                    "del_cred", "failure");
                if (!confirm.empty()) {
                    sodium_memzero(confirm.data(), confirm.size());
                    confirm.clear();
                }
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Master password check failed.\n";
                continue;
            }

            std::vector<byte> ct;
            if (!load_vault_ciphertext(ct)) {
                audit_log_level(LogLevel::ERROR,
                    "Deletion: cannot read vault ciphertext",
                    "del_cred", "failure");
                sodium_memzero(confirm.data(), confirm.size());
                confirm.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }

            byte* plain = nullptr;
            size_t plain_len = 0;
            if (decrypt_vault_blob(verifyKey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                sodium_memzero(plain, plain_len);
                free(plain);

                // proceed to delete
                vault.erase(it);
                audit_log_level(LogLevel::INFO,
                    "Deletion success for " + label,
                    "del_cred", "success");

                // persist
                std::string ser = serialize_vault(vault);
                if (ser.size() > MAX_VAULT_SIZE / 2) {
                    audit_log_level(LogLevel::ERROR,
                        "serialize_vault too large during deletion save",
                        "del_cred", "failure");
                    std::cerr << "An unexpected error occurred.\n";
                    continue;
                }

                byte* ct2 = nullptr;
                size_t ct2_len = 0;
                byte new_nonce[NONCE_LEN];
                if (!encrypt_vault_blob(key,
                    reinterpret_cast<const byte*>(ser.data()),
                    ser.size(),
                    &ct2, &ct2_len, new_nonce)) {
                    audit_log_level(LogLevel::ERROR,
                        "Encryption failed on save (delete credential)",
                        "del_cred", "failure");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    if (!atomic_write_file(g_vault_filename, ct2, ct2_len) ||
                        !save_meta(salt, new_nonce)) {
                        audit_log_level(LogLevel::ERROR,
                            "Failed to persist vault (delete credential)",
                            "del_cred", "failure");
                        std::cerr << "An unexpected error occurred. Check audit log.\n";
                    }
                    else {
                        memcpy(nonce, new_nonce, NONCE_LEN);
                    }
                    sodium_memzero(ct2, ct2_len);
                    free(ct2);
                }
            }
            else {
                audit_log_level(LogLevel::WARN,
                    "Deletion attempt failed (wrong master) for " + label,
                    "del_cred", "failure");
                std::cout << "Master password check failed. Not deleted.\n";
            }

            sodium_memzero(confirm.data(), confirm.size());
            confirm.clear();
            sodium_memzero(verifyKey, KEY_LEN);
        }
        else if (choice == "5") { // ------ Reveal existing credentials ------
            std::string label;
            std::cout << "Reveal - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }

            audit_log_level(LogLevel::INFO,
                "Reveal password requested for " + label,
                "show_cred", "notify");
            std::cout << "Username: " << it->second.username << "\n";
            std::cout << "Password: " << it->second.password << "\n";
            std::cout << "(action logged)\n";
        }
        else if (choice == "6") { // ------ Copy existing credentials ------
            std::string label;
            std::cout << "Copy - Label: ";
            if (!std::getline(std::cin, label)) break;
            g_reset_timer = true;

            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            audit_log_level(LogLevel::INFO,
                "Copy requested for " + label,
                "copy_cred", "notify");

            std::cout << "Copy to: (1) secure internal buffer  (2) system clipboard (timed clear)\n";
            std::cout << "Choose 1 or 2: ";

            std::string opt;
            if (!std::getline(std::cin, opt)) break;
            g_reset_timer = true;

            if (opt == "1") {
                // Secure buffer allocation (mlock)
                size_t len = it->second.password.size();
                if (len == 0 || len > MAX_PASS_LEN) {
                    std::cout << "Password invalid size\n";
                    continue;
                }
                byte* buf = (byte*)malloc(len + 1);
                if (!buf) {
                    std::cout << "Alloc fail\n";
                    continue;
                }
                memcpy(buf, it->second.password.data(), len);
                buf[len] = 0;

#if defined(MADV_DONTNEED)
                if (mlock(buf, len + 1) != 0) {
                    audit_log_level(LogLevel::WARN,
                        "mlock failed for secure buffer",
                        "copy_cred", "failure");
                }
#endif

                std::cout << "Password copied to secure buffer (NOT system clipboard). "
                    "Press Enter to clear it now.\n";
                audit_log_level(LogLevel::INFO,
                    "Credential copied to secure buffer for " + label,
                    "copy_cred", "success");

                std::string dummy;
                if (!std::getline(std::cin, dummy)) {
                    // Even if stdin closes, just continue to wipe
                }
                g_reset_timer = true;

                // clear buffer
                sodium_memzero(buf, len + 1);
#if defined(MADV_DONTNEED)
                munlock(buf, len + 1);
#endif
                free(buf);
                audit_log_level(LogLevel::INFO,
                    "Secure buffer cleared for " + label,
                    "copy_cred", "success");
            }
            else if (opt == "2") {
#if defined(_WIN32)
                if (windows_clipboard_history_enabled()) {
                    std::cout << "WARNING: Windows Clipboard History is enabled.\n";
                    std::cout << "Passwords you copy may remain visible in Win+V history.\n";
                }
#else
                if (running_in_wsl()) {
                    if (wsl_clipboard_history_enabled()) {
                        std::cout << "WARNING: Windows Clipboard History is enabled.\n";
                        std::cout << "Passwords you copy may remain visible in Win+V history.\n";
                    }
                }
#endif
                // system clipboard flow
                unsigned timeout_secs = 15; // default
                std::cout << "Timeout seconds (default 15): ";
                std::string ts;
                if (!std::getline(std::cin, ts)) break;
                g_reset_timer = true;

                if (!ts.empty()) {
                    try {
                        timeout_secs = std::stoul(ts);
                    }
                    catch (...) {
                        timeout_secs = 15;
                    }
                    if (timeout_secs > 600) timeout_secs = 600; // cap
                }

                // Copy with timed clear
                copy_with_timed_clear(it->second.password, timeout_secs);
                audit_log_level(LogLevel::INFO,
                    "Copied " + label + " -> system clipboard (timed for " +
                    std::to_string(timeout_secs) + ")",
                    "copy_cred", "success");
                std::cout << "Password copied to system clipboard for "
                    << timeout_secs << " seconds. Action logged.\n";
            }
            else {
                std::cout << "Invalid option\n";
            }
        }
        else if (choice == "7") { // ------ Exit the password manager ------
            running = false;
        }
        else if (choice == "8") { // ------ Delete entire vault ------
            std::cout << "WARNING: This will permanently delete your entire vault!\n";
            std::cout << "Type DELETE to confirm: ";
            std::string confirmWord;
            if (!std::getline(std::cin, confirmWord)) break;
            g_reset_timer = true;

            audit_log_level(LogLevel::INFO,
                "Deletion attempt for the vault",
                "del_vault", "notify");

            if (confirmWord != "DELETE") {
                std::cout << "Aborted.\n";
                continue;
            }

            std::vector<byte> masterCheck =
                get_password_bytes("Enter master password to confirm: ");
            g_reset_timer = true;
            if (masterCheck.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }

            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);
            if (!derive_key_from_password(masterCheck.data(), masterCheck.size(), salt, verifyKey)) {
                audit_log_level(LogLevel::WARN,
                    "Vault delete: key derivation failed during verification",
                    "del_vault", "failure");
                sodium_memzero(masterCheck.data(), masterCheck.size());
                masterCheck.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Key derivation failed.\n";
                continue;
            }

            std::vector<byte> ct;
            if (!load_vault_ciphertext(ct)) {
                audit_log_level(LogLevel::ERROR,
                    "Vault delete: no vault found (load failed)",
                    "del_vault", "failure");
                sodium_memzero(masterCheck.data(), masterCheck.size());
                masterCheck.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "No vault file found.\n";
                continue;
            }

            byte* plain = nullptr;
            size_t plain_len = 0;
            if (!decrypt_vault_blob(verifyKey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                audit_log_level(LogLevel::WARN,
                    "Vault delete: incorrect master password",
                    "del_vault", "failure");
                sodium_memzero(masterCheck.data(), masterCheck.size());
                masterCheck.clear();
                sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Incorrect master password. Aborted.\n";
                continue;
            }

            sodium_memzero(plain, plain_len);
            free(plain);
            sodium_memzero(masterCheck.data(), masterCheck.size());
            masterCheck.clear();
            sodium_memzero(verifyKey, KEY_LEN);

            // wipe in-memory vault & keys
            secure_clear_vault(vault);
            sodium_memzero(key, KEY_LEN);
            sodium_memzero(salt, SALT_LEN);
            sodium_memzero(nonce, NONCE_LEN);

            secure_delete_file(g_vault_filename.c_str());
            secure_delete_file(g_meta_filename.c_str());
            secure_delete_file(g_audit_log_path.c_str());

            std::cout << "Vault deleted.\n";
            running = false;
        }
    }
    clear_screen();
    g_timer_running = false;
    std::cout << "Goodbye.\n";
    return cleanup_and_exit(0, vault, key, salt, nonce);
}
