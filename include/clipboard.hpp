#pragma once
#include "passman_common.hpp"
#include "logging.hpp"
#include "util.hpp"

// -------- Global vault paths --------
extern std::string g_vault_root;       // e.g. /home/user/.securepass/vaults
extern std::string g_vault_dir;        // e.g. /home/user/.securepass/vaults/default
extern std::string g_vault_name;       // e.g. "default"
extern std::string g_vault_filename;   // g_vault_dir + "/vault.bin"
extern std::string g_meta_filename;    // g_vault_dir + "/vault.meta"
extern std::string g_audit_log_path;   // g_vault_dir + "/audit.log"

// -------- Ownership and permission checks --------
bool check_dir_ownership_and_perms(const std::string& path);
bool check_file_ownership_and_perms(const std::string& path, bool allow_missing);

// ---------- Multi-vault initialization ----------
bool init_vault_paths_interactive();

// -------- Atomic file write helper --------
bool atomic_write_file(const std::string& path, const byte* buf, size_t len);

// -------- Meta / vault IO --------
bool save_meta(const byte salt[SALT_LEN], const byte nonce[NONCE_LEN]);
bool load_meta(byte salt[SALT_LEN], byte nonce[NONCE_LEN]);
bool load_vault_ciphertext(std::vector<byte>& ct);

// -------- Secure delete --------
void secure_delete_file(const char* path);
