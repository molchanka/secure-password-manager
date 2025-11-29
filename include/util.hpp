#pragma once
#include "passman_common.hpp"
#include "logging.hpp"

// ---------- SessionID ----------
std::string generate_session_id();

// ---------- Helpers: input validation ----------
bool contains_control_or_tab_or_null(const std::string& s);
bool valid_label_or_username(const std::string& s);
bool valid_password(const std::string& s);
bool valid_vault_name(const std::string& v);

// ---------- Secure input ----------
std::vector<byte> get_password_bytes(const char* prompt);

// ---------- Centralized cleanup & exit ----------
int cleanup_and_exit(
    int code,
    Vault& vault,
    unsigned char key[KEY_LEN],
    unsigned char salt[SALT_LEN],
    unsigned char nonce[NONCE_LEN]
);

// ---------- Vault memory cleanup ----------
void secure_clear_vault(Vault& v);

// ---------- Menu ----------
void print_menu();
