#pragma once
#include "passman_common.hpp"
#include "logging.hpp"

#include <atomic>
#include <thread>
#include <functional>
#include <string>
#include <chrono>
#include <vector>

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
    unsigned char key[KEY_LEN],
    unsigned char salt[SALT_LEN],
    unsigned char nonce[NONCE_LEN]
);

// ---------- Vault memory cleanup ----------
void secure_clear_vault(Vault& v);

// ---------- Menu ----------
void clear_screen();
void print_menu();

// ---------- Timer ----------
static std::atomic<bool> g_reset_timer{ false };
static std::atomic<bool> g_timer_running{ true };
constexpr int INACTIVITY_LIMIT = 60; // seconds
void start_inactivity_timer(std::function<void()> on_timeout);