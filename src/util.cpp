#include "util.hpp"
#include "vault.hpp"

#if !defined(_WIN32)
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#endif

#include <atomic>
#include <thread>
#include <chrono>
#include <functional>


// ---------- SessionID ----------
std::string generate_session_id() {
    std::array<byte, 16> buf{};
    randombytes_buf(buf.data(), buf.size());

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(32);

    for (size_t i = 0; i < buf.size(); ++i) {
        out[2 * i] = hex[(buf[i] >> 4) & 0x0F];
        out[2 * i + 1] = hex[buf[i] & 0x0F];
    }
    return out;
}


// ---------- Helpers: input validation ----------
bool contains_control_or_tab_or_null(const std::string& s) {
    for (unsigned char c : s) {
        if (c == '\t' || c == '\0') return true;
        if ((c < 0x20) && c != '\n' && c != '\r') return true; // other control chars
    }
    return false;
}

bool valid_label_or_username(const std::string& s) {
    if (s.empty()) return false;
    if (s.size() > MAX_LABEL_LEN) return false;
    if (contains_control_or_tab_or_null(s)) return false;

    // disallow whitespace-only
    if (std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); })) return false;
    return true;
}

bool valid_password(const std::string& s) {
    if (s.empty()) return false;
    if (s.size() > MAX_PASS_LEN) return false;
    return !contains_control_or_tab_or_null(s);
}

bool valid_vault_name(const std::string& v) {
    if (s.empty() || s.size() > MAX_VAULT_NAME_LEN) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '-'; // allow alnum, '_', '-'
    });
}

// ---------- Secure input ----------
static void disable_echo(bool disable) {
#if !defined(_WIN32)
    termios tty;
    if (tcgetattr(STDIN_FILENO, &tty) != 0) return;

    if (disable) tty.c_lflag &= ~ECHO;
    else         tty.c_lflag |= ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

std::vector<byte> get_password_bytes(const char* prompt) {
    std::cout << prompt;
    std::fflush(stdout);

    disable_echo(true);

    std::string s;
    std::getline(std::cin, s);

    disable_echo(false);
    std::cout << "\n";

    std::vector<byte> out(s.begin(), s.end());
    if (!s.empty()) {
        volatile char* p = &s[0];
        std::fill(p, p + s.size(), 0);
    }
    return out;
}

// ---------- Vault memory cleanup ----------
void secure_clear_vault(Vault& v) {
    for (auto& p : v) {
        if (!p.second.username.empty()) sodium_memzero(&p.second.username[0], p.second.username.size());
        if (!p.second.password.empty()) sodium_memzero(&p.second.password[0], p.second.password.size());
        if (!p.second.notes.empty()) sodium_memzero(&p.second.notes[0], p.second.notes.size());
    }
    v.clear();
}

// ---------- Centralized cleanup & exit ----------
int cleanup_and_exit(
    int code,
    Vault& vault,
    byte key[KEY_LEN],
    byte salt[SALT_LEN],
    byte nonce[NONCE_LEN]
) {
    secure_clear_vault(vault);

    sodium_memzero(key, KEY_LEN);
    sodium_memzero(salt, SALT_LEN);
    sodium_memzero(nonce, NONCE_LEN);

    audit_log_level(LogLevel::INFO,
        "Session closed with code " + std::to_string(code),
        "util_module",
        "notify");

    return code;
}

// ---------------- Inactivity timer implementation ----------------
void start_inactivity_timer(std::function<void()> on_timeout) {
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

// ---------- Program flow helpers ----------
void clear_screen() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hOut, &csbi)) return;

    DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    DWORD count;
    COORD home = { 0,0 };

    FillConsoleOutputCharacter(hOut, ' ', cellCount, home, &count);
    FillConsoleOutputAttribute(hOut, csbi.wAttributes, cellCount, home, &count);
    SetConsoleCursorPosition(hOut, home);
#else
    // Clear visible screen and scrollback buffer
    std::cout << "\033[3J\033[2J\033[H";
#endif
}

void print_menu() {
    clear_screen();
    std::cout << "\n";
    std::cout << "SecurePass CLI - Menu:\n";
    std::cout << "1) List credentials\n";
    std::cout << "2) Add credential (+New)\n";
    std::cout << "3) Update credential\n";
    std::cout << "4) Delete credential\n";
    std::cout << "5) Reveal credential (logs action)\n";
    std::cout << "6) Copy credential to secure buffer\n";
    std::cout << "7) Quit\n";
    std::cout << "8) Delete current vault\n";
}