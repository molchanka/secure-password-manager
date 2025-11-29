#include "util.hpp"
#include "vault.hpp"

#if !defined(_WIN32)
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#endif

// ---------- SessionID ----------
std::string generate_session_id() {
    unsigned char buf[16];
    std::random_device rd;
    for (std::size_t i = 0; i < sizeof(buf); ++i) {
        buf[i] = static_cast<unsigned char>(rd());
    }
    static const char* hex = "0123456789abcdef";
    char out[33];
    out[32] = '\0';
    for (std::size_t i = 0; i < sizeof(buf); ++i) {
        out[2 * i] = hex[(buf[i] >> 4) & 0x0F];
        out[2 * i + 1] = hex[buf[i] & 0x0F];
    }
    return std::string(out);
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
    if (contains_control_or_tab_or_null(s)) return false;
    return true;
}

bool valid_vault_name(const std::string& v) {
    if (v.empty()) return false;
    if (v.size() > MAX_VAULT_NAME_LEN) return false;
    for (unsigned char c : v) {
        if (!(std::isalnum(c) || c == '_' || c == '-')) { // allow alnum, '_', '-'
            return false;
        }
    }
    return true;
}

// ---------- Secure input (returns vector<byte> so we can wipe reliably) ----------
std::vector<byte> get_password_bytes(const char* prompt) {
    std::vector<byte> rv;
    std::cout << prompt;
    std::fflush(stdout);
    if (!isatty(STDIN_FILENO)) {
        std::string tmp;
        if (!std::getline(std::cin, tmp)) return rv;
        rv.assign(tmp.begin(), tmp.end());
        return rv;
    }
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        // fallback
        std::string tmp;
        if (!std::getline(std::cin, tmp)) return rv;
        rv.assign(tmp.begin(), tmp.end());
        return rv;
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        // fallback - log but do not expose
        audit_log_level(LogLevel::WARN, "tcsetattr failed while disabling echo", "util_module", "failure");
    }
    std::string tmp;
    std::getline(std::cin, tmp);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
        audit_log_level(LogLevel::WARN, "tcsetattr failed while restoring attrs", "util_module", "failure");
    }
    std::cout << "\n";
    rv.assign(tmp.begin(), tmp.end());
    return rv;
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
int cleanup_and_exit(int code, Vault& vault, unsigned char key[KEY_LEN],
    unsigned char salt[SALT_LEN], unsigned char nonce[NONCE_LEN]) {
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

    audit_log_level(LogLevel::INFO, std::string("Session closed with code ") + std::to_string(code), "util_module", "notify");
    return code;
}

// ---------- Program flow helpers ----------
void clear_screen() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD cellCount, count;
    COORD homeCoords = { 0, 0 };

    if (hOut == INVALID_HANDLE_VALUE) return;

    if (!GetConsoleScreenBufferInfo(hOut, &csbi)) return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;

    FillConsoleOutputCharacter(hOut, ' ', cellCount, homeCoords, &count);
    FillConsoleOutputAttribute(hOut, csbi.wAttributes, cellCount, homeCoords, &count);
    SetConsoleCursorPosition(hOut, homeCoords);
#else
    // secure erase (visible + scrollback)
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