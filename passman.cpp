// passman.cpp
// Build: g++ -std=c++17 -O2 -Wall passman.cpp -lsodium -o passman


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
static constexpr size_t MAX_VAULT_NAME_LEN = 64;
static constexpr size_t MAX_NOTES_LEN = 4096;
static constexpr size_t MAX_VAULT_SIZE = 10 * 1024 * 1024; // 10 MB hard cap

using byte = unsigned char;

struct Cred {
    std::string label;   // e.g. "gmail"
    std::string username;
    std::string password;
    std::string notes;
};

using Vault = std::map<std::string, Cred>; // key by label


// ---------- SessionID ---------- 
static std::string generate_session_id() {
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


// -------- Global vault paths --------
static std::string g_vault_root;       // e.g. /home/user/.securepass/vaults
static std::string g_vault_dir;        // e.g. /home/user/.securepass/vaults/default
static std::string g_vault_name;       // e.g. "default"
static std::string g_vault_filename;   // g_vault_dir + "/vault.bin"
static std::string g_meta_filename;    // g_vault_dir + "/vault.meta"
static std::string g_audit_log_path;   // g_vault_dir + "/audit.log"


// ---------- Helpers: input validation ----------
static bool contains_control_or_tab_or_null(const std::string& s) {
    for (unsigned char c : s) {
        if (c == '\t' || c == '\0') return true;
        if ((c < 0x20) && c != '\n' && c != '\r') return true; // other control chars
    }
    return false;
}

static bool valid_label_or_username(const std::string& s) {
    if (s.empty()) return false;
    if (s.size() > MAX_LABEL_LEN) return false;
    if (contains_control_or_tab_or_null(s)) return false;
    // disallow whitespace-only
    if (std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isspace(c); })) return false;
    return true;
}

static bool valid_password(const std::string& s) {
    if (s.empty()) return false;
    if (s.size() > MAX_PASS_LEN) return false;
    if (contains_control_or_tab_or_null(s)) return false;
    return true;
}

static bool valid_vault_name(const std::string& v) {
    if (v.empty()) return false;
    if (v.size() > MAX_VAULT_NAME_LEN) return false;
    for (unsigned char c : v) {
        if (!(std::isalnum(c) || c == '_' || c == '-')) { // allow alnum, '_', '-'
            return false;
        }
    }
    return true;
}


// ---------- Vault name and path helpers ----------
static std::string get_user_home_dir() {
#if defined(_WIN32)
    const char* home = std::getenv("USERPROFILE");
    if (!home || !*home) {
        home = std::getenv("HOMEPATH");
    }
    if (!home || !*home) {
        return ".";
    }
    return std::string(home);
#else
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        struct passwd* pw = getpwuid(geteuid());
        if (pw && pw->pw_dir) {
            home = pw->pw_dir;
        }
    }
    if (!home || !*home) return ".";
    return std::string(home);
#endif
}

static bool ensure_dir_exists(const std::string & path, mode_t mode) {
#if defined(_WIN32)
    if (_mkdir(path.c_str()) != 0 && errno != EEXIST) {
        std::cerr << "Failed to create directory " << path << ": " << strerror(errno) << "\n";
        return false;
    }
    return true;
#else
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            std::cerr << path << " exists but is not a directory\n";
            return false;
        }
        if ((st.st_mode & 0777) != mode) {
            chmod(path.c_str(), mode);
        }
        return true;
    }
    if (mkdir(path.c_str(), mode) != 0) {
        if (errno != EEXIST) {
            std::cerr << "Failed to create directory " << path << ": " << strerror(errno) << "\n";
            return false;
        }
    }
    return true;
#endif
}


// -------- Logging (levels) --------
enum class LogLevel { INFO, WARN, ERROR, ALERT }; // levels

struct LogContext {
    std::string userId;
    std::string sessionId;
    std::string ip;
};

static LogContext g_log_ctx;

static std::string get_system_username() {
#if defined(_WIN32)
    char buf[256];
    DWORD len = static_cast<DWORD>(sizeof(buf));
    if (GetUserNameA(buf, &len)) {
        return std::string(buf);
    }
    const char* envUser = std::getenv("USERNAME");
    if (envUser && *envUser) {
        return std::string(envUser);
    }
    return "unknown";
#else
    // Use effective UID to handle sudo / different users correctly
    uid_t uid = geteuid();
    struct passwd* pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        return std::string(pw->pw_name);
    }
    const char* envUser = std::getenv("USER");
    if (envUser && *envUser) {
        return std::string(envUser);
    }
    return "unknown";
#endif
}

// Detect client IP based on SSH env, else fallback to localhost
static std::string get_client_ip() {
    const char* ssh_conn = std::getenv("SSH_CONNECTION");
    if (ssh_conn && ssh_conn[0]) {
        // SSH_CONNECTION="client_ip client_port server_ip server_port"
        std::istringstream iss(ssh_conn);
        std::string ip;
        if (iss >> ip) {
            return ip;
        }
    }
    const char* ssh_client = std::getenv("SSH_CLIENT");
    if (ssh_client && ssh_client[0]) {
        // SSH_CLIENT="client_ip client_port local_port"
        std::istringstream iss(ssh_client);
        std::string ip;
        if (iss >> ip) {
            return ip;
        }
    }
    // Local execution (no SSH)
    return "127.0.0.1";
}

// Initialize global logging context (userId, sessionId, IP)
static void init_log_context() {
    g_log_ctx.userId = get_system_username();
    g_log_ctx.sessionId = generate_session_id();
    g_log_ctx.ip = get_client_ip();
}

static void audit_log_level(LogLevel lvl, const std::string& entry, const std::string& event = "", const std::string& outcome = "") {
    //int fd = open(AUDIT_LOG, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    const char* path = nullptr;
    static const char* default_log = "audit.log";
    if (!g_audit_log_path.empty()) path = g_audit_log_path.c_str();
    else path = default_log;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        std::cerr << "Open audit log failed.\n";
        return;
    }

    time_t t = time(nullptr);
    char tbuf[64];
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmv);

    const char* lname = "INFO";
    switch (lvl) {
        case LogLevel::INFO:  lname = "INFO"; break;
        case LogLevel::WARN:  lname = "WARN"; break;
        case LogLevel::ERROR: lname = "ERROR"; break;
        case LogLevel::ALERT: lname = "ALERT"; break;
    }

    // ----- gather username -----
    std::string username;
#if defined(_WIN32)
    {
        char buf[256];
        DWORD sz = sizeof(buf);
        if (GetUserNameA(buf, &sz)) username = buf;
        else username = "unknown";
    }
#else
    {
        const char* u = getenv("USER");
        if (!u) u = getenv("LOGNAME");
        username = (u ? u : "unknown");
    }
#endif

    // ----- session id (pid) -----
    std::string sessionId = std::to_string((long long)getpid());

    // ----- IP detection -----
    std::string ip = "127.0.0.1";
    const char* ssh_conn = getenv("SSH_CONNECTION");
    const char* ssh_client = getenv("SSH_CLIENT");

    if (ssh_conn) {
        // SSH_CONNECTION format is: "<client_ip> <client_port> <server_ip> <server_port>"
        std::istringstream iss(ssh_conn);
        iss >> ip;
    }
    else if (ssh_client) {
        // SSH_CLIENT format is: "<client_ip> <client_port> <server_port>"
        std::istringstream iss(ssh_client);
        iss >> ip;
    }

    // ----- build message -----
    std::ostringstream oss;
    oss << tbuf
        << " [" << lname << "] "
        << "event=" << (event.empty() ? entry : event)
        << " userId=" << username
        << " sessionId=" << sessionId
        << " ip=" << ip
        << " outcome=" << (outcome.empty() ? "none" : outcome)
        << "\n";

    std::string msg = oss.str();

    if (write(fd, msg.c_str(), msg.size()) < 0) {
        std::cerr << "Write audit log failed.\n";
    }
    if (close(fd) != 0) {
        std::cerr << "Close audit log failed.\n";
    }
}

static void audit_log(const std::string& entry) { audit_log_level(LogLevel::INFO, entry); }

// -------- Ownership and permission checks
static bool check_dir_ownership_and_perms(const std::string& path) {
#if defined(_WIN32)
    (void)path;
    return true;
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "Internal error: vault file check failed.\n";
        return false;
    }
    uid_t uid = geteuid();
    if (st.st_uid != uid) {
        audit_log_level(LogLevel::ERROR, "Directory ownership violation: " + path);
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    mode_t perms = st.st_mode & 0777;
    // For directories we require no group/other access
    if ((perms & 0077) != 0) {
        audit_log_level(LogLevel::ERROR, "Insecure directory permissions on: " + path);
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    return true;
#endif
}

static bool check_file_ownership_and_perms(const std::string& path, bool allow_missing) {
#if defined(_WIN32)
    (void)path; (void)allow_missing;
    return true;
#else
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT && allow_missing) return true;
        std::cerr << "Internal error: vault file check failed.\n";
        return false;
    }
    uid_t uid = geteuid();
    if (st.st_uid != uid) {
        audit_log_level(LogLevel::ERROR, "File ownership violation: " + path);
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    mode_t perms = st.st_mode & 0777;
    if ((perms & 0077) != 0) {
        audit_log_level(LogLevel::ERROR, "Insecure file permissions on: " + path);
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    return true;
#endif
}


// ---------- Secure input (returns vector<byte> so we can wipe reliably) ----------
static std::vector<byte> get_password_bytes(const char* prompt) {
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
        audit_log_level(LogLevel::WARN, "tcsetattr failed while disabling echo");
    }
    std::string tmp;
    std::getline(std::cin, tmp);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
        audit_log_level(LogLevel::WARN, "tcsetattr failed while restoring attrs");
    }
    std::cout << "\n";
    rv.assign(tmp.begin(), tmp.end());
    return rv;
}

//// helper to convert vector<byte> to std::string (copy) and wipe the vector
//static std::string passwd_vec_to_string_and_wipe(std::vector<byte>& v) {
//    std::string s(v.begin(), v.end());
//    sodium_memzero(v.data(), v.size());
//    v.clear();
//    return s;
//}


//// zero and unlock memory safely
//static void secure_free(unsigned char* buf, size_t len) {
//    if (!buf || len == 0) return;
//    sodium_memzero(buf, len);
//    // attempt to munlock if possible
//#if defined(MADV_DONTNEED)
//    munlock(buf, len);
//#endif
//    free(buf);
//}


//// get password
//static std::string get_password(const char* prompt) {
//    std::string pw;
//    std::cout << prompt;
//    std::fflush(stdout);
//    // turn off echo on POSIX
//    struct termios oldt, newt;
//    if (!isatty(STDIN_FILENO)) {
//        std::string tmp;
//        if (!std::getline(std::cin, tmp)) return pw;
//        pw.assign(tmp.begin(), tmp.end());
//        return pw;
//    }
//    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
//        std::string tmp;
//        if (!std::getline(std::cin, tmp)) return pw;
//        pw.assign(tmp.begin(), tmp.end());
//        return pw;
//    }
//    newt = oldt;
//    newt.c_lflag &= ~ECHO;
//    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
//        audit_log_level(LogLevel::WARN, "tcsetattr failed while disabling echo");
//    }
//    std::string tmp;
//    std::getline(std::cin, tmp);
//    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
//        audit_log_level(LogLevel::WARN, "tcsetattr failed while restoring attrs");
//    }
//    std::cout << "\n";
//    pw.assign(tmp.begin(), tmp.end());
//    return pw;
//}


// ---------- Base64 helpers ----------
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


// ---------------- Cross-platform clipboard helpers ----------------
static bool run_writer_with_stdin(const std::vector<const char*>& argv, const std::string& input) {
#if defined(_WIN32)
    (void)argv; (void)input;
    return false; // Will not be used on Windows.
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return false;
    }
    if (pid == 0) {
        // child: replace stdin with read end
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        // build argv for exec
        std::vector<char*> args;
        for (auto p : argv) args.push_back(const_cast<char*>(p));
        args.push_back(nullptr);
        // execvp is safe here because argv[0] is a literal from code or user-checked path
        execvp(args[0], args.data());
        _exit(127); // exec failed
    }
    // parent: write then close write-end
    close(pipefd[0]);
    ssize_t to_write = (ssize_t)input.size();
    const char* buf = input.data();
    while (to_write > 0) {
        ssize_t w = write(pipefd[1], buf, to_write);
        if (w <= 0) break;
        buf += w;
        to_write -= w;
    }
    close(pipefd[1]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

static bool run_reader_to_string(const std::vector<const char*>& argv, std::string& out) {
#if defined(_WIN32)
    (void)argv; (void)out;
    return false;
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return false; }
    if (pid == 0) {
        // child: replace stdout with write end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        std::vector<char*> args;
        for (auto p : argv) args.push_back(const_cast<char*>(p));
        args.push_back(nullptr);
        execvp(args[0], args.data());
        _exit(127);
    }
    // parent: read
    close(pipefd[1]);
    std::string s;
    char buf[4096];
    ssize_t r;
    while ((r = read(pipefd[0], buf, sizeof(buf))) > 0) {
        s.append(buf, buf + r);
        if (s.size() > 1024 * 1024) break; // avoid insane size
    }
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return false;
    // trim trailing newlines
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    out.swap(s);
    return true;
#endif
}


// Windows section ---------------
#if defined(_WIN32)
static bool clipboard_set_win(const std::string& data) {
    if (!OpenClipboard(nullptr)) return false;
    if (!EmptyClipboard()) { CloseClipboard(); return false; }
    SIZE_T lenBytes = (data.size() + 1);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, lenBytes);
    if (!h) { CloseClipboard(); return false; }
    void* p = GlobalLock(h);
    if (!p) { GlobalFree(h); CloseClipboard(); return false; }
    memcpy(p, data.data(), data.size());
    // Ensure trailing NUL
    ((char*)p)[data.size()] = '\0';
    GlobalUnlock(h);
    if (!SetClipboardData(CF_TEXT, h)) {
        GlobalFree(h);
        CloseClipboard();
        return false;
    }
    // Do not free h after SetClipboardData successful (system owns it).
    CloseClipboard();
    return true;
}

static bool clipboard_get_win(std::string& out) {
    out.clear();
    if (!OpenClipboard(nullptr)) return false;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) { CloseClipboard(); return false; }
    char* p = static_cast<char*>(GlobalLock(h));
    if (!p) { CloseClipboard(); return false; }
    out.assign(p);
    GlobalUnlock(h);
    CloseClipboard();
    return true;
}

static bool clipboard_clear_win() {
    if (!OpenClipboard(nullptr)) return false;
    bool ok = EmptyClipboard();
    CloseClipboard();
    return ok;
}

static bool windows_clipboard_history_enabled() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(value);

    // HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory
    if (RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Clipboard",
        0,
        KEY_READ,
        &hKey) != ERROR_SUCCESS)
    {
        return false; // key missing → treat as disabled
    }

    LONG result = RegQueryValueExA(
        hKey,
        "EnableClipboardHistory",
        NULL,
        NULL,
        (LPBYTE)&value,
        &size
    );
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return false;
    }

    return (value == 1);
}
#endif
// ----------------

// WSL section ---------------
static bool wsl_clipboard_history_enabled() {
    const char* pwsh = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
    if (access(pwsh, X_OK) != 0) return false; // not WSL or no pwsh

    std::vector<const char*> args = {
        pwsh,
        "-NoProfile",
        "-Command",
        "(Get-ItemProperty HKCU:\\Software\\Microsoft\\Clipboard).EnableClipboardHistory"
    };

    std::string out;
    if (!run_reader_to_string(args, out)) return false;

    // PowerShell outputs e.g. "1" or "0" or empty
    return (out == "1");
}


static bool running_in_wsl() {
    FILE* f = fopen("/proc/version", "r");
    if (!f) return false;

    char buf[256];
    size_t nread = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (nread == 0) {
        // Could not read; assume not WSL.
        return false;
    }

    buf[nread] = '\0';  // explicit NUL-termination

    return (strstr(buf, "Microsoft") || strstr(buf, "WSL"));
}
// ----------------

static bool clipboard_set_posix(const std::string& data) {
    // prefer wl-copy (Wayland), then pbcopy (macOS), then xclip/xsel
    const std::vector<std::vector<const char*>> writers = {
        { "wl-copy", "--no-newline" },      // wl-copy doesn't add newline if we pass option
        { "pbcopy" },                       // macOS
        { "xclip", "-selection", "clipboard" },
        { "xsel", "--clipboard", "--input" }
    };
    for (const auto& a : writers) {
        if (access(a[0], X_OK) == 0) {
            if (run_writer_with_stdin(a, data)) return true;
        }
    }
    // WSL integration
    if (running_in_wsl()) {
        const char* winclip = "/mnt/c/Windows/System32/clip.exe";
        const char* pwsh = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
        if (access(winclip, X_OK) == 0 && access(pwsh, X_OK) == 0) {
            std::vector<const char*> args = { winclip };
            return run_writer_with_stdin(args, data);
        }
    }
    return false;
}

static bool clipboard_get_posix(std::string& out) {
    const std::vector<std::vector<const char*>> readers = {
        { "wl-paste", "--no-newline" },
        { "pbpaste" },
        { "xclip", "-selection", "clipboard", "-o" },
        { "xsel", "--clipboard", "--output" }
    };
    for (const auto& a : readers) {
        if (access(a[0], X_OK) == 0) {
            if (run_reader_to_string(a, out)) return true;
        }
    }

    // WSL integration
    if (running_in_wsl()) {
        const char* pwsh = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
        if (access(pwsh, X_OK) == 0) {
            std::vector<const char*> args = {
                pwsh,
                "-NoProfile",
                "-Command",
                "Get-Clipboard"
            };
            return run_reader_to_string(args, out);
        }
    }
    return false;
}

static bool clipboard_clear_posix() {
    // Clearing: set empty string
    return clipboard_set_posix(std::string());

    // WSL: clear Windows clipboard via clip.exe
    if (running_in_wsl()) {
        const char* winclip = "/mnt/c/Windows/System32/clip.exe";
        if (access(winclip, X_OK) == 0) {
            std::vector<const char*> args = { winclip };
            return run_writer_with_stdin(args, "");
        }
    }
}

// High-level small wrappers:
static bool clipboard_set(const std::string& data) {
#if defined(_WIN32)
    return clipboard_set_win(data);
#else
    return clipboard_set_posix(data);
#endif
}

static bool clipboard_get(std::string& out) {
#if defined(_WIN32)
    return clipboard_get_win(out);
#else
    return clipboard_get_posix(out);
#endif
}

static bool clipboard_clear() {
#if defined(_WIN32)
    return clipboard_clear_win();
#else
    return clipboard_clear_posix();
#endif
}

// copy with timed clear: copies data to clipboard and clears after `seconds` only if the
// clipboard still contains identical content. zeroes local buffers used.
static void copy_with_timed_clear(const std::string& secret, unsigned seconds) {
    if (secret.empty()) return;
    std::vector<unsigned char> buf(secret.begin(), secret.end());
    bool ok = false;
#if defined(_WIN32)
    std::string tmp((char*)buf.data(), buf.size());
    ok = clipboard_set(tmp);
    sodium_memzero((void*)tmp.data(), tmp.size());
#else
    std::string tmp((char*)buf.data(), buf.size());
    ok = clipboard_set(tmp);
    sodium_memzero((void*)tmp.data(), tmp.size());
#endif
    sodium_memzero(buf.data(), buf.size());
    buf.clear();

    if (!ok) {
        audit_log_level(LogLevel::WARN, "clipboard_set failed for timed copy");
        return;
    }

    std::thread([secret, seconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        std::string current;
        if (!clipboard_get(current)) {
            return;
        }
        std::string expected = secret;
        // compare exactly, if matches, clear
        if (current == expected) {
            clipboard_clear();
            audit_log_level(LogLevel::INFO, "Clipboard cleared after timeout");
        }
        // wipe current
        if (!current.empty()) {
            sodium_memzero(&current[0], current.size());
        }
        }).detach();
}


// ---------- Centralized cleanup & exit ----------
static int cleanup_and_exit(int code, Vault& vault, unsigned char key[KEY_LEN],
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

    audit_log_level(LogLevel::INFO, std::string("Session closed with code ") + std::to_string(code));
    return code;
}


// -------- Vault --------
static std::string escape_str(const std::string& s) {
    std::string r; r.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\n') { r += "\\n"; }
        else if (c == '\\') { r += "\\\\"; }
        else r.push_back(c);
    }
    return r;
}


static std::string unescape_str(const std::string& x) {
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
}


static std::string serialize_vault(const Vault& v) {
    std::ostringstream oss;
    for (const auto& p : v) {
        // escape newlines by \\n
        oss << p.first << '\t'
            << escape_str(p.second.username) << '\t'
            << escape_str(p.second.password) << '\t'
            << escape_str(p.second.notes) << '\n';
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
        size_t start = 0;
        for (size_t pos = 0; pos <= line.size(); ++pos) {
            if (pos == line.size() || line[pos] == '\t') {
                toks.push_back(line.substr(start, pos - start));
                start = pos + 1;
            }
        }
        if (toks.size() >= 4) {
            Cred c{ toks[0], unescape_str(toks[1]), unescape_str(toks[2]), unescape_str(toks[3]) };
            v[toks[0]] = std::move(c);
        }
        else {
            // malformed line -> skip and log
            audit_log_level(LogLevel::WARN, "deserialize_vault: skipped malformed line");
        }
    }
    return v;
}


// ---------- Multi-vault initialization ----------
static bool init_vault_paths_interactive() {
    std::string home = get_user_home_dir();
#if defined(_WIN32)
    const char sep = '\\';
    g_vault_root = home + "\\.passman";
    std::string vaults_dir = g_vault_root + "\\vaults";
#else
    const char sep = '/';
    g_vault_root = home + "/.passman";
    std::string vaults_dir = g_vault_root + "/vaults";
#endif
    if (!ensure_dir_exists(g_vault_root, S_IRWXU)) {
        return false;
    }
    if (!ensure_dir_exists(vaults_dir, S_IRWXU)) {
        return false;
    }

    // choose vault name
    while (true) {
        std::cout << "Select vault name (e.g. 'default'): ";
        if (!std::getline(std::cin, g_vault_name)) {
            return false;
        }
        if (!valid_vault_name(g_vault_name)) {
            std::cout << "Invalid vault name. Use only letters, digits, '_' or '-', max " << MAX_VAULT_NAME_LEN << " characters.\n";
            continue;
        }
        break;
    }

    // build per-vault directory & paths
    g_vault_dir = vaults_dir + sep + g_vault_name;
    if (!ensure_dir_exists(g_vault_dir, S_IRWXU)) {
        return false;
    }
#if defined(_WIN32)
    g_vault_filename = g_vault_dir + "\\vault.bin";
    g_meta_filename = g_vault_dir + "\\vault.meta";
    g_audit_log_path = g_vault_dir + "\\audit.log";
#else
    g_vault_filename = g_vault_dir + "/vault.bin";
    g_meta_filename = g_vault_dir + "/vault.meta";
    g_audit_log_path = g_vault_dir + "/audit.log";
#endif
    // enforce per-user ownership and tight permissions on vault dir
    if (!check_dir_ownership_and_perms(g_vault_dir)) {
        return false;
    }

    // if files don't exist yet
    if (!check_file_ownership_and_perms(g_vault_filename, true)) return false;
    if (!check_file_ownership_and_perms(g_meta_filename, true)) return false;
    if (!check_file_ownership_and_perms(g_audit_log_path, true)) return false;

    return true;
}


// -------- Crypto helpers --------
static bool derive_key_from_password(const byte* pw, size_t pw_len, const byte salt[SALT_LEN], byte key[KEY_LEN]) {
    if (!pw || pw_len == 0) return false;
    if (crypto_pwhash(key, KEY_LEN,
        reinterpret_cast<const char*>(pw), pw_len,
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


static bool decrypt_vault_blob(const byte key[KEY_LEN], const byte *ct, size_t ct_len,
                                const byte nonce[NONCE_LEN], byte **out_plain, size_t* out_plain_len) {
    if (!ct || ct_len < ABYTES) { audit_log_level(LogLevel::WARN, "decrypt_vault_blob: ct too small"); return false; }
    *out_plain = (byte*)malloc(ct_len); // ciphertext len is >= plaintext
    if (!*out_plain) { audit_log_level(LogLevel::ERROR, "decrypt_vault_blob: malloc failed"); return false; }
    unsigned long long mlen = 0;
    if (!*out_plain) return false;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(*out_plain, &mlen,
        NULL,
        ct, ct_len,
        NULL, 0,
        nonce, key) != 0) {
        sodium_memzero(*out_plain, ct_len);
        free(*out_plain);
        *out_plain = nullptr;
        audit_log_level(LogLevel::ERROR, "decrypt_vault_blob: authentication failed");
        return false;
    }
    *out_plain_len = (size_t)mlen;
    return true;
}


// -------- Atomic file write helper -------- 
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


static bool save_meta(const byte salt[SALT_LEN], const byte nonce[NONCE_LEN]) {
    if (!salt || !nonce) return false;
    std::string b64salt = to_base64(salt, SALT_LEN);
    std::string b64nonce = to_base64(nonce, NONCE_LEN);
    std::string content = b64salt + "\n" + b64nonce + "\n";
    // atomic write
    if (!atomic_write_file(g_meta_filename, reinterpret_cast<const byte*>(content.data()), content.size())) {
        audit_log_level(LogLevel::ERROR, "save_meta: atomic write failed");
        return false;
    }
    return true;
}


static bool load_meta(byte salt[SALT_LEN], byte nonce[NONCE_LEN]) {
    FILE* f = fopen(g_meta_filename.c_str(), "r");
    if (!f) {
        audit_log_level(LogLevel::ERROR, "load_meta: fopen failed");
        return false;
    }

    std::string s_salt, s_nonce;
    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        audit_log_level(LogLevel::ERROR, "load_meta: fgets salt failed");
        return false;
    }
    s_salt = buf;
    while (!s_salt.empty() && (s_salt.back() == '\n' || s_salt.back() == '\r')) s_salt.pop_back();
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        audit_log_level(LogLevel::ERROR, "load_meta: fgets nonce failed");
        return false;
    }
    s_nonce = buf;
    while (!s_nonce.empty() && (s_nonce.back() == '\n' || s_nonce.back() == '\r')) s_nonce.pop_back();

    fclose(f);

    if (s_salt.empty() || s_nonce.empty()) {
        audit_log_level(LogLevel::WARN, "load_meta: meta file missing lines");
        return false;
    }

    auto vs = from_base64(s_salt);
    auto vn = from_base64(s_nonce);
    if (vn.size() != NONCE_LEN || vs.size() != SALT_LEN) {
        audit_log_level(LogLevel::WARN, "load_meta: meta decode length mismatch");
        return false;
    }
    memcpy(salt, vs.data(), SALT_LEN);
    memcpy(nonce, vn.data(), NONCE_LEN);
    return true;
}


static bool load_vault_ciphertext(std::vector<byte>& ct) {
    FILE* f = fopen(g_vault_filename.c_str(), "rb");
    if (!f) return false;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR, "fseek end failed");
        return false;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR, "ftell failed");
        return false;
    }
    if ((unsigned long)sz > MAX_VAULT_SIZE) {  // Prevent integer overflow & large files
        audit_log_level(LogLevel::WARN, "Vault file too large or corrupt.");
        fclose(f);
        return false;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR, "fseek set failed");
        return false;
    }
    size_t size = static_cast<size_t>(sz);
    ct.resize(size);
    if (size > 0) {
        size_t r = fread(ct.data(), 1, size, f);
        if (r != size) {
            fclose(f);
            ct.clear();
            audit_log_level(LogLevel::ERROR, "fread failed on vault");
            return false;
        }
    }
    fclose(f);
    return true;
}

static void secure_delete_file(const char* path) {
    if (!path) return;
    FILE* f = fopen(path, "r+");
    if (!f) { unlink(path); return; }
    if (fseek(f, 0, SEEK_END) == 0) {
        long lsz = ftell(f);
        if (lsz > 0 && (unsigned long)lsz <= MAX_VAULT_SIZE) {
            rewind(f);
            std::vector<byte> zeros((size_t)lsz, 0);
            size_t w = fwrite(zeros.data(), 1, zeros.size(), f);
            if (w != zeros.size()) audit_log_level(LogLevel::WARN, "secure_delete_file: fwrite short");
            fflush(f);
            fsync(fileno(f));
        }
        else {
            audit_log_level(LogLevel::WARN, "secure_delete_file: file size invalid or too large");
        }
    }
    fclose(f);
    if (unlink(path) != 0) audit_log_level(LogLevel::WARN, std::string("unlink failed: ") + strerror(errno));
}

// ---------- Small utilities ----------
static void secure_clear_vault(Vault& v) {
    for (auto& p : v) {
        if (!p.second.username.empty()) sodium_memzero(&p.second.username[0], p.second.username.size());
        if (!p.second.password.empty()) sodium_memzero(&p.second.password[0], p.second.password.size());
        if (!p.second.notes.empty()) sodium_memzero(&p.second.notes[0], p.second.notes.size());
    }
    v.clear();
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


// ---------- Main program ----------
int main() {
    init_log_context();

    if (!init_vault_paths_interactive()) {
        std::fprintf(stderr, "Failed to initialize vault paths.\n");
        return 1;
    }

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
    bool vault_exists = (access(g_vault_filename.c_str(), F_OK) == 0 && access(g_meta_filename.c_str(), F_OK) == 0);
    if (!vault_exists) {
        std::cout << "No vault found. Initialize new vault.\n";
        // generate salt and ask master password twice
        randombytes_buf(salt, SALT_LEN);
        std::vector<byte> pw1 = get_password_bytes("Create master password: ");
        std::vector<byte> pw2 = get_password_bytes("Confirm master password: ");
        if (pw1 != pw2) {
            audit_log_level(LogLevel::WARN, "Vault init: passwords did not match");
            std::cerr << "Passwords do not match. Exiting.\n";
            sodium_memzero(pw1.data(), pw1.size());
            sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(2, vault, key, salt, nonce);
        }
        if (!derive_key_from_password(pw1.data(), pw1.size(), salt, key)) {
            audit_log_level(LogLevel::ERROR, "Vault init: key derivation failed");
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
        if (!encrypt_vault_blob(key, reinterpret_cast<const byte*>(ser.data()), ser.size(), &ct, &ct_len, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: encrypt_vault_blob failed");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(pw1.data(), pw1.size()); sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        // atomic write vault
        if (ct_len > MAX_VAULT_SIZE) {
            audit_log_level(LogLevel::ERROR, "Vault init: ciphertext too large");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            sodium_memzero(pw1.data(), pw1.size()); sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        if (!atomic_write_file(g_vault_filename, ct, ct_len) || !save_meta(salt, new_nonce)) {
            audit_log_level(LogLevel::ERROR, "Vault init: saving vault/meta failed");
            std::cerr << "An unexpected error occurred. Check audit log.\n";
            sodium_memzero(ct, ct_len);
            free(ct);
            sodium_memzero(pw1.data(), pw1.size()); sodium_memzero(pw2.data(), pw2.size());
            return cleanup_and_exit(3, vault, key, salt, nonce);
        }
        sodium_memzero(ct, ct_len);
        free(ct);
        sodium_memzero(pw1.data(), pw1.size());
        sodium_memzero(pw2.data(), pw2.size());
        sodium_memzero(key, KEY_LEN);
        std::cout << "Vault initialized. Restart to open.\n";
        std::cerr << g_vault_filename + "\n";
        audit_log_level(LogLevel::INFO, "New vault initialized");
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
        audit_log_level(LogLevel::ERROR, "Failed to load vault metadata");
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
            audit_log_level(LogLevel::WARN, "derive_key_from_password failed during unlock");
            sodium_memzero(master.data(), master.size());
            continue;
        }
        // try decrypting
        std::vector<byte> ct;
        if (!load_vault_ciphertext(ct)) {
            audit_log_level(LogLevel::ERROR, "Unable to read vault ciphertext");
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
            audit_log_level(LogLevel::INFO, "Master password accepted - session opened");
            break;
        }
        else {
            attempts++;
            audit_log_level(LogLevel::WARN, "Failed master password attempt");
            sodium_memzero(master.data(), master.size());
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

        if (choice == "1") { // ------ List credentials ------ 
            std::cout << "Stored credentials:\n";
            for (auto& p : vault) {
                std::cout << " - " << p.first << " (user: " << p.second.username << ")\n";
            }
        }
        else if (choice == "2") { // ------ Add new credentials ------ 
            std::string label, user, notes;
            std::cout << "+New - Label: ";
            std::getline(std::cin, label);
            if (!valid_label_or_username(label)) {
                std::cout << "Invalid label\n";
                continue;
            }
            std::cout << " Username: "; std::getline(std::cin, user);
            if (!valid_label_or_username(user)) {
                std::cout << "Invalid username\n";
                continue;
            }

            std::cout << " Password (leave empty to prompt hidden): ";
            std::string tmp;
            std::getline(std::cin, tmp);
            std::vector<byte> pwvec;
            if (tmp.empty()) pwvec = get_password_bytes("Password: ");
            else pwvec.assign(tmp.begin(), tmp.end());
            if (pwvec.empty()) {
                std::cout << "Password empty\n";
                continue;
            }
            std::string pass = std::string(pwvec.begin(), pwvec.end());
            sodium_memzero(pwvec.data(), pwvec.size()); pwvec.clear();
            if (!valid_password(pass)) {
                std::cout << "Invalid password\n";
                sodium_memzero((void*)pass.data(), pass.size());
                continue;
            }

            std::cout << " Notes: "; std::getline(std::cin, notes);
            if (notes.size() > 4096) notes.resize(4096);

            Cred c{ label, user, pass, notes };
            vault[label] = c;
            audit_log_level(LogLevel::INFO, "Add credential: " + label);

            // persist
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR, "serialize_vault produced excessively large output");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }
            byte* ct = nullptr;
            size_t ct_len = 0;
            byte new_nonce[NONCE_LEN];
            if (!encrypt_vault_blob(key, reinterpret_cast<const byte*>(ser.data()), ser.size(), &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR, "Encryption failed on save (add credential)");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(VAULT_FILENAME, ct, ct_len) || !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Failed to persist vault (add credential)");
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
            std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) { std::cout << "Not found\n"; continue; }

            // ask old password for that entry
            std::vector<byte> oldpw_vec = get_password_bytes("Old password for this entry: ");
            if (oldpw_vec.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }
            bool match = false;
            if (oldpw_vec.size() == it->second.password.size()) {
                match = (sodium_memcmp(oldpw_vec.data(), reinterpret_cast<const byte*>(it->second.password.data()),
                        oldpw_vec.size()) == 0);
            }
            else match = false;

            if (!match) {
                audit_log_level(LogLevel::WARN, "Failed update attempt for " + label);
                std::cout << "Old password mismatch\n";
                sodium_memzero(oldpw_vec.data(), oldpw_vec.size());
                oldpw_vec.clear();
                continue;
            }
            audit_log_level(LogLevel::INFO, "Update attempt for " + label);

            std::vector<byte> newpw_vec = get_password_bytes("New password: ");
            if (newpw_vec.empty() || newpw_vec.size() > MAX_PASS_LEN) {
                std::cout << "Invalid new password\n";
                sodium_memzero(oldpw_vec.data(), oldpw_vec.size()); oldpw_vec.clear();
                sodium_memzero(newpw_vec.data(), newpw_vec.size()); newpw_vec.clear();
                continue;
            }
            std::string newpw(newpw_vec.begin(), newpw_vec.end());
            sodium_memzero(newpw_vec.data(), newpw_vec.size()); newpw_vec.clear();
            it->second.password = newpw;
            audit_log_level(LogLevel::INFO, "Update success for " + label);

            // persist
            std::string ser = serialize_vault(vault);
            if (ser.size() > MAX_VAULT_SIZE / 2) {
                audit_log_level(LogLevel::ERROR, "serialize_vault too large on update");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }
            byte *ct = nullptr; size_t ct_len = 0; byte new_nonce[NONCE_LEN];
            if (!encrypt_vault_blob(key, reinterpret_cast<const byte*>(ser.data()), ser.size(), &ct, &ct_len, new_nonce)) {
                audit_log_level(LogLevel::ERROR, "Encryption failed on save (update)");
                std::cerr << "An unexpected error occurred. Check audit log.\n";
            }
            else {
                if (!atomic_write_file(VAULT_FILENAME, ct, ct_len) || !save_meta(salt, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Failed to persist vault (update)");
                    std::cerr << "An unexpected error occurred. Check audit log.\n";
                }
                else {
                    memcpy(nonce, new_nonce, NONCE_LEN);
                }
                sodium_memzero(ct, ct_len);
                free(ct);
            }
            sodium_memzero(oldpw_vec.data(), oldpw_vec.size()); oldpw_vec.clear();
            sodium_memzero((void*)newpw.data(), newpw.size());
        }
        else if (choice == "4") { // ------ Delete existing credentials ------ 
            std::string label;
            std::cout << "Delete - Label: ";
            std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            std::vector<byte> confirm = get_password_bytes("Type MASTER password to confirm deletion: ");
            if (confirm.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }
            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);
            if (!derive_key_from_password(confirm.data(), confirm.size(), salt, verifyKey)) {
                audit_log_level(LogLevel::WARN, "Deletion: key derivation failed while verifying master");
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
                audit_log_level(LogLevel::ERROR, "Deletion: cannot read vault ciphertext");
                sodium_memzero(confirm.data(), confirm.size()); confirm.clear(); sodium_memzero(verifyKey, KEY_LEN);
                std::cerr << "An unexpected error occurred. Check audit log.\n";
                continue;
            }
            byte* plain = nullptr; size_t plain_len = 0;
            if (decrypt_vault_blob(verifyKey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                sodium_memzero(plain, plain_len); free(plain);
                // proceed to delete
                vault.erase(it);
                audit_log_level(LogLevel::INFO, "Deletion success for " + label);
                // persist
                std::string ser = serialize_vault(vault);
                if (ser.size() > MAX_VAULT_SIZE / 2) { audit_log_level(LogLevel::ERROR, "serialize_vault too large during deletion save"); std::cerr << "An unexpected error occurred.\n"; continue; }
                byte* ct2 = nullptr; size_t ct2_len = 0; byte new_nonce[NONCE_LEN];
                if (!encrypt_vault_blob(key, reinterpret_cast<const byte*>(ser.data()), ser.size(), &ct2, &ct2_len, new_nonce)) {
                    audit_log_level(LogLevel::ERROR, "Encryption failed on save (delete credential)");
                    std::cerr << "An unexpected error occurred.\n";
                }
                else {
                    if (!atomic_write_file(VAULT_FILENAME, ct2, ct2_len) || !save_meta(salt, new_nonce)) {
                        audit_log_level(LogLevel::ERROR, "Failed to persist vault (delete credential)");
                        std::cerr << "An unexpected error occurred.\n";
                    }
                    else {
                        memcpy(nonce, new_nonce, NONCE_LEN);
                    }
                    sodium_memzero(ct2, ct2_len); free(ct2);
                }
            }
            else {
                audit_log_level(LogLevel::WARN, "Deletion attempt failed (wrong master) for " + label);
                std::cout << "Master password check failed. Not deleted.\n";
            }
            sodium_memzero(confirm.data(), confirm.size()); confirm.clear();
            sodium_memzero(verifyKey, KEY_LEN);
        }
        else if (choice == "5") { // ------ Reveal existing credentials ------ 
            std::string label;
            std::cout << "Reveal - Label: ";
            std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            audit_log_level(LogLevel::INFO, "Reveal password requested for " + label);
            std::cout << "Username: " << it->second.username << "\n";
            std::cout << "Password: " << it->second.password << "\n";
            std::cout << "(action logged)\n";
        }
        else if (choice == "6") { // ------ Copy existing credentials ------ 
            std::string label;
            std::cout << "Copy - Label: ";
            std::getline(std::cin, label);
            auto it = vault.find(label);
            if (it == vault.end()) {
                std::cout << "Not found\n";
                continue;
            }
            audit_log_level(LogLevel::INFO, "Copy requested for " + label);

            std::cout << "Copy to: (1) secure internal buffer (current behavior)  (2) system clipboard (timed clear)\n";
            std::cout << "Choose 1 or 2: ";
            std::string opt; std::getline(std::cin, opt);

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
                std::string ts; std::getline(std::cin, ts);
                if (!ts.empty()) {
                    try { timeout_secs = std::stoul(ts); }
                    catch (...) { timeout_secs = 15; }
                    if (timeout_secs > 600) timeout_secs = 600; // cap
                }

                // Copy with timed clear
                copy_with_timed_clear(it->second.password, timeout_secs);
                audit_log_level(LogLevel::INFO, "Copy requested for " + label + " -> system clipboard (timed for " + std::to_string(timeout_secs) + ")");
                std::cout << "Password copied to system clipboard for " << timeout_secs << " seconds. Action logged.\n";
            }
            else {
                std::cout << "Invalid option\n";
            }
        }
        else if (choice == "7") { // ------ Exit the password manager ------ 
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

            std::vector<byte> masterCheck = get_password_bytes("Enter master password to confirm: ");
            if (masterCheck.empty()) {
                std::cout << "Invalid input\n";
                continue;
            }
            byte verifyKey[KEY_LEN];
            sodium_memzero(verifyKey, KEY_LEN);
            if (!derive_key_from_password(masterCheck.data(), masterCheck.size(), salt, verifyKey)) {
                audit_log_level(LogLevel::WARN, "Vault delete: key derivation failed during verification");
                sodium_memzero(masterCheck.data(), masterCheck.size()); masterCheck.clear(); sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "Key derivation failed.\n";
                continue;
            }

            std::vector<byte> ct;
            if (!load_vault_ciphertext(ct)) {
                audit_log_level(LogLevel::ERROR, "Vault delete: no vault found (load failed)");
                sodium_memzero(masterCheck.data(), masterCheck.size()); masterCheck.clear(); sodium_memzero(verifyKey, KEY_LEN);
                std::cout << "No vault file found.\n";
                continue;
            }

            byte* plain = nullptr; size_t plain_len = 0;
            if (!decrypt_vault_blob(verifyKey, ct.data(), ct.size(), nonce, &plain, &plain_len)) {
                audit_log_level(LogLevel::WARN, "Vault delete: incorrect master password");
                sodium_memzero(masterCheck.data(), masterCheck.size()); masterCheck.clear(); sodium_memzero(verifyKey, KEY_LEN);
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

    audit_log_level(LogLevel::INFO, "Session closed");
    std::cout << "Goodbye.\n";
    return cleanup_and_exit(0, vault, key, salt, nonce);
}
