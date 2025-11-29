#include "clipboard.hpp"
#include "logging.hpp"

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
    EmptyClipboard();

    int wlen = MultiByteToWideChar(
        CP_UTF8, 0, data.c_str(), -1, nullptr, 0
    );
    if (wlen <= 0) { CloseClipboard(); return false; }

    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, wlen * sizeof(wchar_t));
    if (!h) { CloseClipboard(); return false; }

    wchar_t* wdata = (wchar_t*)GlobalLock(h);
    MultiByteToWideChar(CP_UTF8, 0, data.c_str(), -1, wdata, wlen);
    GlobalUnlock(h);

    SetClipboardData(CF_UNICODETEXT, h);
    CloseClipboard();
    return true;
}


static bool clipboard_get_win(std::string& out) {
    out.clear();
    if (!OpenClipboard(nullptr)) return false;

    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) { CloseClipboard(); return false; }

    wchar_t* wdata = (wchar_t*)GlobalLock(h);
    if (!wdata) { CloseClipboard(); return false; }

    // UTF-16 → UTF-8
    int len = WideCharToMultiByte(
        CP_UTF8, 0, wdata, -1, nullptr, 0, nullptr, nullptr
    );

    std::string utf8(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wdata, -1, utf8.data(), len, nullptr, nullptr);

    out = utf8;

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

bool windows_clipboard_history_enabled() {
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
bool running_in_wsl() {
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

bool wsl_clipboard_history_enabled() {
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
bool clipboard_set(const std::string& data) {
#if defined(_WIN32)
    return clipboard_set_win(data);
#else
    return clipboard_set_posix(data);
#endif
}

bool clipboard_get(std::string& out) {
#if defined(_WIN32)
    return clipboard_get_win(out);
#else
    return clipboard_get_posix(out);
#endif
}

bool clipboard_clear() {
#if defined(_WIN32)
    return clipboard_clear_win();
#else
    return clipboard_clear_posix();
#endif
}

// copy with timed clear: copies data to clipboard and clears after `seconds` only if the
// clipboard still contains identical content. zeroes local buffers used.
void copy_with_timed_clear(const std::string& secret, unsigned seconds) {
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
        audit_log_level(LogLevel::WARN, "clipboard_set failed for timed copy", "clipboard_module", "failure");
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
            audit_log_level(LogLevel::INFO, "Clipboard cleared after timeout", "clipboard_module", "success");
        }
        // wipe current
        if (!current.empty()) {
            sodium_memzero(&current[0], current.size());
        }
        }).detach();
}
