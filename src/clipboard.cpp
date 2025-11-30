#include "clipboard.hpp"
#include "logging.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

#if !defined(_WIN32)
#include <unistd.h>
#include <sys/wait.h>
#endif

// ---------------- Cross-platform clipboard helpers ----------------
#if !defined(_WIN32)
static bool run_writer_with_stdin(const std::vector<const char*>& argv, // !WIN32
    const std::string& input)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        // child: replace stdin with read end
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (auto p : argv) args.push_back(const_cast<char*>(p));
        args.push_back(nullptr);

        execvp(args[0], args.data());
        _exit(127);
    }

    // parent: write input
    close(pipefd[0]);
    ssize_t remaining = static_cast<ssize_t>(input.size());
    const char* ptr = input.data();

    while (remaining > 0) {
        ssize_t w = write(pipefd[1], ptr, remaining);
        if (w <= 0) break;
        ptr += w;
        remaining -= w;
    }
    close(pipefd[1]);

    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool run_reader_to_string(const std::vector<const char*>& argv, // !WIN32
    std::string& out)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        // child: stdout -> pipe write end
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (auto p : argv) args.push_back(const_cast<char*>(p));
        args.push_back(nullptr);

        execvp(args[0], args.data());
        _exit(127);
    }

    // parent: read from pipe
    close(pipefd[1]);
    std::string s;
    char buf[4096];
    ssize_t r;
    size_t max_size = 1024 * 1024; // 1 MB cap

    while ((r = read(pipefd[0], buf, sizeof(buf))) > 0) {
        if (s.size() + static_cast<size_t>(r) > max_size) {
            // Avoid insane sizes; truncate
            s.append(buf, buf + (max_size - s.size()));
            break;
        }
        s.append(buf, buf + r);
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return false;
    }

    // trim trailing newlines
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }

    out = std::move(s);
    return true;
}
#endif


// ---------------- Platform detection for WSL ----------------
bool running_in_wsl() {
    FILE* f = fopen("/proc/version", "r");
    if (!f) return false;

    char buf[256];
    size_t nread = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (nread == 0) {
        // could not read - not WSL
        return false;
    }

    buf[nread] = '\0';

    return (strstr(buf, "Microsoft") || strstr(buf, "WSL"));
}


// ---------------- Clipboard operations ----------------
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

    return (out == "1");
}

bool windows_clipboard_history_enabled() {
#if defined(_WIN32)
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

bool clipboard_set(const std::string& data) {
#if defined(_WIN32)
    if (!OpenClipboard(nullptr)) {
        audit_log_level(LogLevel::WARN,
            "clipboard_set: OpenClipboard failed",
            "clipboard_module",
            "failure");
        return false;
    }
    if (!EmptyClipboard()) {
        CloseClipboard();
        audit_log_level(LogLevel::WARN,
            "clipboard_set: EmptyClipboard failed",
            "clipboard_module",
            "failure");
        return false;
    }

    size_t len = data.size();
    HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (!hglb) {
        CloseClipboard();
        return false;
    }

    char* dst = static_cast<char*>(GlobalLock(hglb));
    if (!dst) {
        GlobalFree(hglb);
        CloseClipboard();
        return false;
    }

    memcpy(dst, data.data(), len);
    dst[len] = '\0';
    GlobalUnlock(hglb);

    if (!SetClipboardData(CF_TEXT, hglb)) {
        GlobalFree(hglb);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
#else
    const char* wayland = std::getenv("WAYLAND_DISPLAY");
    std::vector<const char*> cmd;
    if (wayland && *wayland) {
        cmd = { "wl-copy" };
    }
    else {
        cmd = { "xclip", "-selection", "clipboard" };
    }

    bool ok = run_writer_with_stdin(cmd, data);
    if (!ok) {
        audit_log_level(LogLevel::WARN,
            "clipboard_set: external tool failed",
            "clipboard_module",
            "failure");
    }
    return ok;
#endif
}

bool clipboard_get(std::string& out) {
#if defined(_WIN32)
    if (!OpenClipboard(nullptr)) return false;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) {
        CloseClipboard();
        return false;
    }
    const char* src = static_cast<const char*>(GlobalLock(h));
    if (!src) {
        CloseClipboard();
        return false;
    }

    out.assign(src);
    GlobalUnlock(h);
    CloseClipboard();
    return true;
#else
    const char* wayland = std::getenv("WAYLAND_DISPLAY");
    std::vector<const char*> cmd;
    if (wayland && *wayland) {
        cmd = { "wl-paste" };
    }
    else {
        cmd = { "xclip", "-selection", "clipboard", "-o" };
    }

    std::string tmp;
    if (!run_reader_to_string(cmd, tmp)) {
        audit_log_level(LogLevel::WARN,
            "clipboard_get: external tool failed",
            "clipboard_module",
            "failure");
        return false;
    }
    out = std::move(tmp);
    return true;
#endif
}

bool clipboard_clear() {
    return clipboard_set(std::string{});
}


// ---------------- Copy with timed clear ----------------
void copy_with_timed_clear(const std::string& secret, unsigned seconds) {
    if (!clipboard_set(secret)) {
        std::cout << "Failed to copy to clipboard.\n";
        return;
    }

    std::thread([secret, seconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));

        // only clear if clipboard still contains the same secret
        std::string current;
        if (!clipboard_get(current)) {
            return;
        }
        if (current == secret) {
            clipboard_clear();
            audit_log_level(LogLevel::INFO,
                "Clipboard cleared after timeout",
                "clipboard_module",
                "success");
        }
        }).detach();
}