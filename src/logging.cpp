#include "clipboard.hpp"
#include "logging.hpp"
#include "io.hpp"
#include "util.hpp"

LogContext g_log_ctx;


// ---------------- Get username ----------------
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


// ---------------- Get IP - client IP if SSH, else localhost ----------------
static std::string get_client_ip() {
    const char* ssh_conn = std::getenv("SSH_CONNECTION");
    if (ssh_conn && ssh_conn[0]) {
        std::istringstream iss(ssh_conn);
        std::string ip;
        if (iss >> ip) {
            return ip;
        }
    }

    const char* ssh_client = std::getenv("SSH_CLIENT");
    if (ssh_client && ssh_client[0]) {
        std::istringstream iss(ssh_client);
        std::string ip;
        if (iss >> ip) {
            return ip;
        }
    }

    // local execution
    return "127.0.0.1";
}


// ---------------- Global logging context init ----------------
void init_log_context() {
    g_log_ctx.userId = get_system_username();
    g_log_ctx.sessionId = generate_session_id();
    g_log_ctx.ip = get_client_ip();
}


// ---------------- Logging (levels) ----------------
static const char* log_level_str(LogLevel lvl) {
    switch (lvl) {
    case LogLevel::INFO:  return "INFO";
    case LogLevel::WARN:  return "WARN";
    case LogLevel::ERROR: return "ERROR";
    case LogLevel::ALERT: return "ALERT";
    default:              return "UNKNOWN";
    }
}

void audit_log_level(
    LogLevel lvl,
    const std::string& entry,
    const std::string& event,
    const std::string& outcome
)
{
    // determine log path
    const char* default_log = AUDIT_LOG;
    const char* path = (!g_audit_log_path.empty()
        ? g_audit_log_path.c_str()
        : default_log);

    FILE* f = std::fopen(path, "a");
    if (!f) {
        std::fprintf(stderr, "[audit-fail] %s: %s\n",
            log_level_str(lvl),
            entry.c_str());
        return;
    }

#if !defined(_WIN32)
    fchmod(fileno(f), S_IRUSR | S_IWUSR);
#endif

    // timestamp
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    char tbuf[64];
    if (std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
        std::strncpy(tbuf, "0000-00-00 00:00:00", sizeof(tbuf));
        tbuf[sizeof(tbuf) - 1] = '\0';
    }

    // sanitize message fields to avoid newlines in log entries
    auto sanitize = [](const std::string& s) {
        std::string r = s;
        for (char& c : r) {
            if (c == '\n' || c == '\r') c = ' ';
        }
        return r;
        };

    std::string s_entry = sanitize(entry);
    std::string s_event = sanitize(event);
    std::string s_outcome = sanitize(outcome);

    // timestamp | level | user | ip | session | event | outcome | message
    std::fprintf(
        f,
        "%s | %s | user=%s | ip=%s | session=%s | event=%s | outcome=%s | %s\n",
        tbuf,
        log_level_str(lvl),
        g_log_ctx.userId.c_str(),
        g_log_ctx.ip.c_str(),
        g_log_ctx.sessionId.c_str(),
        s_event.c_str(),
        s_outcome.c_str(),
        s_entry.c_str()
    );

    std::fflush(f);
#if !defined(_WIN32)
    fsync(fileno(f));
#endif
    std::fclose(f);
}
