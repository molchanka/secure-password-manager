#include "clipboard.hpp"
#include "logging.hpp"
#include "io.hpp"
#include "util.hpp" // for generate_session_id if needed

LogContext g_log_ctx;

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
void init_log_context() {
    g_log_ctx.userId = get_system_username();
    g_log_ctx.sessionId = generate_session_id();
    g_log_ctx.ip = get_client_ip();
}

void audit_log_level(LogLevel lvl, const std::string& entry,
    const std::string& event, const std::string& outcome)
{
    const char* path = nullptr;
    static const char* default_log = "audit.log";
    path = (!g_audit_log_path.empty() ? g_audit_log_path.c_str() : default_log);

    int flags = O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC;
#ifdef _WIN32
    flags |= O_BINARY;
#endif

    int fd = open(path, flags, S_IRUSR | S_IWUSR);
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

    // username
    std::string username;
#if defined(_WIN32)
    {
        char buf[256]; DWORD sz = sizeof(buf);
        username = (GetUserNameA(buf, &sz) ? buf : "unknown");
    }
#else
    {
        const char* u = getenv("USER");
        if (!u) u = getenv("LOGNAME");
        username = (u ? u : "unknown");
    }
#endif

    std::string sessionId = std::to_string((long long)getpid());

    // determine IP (SSH)
    std::string ip = "127.0.0.1";
    if (const char* ssh_conn = getenv("SSH_CONNECTION")) {
        std::istringstream iss(ssh_conn);
        iss >> ip;
    }
    else if (const char* ssh_client = getenv("SSH_CLIENT")) {
        std::istringstream iss(ssh_client);
        iss >> ip;
    }

    std::ostringstream oss;
    oss << tbuf
        << " [" << lname << "] "
        << "event=" << (event.empty() ? "none" : event)
        << " userId=" << username
        << " sessionId=" << sessionId
        << " ip=" << ip
        << " outcome=" << (outcome.empty() ? "none" : outcome)
        << " desc=" << (entry.empty() ? "none" : entry)
        << "\n";

    std::string msg = oss.str();

    if (write(fd, msg.c_str(), msg.size()) < 0)
        std::cerr << "Write audit log failed.\n";

    if (close(fd) != 0)
        std::cerr << "Close audit log failed.\n";
}
