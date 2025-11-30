#pragma once
#include "passman_common.hpp"

// -------- Logging (levels) --------
enum class LogLevel { INFO, WARN, ERROR, ALERT }; // levels

struct LogContext {
    std::string userId;
    std::string sessionId;
    std::string ip;
};

extern LogContext g_log_ctx;

// Initialize global logging context
void init_log_context();

// Log with level, message, optional event + outcome
// audit_log_level(LogLevel::INFO, "User logged in", "session", "success");
void audit_log_level(
    LogLevel lvl,
    const std::string& entry,
    const std::string& event = "",
    const std::string& outcome = ""
);
