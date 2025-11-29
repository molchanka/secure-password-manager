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

void init_log_context();

void audit_log_level(
    LogLevel lvl,
    const std::string& entry,
    const std::string& event = "",
    const std::string& outcome = ""
);

void audit_log(const std::string& entry);
