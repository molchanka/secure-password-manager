#pragma once
#include "passman_common.hpp"
#include "logging.hpp"
#include "util.hpp"

#include <string>

// -------- Clipboard API exposed to main --------

// Set clipboard to given string
bool clipboard_set(const std::string& data);

// Read clipboard into 'out'
bool clipboard_get(std::string& out);

// Clear clipboard contents
bool clipboard_clear();

// Copy with timed clear
void copy_with_timed_clear(const std::string& secret, unsigned seconds);

bool windows_clipboard_history_enabled();

// WSL detection and clipboard history detection
bool wsl_clipboard_history_enabled();
bool running_in_wsl();
