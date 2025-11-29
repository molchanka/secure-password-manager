#pragma once
#include "passman_common.hpp"
#include "logging.hpp"

// Clipboard API exposed to main

bool clipboard_set(const std::string& data);
bool clipboard_get(std::string& out);
bool clipboard_clear();

// copy with timed clear: copies data to clipboard and clears after `seconds`
// only if the clipboard still contains identical content.
void copy_with_timed_clear(const std::string& secret, unsigned seconds);

#if defined(_WIN32)
bool windows_clipboard_history_enabled();
#endif

bool wsl_clipboard_history_enabled();
bool running_in_wsl();
