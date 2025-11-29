#pragma once
#include "passman_common.hpp"
#include "logging.hpp"

// -------- Vault serialization --------
std::string escape_str(const std::string& s);
std::string unescape_str(const std::string& x);
std::string serialize_vault(const Vault& v);
Vault deserialize_vault(const std::string& s);
