#include "vault.hpp"

// -------- Escaping --------
std::string escape_str(const std::string& s) {
    std::string r; r.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\n') { r += "\\n"; }
        else if (c == '\\') { r += "\\\\"; }
        else r.push_back(c);
    }
    return r;
}

std::string unescape_str(const std::string& x) {
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


// ----------- Serialize vault to text ------------
std::string serialize_vault(const Vault& v) {
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


// ----------- Deserialize text to vault ------------
Vault deserialize_vault(const std::string& s) {
    Vault v;
    std::istringstream iss(s);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        std::vector<std::string> toks;
        toks.reserve(4);

        size_t start = 0;
        for (size_t pos = 0; pos <= line.size(); ++pos) {
            if (pos == line.size() || line[pos] == '\t') {
                toks.emplace_back(line.substr(start, pos - start));
                start = pos + 1;
            }
        }

        if (toks.size() < 4) {
            // malformed line -> skip and log
            audit_log_level(LogLevel::WARN,
                "deserialize_vault: skipped malformed line",
                "vault_module",
                "failure");
            continue;
        }

        const std::string& label = toks[0];
        Cred c{
            label,
            unescape_str(toks[1]),
            unescape_str(toks[2]),
            unescape_str(toks[3])
        };

        v[label] = std::move(c);
    }

    return v;
}