#include "io.hpp"
#include "util.hpp"
#include "logging.hpp"
#include "vault.hpp"
#include "passman_common.hpp"

#if !defined(_WIN32)
#include <pwd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#else
#include <direct.h>
#include <windows.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>

// -------- Global vault paths --------
std::string g_vault_root;
std::string g_vault_dir;
std::string g_vault_name;
std::string g_vault_filename;
std::string g_meta_filename;
std::string g_audit_log_path;

// ---------- Path helpers ----------
static std::string get_user_home_dir() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        struct passwd* pw = getpwuid(geteuid());
        if (pw && pw->pw_dir) {
            home = pw->pw_dir;
        }
}
    if (!home || !*home) return ".";
    return std::string(home);
}

static bool ensure_dir_exists(const std::string& path, mode_t mode) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            std::cerr << path << " exists but is not a directory\n";
            return false;
        }
        if ((st.st_mode & 0777) != mode) {
            chmod(path.c_str(), mode);
        }
        return true;
    }
    if (mkdir(path.c_str(), mode) != 0) {
        if (errno != EEXIST) {
            std::cerr << "Failed to create directory " << path << ": " << strerror(errno) << "\n";
            return false;
        }
    }
    return true;
}

// -------- Ownership and permission checks ----------
bool check_dir_ownership_and_perms(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        std::cerr << "Internal error: vault file check failed.\n";
        return false;
    }
    uid_t uid = geteuid();
    if (st.st_uid != uid) {
        audit_log_level(LogLevel::ERROR,
            "Directory ownership violation: " + path,
            "io_module",
            "failure");
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    mode_t perms = st.st_mode & 0777;
    // No group/other access allowed
    if ((perms & 0077) != 0) {
        audit_log_level(LogLevel::ERROR,
            "Insecure directory permissions on: " + path,
            "io_module",
            "failure");
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    return true;
}

bool check_file_ownership_and_perms(const std::string& path, bool allow_missing) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        if (errno == ENOENT && allow_missing) return true;
        std::cerr << "Internal error: vault file check failed.\n";
        return false;
    }
    uid_t uid = geteuid();
    if (st.st_uid != uid) {
        audit_log_level(LogLevel::ERROR,
            "File ownership violation: " + path,
            "io_module",
            "failure");
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    mode_t perms = st.st_mode & 0777;
    if ((perms & 0077) != 0) {
        audit_log_level(LogLevel::ERROR,
            "Insecure file permissions on: " + path,
            "io_module",
            "failure");
        std::cerr << "Internal error: vault file access check failed.\n";
        return false;
    }
    return true;
}


// ---------- Multi-vault initialization ----------
bool init_vault_paths() {
    std::string home = get_user_home_dir();
    const char sep = '/';
    g_vault_root = home + "/.passman";
    std::string vaults_dir = g_vault_root + "/vaults";

    if (!ensure_dir_exists(g_vault_root, S_IRWXU)) {
        return false;
    }
    if (!ensure_dir_exists(vaults_dir, S_IRWXU)) {
        return false;
    }

    // choose vault name
    unsigned attempts = 0;
    const unsigned MAX_ATTEMPTS = 5;
    while (attempts < MAX_ATTEMPTS) {
        std::cout << "Vault name: ";
        if (!std::getline(std::cin, g_vault_name)) {
            return false;
        }

        if (!valid_vault_name(g_vault_name)) {
            std::cout << "Invalid vault name. Use only letters, digits, '_' or '-', max "
                << MAX_VAULT_NAME_LEN << " characters.\n";
            attempts++;
            continue;
        }
        break;
    }

    if (g_vault_name.empty() || attempts >= MAX_ATTEMPTS) {
        audit_log_level(LogLevel::ERROR,
            "Vault name selection failed",
            "io_module",
            "failure");
        return false;
    }

    // build per-vault directory and paths
    g_vault_dir = vaults_dir + sep + g_vault_name;
    if (!ensure_dir_exists(g_vault_dir, S_IRWXU)) {
        return false;
    }

    g_vault_filename = g_vault_dir + "/vault.bin";
    g_meta_filename = g_vault_dir + "/vault.meta";
    g_audit_log_path = g_vault_dir + "/audit.log";

    // enforce per-user ownership and tight perms on dir
    if (!check_dir_ownership_and_perms(g_vault_dir)) {
        return false;
    }

    // if files don't exist yet, just check that any existing ones are secure
    if (!check_file_ownership_and_perms(g_vault_filename, true)) return false;
    if (!check_file_ownership_and_perms(g_meta_filename, true))  return false;
    if (!check_file_ownership_and_perms(g_audit_log_path, true)) return false;

    return true;
    }


// -------- Atomic file write helper -------- 
bool atomic_write_file(const std::string& path, const byte* buf, size_t len) {
    if (!buf) return false;
    if (len > MAX_VAULT_SIZE) {
        audit_log_level(LogLevel::ERROR,
            "atomic_write_file: attempt to write huge file",
            "io_module",
            "failure");
        return false;
    }

    std::string tmpl = path + ".tmpXXXXXX";
    std::vector<char> temp(tmpl.begin(), tmpl.end());
    temp.push_back('\0');

    int fd = mkostemp(temp.data(), O_CLOEXEC);
    if (fd < 0) {
        std::cerr << "mkostemp failed\n";
        return false;
    }
    // set perms to 0600
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        std::cerr << "fchmod failed\n";
        close(fd);
        unlink(temp.data());
        return false;
    }
    ssize_t w = write(fd, buf, len);
    if (w < 0 || (size_t)w != len) {
        std::cerr << "write failed\n";
        close(fd);
        unlink(temp.data());
        return false;
    }
    if (fsync(fd) != 0) {
        std::cerr << "fsync failed\n";
    }
    if (close(fd) != 0) {
        std::cerr << "close failed\n";
    }
    if (rename(temp.data(), path.c_str()) != 0) {
        std::cerr << "rename failed\n";
        unlink(temp.data());
        return false;
    }
    return true;
}


// -------- Meta (salt + nonce) helpers --------
static std::string to_base64(const byte* bin, size_t len) {
    if (!bin) return "";
    size_t out_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    if (out_len == 0) return "";
    std::string out;
    out.resize(out_len);
    sodium_bin2base64(&out[0], out_len, bin, len, sodium_base64_VARIANT_ORIGINAL);
    // trim at first null
    size_t pos = out.find('\0');
    if (pos != std::string::npos) out.resize(pos);
    return out;
}

static std::vector<byte> from_base64(const std::string& b64) {
    if (b64.empty()) return {};
    size_t max_out = b64.size();
    std::vector<byte> out(max_out);
    size_t out_len = 0;
    if (sodium_base642bin(out.data(),
        out.size(),
        b64.c_str(),
        b64.size(),
        NULL,
        &out_len,
        NULL,
        sodium_base64_VARIANT_ORIGINAL) != 0) {
        return {};
    }
    if (out_len > out.size()) return {};
    out.resize(out_len);
    return out;
}

bool save_meta(const byte salt[SALT_LEN], const byte nonce[NONCE_LEN]) {
    if (!salt || !nonce) return false;
    std::string b64salt = to_base64(salt, SALT_LEN);
    std::string b64nonce = to_base64(nonce, NONCE_LEN);
    std::string content = b64salt + "\n" + b64nonce + "\n";

    if (!atomic_write_file(g_meta_filename,
        reinterpret_cast<const byte*>(content.data()),
        content.size())) {
        audit_log_level(LogLevel::ERROR,
            "save_meta: atomic write failed",
            "io_module",
            "failure");
        return false;
    }
    return true;
}

bool load_meta(byte salt[SALT_LEN], byte nonce[NONCE_LEN]) {
    FILE* f = fopen(g_meta_filename.c_str(), "r");
    if (!f) {
        audit_log_level(LogLevel::ERROR,
            "load_meta: fopen failed",
            "io_module",
            "failure");
        return false;
    }

    std::string s_salt, s_nonce;
    char buf[4096];

    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        audit_log_level(LogLevel::ERROR,
            "load_meta: fgets salt failed",
            "io_module",
            "failure");
        return false;
    }
    s_salt = buf;
    while (!s_salt.empty() && (s_salt.back() == '\n' || s_salt.back() == '\r'))
        s_salt.pop_back();

    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        audit_log_level(LogLevel::ERROR,
            "load_meta: fgets nonce failed",
            "io_module",
            "failure");
        return false;
    }
    s_nonce = buf;
    while (!s_nonce.empty() && (s_nonce.back() == '\n' || s_nonce.back() == '\r'))
        s_nonce.pop_back();

    fclose(f);

    if (s_salt.empty() || s_nonce.empty()) {
        audit_log_level(LogLevel::WARN,
            "load_meta: meta file missing lines",
            "io_module",
            "failure");
        return false;
    }

    auto vs = from_base64(s_salt);
    auto vn = from_base64(s_nonce);
    if (vn.size() != NONCE_LEN || vs.size() != SALT_LEN) {
        audit_log_level(LogLevel::WARN,
            "load_meta: meta decode length mismatch",
            "io_module",
            "failure");
        return false;
    }
    memcpy(salt, vs.data(), SALT_LEN);
    memcpy(nonce, vn.data(), NONCE_LEN);
    return true;
}


// -------- Vault ciphertext --------
bool load_vault_ciphertext(std::vector<byte>& ct) {
    FILE* f = fopen(g_vault_filename.c_str(), "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR,
            "fseek end failed",
            "io_module",
            "failure");
        return false;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR,
            "ftell failed",
            "io_module",
            "failure");
        return false;
    }
    if ((unsigned long)sz > MAX_VAULT_SIZE) {
        audit_log_level(LogLevel::WARN,
            "Vault file too large or corrupt",
            "io_module",
            "failure");
        fclose(f);
        return false;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        audit_log_level(LogLevel::ERROR,
            "fseek set failed",
            "io_module",
            "failure");
        return false;
    }

    size_t size = static_cast<size_t>(sz);
    ct.resize(size);
    if (size > 0) {
        size_t r = fread(ct.data(), 1, size, f);
        if (r != size) {
            fclose(f);
            ct.clear();
            audit_log_level(LogLevel::ERROR,
                "fread failed on vault",
                "io_module",
                "failure");
            return false;
        }
    }

    fclose(f);
    return true;
}


// -------- Secure deletion --------
void secure_delete_file(const char* path) {
    if (!path) return;
    struct stat st;
    if (lstat(path, &st) != 0) {
        unlink(path);
        return;
    }

    if (S_ISLNK(st.st_mode)) {
        audit_log_level(LogLevel::WARN,
            std::string("secure_delete_file: refused to delete symlink: ") + path,
            "io_module",
            "failure");
        return;
    }

    if (st.st_uid != geteuid()) {
        audit_log_level(LogLevel::WARN,
            "secure_delete_file: refused, wrong owner",
            "io_module",
            "failure");
        return;
    }

    FILE* f = fopen(path, "r+");
    if (!f) {
        std::remove(path);
        return;
    }

    long lsz = st.st_size;
    if (lsz > 0 && (unsigned long)lsz <= MAX_VAULT_SIZE) {
        rewind(f);
        std::vector<byte> zeros((size_t)lsz, 0);
        (void)fwrite(zeros.data(), 1, zeros.size(), f);
        fflush(f);
        fsync(fileno(f));
    }

    fclose(f);
    std::remove(path);
}