#include "crypto.hpp"

// -------- Crypto helpers --------
bool derive_key_from_password(const byte* pw, size_t pw_len, const byte salt[SALT_LEN], byte key[KEY_LEN]) {
    if (!pw || pw_len == 0) return false;
    if (crypto_pwhash(key, KEY_LEN,
        reinterpret_cast<const char*>(pw), pw_len,
        salt,
        OPSLIMIT, MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        audit_log_level(LogLevel::ERROR, "crypto_pwhash failed", "crypto_module", "failure");
        return false; // out of memory
    }
    return true;
}

bool encrypt_vault_blob(const byte key[KEY_LEN], const byte* plaintext, size_t plen,
    byte** out_ct, size_t* out_ct_len, byte nonce[NONCE_LEN]) {
    if (!plaintext) return false;
    if (plen > MAX_VAULT_SIZE) {
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: plaintext too large", "crypto_module", "failure");
        return false;
    }
    if (plen > SIZE_MAX - ABYTES) {
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: size overflow guard", "crypto_module", "failure");
        return false;
    }
    // generate nonce
    randombytes_buf(nonce, NONCE_LEN);
    unsigned long long ct_len64 = 0;
    size_t alloc_len = plen + ABYTES;
    *out_ct = (byte*)malloc(alloc_len);
    if (!*out_ct) {
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: malloc failed", "crypto_module", "failure");
        return false;
    }
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(*out_ct, &ct_len64, plaintext, plen, NULL, 0, NULL, nonce, key) != 0) {
        sodium_memzero(*out_ct, alloc_len);
        free(*out_ct);
        audit_log_level(LogLevel::ERROR, "encrypt_vault_blob: encrypt failed", "crypto_module", "failure");
        return false;
    }
    *out_ct_len = (size_t)ct_len64;
    return true;
}

bool decrypt_vault_blob(const byte key[KEY_LEN], const byte* ct, size_t ct_len,
    const byte nonce[NONCE_LEN], byte** out_plain, size_t* out_plain_len) {
    if (!ct || ct_len < ABYTES) {
        audit_log_level(LogLevel::WARN, "decrypt_vault_blob: ct too small", "crypto_module", "failure");
        return false;
    }
    *out_plain = (byte*)malloc(ct_len); // ciphertext len is >= plaintext
    if (!*out_plain) {
        audit_log_level(LogLevel::ERROR, "decrypt_vault_blob: malloc failed", "crypto_module", "failure");
        return false;
    }
    unsigned long long mlen = 0;
    if (!*out_plain) return false;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(*out_plain, &mlen,
        NULL,
        ct, ct_len,
        NULL, 0,
        nonce, key) != 0) {
        sodium_memzero(*out_plain, ct_len);
        free(*out_plain);
        *out_plain = nullptr;
        audit_log_level(LogLevel::ERROR, "decrypt_vault_blob: authentication failed", "crypto_module", "failure");
        return false;
    }
    *out_plain_len = (size_t)mlen;
    return true;
}
