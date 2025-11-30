#include "crypto.hpp"

// -------- Crypto helpers --------
bool derive_key_from_password( // symmetric key derivation from password using Argon2id
    const byte* pw,
    size_t pw_len,
    const byte salt[SALT_LEN],
    byte key[KEY_LEN]
)
{
    if (!pw || !salt || !key) {
        audit_log_level(LogLevel::ERROR,
            "derive_key_from_password: null pointer",
            "crypto_module",
            "failure");
        return false;
    }

    if (pw_len == 0 || pw_len > MAX_PASS_LEN) {
        audit_log_level(LogLevel::WARN,
            "derive_key_from_password: invalid password length",
            "crypto_module",
            "failure");
        return false;
    }

    if (crypto_pwhash(key,
        KEY_LEN,
        reinterpret_cast<const char*>(pw),
        pw_len,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        audit_log_level(LogLevel::ERROR,
            "derive_key_from_password: crypto_pwhash failed",
            "crypto_module",
            "failure");
        return false;
    }

    return true;
}

bool encrypt_vault_blob( // vault plaintext encrytption using XChaCha20-Poly1305-IETF
    const byte key[KEY_LEN],
    const byte* plaintext,
    size_t plen,
    byte** out_ct,
    size_t* out_ct_len,
    byte nonce[NONCE_LEN]
)
{
    if (!out_ct || !out_ct_len || !nonce || !key) {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob: null output pointer",
            "crypto_module",
            "failure");
        return false;
    }

    if (plen > 0 && !plaintext) {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob: non-zero length but plaintext null",
            "crypto_module",
            "failure");
        return false;
    }

    if (plen > MAX_VAULT_SIZE) {
        audit_log_level(LogLevel::WARN,
            "encrypt_vault_blob: plaintext too large",
            "crypto_module",
            "failure");
        return false;
    }

    // overflow guard plen + ABYTES
    if (plen > (std::numeric_limits<size_t>::max)() - ABYTES) {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob: size overflow",
            "crypto_module",
            "failure");
        return false;
    }

    randombytes_buf(nonce, NONCE_LEN);

    size_t alloc_len = plen + ABYTES;
    byte* ct = static_cast<byte*>(std::malloc(alloc_len));
    if (!ct) {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob: malloc failed",
            "crypto_module",
            "failure");
        return false;
    }

    unsigned long long ct_len_ull = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct,
        &ct_len_ull,
        plaintext,
        plen,
        nullptr,          // additional data - none
        0,
        nullptr,          // nsec - not used
        nonce,
        key) != 0)
    {
        audit_log_level(LogLevel::ERROR,
            "encrypt_vault_blob: crypto_aead_xchacha20poly1305_ietf_encrypt failed",
            "crypto_module",
            "failure");
        sodium_memzero(ct, alloc_len);
        std::free(ct);
        return false;
    }

    // safe - crypto_aead results in ct_len <= plen + ABYTES
    size_t ct_len = static_cast<size_t>(ct_len_ull);
    *out_ct = ct;
    *out_ct_len = ct_len;

    return true;
}


bool decrypt_vault_blob( // vault ciphertext decryption with XChaCha20-Poly1305-IETF
    const byte key[KEY_LEN],
    const byte* ct,
    size_t ct_len,
    const byte nonce[NONCE_LEN],
    byte** out_plain,
    size_t* out_plain_len
)
{
    if (!out_plain || !out_plain_len || !nonce || !key) {
        audit_log_level(LogLevel::ERROR,
            "decrypt_vault_blob: null output pointer",
            "crypto_module",
            "failure");
        return false;
    }

    *out_plain = nullptr;
    *out_plain_len = 0;

    if (!ct || ct_len < ABYTES) {
        audit_log_level(LogLevel::WARN,
            "decrypt_vault_blob: ciphertext too small or null",
            "crypto_module",
            "failure");
        return false;
    }

    size_t max_plain_len = ct_len - ABYTES;

    byte* plain = static_cast<byte*>(std::malloc(max_plain_len));
    if (!plain) {
        audit_log_level(LogLevel::ERROR,
            "decrypt_vault_blob: malloc failed",
            "crypto_module",
            "failure");
        return false;
    }

    unsigned long long out_len_ull = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        plain,
        &out_len_ull,
        nullptr,      // nsec - not used
        ct,
        ct_len,
        nullptr,      // additional data - none
        0,
        nonce,
        key) != 0)
    {
        // wrong key, corrupted or tampered ciphertext
        audit_log_level(LogLevel::WARN,
            "decrypt_vault_blob: authentication failed",
            "crypto_module",
            "failure");
        sodium_memzero(plain, max_plain_len);
        std::free(plain);
        return false;
    }

    size_t out_len = static_cast<size_t>(out_len_ull);
    if (out_len > max_plain_len) {
        audit_log_level(LogLevel::ERROR,
            "decrypt_vault_blob: output length larger than buffer",
            "crypto_module",
            "failure");
        sodium_memzero(plain, max_plain_len);
        std::free(plain);
        return false;
    }

    *out_plain = plain;
    *out_plain_len = out_len;
    return true;
}
