#pragma once
#include "passman_common.hpp"
#include "logging.hpp"

// -------- Crypto helpers --------
bool derive_key_from_password(
    const byte* pw,
    size_t pw_len,
    const byte salt[SALT_LEN],
    byte key[KEY_LEN]
);

bool encrypt_vault_blob(
    const byte key[KEY_LEN],
    const byte* plaintext,
    size_t plen,
    byte** out_ct,
    size_t* out_ct_len,
    byte nonce[NONCE_LEN]
);

bool decrypt_vault_blob(
    const byte key[KEY_LEN],
    const byte* ct,
    size_t ct_len,
    const byte nonce[NONCE_LEN],
    byte** out_plain,
    size_t* out_plain_len
);
