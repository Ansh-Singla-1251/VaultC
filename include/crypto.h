#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int generate_salt(uint8_t *salt, size_t length);

int verify_password(
    const char *password,
    const uint8_t *salt,
    size_t salt_length,
    const uint8_t *expected_hash,
    size_t hash_length
);

int derive_key(
    const char *password,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *key,
    size_t key_length
);

#endif