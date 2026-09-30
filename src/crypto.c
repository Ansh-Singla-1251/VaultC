#include <stdio.h>
#include <string.h>
#include <argon2.h>

#include "../include/crypto.h"

int generate_salt(uint8_t *salt, size_t length)
{
    if (salt == NULL || length == 0)
        return 0;

    FILE *random_source = fopen("/dev/urandom", "rb");

    if (random_source == NULL)
    {
        perror("Failed to access system random source");
        return 0;
    }

    size_t bytes_read = fread(salt, 1, length, random_source);

    fclose(random_source);

    if (bytes_read != length)
    {
        printf("Failed to generate random salt.\n");
        return 0;
    }

    return 1;
}

int derive_key(
    const char *password,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *key,
    size_t key_length)
{
    if (password == NULL ||
        salt == NULL ||
        key == NULL ||
        salt_length == 0 ||
        key_length == 0)
    {
        return 0;
    }

    int result = argon2id_hash_raw(
        3,
        64 * 1024,
        1,
        password,
        strlen(password),
        salt,
        salt_length,    
        key,
        key_length
    );

    if (result != ARGON2_OK)
    {
        printf("Key derivation failed: %s\n",
               argon2_error_message(result));

        return 0;
    }

    return 1;
}
int verify_password(
    const char *password,
    const uint8_t *salt,
    size_t salt_length,
    const uint8_t *expected_hash,
    size_t hash_length)
{
    if (password == NULL ||
        salt == NULL ||
        expected_hash == NULL ||
        hash_length == 0)
    {
        return 0;
    }

    uint8_t derived_hash[hash_length];

    if (!derive_key(
            password,
            salt,
            salt_length,
            derived_hash,
            hash_length))
    {
        return 0;
    }

    return memcmp(
        derived_hash,
        expected_hash,
        hash_length) == 0;
}