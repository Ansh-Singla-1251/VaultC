#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define VAULT_KEY_SIZE 32
#define VAULT_KEY_NONCE_SIZE 24
#define VAULT_KEY_TAG_SIZE 16
#define FILE_STREAM_HEADER_SIZE 24
#define FILE_STREAM_TAG_SIZE 17
#define FILE_CHUNK_SIZE 8192

int generate_salt(uint8_t *salt, size_t length);

int generate_random_bytes(uint8_t *buffer, size_t length);

int derive_key(const char *password, const uint8_t *salt, size_t salt_length, uint8_t *key, size_t key_length);

int verify_password(const char *password, const uint8_t *salt, size_t salt_length, const uint8_t *expected_hash, size_t hash_length);

int encrypt_vault_key(const uint8_t *vault_key, const uint8_t *password_key, const uint8_t *nonce, uint8_t *encrypted_key);

int decrypt_vault_key(const uint8_t *encrypted_key, const uint8_t *password_key, const uint8_t *nonce, uint8_t *vault_key);

int encrypt_file(FILE *source, FILE *vault, const uint8_t *vault_key, uint8_t *stream_header, uint64_t *encrypted_size);

int decrypt_file(FILE *vault, FILE *output, const uint8_t *vault_key, const uint8_t *stream_header, uint64_t original_size, uint64_t encrypted_size);

#endif