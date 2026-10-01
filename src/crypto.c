#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <argon2.h>

#include "../include/crypto.h"

int generate_random_bytes(uint8_t *buffer, size_t length){
    if(buffer == NULL || length == 0)
        return 0;

    randombytes_buf(buffer, length);

    return 1;
}

int generate_salt(uint8_t *salt, size_t length){
    return generate_random_bytes(salt, length);
}

int derive_key(const char *password, const uint8_t *salt, size_t salt_length, uint8_t *key, size_t key_length){
    if(password == NULL || salt == NULL || key == NULL || salt_length == 0 || key_length == 0)
        return 0;

    int result = argon2id_hash_raw(3, 64 * 1024, 1, password, strlen(password), salt, salt_length, key, key_length);

    if(result != ARGON2_OK){
        printf("Key derivation failed: %s\n", argon2_error_message(result));
        return 0;
    }

    return 1;
}

int verify_password(const char *password, const uint8_t *salt, size_t salt_length, const uint8_t *expected_hash, size_t hash_length){
    if(password == NULL || salt == NULL || expected_hash == NULL || hash_length == 0)
        return 0;

    uint8_t derived_hash[hash_length];

    if(!derive_key(password, salt, salt_length, derived_hash, hash_length))
        return 0;

    return sodium_memcmp(derived_hash, expected_hash, hash_length) == 0;
}

int encrypt_vault_key(const uint8_t *vault_key, const uint8_t *password_key, const uint8_t *nonce, uint8_t *encrypted_key){
    if(vault_key == NULL || password_key == NULL || nonce == NULL || encrypted_key == NULL)
        return 0;

    unsigned long long encrypted_length;

    int result = crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted_key, &encrypted_length, vault_key, VAULT_KEY_SIZE, NULL, 0, NULL, nonce, password_key);

    if(result != 0)
        return 0;

    return encrypted_length == VAULT_KEY_SIZE + VAULT_KEY_TAG_SIZE;
}

int decrypt_vault_key(const uint8_t *encrypted_key, const uint8_t *password_key, const uint8_t *nonce, uint8_t *vault_key){
    if(encrypted_key == NULL || password_key == NULL || nonce == NULL || vault_key == NULL)
        return 0;

    unsigned long long decrypted_length;

    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(vault_key, &decrypted_length, NULL, encrypted_key, VAULT_KEY_SIZE + VAULT_KEY_TAG_SIZE, NULL, 0, nonce, password_key);

    if(result != 0)
        return 0;

    return decrypted_length == VAULT_KEY_SIZE;
}

int encrypt_file(FILE *source, FILE *vault, const uint8_t *vault_key, uint8_t *stream_header, uint64_t *encrypted_size){
    if(source == NULL || vault == NULL || vault_key == NULL || stream_header == NULL || encrypted_size == NULL)
        return 0;

    crypto_secretstream_xchacha20poly1305_state state;

    if(crypto_secretstream_xchacha20poly1305_init_push(&state, stream_header, vault_key) != 0)
        return 0;

    uint8_t current_buffer[FILE_CHUNK_SIZE];
    uint8_t next_buffer[FILE_CHUNK_SIZE];
    uint8_t output_buffer[FILE_CHUNK_SIZE + FILE_STREAM_TAG_SIZE];

    size_t current_size = fread(current_buffer, 1, FILE_CHUNK_SIZE, source);

    if(ferror(source))
        return 0;

    if(current_size == 0){
        unsigned long long encrypted_length;

        if(crypto_secretstream_xchacha20poly1305_push(&state, output_buffer, &encrypted_length, NULL, 0, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0)
            return 0;

        if(fwrite(output_buffer, 1, encrypted_length, vault) != encrypted_length)
            return 0;

        *encrypted_size = encrypted_length;

        return 1;
    }

    uint64_t total_encrypted = 0;

    while(1){
        size_t next_size = fread(next_buffer, 1, FILE_CHUNK_SIZE, source);

        if(ferror(source))
            return 0;

        int is_last = next_size == 0;

        unsigned char tag = is_last ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long encrypted_length;

        if(crypto_secretstream_xchacha20poly1305_push(&state, output_buffer, &encrypted_length, current_buffer, current_size, NULL, 0, tag) != 0)
            return 0;

        if(fwrite(output_buffer, 1, encrypted_length, vault) != encrypted_length)
            return 0;

        total_encrypted += encrypted_length;

        if(is_last)
            break;

        memcpy(current_buffer, next_buffer, next_size);
        current_size = next_size;
    }

    *encrypted_size = total_encrypted;

    return 1;
}

int decrypt_file(FILE *vault, FILE *output, const uint8_t *vault_key, const uint8_t *stream_header, uint64_t original_size, uint64_t encrypted_size){
    if(vault == NULL || output == NULL || vault_key == NULL || stream_header == NULL)
        return 0;

    crypto_secretstream_xchacha20poly1305_state state;

    if(crypto_secretstream_xchacha20poly1305_init_pull(&state, stream_header, vault_key) != 0)
        return 0;

    uint8_t input_buffer[FILE_CHUNK_SIZE + FILE_STREAM_TAG_SIZE];
    uint8_t output_buffer[FILE_CHUNK_SIZE];

    uint64_t remaining_encrypted = encrypted_size;
    uint64_t remaining_original = original_size;

    while(remaining_encrypted > 0){
        size_t ciphertext_size;

        if(remaining_original > FILE_CHUNK_SIZE)
            ciphertext_size = FILE_CHUNK_SIZE + FILE_STREAM_TAG_SIZE;
        else
            ciphertext_size = (size_t)remaining_encrypted;

        if(ciphertext_size > sizeof(input_buffer) || ciphertext_size > remaining_encrypted)
            return 0;

        if(fread(input_buffer, 1, ciphertext_size, vault) != ciphertext_size)
            return 0;

        unsigned long long decrypted_length;
        unsigned char tag;

        if(crypto_secretstream_xchacha20poly1305_pull(&state, output_buffer, &decrypted_length, &tag, input_buffer, ciphertext_size, NULL, 0) != 0)
            return 0;

        if(decrypted_length > remaining_original)
            return 0;

        if(fwrite(output_buffer, 1, decrypted_length, output) != decrypted_length)
            return 0;

        remaining_encrypted -= ciphertext_size;
        remaining_original -= decrypted_length;

        if(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL){
            if(remaining_encrypted != 0 || remaining_original != 0)
                return 0;

            return 1;
        }
    }

    return 0;
}