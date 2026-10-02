#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>

#include "../include/crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

static void check(int condition, const char *name){
    if(condition){
        printf("[PASS] %s\n", name);
        tests_passed++;
    }else{
        printf("[FAIL] %s\n", name);
        tests_failed++;
    }
}

static void test_random_bytes(void){
    uint8_t first[32];
    uint8_t second[32];

    check(generate_random_bytes(first, sizeof(first)), "Random byte generation");
    check(generate_random_bytes(second, sizeof(second)), "Second random byte generation");
    check(sodium_memcmp(first, second, sizeof(first)) != 0, "Random values differ");
}

static void test_password_derivation(void){
    const char *password = "test-password";
    uint8_t salt[16];
    uint8_t key[32];
    uint8_t hash[32];

    generate_salt(salt, sizeof(salt));

    check(derive_key(password, salt, sizeof(salt), key, sizeof(key)), "Password key derivation");

    memcpy(hash, key, sizeof(hash));

    check(verify_password(password, salt, sizeof(salt), hash, sizeof(hash)), "Correct password verification");
    check(!verify_password("wrong-password", salt, sizeof(salt), hash, sizeof(hash)), "Wrong password rejection");
}

static void test_vault_key_encryption(void){
    uint8_t vault_key[VAULT_KEY_SIZE];
    uint8_t password_key[VAULT_KEY_SIZE];
    uint8_t nonce[VAULT_KEY_NONCE_SIZE];
    uint8_t encrypted_key[VAULT_KEY_SIZE + VAULT_KEY_TAG_SIZE];
    uint8_t decrypted_key[VAULT_KEY_SIZE];

    generate_random_bytes(vault_key, sizeof(vault_key));
    generate_random_bytes(password_key, sizeof(password_key));
    generate_random_bytes(nonce, sizeof(nonce));

    check(encrypt_vault_key(vault_key, password_key, nonce, encrypted_key), "Vault key encryption");

    check(decrypt_vault_key(encrypted_key, password_key, nonce, decrypted_key), "Vault key decryption");

    check(sodium_memcmp(vault_key, decrypted_key, sizeof(vault_key)) == 0, "Decrypted key matches original");
}

static void test_tampered_vault_key(void){
    uint8_t vault_key[VAULT_KEY_SIZE];
    uint8_t password_key[VAULT_KEY_SIZE];
    uint8_t nonce[VAULT_KEY_NONCE_SIZE];
    uint8_t encrypted_key[VAULT_KEY_SIZE + VAULT_KEY_TAG_SIZE];
    uint8_t decrypted_key[VAULT_KEY_SIZE];

    generate_random_bytes(vault_key, sizeof(vault_key));
    generate_random_bytes(password_key, sizeof(password_key));
    generate_random_bytes(nonce, sizeof(nonce));

    encrypt_vault_key(vault_key, password_key, nonce, encrypted_key);

    encrypted_key[0] ^= 0x01;

    check(!decrypt_vault_key(encrypted_key, password_key, nonce, decrypted_key), "Tampered vault key rejection");
}

int main(void){
    if(sodium_init() < 0){
        printf("libsodium initialization failed.\n");
        return 1;
    }

    printf("VaultC Crypto Tests\n");
    printf("===================\n");

    test_random_bytes();
    test_password_derivation();
    test_vault_key_encryption();
    test_tampered_vault_key();

    printf("\nTests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}