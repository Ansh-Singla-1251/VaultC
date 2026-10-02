#include <stdio.h>
#include <stdlib.h>
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

static int create_test_file(const char *path, size_t size){
    FILE *file;
    uint8_t buffer[8192];

    file = fopen(path, "wb");

    if(file == NULL)
        return 0;

    for(size_t i = 0; i < size; i += sizeof(buffer)){
        size_t chunk_size = size - i;

        if(chunk_size > sizeof(buffer))
            chunk_size = sizeof(buffer);

        for(size_t j = 0; j < chunk_size; j++)
            buffer[j] = (uint8_t)((i + j) % 256);

        if(fwrite(buffer, 1, chunk_size, file) != chunk_size){
            fclose(file);
            return 0;
        }
    }

    fclose(file);

    return 1;
}

static int compare_files(const char *first_path, const char *second_path){
    FILE *first;
    FILE *second;
    uint8_t first_buffer[8192];
    uint8_t second_buffer[8192];

    first = fopen(first_path, "rb");
    second = fopen(second_path, "rb");

    if(first == NULL || second == NULL){
        if(first != NULL)
            fclose(first);

        if(second != NULL)
            fclose(second);

        return 0;
    }

    while(1){
        size_t first_size = fread(first_buffer, 1, sizeof(first_buffer), first);
        size_t second_size = fread(second_buffer, 1, sizeof(second_buffer), second);

        if(first_size != second_size){
            fclose(first);
            fclose(second);
            return 0;
        }

        if(first_size == 0)
            break;

        if(memcmp(first_buffer, second_buffer, first_size) != 0){
            fclose(first);
            fclose(second);
            return 0;
        }
    }

    fclose(first);
    fclose(second);

    return 1;
}

static int run_round_trip_test(size_t size){
    FILE *source;
    FILE *vault;
    FILE *output;
    uint8_t vault_key[VAULT_KEY_SIZE];
    uint8_t stream_header[FILE_STREAM_HEADER_SIZE];
    uint64_t encrypted_size;
    char source_path[64];
    char vault_path[64];
    char output_path[64];

    snprintf(source_path, sizeof(source_path), "tests/data/source_%zu.bin", size);
    snprintf(vault_path, sizeof(vault_path), "tests/data/encrypted_%zu.bin", size);
    snprintf(output_path, sizeof(output_path), "tests/data/output_%zu.bin", size);

    if(!create_test_file(source_path, size))
        return 0;

    generate_random_bytes(vault_key, sizeof(vault_key));

    source = fopen(source_path, "rb");
    vault = fopen(vault_path, "wb");

    if(source == NULL || vault == NULL){
        if(source != NULL)
            fclose(source);

        if(vault != NULL)
            fclose(vault);

        return 0;
    }

    if(!encrypt_file(source, vault, vault_key, stream_header, &encrypted_size)){
        fclose(source);
        fclose(vault);
        return 0;
    }

    fclose(source);
    fclose(vault);

    vault = fopen(vault_path, "rb");
    output = fopen(output_path, "wb");

    if(vault == NULL || output == NULL){
        if(vault != NULL)
            fclose(vault);

        if(output != NULL)
            fclose(output);

        return 0;
    }

    if(!decrypt_file(vault, output, vault_key, stream_header, size, encrypted_size)){
        fclose(vault);
        fclose(output);
        return 0;
    }

    fclose(vault);
    fclose(output);

    return compare_files(source_path, output_path);
}

static void test_file_sizes(void){
    check(run_round_trip_test(0), "Empty file");
    check(run_round_trip_test(1), "1 byte file");
    check(run_round_trip_test(8191), "8191 byte file");
    check(run_round_trip_test(8192), "8192 byte file");
    check(run_round_trip_test(8193), "8193 byte file");
    check(run_round_trip_test(100 * 1024), "100 KB file");
}

int main(void){
    if(sodium_init() < 0){
        printf("libsodium initialization failed.\n");
        return 1;
    }

    printf("VaultC File Encryption Tests\n");
    printf("============================\n");

    test_file_sizes();

    printf("\nTests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}