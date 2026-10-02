#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/vault.h"

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

static int create_test_file(const char *path){
    FILE *file;

    file = fopen(path, "wb");

    if(file == NULL)
        return 0;

    fprintf(file, "VaultC integration test file.\n");
    fprintf(file, "Testing complete vault operations.\n");

    fclose(file);

    return 1;
}

static int compare_files(const char *first_path, const char *second_path){
    FILE *first;
    FILE *second;
    int first_character;
    int second_character;

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
        first_character = fgetc(first);
        second_character = fgetc(second);

        if(first_character != second_character){
            fclose(first);
            fclose(second);
            return 0;
        }

        if(first_character == EOF)
            break;
    }

    fclose(first);
    fclose(second);

    return 1;
}

int main(void){
    const char *vault_path = "tests/data/integration.vlt";
    const char *source_path = "tests/data/integration_source.txt";
    const char *output_path = "integration_source.txt";

    remove(vault_path);
    remove(source_path);
    remove(output_path);

    printf("VaultC Integration Tests\n");
    printf("========================\n");

    check(create_test_file(source_path), "Create test file");

    check(create_vault(vault_path), "Create vault");

    check(add_file(vault_path, source_path), "Add file to vault");

    check(list_vault(vault_path), "List vault");

    check(extract_file(vault_path, "integration_source.txt"), "Extract file");

    check(compare_files(source_path, output_path), "Extracted file matches original");

    check(verify_vault(vault_path), "Verify vault");

    check(remove_file(vault_path, "integration_source.txt"), "Remove file");

    check(verify_vault(vault_path), "Verify vault after removal");

    remove(vault_path);
    remove(source_path);
    remove(output_path);

    printf("\nTests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}