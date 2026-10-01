#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#include "../include/vault.h"
#include "../include/storage.h"
#include "../include/crypto.h"

static int read_password(const char *prompt, char *password, size_t size){
    struct termios old_settings;
    struct termios new_settings;

    printf("%s", prompt);
    fflush(stdout);

    if(tcgetattr(STDIN_FILENO, &old_settings) != 0)
        return 0;

    new_settings = old_settings;
    new_settings.c_lflag &= ~(ECHO);

    if(tcsetattr(STDIN_FILENO, TCSANOW, &new_settings) != 0)
        return 0;

    if(fgets(password, size, stdin) == NULL){
        tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
        return 0;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    printf("\n");

    password[strcspn(password, "\n")] = '\0';

    return 1;
}

static int load_vault_key(FILE *file, VaultHeader *header, uint8_t *vault_key){
    char password[256];
    uint8_t password_key[VAULT_KEY_SIZE];

    if(file == NULL || header == NULL || vault_key == NULL)
        return 0;

    if(!read_password("Enter vault password: ", password, sizeof(password)))
        return 0;

    if(!derive_key(password, header->password_salt, sizeof(header->password_salt), password_key, sizeof(password_key))){
        memset(password, 0, sizeof(password));
        memset(password_key, 0, sizeof(password_key));
        return 0;
    }

    if(!verify_password(password, header->password_salt, sizeof(header->password_salt), header->password_hash, sizeof(header->password_hash))){
        printf("Incorrect password.\n");
        memset(password, 0, sizeof(password));
        memset(password_key, 0, sizeof(password_key));
        return 0;
    }

    if(!decrypt_vault_key(header->encrypted_vault_key, password_key, header->vault_key_nonce, vault_key)){
        printf("Vault key authentication failed.\n");
        memset(password, 0, sizeof(password));
        memset(password_key, 0, sizeof(password_key));
        return 0;
    }

    memset(password, 0, sizeof(password));
    memset(password_key, 0, sizeof(password_key));

    return 1;
}

static int get_file_size(FILE *file, uint64_t *size){
    long current_position;
    long end_position;

    if(file == NULL || size == NULL)
        return 0;

    current_position = ftell(file);

    if(current_position < 0)
        return 0;

    if(fseek(file, 0, SEEK_END) != 0)
        return 0;

    end_position = ftell(file);

    if(end_position < 0)
        return 0;

    if(fseek(file, current_position, SEEK_SET) != 0)
        return 0;

    *size = (uint64_t)end_position;

    return 1;
}

static const char *get_filename(const char *path){
    const char *slash;
    const char *backslash;

    slash = strrchr(path, '/');
    backslash = strrchr(path, '\\');

    if(slash != NULL && backslash != NULL)
        return slash > backslash ? slash + 1 : backslash + 1;

    if(slash != NULL)
        return slash + 1;

    if(backslash != NULL)
        return backslash + 1;

    return path;
}

int create_vault(const char *path){
    FILE *file;
    VaultHeader header;
    FileRecord empty_record;
    char password[256];
    char confirmation[256];
    uint8_t password_key[VAULT_KEY_SIZE];
    uint8_t vault_key[VAULT_KEY_SIZE];

    if(path == NULL)
        return 0;

    file = fopen(path, "wb");

    if(file == NULL){
        printf("Failed to create vault.\n");
        return 0;
    }

    memset(&header, 0, sizeof(header));
    memset(&empty_record, 0, sizeof(empty_record));
    memset(password_key, 0, sizeof(password_key));
    memset(vault_key, 0, sizeof(vault_key));

    memcpy(header.magic, VAULT_MAGIC, sizeof(header.magic));
    header.version = VAULT_VERSION;
    header.header_size = sizeof(VaultHeader);
    header.index_offset = sizeof(VaultHeader);
    header.index_size = sizeof(FileRecord) * MAX_FILES;
    header.data_offset = header.index_offset + header.index_size;
    header.file_count = 0;

    if(!read_password("Enter vault password: ", password, sizeof(password))){
        fclose(file);
        return 0;
    }

    if(!read_password("Confirm vault password: ", confirmation, sizeof(confirmation))){
        memset(password, 0, sizeof(password));
        fclose(file);
        return 0;
    }

    if(strcmp(password, confirmation) != 0){
        printf("Passwords do not match.\n");
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        fclose(file);
        return 0;
    }

    if(!generate_salt(header.password_salt, sizeof(header.password_salt))){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        fclose(file);
        return 0;
    }

    if(!derive_key(password, header.password_salt, sizeof(header.password_salt), password_key, sizeof(password_key))){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        fclose(file);
        return 0;
    }

    memcpy(header.password_hash, password_key, sizeof(header.password_hash));

    if(!generate_random_bytes(vault_key, sizeof(vault_key))){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(password_key, 0, sizeof(password_key));
        fclose(file);
        return 0;
    }

    if(!generate_random_bytes(header.vault_key_nonce, sizeof(header.vault_key_nonce))){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(password_key, 0, sizeof(password_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(file);
        return 0;
    }

    if(!encrypt_vault_key(vault_key, password_key, header.vault_key_nonce, header.encrypted_vault_key)){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(password_key, 0, sizeof(password_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(file);
        return 0;
    }

    if(!write_vault_header(file, &header)){
        memset(password, 0, sizeof(password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(password_key, 0, sizeof(password_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(file);
        return 0;
    }

    for(int i = 0; i < MAX_FILES; i++){
        if(!write_file_record(file, &empty_record)){
            memset(password, 0, sizeof(password));
            memset(confirmation, 0, sizeof(confirmation));
            memset(password_key, 0, sizeof(password_key));
            memset(vault_key, 0, sizeof(vault_key));
            fclose(file);
            return 0;
        }
    }

    memset(password, 0, sizeof(password));
    memset(confirmation, 0, sizeof(confirmation));
    memset(password_key, 0, sizeof(password_key));
    memset(vault_key, 0, sizeof(vault_key));

    fclose(file);

    printf("Vault created successfully.\n");

    return 1;
}

int open_vault(const char *path){
    FILE *file;
    VaultHeader header;
    uint8_t vault_key[VAULT_KEY_SIZE];

    if(path == NULL)
        return 0;

    file = fopen(path, "rb");

    if(file == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(file, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(file);
        return 0;
    }

    if(!load_vault_key(file, &header, vault_key)){
        fclose(file);
        return 0;
    }

    memset(vault_key, 0, sizeof(vault_key));

    fclose(file);

    printf("Vault opened successfully.\n");

    return 1;
}

int list_vault(const char *path){
    FILE *file;
    VaultHeader header;
    FileRecord *records;

    if(path == NULL)
        return 0;

    file = fopen(path, "rb");

    if(file == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(file, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(file);
        return 0;
    }

    records = NULL;

    if(!read_file_index(file, &header, &records)){
        printf("Failed to read vault index.\n");
        fclose(file);
        return 0;
    }

    printf("\nFiles in vault:\n");

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active){
            printf("%u. %s (%llu bytes)\n", records[i].id, records[i].name, (unsigned long long)records[i].original_size);
        }
    }

    free(records);
    fclose(file);

    return 1;
}

int add_file(const char *vault_path, const char *file_path){
    FILE *source;
    FILE *vault;
    VaultHeader header;
    FileRecord *records;
    FileRecord record;
    uint8_t vault_key[VAULT_KEY_SIZE];
    const char *filename;
    uint64_t original_size;
    uint64_t encrypted_size;

    if(vault_path == NULL || file_path == NULL)
        return 0;

    source = fopen(file_path, "rb");

    if(source == NULL){
        printf("Failed to open source file.\n");
        return 0;
    }

    if(!get_file_size(source, &original_size)){
        fclose(source);
        return 0;
    }

    vault = fopen(vault_path, "rb+");

    if(vault == NULL){
        fclose(source);
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(source);
        fclose(vault);
        return 0;
    }

    if(!load_vault_key(vault, &header, vault_key)){
        fclose(source);
        fclose(vault);
        return 0;
    }

    records = NULL;

    if(!read_file_index(vault, &header, &records)){
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    if(header.file_count >= MAX_FILES){
        printf("Vault is full.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    filename = get_filename(file_path);

    if(filename[0] == '\0'){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, filename) == 0){
            printf("A file with that name already exists.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(source);
            fclose(vault);
            return 0;
        }
    }

    memset(&record, 0, sizeof(record));

    record.id = header.file_count + 1;
    strncpy(record.name, filename, MAX_FILENAME_LENGTH - 1);
    record.name[MAX_FILENAME_LENGTH - 1] = '\0';
    record.original_size = original_size;
    record.data_offset = header.data_offset;
    record.active = 1;

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && records[i].data_offset + records[i].encrypted_size > record.data_offset)
            record.data_offset = records[i].data_offset + records[i].encrypted_size;
    }

    if(fseek(vault, (long)record.data_offset, SEEK_SET) != 0){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    if(!encrypt_file(source, vault, vault_key, record.stream_header, &encrypted_size)){
        printf("File encryption failed.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    record.encrypted_size = encrypted_size;

    if(fseek(vault, (long)(header.index_offset + (header.file_count * sizeof(FileRecord))), SEEK_SET) != 0){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    if(!write_file_record(vault, &record)){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    header.file_count++;

    if(!write_vault_header(vault, &header)){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(source);
        fclose(vault);
        return 0;
    }

    free(records);
    memset(vault_key, 0, sizeof(vault_key));

    fclose(source);
    fclose(vault);

    printf("File encrypted and added successfully.\n");

    return 1;
}

int extract_file(const char *vault_path, const char *filename){
    FILE *vault;
    FILE *output;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];
    FileRecord *target;
    char output_name[MAX_FILENAME_LENGTH];

    if(vault_path == NULL || filename == NULL)
        return 0;

    vault = fopen(vault_path, "rb");

    if(vault == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(vault);
        return 0;
    }

    if(!load_vault_key(vault, &header, vault_key)){
        fclose(vault);
        return 0;
    }

    records = NULL;

    if(!read_file_index(vault, &header, &records)){
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    target = NULL;

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, filename) == 0){
            target = &records[i];
            break;
        }
    }

    if(target == NULL){
        printf("File not found in vault.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    output = fopen(filename, "wb");

    if(output == NULL){
        printf("Failed to create output file.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(fseek(vault, (long)target->data_offset, SEEK_SET) != 0){
        fclose(output);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!decrypt_file(vault, output, vault_key, target->stream_header, target->original_size, target->encrypted_size)){
        printf("File authentication or decryption failed.\n");
        fclose(output);
        remove(filename);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    fclose(output);
    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    printf("File extracted successfully.\n");

    return 1;
}

int remove_file(const char *vault_path, const char *filename){
    FILE *vault;
    VaultHeader header;
    FileRecord *records;

    if(vault_path == NULL || filename == NULL)
        return 0;

    vault = fopen(vault_path, "rb+");

    if(vault == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(vault);
        return 0;
    }

    records = NULL;

    if(!read_file_index(vault, &header, &records)){
        fclose(vault);
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, filename) == 0){
            records[i].active = 0;

            if(fseek(vault, (long)(header.index_offset + (i * sizeof(FileRecord))), SEEK_SET) != 0){
                free(records);
                fclose(vault);
                return 0;
            }

            if(!write_file_record(vault, &records[i])){
                free(records);
                fclose(vault);
                return 0;
            }

            free(records);
            fclose(vault);

            printf("File removed from vault.\n");

            return 1;
        }
    }

    printf("File not found in vault.\n");

    free(records);
    fclose(vault);

    return 0;
}

int rename_file(const char *vault_path, const char *old_name, const char *new_name){
    FILE *vault;
    VaultHeader header;
    FileRecord *records;

    if(vault_path == NULL || old_name == NULL || new_name == NULL)
        return 0;

    vault = fopen(vault_path, "rb+");

    if(vault == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(vault);
        return 0;
    }

    records = NULL;

    if(!read_file_index(vault, &header, &records)){
        fclose(vault);
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, new_name) == 0){
            printf("A file with the new name already exists.\n");
            free(records);
            fclose(vault);
            return 0;
        }
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, old_name) == 0){
            strncpy(records[i].name, new_name, MAX_FILENAME_LENGTH - 1);
            records[i].name[MAX_FILENAME_LENGTH - 1] = '\0';

            if(fseek(vault, (long)(header.index_offset + (i * sizeof(FileRecord))), SEEK_SET) != 0){
                free(records);
                fclose(vault);
                return 0;
            }

            if(!write_file_record(vault, &records[i])){
                free(records);
                fclose(vault);
                return 0;
            }

            free(records);
            fclose(vault);

            printf("File renamed successfully.\n");

            return 1;
        }
    }

    printf("File not found in vault.\n");

    free(records);
    fclose(vault);

    return 0;
}

int search_files(const char *vault_path, const char *query){
    FILE *vault;
    VaultHeader header;
    FileRecord *records;
    int found = 0;

    if(vault_path == NULL || query == NULL)
        return 0;

    vault = fopen(vault_path, "rb");

    if(vault == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(vault);
        return 0;
    }

    records = NULL;

    if(!read_file_index(vault, &header, &records)){
        fclose(vault);
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strstr(records[i].name, query) != NULL){
            printf("%s (%llu bytes)\n", records[i].name, (unsigned long long)records[i].original_size);
            found = 1;
        }
    }

    if(!found)
        printf("No matching files found.\n");

    free(records);
    fclose(vault);

    return 1;
}