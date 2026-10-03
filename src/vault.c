#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sodium.h>

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

    memset(password, 0, sizeof(password));
    memset(password_key, 0, sizeof(password_key));

    if(!read_password("Enter vault password: ", password, sizeof(password)))
        return 0;

    if(!derive_key(password, header->password_salt, sizeof(header->password_salt), password_key, sizeof(password_key))){
        memset(password, 0, sizeof(password));
        memset(password_key, 0, sizeof(password_key));
        return 0;
    }

    if(sodium_memcmp(password_key, header->password_hash, sizeof(password_key)) != 0){
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
    off_t current_position;
    off_t end_position;

    if(file == NULL || size == NULL)
        return 0;

    current_position = ftello(file);

    if(current_position < 0)
        return 0;

    if(fseeko(file, 0, SEEK_END) != 0)
        return 0;

    end_position = ftello(file);

    if(end_position < 0)
        return 0;

    if(fseeko(file, current_position, SEEK_SET) != 0)
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

static int is_directory(const char *path){
    struct stat path_info;

    if(path == NULL)
        return 0;

    if(stat(path, &path_info) != 0)
        return 0;

    return S_ISDIR(path_info.st_mode);
}

static int is_regular_file(const char *path){
    struct stat path_info;

    if(path == NULL)
        return 0;

    if(stat(path, &path_info) != 0)
        return 0;

    return S_ISREG(path_info.st_mode);
}

static int build_path(const char *base, const char *name, char *result, size_t result_size){
    int written;

    if(base == NULL || name == NULL || result == NULL || result_size == 0)
        return 0;

    written = snprintf(result, result_size, "%s/%s", base, name);

    if(written < 0 || (size_t)written >= result_size)
        return 0;

    return 1;
}

static int create_parent_directories(const char *path){
    char directory_path[MAX_FILENAME_LENGTH * 4];
    char *separator;

    if(path == NULL)
        return 0;

    if(strlen(path) >= sizeof(directory_path))
        return 0;

    strcpy(directory_path, path);

    separator = strrchr(directory_path, '/');

    if(separator == NULL)
        return 1;

    *separator = '\0';

    if(directory_path[0] == '\0')
        return 1;

    for(char *current = directory_path + 1; *current != '\0'; current++){
        if(*current != '/')
            continue;

        *current = '\0';

        if(mkdir(directory_path, 0755) != 0 && errno != EEXIST)
            return 0;

        *current = '/';
    }

    if(mkdir(directory_path, 0755) != 0 && errno != EEXIST)
        return 0;

    return 1;
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
    memset(password, 0, sizeof(password));
    memset(confirmation, 0, sizeof(confirmation));
    memset(password_key, 0, sizeof(password_key));
    memset(vault_key, 0, sizeof(vault_key));

    memcpy(header.magic, VAULT_MAGIC, sizeof(header.magic));
    header.version = VAULT_VERSION;
    header.header_size = VAULT_HEADER_SIZE;
    header.index_offset = VAULT_HEADER_SIZE;
    header.index_size = (uint64_t)FILE_RECORD_SIZE * MAX_FILES;
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

static int add_file_to_vault(FILE *source, FILE *vault, VaultHeader *header, FileRecord *records, const char *file_path, const char *vault_name, const uint8_t *vault_key){
    FileRecord record;
    uint64_t original_size;
    uint64_t encrypted_size;
    uint32_t slot = MAX_FILES;

    if(source == NULL || vault == NULL || header == NULL || records == NULL || file_path == NULL || vault_name == NULL || vault_key == NULL)
        return 0;

    if(!get_file_size(source, &original_size))
        return 0;

    if(strlen(vault_name) == 0 || strlen(vault_name) >= MAX_FILENAME_LENGTH){
        printf("Filename or path is too long: %s\n", vault_name);
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(!records[i].active && slot == MAX_FILES)
            slot = i;

        if(records[i].active && strcmp(records[i].name, vault_name) == 0){
            printf("A file with that name already exists: %s\n", vault_name);
            return 0;
        }
    }

    if(slot == MAX_FILES){
        printf("Vault is full.\n");
        return 0;
    }

    memset(&record, 0, sizeof(record));

    record.id = slot + 1;
    strncpy(record.name, vault_name, MAX_FILENAME_LENGTH - 1);
    record.name[MAX_FILENAME_LENGTH - 1] = '\0';
    record.original_size = original_size;
    record.data_offset = header->data_offset;
    record.active = 1;

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].encrypted_size > 0 && records[i].data_offset + records[i].encrypted_size > record.data_offset)
            record.data_offset = records[i].data_offset + records[i].encrypted_size;
    }

    if(fseeko(vault, (off_t)record.data_offset, SEEK_SET) != 0)
        return 0;

    if(!encrypt_file(source, vault, vault_key, record.stream_header, &encrypted_size)){
        printf("File encryption failed: %s\n", vault_name);
        return 0;
    }

    record.encrypted_size = encrypted_size;

    if(fseeko(vault, (off_t)(header->index_offset + ((uint64_t)slot * FILE_RECORD_SIZE)), SEEK_SET) != 0)
        return 0;

    if(!write_file_record(vault, &record))
        return 0;

    records[slot] = record;
    header->file_count++;

    if(!write_vault_header(vault, header))
        return 0;

    printf("Added: %s\n", vault_name);

    return 1;
}

static int add_directory_recursive(FILE *vault, VaultHeader *header, FileRecord *records, const char *directory_path, const char *relative_path, const uint8_t *vault_key){
    DIR *directory;
    struct dirent *entry;
    char source_path[MAX_FILENAME_LENGTH * 4];
    char vault_path[MAX_FILENAME_LENGTH];
    struct stat path_info;
    FILE *source;
    int result = 1;

    if(vault == NULL || header == NULL || records == NULL || directory_path == NULL || relative_path == NULL || vault_key == NULL)
        return 0;

    directory = opendir(directory_path);

    if(directory == NULL){
        printf("Failed to open directory: %s\n", directory_path);
        return 0;
    }

    while((entry = readdir(directory)) != NULL){
        if(strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if(!build_path(directory_path, entry->d_name, source_path, sizeof(source_path))){
            printf("Path is too long: %s\n", entry->d_name);
            result = 0;
            break;
        }

        if(!build_path(relative_path, entry->d_name, vault_path, sizeof(vault_path))){
            printf("Vault path is too long: %s\n", entry->d_name);
            result = 0;
            break;
        }

        if(strlen(vault_path) >= MAX_FILENAME_LENGTH){
            printf("Vault path is too long: %s\n", vault_path);
            result = 0;
            break;
        }

        if(stat(source_path, &path_info) != 0){
            printf("Failed to inspect: %s\n", source_path);
            result = 0;
            break;
        }

        if(S_ISDIR(path_info.st_mode)){
            if(!add_directory_recursive(vault, header, records, source_path, vault_path, vault_key)){
                result = 0;
                break;
            }

            continue;
        }

        if(!S_ISREG(path_info.st_mode))
            continue;

        if(header->file_count >= MAX_FILES){
            printf("Vault is full.\n");
            result = 0;
            break;
        }

        source = fopen(source_path, "rb");

        if(source == NULL){
            printf("Failed to open source file: %s\n", source_path);
            result = 0;
            break;
        }

        if(!add_file_to_vault(source, vault, header, records, source_path, vault_path, vault_key)){
            fclose(source);
            result = 0;
            break;
        }

        fclose(source);
    }

    closedir(directory);

    return result;
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

    records = NULL;

    if(!read_file_index(file, &header, &records)){
        memset(vault_key, 0, sizeof(vault_key));
        fclose(file);
        return 0;
    }

    printf("\nFiles in vault:\n");

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active)
            printf("%u. %s (%llu bytes)\n", records[i].id, records[i].name, (unsigned long long)records[i].original_size);
    }

    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(file);

    return 1;
}

int add_file(const char *vault_path, const char *file_path){
    FILE *source;
    FILE *vault;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];
    const char *filename;
    char relative_path[MAX_FILENAME_LENGTH];
    int result;

    if(vault_path == NULL || file_path == NULL)
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

    if(is_directory(file_path)){
        filename = get_filename(file_path);

        if(filename[0] == '\0' || strlen(filename) >= MAX_FILENAME_LENGTH){
            printf("Invalid directory name.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        if(!add_directory_recursive(vault, &header, records, file_path, filename, vault_key)){
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        result = 1;
    }else{
        if(!is_regular_file(file_path)){
            printf("Source path is not a regular file or directory.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        filename = get_filename(file_path);

        if(filename[0] == '\0' || strlen(filename) >= MAX_FILENAME_LENGTH){
            printf("Invalid filename.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        strcpy(relative_path, filename);

        source = fopen(file_path, "rb");

        if(source == NULL){
            printf("Failed to open source file.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        if(header.file_count >= MAX_FILES){
            printf("Vault is full.\n");
            fclose(source);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        result = add_file_to_vault(source, vault, &header, records, file_path, relative_path, vault_key);

        fclose(source);
    }

    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    if(!result)
        return 0;

    printf("File(s) encrypted and added successfully.\n");

    return 1;
}

int extract_file(const char *vault_path, const char *filename){
    FILE *vault;
    FILE *output;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];
    FileRecord *target;

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

    if(!create_parent_directories(filename)){
        printf("Failed to create output directories.\n");
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

    if(fseeko(vault, (off_t)target->data_offset, SEEK_SET) != 0){
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
    uint8_t vault_key[VAULT_KEY_SIZE];

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

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, filename) == 0){
            records[i].active = 0;

            if(fseeko(vault, (off_t)(header.index_offset + ((uint64_t)i * FILE_RECORD_SIZE)), SEEK_SET) != 0){
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            if(!write_file_record(vault, &records[i])){
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            if(header.file_count > 0)
                header.file_count--;

            if(!write_vault_header(vault, &header)){
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);

            printf("File removed from vault.\n");

            return 1;
        }
    }

    printf("File not found in vault.\n");

    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    return 0;
}

int rename_file(const char *vault_path, const char *old_name, const char *new_name){
    FILE *vault;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];

    if(vault_path == NULL || old_name == NULL || new_name == NULL)
        return 0;

    if(strlen(new_name) == 0 || strlen(new_name) >= MAX_FILENAME_LENGTH){
        printf("Invalid new filename.\n");
        return 0;
    }

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

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, new_name) == 0){
            printf("A file with the new name already exists.\n");
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strcmp(records[i].name, old_name) == 0){
            strncpy(records[i].name, new_name, MAX_FILENAME_LENGTH - 1);
            records[i].name[MAX_FILENAME_LENGTH - 1] = '\0';

            if(fseeko(vault, (off_t)(header.index_offset + ((uint64_t)i * FILE_RECORD_SIZE)), SEEK_SET) != 0){
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            if(!write_file_record(vault, &records[i])){
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);

            printf("File renamed successfully.\n");

            return 1;
        }
    }

    printf("File not found in vault.\n");

    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    return 0;
}

int search_files(const char *vault_path, const char *query){
    FILE *vault;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];
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

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(records[i].active && strstr(records[i].name, query) != NULL){
            printf("%s (%llu bytes)\n", records[i].name, (unsigned long long)records[i].original_size);
            found = 1;
        }
    }

    if(!found)
        printf("No matching files found.\n");

    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    return 1;
}

int verify_vault(const char *path){
    FILE *vault;
    FILE *temporary;
    VaultHeader header;
    FileRecord *records;
    uint8_t vault_key[VAULT_KEY_SIZE];
    char temporary_name[] = "/tmp/vaultc_verify_XXXXXX";
    int temporary_fd;
    int verified = 1;

    if(path == NULL)
        return 0;

    vault = fopen(path, "rb");

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

    temporary_fd = mkstemp(temporary_name);

    if(temporary_fd < 0){
        printf("Failed to create verification file.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    close(temporary_fd);

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(!records[i].active)
            continue;

        if(fseeko(vault, (off_t)records[i].data_offset, SEEK_SET) != 0){
            verified = 0;
            break;
        }

        temporary = fopen(temporary_name, "wb");

        if(temporary == NULL){
            verified = 0;
            break;
        }

        if(!decrypt_file(vault, temporary, vault_key, records[i].stream_header, records[i].original_size, records[i].encrypted_size)){
            fclose(temporary);
            verified = 0;
            break;
        }

        fclose(temporary);

        printf("Verified: %s\n", records[i].name);
    }

    remove(temporary_name);
    free(records);
    memset(vault_key, 0, sizeof(vault_key));
    fclose(vault);

    if(!verified){
        printf("Vault verification failed.\n");
        return 0;
    }

    printf("Vault verification successful.\n");

    return 1;
}

int change_password(const char *path){
    FILE *vault;
    VaultHeader header;
    char current_password[256];
    char new_password[256];
    char confirmation[256];
    uint8_t current_key[VAULT_KEY_SIZE];
    uint8_t new_key[VAULT_KEY_SIZE];
    uint8_t vault_key[VAULT_KEY_SIZE];
    uint8_t new_salt[sizeof(header.password_salt)];
    uint8_t new_nonce[sizeof(header.vault_key_nonce)];
    uint8_t new_encrypted_vault_key[sizeof(header.encrypted_vault_key)];

    if(path == NULL)
        return 0;

    vault = fopen(path, "rb+");

    if(vault == NULL){
        printf("Failed to open vault.\n");
        return 0;
    }

    memset(&header, 0, sizeof(header));
    memset(current_password, 0, sizeof(current_password));
    memset(new_password, 0, sizeof(new_password));
    memset(confirmation, 0, sizeof(confirmation));
    memset(current_key, 0, sizeof(current_key));
    memset(new_key, 0, sizeof(new_key));
    memset(vault_key, 0, sizeof(vault_key));
    memset(new_salt, 0, sizeof(new_salt));
    memset(new_nonce, 0, sizeof(new_nonce));
    memset(new_encrypted_vault_key, 0, sizeof(new_encrypted_vault_key));

    if(!read_vault_header(vault, &header) || !validate_vault_header(&header)){
        printf("Invalid vault file.\n");
        fclose(vault);
        return 0;
    }

    if(!read_password("Enter current vault password: ", current_password, sizeof(current_password))){
        fclose(vault);
        return 0;
    }

    if(!derive_key(current_password, header.password_salt, sizeof(header.password_salt), current_key, sizeof(current_key))){
        memset(current_password, 0, sizeof(current_password));
        fclose(vault);
        return 0;
    }

    if(sodium_memcmp(current_key, header.password_hash, sizeof(current_key)) != 0){
        printf("Incorrect password.\n");
        memset(current_password, 0, sizeof(current_password));
        memset(current_key, 0, sizeof(current_key));
        fclose(vault);
        return 0;
    }

    if(!decrypt_vault_key(header.encrypted_vault_key, current_key, header.vault_key_nonce, vault_key)){
        printf("Vault key authentication failed.\n");
        memset(current_password, 0, sizeof(current_password));
        memset(current_key, 0, sizeof(current_key));
        fclose(vault);
        return 0;
    }

    if(!read_password("Enter new vault password: ", new_password, sizeof(new_password))){
        memset(current_password, 0, sizeof(current_password));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!read_password("Confirm new vault password: ", confirmation, sizeof(confirmation))){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(strcmp(new_password, confirmation) != 0){
        printf("Passwords do not match.\n");
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(strlen(new_password) == 0){
        printf("New password cannot be empty.\n");
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!generate_salt(new_salt, sizeof(new_salt))){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!derive_key(new_password, new_salt, sizeof(new_salt), new_key, sizeof(new_key))){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!generate_random_bytes(new_nonce, sizeof(new_nonce))){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(new_key, 0, sizeof(new_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(!encrypt_vault_key(vault_key, new_key, new_nonce, new_encrypted_vault_key)){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(new_key, 0, sizeof(new_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    memcpy(header.password_salt, new_salt, sizeof(header.password_salt));
    memcpy(header.password_hash, new_key, sizeof(header.password_hash));
    memcpy(header.vault_key_nonce, new_nonce, sizeof(header.vault_key_nonce));
    memcpy(header.encrypted_vault_key, new_encrypted_vault_key, sizeof(header.encrypted_vault_key));

    if(!write_vault_header(vault, &header)){
        memset(current_password, 0, sizeof(current_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        memset(current_key, 0, sizeof(current_key));
        memset(new_key, 0, sizeof(new_key));
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    memset(current_password, 0, sizeof(current_password));
    memset(new_password, 0, sizeof(new_password));
    memset(confirmation, 0, sizeof(confirmation));
    memset(current_key, 0, sizeof(current_key));
    memset(new_key, 0, sizeof(new_key));
    memset(vault_key, 0, sizeof(vault_key));
    memset(new_salt, 0, sizeof(new_salt));
    memset(new_nonce, 0, sizeof(new_nonce));
    memset(new_encrypted_vault_key, 0, sizeof(new_encrypted_vault_key));

    fclose(vault);

    printf("Vault password changed successfully.\n");

    return 1;
}
int compact_vault(const char *path){
    FILE *vault;
    FILE *temporary;
    VaultHeader header;
    VaultHeader new_header;
    FileRecord *records;
    FileRecord updated_record;
    char temporary_name[4096];
    uint8_t vault_key[VAULT_KEY_SIZE];
    uint8_t buffer[65536];
    struct stat original_info;
    uint64_t new_data_offset;
    uint64_t remaining;
    size_t chunk_size;
    int temporary_fd;
    int result = 0;

    if(path == NULL)
        return 0;

    if(stat(path, &original_info) != 0){
        printf("Failed to inspect vault.\n");
        return 0;
    }

    vault = fopen(path, "rb");

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

    if(snprintf(temporary_name, sizeof(temporary_name), "%s.compact.XXXXXX", path) < 0 || strlen(temporary_name) >= sizeof(temporary_name)){
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    temporary_fd = mkstemp(temporary_name);

    if(temporary_fd < 0){
        printf("Failed to create temporary vault.\n");
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    temporary = fdopen(temporary_fd, "wb+");

    if(temporary == NULL){
        close(temporary_fd);
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    fchmod(temporary_fd, original_info.st_mode & 0777);

    new_header = header;
    new_header.file_count = 0;
    new_data_offset = new_header.data_offset;

    if(!write_vault_header(temporary, &new_header)){
        fclose(temporary);
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    memset(&updated_record, 0, sizeof(updated_record));

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(!write_file_record(temporary, &updated_record)){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(!records[i].active)
            continue;

        if(fseeko(vault, (off_t)records[i].data_offset, SEEK_SET) != 0){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        if(fseeko(temporary, (off_t)new_data_offset, SEEK_SET) != 0){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        remaining = records[i].encrypted_size;

        while(remaining > 0){
            chunk_size = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;

            if(fread(buffer, 1, chunk_size, vault) != chunk_size){
                fclose(temporary);
                remove(temporary_name);
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            if(fwrite(buffer, 1, chunk_size, temporary) != chunk_size){
                fclose(temporary);
                remove(temporary_name);
                free(records);
                memset(vault_key, 0, sizeof(vault_key));
                fclose(vault);
                return 0;
            }

            remaining -= chunk_size;
        }

        updated_record = records[i];
        updated_record.data_offset = new_data_offset;

        if(new_data_offset > UINT64_MAX - updated_record.encrypted_size){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        new_data_offset += updated_record.encrypted_size;
        new_header.file_count++;

        if(fseeko(temporary, (off_t)(new_header.index_offset + ((uint64_t)i * FILE_RECORD_SIZE)), SEEK_SET) != 0){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }

        if(!write_file_record(temporary, &updated_record)){
            fclose(temporary);
            remove(temporary_name);
            free(records);
            memset(vault_key, 0, sizeof(vault_key));
            fclose(vault);
            return 0;
        }
    }

    if(!write_vault_header(temporary, &new_header)){
        fclose(temporary);
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(fflush(temporary) != 0){
        fclose(temporary);
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    if(fsync(fileno(temporary)) != 0){
        fclose(temporary);
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        fclose(vault);
        return 0;
    }

    fclose(temporary);
    fclose(vault);

    if(rename(temporary_name, path) != 0){
        printf("Failed to replace original vault.\n");
        remove(temporary_name);
        free(records);
        memset(vault_key, 0, sizeof(vault_key));
        return 0;
    }

    free(records);
    memset(vault_key, 0, sizeof(vault_key));

    printf("Vault compacted successfully.\n");

    result = 1;

    return result;
}