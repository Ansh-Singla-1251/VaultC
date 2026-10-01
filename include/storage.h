#ifndef STORAGE_H
#define STORAGE_H

#include <stdio.h>
#include <stdint.h>

#define VAULT_MAGIC "VLT01"
#define VAULT_VERSION 1
#define MAX_FILENAME_LENGTH 256
#define MAX_FILES 128
#define FILE_STREAM_HEADER_SIZE 24

typedef struct{
    uint32_t id;
    char name[MAX_FILENAME_LENGTH];
    uint64_t original_size;
    uint64_t encrypted_size;
    uint64_t data_offset;
    uint8_t stream_header[FILE_STREAM_HEADER_SIZE];
    uint8_t active;
} FileRecord;

typedef struct{
    char magic[5];
    uint8_t version;
    uint32_t header_size;

    uint64_t index_offset;
    uint64_t index_size;
    uint64_t data_offset;

    uint32_t file_count;

    uint8_t password_salt[16];
    uint8_t password_hash[32];

    uint8_t vault_key_nonce[24];
    uint8_t encrypted_vault_key[32 + 16];
} VaultHeader;

int write_vault_header(FILE *file, const VaultHeader *header);

int read_vault_header(FILE *file, VaultHeader *header);

int validate_vault_header(const VaultHeader *header);

int write_file_record(FILE *file, const FileRecord *record);

int read_file_record(FILE *file, FileRecord *record);

int read_file_index(FILE *file, const VaultHeader *header, FileRecord **records);

#endif