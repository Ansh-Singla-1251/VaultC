#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "../include/storage.h"

static int write_uint32(FILE *file, uint32_t value){
    uint8_t buffer[4];

    buffer[0] = (uint8_t)(value & 0xff);
    buffer[1] = (uint8_t)((value >> 8) & 0xff);
    buffer[2] = (uint8_t)((value >> 16) & 0xff);
    buffer[3] = (uint8_t)((value >> 24) & 0xff);

    return fwrite(buffer, 1, sizeof(buffer), file) == sizeof(buffer);
}

static int read_uint32(FILE *file, uint32_t *value){
    uint8_t buffer[4];

    if(fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
        return 0;

    *value = ((uint32_t)buffer[0]) |
             ((uint32_t)buffer[1] << 8) |
             ((uint32_t)buffer[2] << 16) |
             ((uint32_t)buffer[3] << 24);

    return 1;
}

static int write_uint64(FILE *file, uint64_t value){
    uint8_t buffer[8];

    for(int i = 0; i < 8; i++)
        buffer[i] = (uint8_t)((value >> (i * 8)) & 0xff);

    return fwrite(buffer, 1, sizeof(buffer), file) == sizeof(buffer);
}

static int read_uint64(FILE *file, uint64_t *value){
    uint8_t buffer[8];

    if(fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer))
        return 0;

    *value = 0;

    for(int i = 0; i < 8; i++)
        *value |= ((uint64_t)buffer[i] << (i * 8));

    return 1;
}

int write_vault_header(FILE *file, const VaultHeader *header){
    if(file == NULL || header == NULL)
        return 0;

    if(fseeko(file, 0, SEEK_SET) != 0)
        return 0;

    if(fwrite(header->magic, 1, sizeof(header->magic), file) != sizeof(header->magic))
        return 0;

    if(fwrite(&header->version, 1, sizeof(header->version), file) != sizeof(header->version))
        return 0;

    if(!write_uint32(file, header->header_size))
        return 0;

    if(!write_uint64(file, header->index_offset))
        return 0;

    if(!write_uint64(file, header->index_size))
        return 0;

    if(!write_uint64(file, header->data_offset))
        return 0;

    if(!write_uint32(file, header->file_count))
        return 0;

    if(fwrite(header->password_salt, 1, sizeof(header->password_salt), file) != sizeof(header->password_salt))
        return 0;

    if(fwrite(header->password_hash, 1, sizeof(header->password_hash), file) != sizeof(header->password_hash))
        return 0;

    if(fwrite(header->vault_key_nonce, 1, sizeof(header->vault_key_nonce), file) != sizeof(header->vault_key_nonce))
        return 0;

    if(fwrite(header->encrypted_vault_key, 1, sizeof(header->encrypted_vault_key), file) != sizeof(header->encrypted_vault_key))
        return 0;

    return 1;
}

int read_vault_header(FILE *file, VaultHeader *header){
    if(file == NULL || header == NULL)
        return 0;

    if(fseeko(file, 0, SEEK_SET) != 0)
        return 0;

    memset(header, 0, sizeof(VaultHeader));

    if(fread(header->magic, 1, sizeof(header->magic), file) != sizeof(header->magic))
        return 0;

    if(fread(&header->version, 1, sizeof(header->version), file) != sizeof(header->version))
        return 0;

    if(!read_uint32(file, &header->header_size))
        return 0;

    if(!read_uint64(file, &header->index_offset))
        return 0;

    if(!read_uint64(file, &header->index_size))
        return 0;

    if(!read_uint64(file, &header->data_offset))
        return 0;

    if(!read_uint32(file, &header->file_count))
        return 0;

    if(fread(header->password_salt, 1, sizeof(header->password_salt), file) != sizeof(header->password_salt))
        return 0;

    if(fread(header->password_hash, 1, sizeof(header->password_hash), file) != sizeof(header->password_hash))
        return 0;

    if(fread(header->vault_key_nonce, 1, sizeof(header->vault_key_nonce), file) != sizeof(header->vault_key_nonce))
        return 0;

    if(fread(header->encrypted_vault_key, 1, sizeof(header->encrypted_vault_key), file) != sizeof(header->encrypted_vault_key))
        return 0;

    return 1;
}

int validate_vault_header(const VaultHeader *header){
    uint64_t expected_index_size;
    uint64_t expected_data_offset;

    if(header == NULL)
        return 0;

    if(memcmp(header->magic, VAULT_MAGIC, sizeof(header->magic)) != 0)
        return 0;

    if(header->version != VAULT_VERSION)
        return 0;

    if(header->header_size != VAULT_HEADER_SIZE)
        return 0;

    if(header->file_count > MAX_FILES)
        return 0;

    expected_index_size = (uint64_t)FILE_RECORD_SIZE * MAX_FILES;

    if(header->index_offset > UINT64_MAX - expected_index_size)
        return 0;

    expected_data_offset = header->index_offset + expected_index_size;

    if(header->index_size != expected_index_size)
        return 0;

    if(header->index_offset < header->header_size)
        return 0;

    if(header->data_offset != expected_data_offset)
        return 0;

    return 1;
}

int validate_file_record(const FileRecord *record, const VaultHeader *header){
    uint64_t data_end;

    if(record == NULL || header == NULL)
        return 0;

    if(record->id > MAX_FILES)
        return 0;

    if(record->active && record->name[0] == '\0')
        return 0;

    if(record->data_offset < header->data_offset && record->encrypted_size > 0)
        return 0;

    if(record->encrypted_size > 0){
        if(record->data_offset > UINT64_MAX - record->encrypted_size)
            return 0;

        data_end = record->data_offset + record->encrypted_size;

        if(data_end < record->data_offset)
            return 0;
    }

    if(record->active && record->encrypted_size == 0 && record->original_size > 0)
        return 0;

    return 1;
}

int write_file_record(FILE *file, const FileRecord *record){
    if(file == NULL || record == NULL)
        return 0;

    if(!write_uint32(file, record->id))
        return 0;

    if(fwrite(record->name, 1, sizeof(record->name), file) != sizeof(record->name))
        return 0;

    if(!write_uint64(file, record->original_size))
        return 0;

    if(!write_uint64(file, record->encrypted_size))
        return 0;

    if(!write_uint64(file, record->data_offset))
        return 0;

    if(fwrite(record->stream_header, 1, sizeof(record->stream_header), file) != sizeof(record->stream_header))
        return 0;

    if(fwrite(&record->active, 1, sizeof(record->active), file) != sizeof(record->active))
        return 0;

    return 1;
}

int read_file_record(FILE *file, FileRecord *record){
    if(file == NULL || record == NULL)
        return 0;

    memset(record, 0, sizeof(FileRecord));

    if(!read_uint32(file, &record->id))
        return 0;

    if(fread(record->name, 1, sizeof(record->name), file) != sizeof(record->name))
        return 0;

    if(!read_uint64(file, &record->original_size))
        return 0;

    if(!read_uint64(file, &record->encrypted_size))
        return 0;

    if(!read_uint64(file, &record->data_offset))
        return 0;

    if(fread(record->stream_header, 1, sizeof(record->stream_header), file) != sizeof(record->stream_header))
        return 0;

    if(fread(&record->active, 1, sizeof(record->active), file) != sizeof(record->active))
        return 0;

    return 1;
}

int read_file_index(FILE *file, const VaultHeader *header, FileRecord **records){
    if(file == NULL || header == NULL || records == NULL)
        return 0;

    if(header->file_count > MAX_FILES)
        return 0;

    *records = malloc(sizeof(FileRecord) * MAX_FILES);

    if(*records == NULL)
        return 0;

    if(fseeko(file, (off_t)header->index_offset, SEEK_SET) != 0){
        free(*records);
        *records = NULL;
        return 0;
    }

    for(uint32_t i = 0; i < MAX_FILES; i++){
        if(!read_file_record(file, &(*records)[i])){
            free(*records);
            *records = NULL;
            return 0;
        }

        if(!validate_file_record(&(*records)[i], header)){
            free(*records);
            *records = NULL;
            return 0;
        }
    }

    return 1;
}