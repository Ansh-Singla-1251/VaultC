#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/storage.h"

int write_vault_header(FILE *file, const VaultHeader *header){
    if(file == NULL || header == NULL)
        return 0;

    if(fseek(file, 0, SEEK_SET) != 0)
        return 0;

    size_t written = fwrite(header, sizeof(VaultHeader), 1, file);

    return written == 1;
}

int read_vault_header(FILE *file, VaultHeader *header){
    if(file == NULL || header == NULL)
        return 0;

    if(fseek(file, 0, SEEK_SET) != 0)
        return 0;

    size_t read = fread(header, sizeof(VaultHeader), 1, file);

    return read == 1;
}

int validate_vault_header(const VaultHeader *header){
    if(header == NULL)
        return 0;

    if(memcmp(header->magic, VAULT_MAGIC, sizeof(header->magic)) != 0)
        return 0;

    if(header->version != VAULT_VERSION)
        return 0;

    if(header->header_size != sizeof(VaultHeader))
        return 0;

    if(header->file_count > MAX_FILES)
        return 0;

    return 1;
}

int write_file_record(FILE *file, const FileRecord *record){
    if(file == NULL || record == NULL)
        return 0;

    size_t written = fwrite(record, sizeof(FileRecord), 1, file);

    return written == 1;
}

int read_file_record(FILE *file, FileRecord *record){
    if(file == NULL || record == NULL)
        return 0;

    size_t read = fread(record, sizeof(FileRecord), 1, file);

    return read == 1;
}

int read_file_index(FILE *file, const VaultHeader *header, FileRecord **records){
    if(file == NULL || header == NULL || records == NULL)
        return 0;

    if(header->file_count > MAX_FILES)
        return 0;

    *records = malloc(sizeof(FileRecord) * MAX_FILES);

    if(*records == NULL)
        return 0;

    if(fseek(file, (long)header->index_offset, SEEK_SET) != 0){
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
    }

    return 1;
}