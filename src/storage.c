#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../include/storage.h"

int read_file_index(
    FILE *file,
    const VaultHeader *header,
    FileRecord **records)
{
    if (file == NULL || header == NULL || records == NULL)
        return 0;

    *records = NULL;

    if (header->file_count == 0)
        return 1;

    FileRecord *temp = malloc(
        header->file_count * sizeof(FileRecord)
    );

    if (temp == NULL)
        return 0;

    if (fseek(file, (long)header->index_offset, SEEK_SET) != 0)
    {
        free(temp);
        return 0;
    }

    for (uint32_t i = 0; i < header->file_count; i++)
    {
        if (!read_file_record(file, &temp[i]))
        {
            free(temp);
            return 0;
        }
    }

    *records = temp;

    return 1;
}

int write_vault_header(FILE *file, const VaultHeader *header)
{
    if (file == NULL || header == NULL)
        return 0;

    if (fwrite(header, sizeof(VaultHeader), 1, file) != 1)
        return 0;

    return 1;
}

int read_vault_header(FILE *file, VaultHeader *header)
{
    FILE *fp = (FILE *)file;

    if (fp == NULL || header == NULL)
        return 0;

    if (fread(header, sizeof(VaultHeader), 1, fp) != 1)
        return 0;

    return 1;
}

int write_file_record(FILE *file, const FileRecord *record)
{
    if (file == NULL || record == NULL)
        return 0;

    if (fwrite(record, sizeof(FileRecord), 1, file) != 1)
        return 0;

    return 1;
}

int read_file_record(FILE *file, FileRecord *record)
{
    if (file == NULL || record == NULL)
        return 0;

    if (fread(record, sizeof(FileRecord), 1, file) != 1)
        return 0;

    return 1;
}

int validate_vault_header(const VaultHeader *header)
{
    if (header == NULL)
        return 0;

    if (memcmp(header->magic, VAULT_MAGIC, 5) != 0)
        return 0;

    if (header->version != VAULT_VERSION)
        return 0;

    if (header->header_size != sizeof(VaultHeader))
        return 0;

    return 1;
}