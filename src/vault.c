#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../include/vault.h"
#include "../include/storage.h"

int create_vault(const char *path)
{
    if (path == NULL)
        return 0;

    FILE *file = fopen(path, "wb");

    if (file == NULL)
    {
        perror("Failed to create vault");
        return 0;
    }

    VaultHeader header = {0};

    memcpy(header.magic, VAULT_MAGIC, 5);

    header.version = VAULT_VERSION;
    header.header_size = sizeof(VaultHeader);

    header.index_offset = sizeof(VaultHeader);
    header.index_size = MAX_FILES * sizeof(FileRecord);
    header.data_offset = header.index_offset + header.index_size;

    if (!write_vault_header(file, &header))
    {
        fclose(file);
        return 0;
    }

    FileRecord empty_record = {0};

    for (int i = 0; i < MAX_FILES; i++)
    {
        if (!write_file_record(file, &empty_record))
        {
            fclose(file);
            return 0;
        }
    }

    fclose(file);

    printf("Vault created: %s\n", path);

    return 1;
}
int open_vault(const char *path)
{
    if (path == NULL)
        return 0;

    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(file, &header))
    {
        fclose(file);
        printf("Failed to read vault header.\n");
        return 0;
    }

    fclose(file);

    if (!validate_vault_header(&header))
    {
        printf("Invalid VaultC file.\n");
        return 0;
    }

    printf("Valid VaultC vault: %s\n", path);

    return 1;
}

int list_vault(const char *path)
{
    if (path == NULL)
        return 0;

    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(file, &header))
    {
        fclose(file);
        printf("Failed to read vault header.\n");
        return 0;
    }

    if (!validate_vault_header(&header))
    {
        fclose(file);
        printf("Invalid VaultC file.\n");
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(file, &header, &records))
    {
        fclose(file);
        printf("Failed to read file index.\n");
        return 0;
    }

    printf("\nFiles in %s:\n\n", path);

    printf("%-5s %-30s %-15s\n",
           "ID", "NAME", "SIZE");

    printf("-----------------------------------------------\n");

    for (uint32_t i = 0; i < header.file_count; i++)
    {
        if (records[i].active)
        {
            printf("%-5u %-30s %-15llu\n",
                   records[i].id,
                   records[i].name,
                   (unsigned long long)records[i].original_size);
        }
    }

    free(records);
    fclose(file);

    return 1;
}

int add_file(const char *vault_path, const char *file_path)
{
    if (vault_path == NULL || file_path == NULL)
        return 0;

    FILE *source = fopen(file_path, "rb");

    if (source == NULL)
    {
        perror("Failed to open source file");
        return 0;
    }

    FILE *vault = fopen(vault_path, "rb+");

    if (vault == NULL)
    {
        fclose(source);
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(vault, &header))
    {
        fclose(source);
        fclose(vault);
        printf("Failed to read vault header.\n");
        return 0;
    }
    if (!validate_vault_header(&header))
    {
        fclose(source);
        fclose(vault);
        printf("Invalid VaultC file.\n");
        return 0;
    }

    /*
     * Find the end of the vault.
     */
    if (fseek(vault, 0, SEEK_END) != 0)
    {
        fclose(source);
        fclose(vault);
        return 0;
    }

    long data_position = ftell(vault);

    if (data_position < 0)
    {
        fclose(source);
        fclose(vault);
        return 0;
    }

    /*
     * Get source file size.
     */
    if (fseek(source, 0, SEEK_END) != 0)
    {
        fclose(source);
        fclose(vault);
        return 0;
    }

    long source_size = ftell(source);

    if (source_size < 0)
    {
        fclose(source);
        fclose(vault);
        return 0;
    }

    rewind(source);

    /*
     * Copy file bytes into vault.
     */
    unsigned char buffer[8192];

    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), source)) > 0)
    {
        if (fwrite(buffer, 1, bytes_read, vault) != bytes_read)
        {
            fclose(source);
            fclose(vault);
            printf("Failed to write file data.\n");
            return 0;
        }
    }

    /*
     * Create metadata record.
     */
    FileRecord record = {0};

    record.id = header.file_count + 1;

    /*
     * Extract filename from path.
     */
    const char *filename = strrchr(file_path, '\\');

    if (filename != NULL)
        filename++;
    else
        filename = file_path;

    strncpy(record.name, filename, MAX_FILENAME_LENGTH - 1);

    record.name[MAX_FILENAME_LENGTH - 1] = '\0';

    record.original_size = (uint64_t)source_size;
    record.encrypted_size = (uint64_t)source_size;
    record.data_offset = (uint64_t)data_position;
    record.active = 1;

    /*
     * For now we append the record after the data.
     */
    uint64_t record_offset =header.index_offset +(uint64_t)(header.file_count * sizeof(FileRecord));

    if (fseek(vault, (long)record_offset, SEEK_SET) != 0)
    {
        fclose(source);
        fclose(vault);
        printf("Failed to access file index.\n");
        return 0;
    }

    if (!write_file_record(vault, &record))
    {
        fclose(source);
        fclose(vault);
        printf("Failed to write file record.\n");
        return 0;
    }

    header.file_count++;
    

    /*
     * Rewrite header.
     */
    rewind(vault);

    if (!write_vault_header(vault, &header))
    {
        fclose(source);
        fclose(vault);
        printf("Failed to update vault header.\n");
        return 0;
    }

    fclose(source);
    fclose(vault);

    printf("Added: %s\n", filename);

    return 1;
}

int extract_file(const char *vault_path, const char *filename)
{
    if (vault_path == NULL || filename == NULL)
        return 0;

    FILE *vault = fopen(vault_path, "rb");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(vault, &header))
    {
        fclose(vault);
        printf("Failed to read vault header.\n");
        return 0;
    }

    if (!validate_vault_header(&header))
    {
        fclose(vault);
        printf("Invalid VaultC file.\n");
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(vault, &header, &records))
    {
        fclose(vault);
        printf("Failed to read file index.\n");
        return 0;
    }

    FileRecord *target = NULL;

    for (uint32_t i = 0; i < header.file_count; i++)
    {
        if (records[i].active &&
            strcmp(records[i].name, filename) == 0)
        {
            target = &records[i];
            break;
        }
    }

    if (target == NULL)
    {
        printf("File not found in vault: %s\n", filename);
        free(records);
        fclose(vault);
        return 0;
    }

    FILE *output = fopen(filename, "rb");

    if (output != NULL)
    {
        fclose(output);

        printf("File already exists: %s\n", filename);
        printf("Extraction cancelled to prevent overwrite.\n");

        free(records);
        fclose(vault);
        return 0;
    }

    output = fopen(filename, "wb");

    if (output == NULL)
    {
        perror("Failed to create output file");
        free(records);
        fclose(vault);
        return 0;
    }

    if (fseek(vault, (long)target->data_offset, SEEK_SET) != 0)
    {
        fclose(output);
        free(records);
        fclose(vault);
        printf("Failed to seek to file data.\n");
        return 0;
    }

    unsigned char buffer[8192];

    uint64_t remaining = target->encrypted_size;

    while (remaining > 0)
    {
        size_t chunk_size = sizeof(buffer);

        if (remaining < chunk_size)
            chunk_size = (size_t)remaining;

        size_t bytes_read = fread(buffer, 1, chunk_size, vault);

        if (bytes_read != chunk_size)
        {
            fclose(output);
            free(records);
            fclose(vault);

            remove(filename);

            printf("Failed to read file data.\n");
            return 0;
        }

        if (fwrite(buffer, 1, bytes_read, output) != bytes_read)
        {
            fclose(output);
            free(records);
            fclose(vault);

            remove(filename);

            printf("Failed to write extracted file.\n");
            return 0;
        }

        remaining -= bytes_read;
    }

    fclose(output);
    free(records);
    fclose(vault);

    printf("Extracted: %s\n", filename);

    return 1;
}