#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include "../include/vault.h"
#include "../include/storage.h"
#include "../include/crypto.h"


static int read_password(const char *prompt,
                         char *password,
                         size_t size)
{
    if (password == NULL || size == 0)
        return 0;

    printf("%s", prompt);
    fflush(stdout);

    struct termios old_terminal;
    struct termios new_terminal;

    if (tcgetattr(STDIN_FILENO, &old_terminal) != 0)
        return 0;

    new_terminal = old_terminal;

    new_terminal.c_lflag &= ~(ECHO);

    if (tcsetattr(STDIN_FILENO,
                  TCSANOW,
                  &new_terminal) != 0)
    {
        return 0;
    }

    if (fgets(password, size, stdin) == NULL)
    {
        tcsetattr(STDIN_FILENO,
                   TCSANOW,
                   &old_terminal);

        return 0;
    }

    tcsetattr(STDIN_FILENO,
               TCSANOW,
               &old_terminal);

    printf("\n");

    password[strcspn(password, "\n")] = '\0';

    return strlen(password) > 0;
}


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

    /*
     * Ask user for password.
     */
    char password[256];
    char confirm_password[256];

    if (!read_password(
            "Enter vault password: ",
            password,
            sizeof(password)))
    {
        fclose(file);
        return 0;
    }

    if (!read_password(
            "Confirm vault password: ",
            confirm_password,
            sizeof(confirm_password)))
    {
        memset(password, 0, sizeof(password));

        fclose(file);
        return 0;
    }

    if (strcmp(password, confirm_password) != 0)
    {
        printf("Passwords do not match.\n");

        memset(password, 0, sizeof(password));
        memset(confirm_password, 0, sizeof(confirm_password));

        fclose(file);

        return 0;
    }

    /*
     * Generate a unique random salt.
     */
    if (!generate_salt(
            header.password_salt,
            sizeof(header.password_salt)))
    {
        memset(password, 0, sizeof(password));
        memset(confirm_password, 0, sizeof(confirm_password));

        fclose(file);

        return 0;
    }

    /*
     * Derive a 32-byte password verification value
     * using Argon2id.
     */
    if (!derive_key(
            password,
            header.password_salt,
            sizeof(header.password_salt),
            header.password_hash,
            sizeof(header.password_hash)))
    {
        memset(password, 0, sizeof(password));
        memset(confirm_password, 0, sizeof(confirm_password));

        fclose(file);

        return 0;
    }

    /*
     * Password is no longer needed.
     */
    memset(password, 0, sizeof(password));
    memset(confirm_password, 0, sizeof(confirm_password));

    /*
     * Initialize vault metadata.
     */
    memcpy(header.magic, VAULT_MAGIC, 5);

    header.version = VAULT_VERSION;
    header.header_size = sizeof(VaultHeader);

    header.index_offset = sizeof(VaultHeader);
    header.index_size = MAX_FILES * sizeof(FileRecord);
    header.data_offset =
        header.index_offset + header.index_size;

    header.file_count = 0;

    /*
     * Write vault header.
     */
    if (!write_vault_header(file, &header))
    {
        fclose(file);
        return 0;
    }

    /*
     * Reserve space for file index.
     */
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
        printf("Failed to read vault header.\n");
        fclose(file);
        return 0;
    }

    if (!validate_vault_header(&header))
    {
        printf("Invalid VaultC vault.\n");
        fclose(file);
        return 0;
    }

    char password[256];

    if (!read_password(
            "Enter vault password: ",
            password,
            sizeof(password)))
    {
        fclose(file);
        return 0;
    }

    int valid = verify_password(
        password,
        header.password_salt,
        sizeof(header.password_salt),
        header.password_hash,
        sizeof(header.password_hash)
    );

    memset(password, 0, sizeof(password));

    if (!valid)
    {
        printf("Incorrect password.\n");
        fclose(file);
        return 0;
    }

    printf("Vault unlocked: %s\n", path);

    fclose(file);

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
        printf("Failed to read vault header.\n");
        fclose(file);
        return 0;
    }

    if (!validate_vault_header(&header))
    {
        printf("Invalid VaultC vault.\n");
        fclose(file);
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(file, &header, &records))
    {
        printf("Failed to read file index.\n");
        fclose(file);
        return 0;
    }

    printf("\nFiles in %s:\n\n", path);

    printf("%-5s %-30s %-12s\n",
           "ID",
           "NAME",
           "SIZE");

    printf("-----------------------------------------------\n");

    int found = 0;

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active)
        {
            printf("%-5u %-30s %-12llu\n",
                   records[i].id,
                   records[i].name,
                   (unsigned long long)
                   records[i].original_size);

            found = 1;
        }
    }

    if (!found)
    {
        printf("Vault is empty.\n");
    }

    free(records);
    fclose(file);

    return 1;
}


int add_file(const char *vault_path,
             const char *file_path)
{
    if (vault_path == NULL ||
        file_path == NULL)
    {
        return 0;
    }

    FILE *source = fopen(file_path, "rb");

    if (source == NULL)
    {
        perror("Failed to open source file");
        return 0;
    }

    FILE *vault = fopen(vault_path, "rb+");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        fclose(source);
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(vault, &header))
    {
        printf("Failed to read vault header.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    if (!validate_vault_header(&header))
    {
        printf("Invalid VaultC vault.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    if (header.file_count >= MAX_FILES)
    {
        printf("Vault is full.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    /*
     * Extract filename from both Windows and Linux paths.
     */
    const char *filename =
        strrchr(file_path, '\\');

    if (filename == NULL)
    {
        filename =
            strrchr(file_path, '/');
    }

    if (filename != NULL)
    {
        filename++;
    }
    else
    {
        filename = file_path;
    }

    /*
     * Prevent duplicate filenames.
     */
    FileRecord *records = NULL;

    if (!read_file_index(
            vault,
            &header,
            &records))
    {
        printf("Failed to read file index.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active &&
            strcmp(records[i].name,
                   filename) == 0)
        {
            printf(
                "File already exists in vault: %s\n",
                filename);

            free(records);

            fclose(source);
            fclose(vault);

            return 0;
        }
    }

    free(records);

    /*
     * Determine source file size.
     */
    if (fseek(source, 0, SEEK_END) != 0)
    {
        printf(
            "Failed to determine source file size.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    long source_size = ftell(source);

    if (source_size < 0)
    {
        printf(
            "Failed to determine source file size.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    rewind(source);

    /*
     * Append file data to the vault.
     */
    if (fseek(vault, 0, SEEK_END) != 0)
    {
        printf(
            "Failed to seek to vault data area.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    long data_position = ftell(vault);

    if (data_position < 0)
    {
        printf(
            "Failed to determine vault data position.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    unsigned char buffer[8192];

    size_t bytes_read;

    while ((bytes_read =
            fread(buffer,
                  1,
                  sizeof(buffer),
                  source)) > 0)
    {
        if (fwrite(buffer,
                   1,
                   bytes_read,
                   vault) != bytes_read)
        {
            printf(
                "Failed to write file data to vault.\n");

            fclose(source);
            fclose(vault);

            return 0;
        }
    }

    if (ferror(source))
    {
        printf(
            "Failed while reading source file.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    /*
     * Create file record.
     */
    FileRecord record = {0};

    record.id = header.file_count + 1;

    strncpy(
        record.name,
        filename,
        MAX_FILENAME_LENGTH - 1);

    record.name[
        MAX_FILENAME_LENGTH - 1] = '\0';

    record.original_size =
        (uint64_t)source_size;

    /*
     * Encryption is not implemented yet.
     * For now encrypted_size equals original_size.
     */
    record.encrypted_size =
        (uint64_t)source_size;

    record.data_offset =
        (uint64_t)data_position;

    record.active = 1;

    /*
     * Write record into file index.
     */
    uint64_t record_offset =
        header.index_offset +
        (uint64_t)(
            header.file_count *
            sizeof(FileRecord)
        );

    if (fseek(
            vault,
            (long)record_offset,
            SEEK_SET) != 0)
    {
        printf(
            "Failed to locate file index slot.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    if (!write_file_record(
            vault,
            &record))
    {
        printf(
            "Failed to write file record.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    /*
     * Update file count.
     */
    header.file_count++;

    if (fseek(vault, 0, SEEK_SET) != 0)
    {
        printf(
            "Failed to update vault header.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    if (!write_vault_header(
            vault,
            &header))
    {
        printf(
            "Failed to update vault header.\n");

        fclose(source);
        fclose(vault);

        return 0;
    }

    fclose(source);
    fclose(vault);

    printf("Added: %s\n", filename);

    return 1;
}


int extract_file(const char *vault_path,
                 const char *filename)
{
    if (vault_path == NULL ||
        filename == NULL)
    {
        return 0;
    }

    FILE *vault =
        fopen(vault_path, "rb");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(
            vault,
            &header))
    {
        printf(
            "Failed to read vault header.\n");

        fclose(vault);
        return 0;
    }

    if (!validate_vault_header(
            &header))
    {
        printf(
            "Invalid VaultC vault.\n");

        fclose(vault);
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(
            vault,
            &header,
            &records))
    {
        printf(
            "Failed to read file index.\n");

        fclose(vault);
        return 0;
    }

    FileRecord *target = NULL;

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active &&
            strcmp(
                records[i].name,
                filename) == 0)
        {
            target = &records[i];
            break;
        }
    }

    if (target == NULL)
    {
        printf(
            "File not found: %s\n",
            filename);

        free(records);
        fclose(vault);

        return 0;
    }

    /*
     * Prevent accidental overwrite.
     */
    FILE *output =
        fopen(filename, "rb");

    if (output != NULL)
    {
        fclose(output);

        printf(
            "File already exists: %s\n",
            filename);

        printf(
            "Extraction cancelled to prevent overwrite.\n");

        free(records);
        fclose(vault);

        return 0;
    }

    output =
        fopen(filename, "wb");

    if (output == NULL)
    {
        perror(
            "Failed to create output file");

        free(records);
        fclose(vault);

        return 0;
    }

    if (fseek(
            vault,
            (long)target->data_offset,
            SEEK_SET) != 0)
    {
        printf(
            "Failed to locate file data.\n");

        fclose(output);
        remove(filename);

        free(records);
        fclose(vault);

        return 0;
    }

    unsigned char buffer[8192];

    uint64_t remaining =
        target->encrypted_size;

    while (remaining > 0)
    {
        size_t chunk_size =
            sizeof(buffer);

        if (remaining < chunk_size)
        {
            chunk_size =
                (size_t)remaining;
        }

        size_t bytes_read =
            fread(
                buffer,
                1,
                chunk_size,
                vault);

        if (bytes_read != chunk_size)
        {
            printf(
                "Failed to read file data from vault.\n");

            fclose(output);
            remove(filename);

            free(records);
            fclose(vault);

            return 0;
        }

        if (fwrite(
                buffer,
                1,
                bytes_read,
                output) != bytes_read)
        {
            printf(
                "Failed to write extracted file.\n");

            fclose(output);
            remove(filename);

            free(records);
            fclose(vault);

            return 0;
        }

        remaining -= bytes_read;
    }

    fclose(output);
    free(records);
    fclose(vault);

    printf(
        "Extracted: %s\n",
        filename);

    return 1;
}


int remove_file(const char *vault_path,
                const char *filename)
{
    if (vault_path == NULL ||
        filename == NULL)
    {
        return 0;
    }

    FILE *vault =
        fopen(vault_path, "rb+");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(
            vault,
            &header))
    {
        printf(
            "Failed to read vault header.\n");

        fclose(vault);
        return 0;
    }

    if (!validate_vault_header(
            &header))
    {
        printf(
            "Invalid VaultC vault.\n");

        fclose(vault);
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(
            vault,
            &header,
            &records))
    {
        printf(
            "Failed to read file index.\n");

        fclose(vault);
        return 0;
    }

    int found = 0;

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active &&
            strcmp(
                records[i].name,
                filename) == 0)
        {
            uint64_t record_offset =
                header.index_offset +
                (uint64_t)(
                    i * sizeof(FileRecord)
                );

            records[i].active = 0;

            if (fseek(
                    vault,
                    (long)record_offset,
                    SEEK_SET) != 0)
            {
                printf(
                    "Failed to locate file record.\n");

                free(records);
                fclose(vault);

                return 0;
            }

            if (!write_file_record(
                    vault,
                    &records[i]))
            {
                printf(
                    "Failed to update file record.\n");

                free(records);
                fclose(vault);

                return 0;
            }

            found = 1;
            break;
        }
    }

    free(records);
    fclose(vault);

    if (!found)
    {
        printf(
            "File not found: %s\n",
            filename);

        return 0;
    }

    printf(
        "Removed: %s\n",
        filename);

    return 1;
}


int rename_file(const char *vault_path,
                const char *old_name,
                const char *new_name)
{
    if (vault_path == NULL ||
        old_name == NULL ||
        new_name == NULL)
    {
        return 0;
    }

    if (strlen(new_name) >=
        MAX_FILENAME_LENGTH)
    {
        printf(
            "New filename is too long.\n");

        return 0;
    }

    FILE *vault =
        fopen(vault_path, "rb+");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(
            vault,
            &header))
    {
        printf(
            "Failed to read vault header.\n");

        fclose(vault);
        return 0;
    }

    if (!validate_vault_header(
            &header))
    {
        printf(
            "Invalid VaultC vault.\n");

        fclose(vault);
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(
            vault,
            &header,
            &records))
    {
        printf(
            "Failed to read file index.\n");

        fclose(vault);
        return 0;
    }

    int target_index = -1;

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active &&
            strcmp(
                records[i].name,
                new_name) == 0)
        {
            printf(
                "A file with that name already exists.\n");

            free(records);
            fclose(vault);

            return 0;
        }

        if (records[i].active &&
            strcmp(
                records[i].name,
                old_name) == 0)
        {
            target_index = (int)i;
        }
    }

    if (target_index == -1)
    {
        printf(
            "File not found: %s\n",
            old_name);

        free(records);
        fclose(vault);

        return 0;
    }

    strcpy(
        records[target_index].name,
        new_name);

    uint64_t record_offset =
        header.index_offset +
        (uint64_t)(
            target_index *
            sizeof(FileRecord)
        );

    if (fseek(
            vault,
            (long)record_offset,
            SEEK_SET) != 0)
    {
        printf(
            "Failed to locate file record.\n");

        free(records);
        fclose(vault);

        return 0;
    }

    if (!write_file_record(
            vault,
            &records[target_index]))
    {
        printf(
            "Failed to update file record.\n");

        free(records);
        fclose(vault);

        return 0;
    }

    free(records);
    fclose(vault);

    printf(
        "Renamed: %s -> %s\n",
        old_name,
        new_name);

    return 1;
}


int search_files(const char *vault_path,
                 const char *query)
{
    if (vault_path == NULL ||
        query == NULL ||
        strlen(query) == 0)
    {
        return 0;
    }

    FILE *vault =
        fopen(vault_path, "rb");

    if (vault == NULL)
    {
        perror("Failed to open vault");
        return 0;
    }

    VaultHeader header;

    if (!read_vault_header(
            vault,
            &header))
    {
        printf(
            "Failed to read vault header.\n");

        fclose(vault);
        return 0;
    }

    if (!validate_vault_header(
            &header))
    {
        printf(
            "Invalid VaultC vault.\n");

        fclose(vault);
        return 0;
    }

    FileRecord *records = NULL;

    if (!read_file_index(
            vault,
            &header,
            &records))
    {
        printf(
            "Failed to read file index.\n");

        fclose(vault);
        return 0;
    }

    printf(
        "\nSearch results for: %s\n\n",
        query);

    printf(
        "%-5s %-30s %-12s\n",
        "ID",
        "NAME",
        "SIZE");

    printf(
        "-----------------------------------------------\n");

    int found = 0;

    for (uint32_t i = 0;
         i < header.file_count;
         i++)
    {
        if (records[i].active &&
            strstr(
                records[i].name,
                query) != NULL)
        {
            printf(
                "%-5u %-30s %-12llu\n",
                records[i].id,
                records[i].name,
                (unsigned long long)
                records[i].original_size);

            found = 1;
        }
    }

    if (!found)
    {
        printf(
            "No matching files found.\n");
    }

    free(records);
    fclose(vault);

    return 1;
}