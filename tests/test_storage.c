#include <stdio.h>
#include <string.h>

#include "../include/storage.h"

int main(void)
{
    FILE *file = fopen("test_storage.bin", "wb+");

    if (file == NULL)
    {
        printf("Failed to create test file.\n");
        return 1;
    }

    FileRecord original = {0};

    original.id = 1;

    strcpy(original.name, "example.pdf");

    original.original_size = 1024;
    original.encrypted_size = 1056;

    original.data_offset = 4096;

    original.active = 1;

    if (!write_file_record(file, &original))
    {
        printf("Failed to write record.\n");
        fclose(file);
        return 1;
    }

    rewind(file);

    FileRecord loaded = {0};

    if (!read_file_record(file, &loaded))
    {
        printf("Failed to read record.\n");
        fclose(file);
        return 1;
    }

    fclose(file);

    if (loaded.id != original.id ||
        strcmp(loaded.name, original.name) != 0 ||
        loaded.original_size != original.original_size ||
        loaded.encrypted_size != original.encrypted_size ||
        loaded.data_offset != original.data_offset ||
        loaded.active != original.active)
    {
        printf("Storage test FAILED.\n");
        return 1;
    }

    printf("Storage test PASSED.\n");

    return 0;
}