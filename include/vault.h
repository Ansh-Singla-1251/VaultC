#ifndef VAULT_H
#define VAULT_H

int create_vault(const char *path);
int open_vault(const char *path);
int list_vault(const char *path);
int add_file(const char *vault_path, const char *file_path);
int extract_file(const char *vault_path, const char *filename);

#endif