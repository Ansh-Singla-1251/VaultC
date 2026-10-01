#include <stdio.h>
#include <string.h>

#include "../include/cli.h"
#include "../include/vault.h"

void print_usage(void){
    printf("VaultC - Secure File Vault\n");
    printf("\n");
    printf("Usage:\n");
    printf("  vault create <vault>\n");
    printf("  vault open <vault>\n");
    printf("  vault add <vault> <file>\n");
    printf("  vault extract <vault> <file>\n");
    printf("  vault list <vault>\n");
    printf("  vault remove <vault> <file>\n");
    printf("  vault rename <vault> <old> <new>\n");
    printf("  vault search <vault> <query>\n");
}

int handle_command(int argc, char *argv[]){
    if(argc < 2){
        print_usage();
        return 1;
    }

    if(strcmp(argv[1], "create") == 0){
        if(argc != 3){
            print_usage();
            return 1;
        }

        return create_vault(argv[2]) ? 0 : 1;
    }

    if(strcmp(argv[1], "open") == 0){
        if(argc != 3){
            print_usage();
            return 1;
        }

        return open_vault(argv[2]) ? 0 : 1;
    }

    if(strcmp(argv[1], "add") == 0){
        if(argc != 4){
            print_usage();
            return 1;
        }

        return add_file(argv[2], argv[3]) ? 0 : 1;
    }

    if(strcmp(argv[1], "extract") == 0){
        if(argc != 4){
            print_usage();
            return 1;
        }

        return extract_file(argv[2], argv[3]) ? 0 : 1;
    }

    if(strcmp(argv[1], "list") == 0){
        if(argc != 3){
            print_usage();
            return 1;
        }

        return list_vault(argv[2]) ? 0 : 1;
    }

    if(strcmp(argv[1], "remove") == 0){
        if(argc != 4){
            print_usage();
            return 1;
        }

        return remove_file(argv[2], argv[3]) ? 0 : 1;
    }

    if(strcmp(argv[1], "rename") == 0){
        if(argc != 5){
            print_usage();
            return 1;
        }

        return rename_file(argv[2], argv[3], argv[4]) ? 0 : 1;
    }

    if(strcmp(argv[1], "search") == 0){
        if(argc != 4){
            print_usage();
            return 1;
        }

        return search_files(argv[2], argv[3]) ? 0 : 1;
    }

    printf("Unknown command: %s\n", argv[1]);
    print_usage();

    return 1;
}