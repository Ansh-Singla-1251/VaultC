CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -largon2 -lsodium

SRC = src/main.c src/vault.c src/storage.c src/crypto.c src/cli.c

TARGET = vault

TEST_CRYPTO = tests/test_crypto
TEST_FILE_CRYPTO = tests/test_file_crypto
TEST_VAULT = tests/test_vault

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIBS) -o $(TARGET)

$(TEST_CRYPTO): tests/test_crypto.c src/crypto.c
	$(CC) $(CFLAGS) tests/test_crypto.c src/crypto.c $(LIBS) -o $(TEST_CRYPTO)

$(TEST_FILE_CRYPTO): tests/test_file_crypto.c src/crypto.c
	$(CC) $(CFLAGS) tests/test_file_crypto.c src/crypto.c $(LIBS) -o $(TEST_FILE_CRYPTO)

$(TEST_VAULT): tests/test_vault.c src/vault.c src/storage.c src/crypto.c
	$(CC) $(CFLAGS) tests/test_vault.c src/vault.c src/storage.c src/crypto.c $(LIBS) -o $(TEST_VAULT)

test: $(TEST_CRYPTO) $(TEST_FILE_CRYPTO) $(TEST_VAULT)
	./$(TEST_CRYPTO)
	./$(TEST_FILE_CRYPTO)
	./$(TEST_VAULT)

clean:
	rm -f $(TARGET)
	rm -f $(TEST_CRYPTO)
	rm -f $(TEST_FILE_CRYPTO)
	rm -f $(TEST_VAULT)
	rm -f tests/data/*.bin
	rm -f tests/data/*.vlt
	rm -f tests/data/*.txt
	rm -f integration_source.txt