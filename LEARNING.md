# VaultC — Learning Journey

## 1. Why I Built VaultC

VaultC started as an attempt to build something more meaningful than a basic CRUD application.

The goal was to create a project that would require understanding how software works at a lower level:

- How files are represented on disk
- How binary data is stored
- How C manages memory
- How encryption works in practice
- How passwords can be converted into cryptographic keys
- How large files can be processed without loading them completely into memory
- How corrupted data can be detected
- How a real command-line application handles errors

The project gradually evolved from a simple encrypted-file idea into a complete encrypted container with authentication, directory support, verification, password changes, and compaction.

---

# 2. Starting Point

Before starting VaultC, I was comfortable with basic C programming and general programming concepts.

However, I had limited practical experience with:

- Designing a binary file format
- Explicit serialization
- Cryptographic APIs
- Password-based key derivation
- Authenticated encryption
- Streaming encryption
- File-offset management
- Recursive filesystem traversal
- Sanitizer-based debugging
- Designing tests around security boundaries

The project therefore became a way to learn these concepts by implementing them rather than only studying them theoretically.

---

# 3. Learning Progression

The project followed this progression:

```text
C Programming
      ↓
File I/O
      ↓
Binary Data
      ↓
Serialization
      ↓
Memory Management
      ↓
File Offsets
      ↓
Cryptography
      ↓
Password-Based Key Derivation
      ↓
Authenticated Encryption
      ↓
Streaming Encryption
      ↓
CLI Architecture
      ↓
Recursive Directory Traversal
      ↓
Testing
      ↓
Sanitizers
      ↓
Security Hardening
```

Each stage introduced problems that led naturally to the next stage.

---

# 4. Learning C File I/O

One of the first important lessons was that a file is ultimately a sequence of bytes.

VaultC uses C file operations such as:

```c
fopen()
fread()
fwrite()
fseek()
fseeko()
fclose()
```

This required understanding:

- Binary vs text files
- File positions
- Reading partial data
- Detecting I/O failures
- Appending data
- Random access

This became particularly important because the vault is not simply one encrypted blob. It contains a structured header, an index, and multiple encrypted data regions.

---

# 5. Learning Binary Serialization

A major design problem appeared when considering how to store C structures.

A tempting approach is:

```c
fwrite(&header, sizeof(header), 1, file);
```

However, the in-memory representation of a C structure can contain padding and depends on implementation details.

That makes directly writing structs to disk a poor choice for a defined binary format.

VaultC therefore serializes individual fields explicitly.

For example:

```text
uint32_t
    ↓
4 bytes

uint64_t
    ↓
8 bytes
```

The project uses explicit little-endian serialization for integer fields.

This taught me that **memory representation and file representation are two different things**.

---

# 6. Understanding File Offsets

VaultC stores encrypted files inside one container.

Therefore, each file needs to know where its encrypted data begins.

A file record stores:

```text
data_offset
encrypted_size
```

The encrypted region is conceptually:

```text
[data_offset, data_offset + encrypted_size)
```

This introduced another important systems concept: integer overflow.

For example, blindly calculating:

```c
data_offset + encrypted_size
```

can overflow if the values are maliciously large.

VaultC therefore checks the addition before using the result.

This was an important lesson because security problems can arise from ordinary arithmetic operations.

---

# 7. Learning Cryptography

Cryptography was one of the biggest learning areas of the project.

Instead of implementing encryption algorithms manually, VaultC uses established libraries:

- Argon2id
- libsodium
- XChaCha20-Poly1305-based SecretStream

This reinforced an important engineering principle:

> Cryptographic primitives should generally come from well-established, reviewed implementations rather than being implemented from scratch.

The learning focus was therefore understanding **how the primitives fit together**.

---

# 8. Passwords Are Not Encryption Keys

An early design question was:

> Why not simply use the user's password as the encryption key?

A password is not suitable as a cryptographic key because human-created passwords have much lower entropy and predictable structure.

VaultC instead uses:

```text
Password
   |
   v
Argon2id + Random Salt
   |
   v
Password-Derived Key
```

Argon2id makes large-scale password guessing more expensive.

The random salt ensures that the same password does not produce the same derived value across different vaults.

---

# 9. Learning Key Separation

A second important design decision was introduced after understanding password-derived keys.

Instead of:

```text
Password
   ↓
Encryption Key
   ↓
All Files
```

VaultC uses:

```text
Password
   ↓
Argon2id
   ↓
Password-Derived Key
   ↓
Protect Vault Key
   ↓
Random Vault Key
   ↓
Encrypt Files
```

This provides a useful property:

### Password changes do not require file re-encryption.

The random vault key remains the same.

Only the encrypted representation of the vault key needs to change.

This became one of the most important architectural decisions in the project.

---

# 10. Learning Authenticated Encryption

Another important lesson was that encryption alone does not guarantee integrity.

An attacker could potentially modify encrypted bytes.

Therefore, VaultC uses authenticated encryption through libsodium's SecretStream construction.

Conceptually:

```text
Plaintext
    |
    v
Encryption
    |
    +---- Authentication
    |
    v
Ciphertext
```

During extraction:

```text
Ciphertext
    |
    v
Authentication
    |
    +---- Failure → Reject
    |
    v
Plaintext
```

This means corrupted or tampered encrypted data should not silently produce output.

---

# 11. The 8192-Byte Boundary Bug

One of the most valuable bugs in the project appeared while testing streaming encryption.

VaultC processes files using:

```text
8192-byte chunks
```

The tests included:

```text
8191 bytes
8192 bytes
8193 bytes
```

An exactly 8192-byte file exposed an incorrect assumption about the size of the authentication overhead produced by SecretStream.

The implementation initially treated the overhead as 16 bytes.

The actual required size was 17 bytes.

This affected buffer calculations.

The important lesson was that **boundary testing finds bugs that normal tests can completely miss**.

The final tests deliberately retained:

```text
8191
8192
8193
```

as permanent regression cases.

---

# 12. Learning Streaming File Processing

A naive implementation could read a complete file:

```text
File
 ↓
Memory
 ↓
Encrypt
 ↓
Vault
```

This would become problematic for large files.

VaultC instead uses:

```text
File
 |
 +--> Chunk → Encrypt → Write
 |
 +--> Chunk → Encrypt → Write
 |
 +--> Chunk → Encrypt → Write
 |
 +--> ...
```

This keeps memory usage approximately independent of the total file size.

The project therefore taught the difference between:

- Processing a file
- Loading a file

Those are not the same thing.

---

# 13. Learning Recursive Directory Traversal

Supporting individual files was relatively straightforward.

Supporting directories introduced a different problem.

A directory can contain:

- Files
- Subdirectories
- More files
- More subdirectories

VaultC therefore recursively traverses directories.

Example:

```text
College/
├── DSA/
│   ├── trees.cpp
│   └── graphs.cpp
└── DBMS/
    └── notes.pdf
```

becomes:

```text
College/DSA/trees.cpp
College/DSA/graphs.cpp
College/DBMS/notes.pdf
```

This introduced practical lessons about:

- `DIR *`
- `readdir()`
- Directory entries
- Relative paths
- Path construction
- Parent-directory creation
- Recursive function design

---

# 14. Learning Logical Deletion

Removing encrypted data immediately creates an interesting problem.

Suppose a vault contains:

```text
[A][B][C][D]
```

and B is removed.

Rewriting everything immediately would be expensive.

VaultC therefore marks the record inactive:

```text
[A][unused][C][D]
```

The encrypted bytes remain until compaction.

This introduced the concept of **logical deletion**.

It also required careful slot management so that new files could reuse inactive records without accidentally overwriting unrelated encrypted data.

---

# 15. The Removed-File Overwrite Bug

During development, a serious storage problem was identified.

If a removed file's space was treated as immediately reusable, new encrypted data could potentially overlap existing encrypted data.

The solution was to separate:

```text
Record slot reuse
```

from:

```text
Encrypted data reuse
```

An inactive record slot can be reused for metadata.

However, new encrypted data is appended rather than blindly overwriting old encrypted regions.

This distinction was an important storage-design lesson.

---

# 16. Learning Vault Compaction

Once logical deletion was implemented, another problem appeared:

```text
Deleting files does not automatically reduce vault size.
```

For example:

```text
Before:

[A][B][C][D]

Delete B:

[A][unused][C][D]
```

VaultC therefore introduced compaction.

Compaction creates a temporary vault and copies only active encrypted data:

```text
[A][unused][C][unused][D]

        ↓ compact

[A][C][D]
```

Importantly, the encrypted data is copied directly.

It does not need to be decrypted and encrypted again.

---

# 17. Learning Atomic Replacement

Compaction also introduced a reliability problem.

Replacing the original vault while it is being rebuilt could leave a partially written vault if something goes wrong.

The implementation therefore uses:

```text
Original Vault
      |
      v
Temporary Vault
      |
      v
Write completely
      |
      v
Flush + Sync
      |
      v
Rename
```

The temporary file is created in the same directory so the final rename occurs on the same filesystem.

This taught an important systems principle:

> Critical file updates should avoid modifying the original state incrementally when a complete temporary replacement is possible.

---

# 18. Learning Validation

A vault file cannot simply be trusted because it has the correct extension.

VaultC validates:

- Magic value
- Version
- Header size
- Index size
- Data offset
- File count
- Record IDs
- File names
- Data offsets
- Encrypted sizes
- Integer overflow conditions

This introduced the principle:

```text
External Data
     |
     v
Validate
     |
     v
Trust
```

rather than:

```text
External Data
     |
     v
Trust Immediately
```

---

# 19. Learning Automated Testing

Initially, manually testing the application was useful for development.

However, manual testing cannot reliably catch regressions.

VaultC therefore developed separate test programs for:

### Cryptography

```text
10 tests
```

### File encryption

```text
6 tests
```

### Vault integration

```text
9 tests
```

Current baseline:

```text
25 / 25 tests passing
```

---

# 20. Testing Strategy

The tests were intentionally designed around boundaries.

Important cases include:

```text
Empty file
1 byte
8191 bytes
8192 bytes
8193 bytes
100 KB
```

Other scenarios include:

```text
Correct password
Wrong password
Tampered ciphertext
Tampered vault key
Multiple files
File removal
Slot reuse
Nested directories
Password changes
Vault compaction
```

The purpose was not simply to increase the number of tests.

The goal was to test places where assumptions were likely to fail.

---

# 21. Learning Sanitizers

The project also introduced compiler sanitizers.

AddressSanitizer was used to detect memory-related problems.

UndefinedBehaviorSanitizer was used to identify undefined behavior.

This was especially useful because C provides direct memory access and therefore places more responsibility on the programmer.

The development process became:

```text
Implement
   ↓
Compile
   ↓
Run Tests
   ↓
Run Sanitizers
   ↓
Find Problems
   ↓
Fix
   ↓
Regression Test
```

---

# 22. Problems That Changed the Design

Several implementation problems directly influenced the final architecture.

| Problem | Lesson | Result |
|---|---|---|
| SecretStream boundary error | Test exact boundaries | Added 8191/8192/8193 tests |
| Removed-file overwrite risk | Separate metadata reuse from data reuse | Append encrypted data |
| Struct serialization | Memory layout ≠ file format | Explicit serialization |
| Large file offsets | 32-bit limits are insufficient | 64-bit offsets |
| Malformed records | External data must be validated | Record validation |
| Password changes | Avoid re-encrypting every file | Separate vault key |
| Deleted data remains | Logical deletion needs reclamation | Compaction |
| Large files | Avoid whole-file buffering | Streaming encryption |

These were not merely implementation details.

They changed the architecture of the project.

---

# 23. What I Learned About Security

The biggest security lessons were:

### 1. Do not invent cryptography

Use established cryptographic libraries.

### 2. Passwords require proper key derivation

A password should not simply become an encryption key.

### 3. Encryption needs integrity

Authenticated encryption protects against undetected modification.

### 4. Randomness matters

Salts, nonces, and encryption keys need cryptographically secure randomness.

### 5. Metadata matters

Protecting file contents does not automatically protect filenames, sizes, or offsets.

### 6. Validation is part of security

Malformed input must not be trusted.

### 7. Security and systems programming overlap

Integer overflow, file handling, memory management, and error handling can all become security issues.

---

# 24. What I Learned About Software Engineering

VaultC also changed how I approached software development.

I learned that a working implementation is only the beginning.

A reliable project also needs:

```text
Clean Architecture
       +
Validation
       +
Testing
       +
Error Handling
       +
Documentation
       +
Security Review
```

The project became much more robust after tests and failure cases were treated as part of development rather than something added at the end.

---

# 25. What I Would Improve

If I continued developing VaultC, I would focus on:

- Authenticated metadata
- Metadata encryption
- Dynamic index allocation
- Crash-recovery journaling
- Fuzz testing
- Filesystem locking
- Better secure-memory handling
- Configurable cryptographic parameters
- Cross-platform testing
- More extensive corruption testing

These improvements would build on the current architecture rather than requiring a complete redesign.

---

# 26. Final Reflection

The most important outcome of VaultC is not the command-line application itself.

The project taught me how multiple low-level concepts interact.

A seemingly simple operation such as:

```text
vault add personal.vlt document.pdf
```

actually involves:

```text
CLI Parsing
     ↓
Password Authentication
     ↓
Key Derivation
     ↓
Vault-Key Recovery
     ↓
File Reading
     ↓
Streaming Encryption
     ↓
Binary Storage
     ↓
Metadata Update
     ↓
Validation
```

Understanding this chain made systems programming much more concrete.

VaultC started as a file-encryption idea and evolved into a practical exercise in C programming, storage design, cryptography, testing, and security engineering.

The biggest lesson was that robust software is built through repeated cycles of:

```text
Build → Test → Find a Problem → Understand Why → Fix → Test Again
```

rather than by writing the final implementation in one pass.