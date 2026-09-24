# Vault Security Controls

The encrypted vault addresses stolen-file, memory-retention, tampering, and interrupted-creation risks.

Controls include:

- Argon2id with per-vault random salt;
- upper bounds on attacker-controlled KDF memory, iteration, and parallelism parameters;
- HKDF-SHA-256 domain separation;
- XChaCha20-Poly1305 authenticated encryption;
- authenticated header metadata;
- zeroized derived keys and decrypted secret storage;
- redacted secret debug output;
- bounded vault-file reads and ciphertext lengths;
- same-directory temporary writes;
- file synchronization before publication;
- create-only hard-link publication so an existing vault is never overwritten by creation;
- Unix vault-file mode `0600`;
- fail-closed behavior for wrong passwords, modified ciphertext, malformed headers, unsupported versions, unknown domains, and randomness failure.

A privileged attacker controlling the running operating system may still capture a password or plaintext while the vault is unlocked. The software does not claim to solve a fully compromised endpoint.
