# Cryptographic Vault Requirements

The vault uses established cryptographic libraries and a migration-capable versioned envelope.

Requirements:

- memory-hard password KDF with per-vault random salt;
- authenticated encryption for secret records;
- operating-system cryptographic randomness;
- domain separation between wallet and integration secrets;
- authenticated metadata and versioning;
- safe failure on authentication errors;
- bounded parser inputs and KDF parameters;
- minimized plaintext lifetime;
- zeroization-capable secret containers where reliable;
- no generic secret debug/log serialization;
- create-only crash-resistant persistence for initial vault creation.

The implemented construction is documented in `docs/architecture/VAULT.md`.
