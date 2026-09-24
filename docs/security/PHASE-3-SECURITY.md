# Phase 3 Vault Security Controls

## Threat mappings

Phase 3 implements controls for:

- TM-007 stolen vault files: Argon2id + per-vault salt + authenticated encryption.
- TM-008 process-memory exposure: derived keys are zeroized and decrypted secrets use zeroizing storage.
- TM-012 secret leakage through debugging: secret wrappers and envelopes redact sensitive byte content from Debug output.
- TM-013 local file exposure: encrypted data remains protected independently of filesystem confidentiality.
- TM-014 metadata/ciphertext modification: KDF metadata, salt, nonce, version, and domain are authenticated as AEAD associated data.
- TM-023 interrupted vault creation: write-new storage uses a temporary sibling file, file synchronization, and same-directory rename.

## Fail-closed behavior

- Incorrect passwords produce authentication failure.
- Modified ciphertext produces authentication failure.
- Modified authenticated header metadata produces authentication failure.
- Unsupported format versions are rejected.
- Invalid KDF parameters are rejected.
- Unknown encryption domains are rejected.
- Existing vault files are never silently overwritten by the Phase 3 create path.
- Randomness failure aborts vault creation.

## Persistence

The storage layer creates the encrypted envelope in a same-directory temporary file, flushes it with `sync_all`, then renames it into place. On Unix the parent directory is also synchronized. The create path uses no overwrite behavior.

Future in-place vault updates/password changes require their own crash-safe replacement design and are not silently invented in Phase 3.

## Limits

A privileged attacker controlling the running operating system may still capture a password or plaintext while the vault is unlocked. Phase 3 reduces lifetime and accidental retention; it does not claim to solve a fully compromised endpoint. Hardware/offline signing remains a later roadmap control.
