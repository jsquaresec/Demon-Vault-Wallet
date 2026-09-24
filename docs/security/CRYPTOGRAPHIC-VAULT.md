# Cryptographic Vault Specification

Phase 0 defines properties, not homemade algorithms.

## Requirements
- A memory-hard password KDF with per-vault random salt and parameters stored with vault metadata.
- Authenticated encryption (AEAD) for secret records.
- Cryptographically secure randomness from maintained OS/library facilities.
- Domain separation between wallet-secret encryption and integration-secret encryption.
- Versioned vault format so algorithms/parameters can migrate safely.
- Authentication failure must not produce partially decrypted state.
- Minimize plaintext secret lifetime and copies; use zeroization-capable containers where supported and document platform/compiler limitations.
- Never serialize secret types through generic debug/logging paths.
- Atomic and durable writes to avoid corrupting the only vault copy.

## Library selection gate
Specific KDF/AEAD crates and parameters are selected and pinned in Phase 3 after current maintenance/security review. Phase 0 prohibits custom primitives and requires a migration-capable envelope format.
