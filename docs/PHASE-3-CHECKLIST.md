# Phase 3 Validation Checklist

- [x] Dedicated `vault-crypto` crate added.
- [x] Argon2id password KDF implemented with per-vault random salt.
- [x] Default KDF uses 65,536 KiB memory, 3 iterations, parallelism 1.
- [x] HKDF-SHA-256 provides wallet/integration domain separation.
- [x] XChaCha20-Poly1305 AEAD implemented with fresh random nonce.
- [x] Vault header metadata is authenticated as associated data.
- [x] Versioned `DVLT` envelope implemented.
- [x] Malformed/unsupported envelopes fail closed.
- [x] Wrong passwords fail closed.
- [x] Ciphertext/header tampering is tested.
- [x] Derived keys are zeroized after use.
- [x] Decrypted secret storage zeroizes on drop.
- [x] Secret Debug output is redacted.
- [x] Create-only write publication implemented with same-directory hard link.
- [x] Existing vaults are never silently overwritten, including racing creation.
- [x] Attacker-controlled KDF memory/iteration parameters are upper-bounded before derivation.
- [x] Vault file reads are size-bounded.
- [x] Unix vault files are created owner-only (`0600`).
- [x] Core create/unlock/lock lifecycle implemented.
- [x] Phase 3 does not implement chain keys, signing, or mainnet.
- [x] Phase 0–2 validators remain mandatory.
- [x] Phase 3 CLI gate validates crypto/storage/core implementation markers.
- [x] Windows/macOS/Linux CI runs full workspace format, lint, test, check, and CLI validation.

Phase 3 is complete only when all Phase 0–3 checks pass on Windows, macOS, and Linux. Completion authorizes Phase 4 (BTC test environment).
