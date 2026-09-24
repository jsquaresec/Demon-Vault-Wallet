# Demon Vault Wallet

Demon Vault is a cybersecurity-first, self-custody desktop wallet for Bitcoin (BTC), Monero (XMR), and Zcash (ZEC).

The current codebase provides:

- a cross-platform Tauri desktop shell;
- a Rust wallet-core boundary;
- deny-by-default policy controls for unavailable sensitive operations;
- outbound-only default network policy;
- a local encrypted vault using Argon2id, HKDF-SHA-256, and XChaCha20-Poly1305;
- domain separation for wallet and integration secrets;
- zeroizing secret containers;
- create-only encrypted-vault persistence;
- Windows, macOS, and Linux CI.

Transaction signing, live blockchain synchronization, and mainnet wallet operations are intentionally unavailable until their implementations are complete and tested.

## Validation

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace
```

The desktop application lives under `apps/desktop`. Core security components live under `crates/`, and architecture/security documentation lives under `docs/`.

## Cryptographic vault

The local vault uses pinned RustCrypto components:

- Argon2id for password-based key derivation;
- HKDF-SHA-256 for domain-separated wallet/integration keys;
- XChaCha20-Poly1305 for authenticated encryption;
- operating-system cryptographic randomness;
- zeroizing containers for decrypted secrets and derived key material.

See `docs/architecture/VAULT.md` and `docs/security/VAULT-SECURITY.md`.
