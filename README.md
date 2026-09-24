# Demon Vault Wallet

Demon Vault is a cybersecurity-first, self-custody desktop wallet planned for Bitcoin (BTC), Monero (XMR), and Zcash (ZEC).

Development is phase-gated. This repository currently contains the locked **Phase 0 architecture and security specification** plus a small Rust validation CLI. Wallet functionality is intentionally not implemented during Phase 0.

## Phase 0 validation

```bash
cargo test
cargo run
```

A successful run prints `Demon Vault Phase 0 CLI: PASS`.

See `docs/architecture/PHASE-0.md` and `docs/PHASE-0-CHECKLIST.md`.
