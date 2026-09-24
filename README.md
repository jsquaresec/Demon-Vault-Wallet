# Demon Vault Wallet

Demon Vault is a cybersecurity-first, self-custody desktop wallet planned for Bitcoin (BTC), Monero (XMR), and Zcash (ZEC).

Development is strictly phase-gated.

- **Phase 0:** architecture and security specification — complete.
- **Phase 1:** threat model — complete.
- **Phase 2:** Rust core + cross-platform desktop GUI foundation — complete after CI validation.

Phase 2 intentionally contains **no real wallet secrets, chain synchronization, transaction signing, or mainnet functionality**. Those capabilities are introduced only in their roadmap phases.

## Security-gate CLI

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace
cargo run -- all
```

A complete validation prints:

```text
Demon Vault Phase 0 CLI: PASS
Demon Vault Phase 1 CLI: PASS
Demon Vault Phase 2 CLI: PASS
Demon Vault security gates: PASS
```

Individual gates can be checked with `cargo run -- phase0`, `phase1`, or `phase2`.

The desktop shell lives under `apps/desktop`. Architecture and phase checklists live under `docs/`.
