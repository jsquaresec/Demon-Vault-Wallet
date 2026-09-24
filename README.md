# Demon Vault Wallet

Demon Vault is a cybersecurity-first, self-custody desktop wallet planned for Bitcoin (BTC), Monero (XMR), and Zcash (ZEC).

Development is strictly phase-gated. **Phase 0 (architecture/security specification)** and **Phase 1 (threat model)** are documented and machine-validated. Production wallet functionality is intentionally not implemented before its roadmap phase.

## Security-gate CLI

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run
```

The default CLI validates every completed phase and prints:

```text
Demon Vault Phase 0 CLI: PASS
Demon Vault Phase 1 CLI: PASS
Demon Vault security gates: PASS
```

Individual gates can also be checked with `cargo run -- phase0` or `cargo run -- phase1`.

Start with `docs/architecture/PHASE-0.md`, `docs/security/threat-model/THREAT-MODEL.md`, and the phase checklists under `docs/`.
