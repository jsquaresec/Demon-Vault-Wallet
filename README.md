# Demon Vault Wallet

Demon Vault is a cybersecurity-first, self-custody desktop wallet for Bitcoin (BTC), Monero (XMR), and Zcash (ZEC).

The current codebase provides:

- a cross-platform Tauri desktop shell;
- a Rust wallet-core boundary;
- deny-by-default policy controls for unavailable sensitive operations;
- outbound-only default network policy;
- hardened outbound networking with HTTPS-only remote endpoints, fail-closed certificate policy, disabled redirects, bounded requests, metadata minimization, and explicit proxy/Tor routes;
- a local encrypted vault using Argon2id, HKDF-SHA-256, and XChaCha20-Poly1305;
- domain separation for wallet and integration secrets;
- zeroizing secret containers;
- create-only encrypted-vault persistence;
- Bitcoin Testnet, Signet, and Regtest address/network validation;
- Bitcoin UTXO, bounded fee-rate, unsigned transaction-construction, and replaceable backend foundations;
- Monero deterministic wallet identity, address/network validation, local ownership scanning, wallet state, bounded fee estimates, and exact transaction authorization;
- Monero automatic remote, custom remote, and loopback-only local-node selection with an untrusted backend boundary;
- Zcash network-aware address parsing with explicit shielded-versus-transparent classification;
- Zcash shielded wallet-state, local scanning, bounded fees, exact authorization, local-signing, and untrusted-backend boundaries;
- SwapDesk provider isolation, quote/order validation, encrypted integration credentials, and best-effort sanitized Discord notifications;
- hardware/offline signing request packages with exact authorization binding and no raw private-key export;
- pre-sign transaction review with recipient/amount/fee/network binding, fee anomaly blocking, expiry, replay-resistant authorization, and typed confirmation;
- desktop bundle metadata with application icons for installed shortcuts/application entries;
- continuous property-based security testing for parsers, transaction bindings, network targets, and signing packages across the normal CI matrix;
- Windows, macOS, and Linux CI.

Bitcoin mainnet is disabled. Generic Bitcoin transaction signing remains disabled. Monero wallet and node primitives are implemented with a local-only signing boundary. Zcash defaults to testnet with shielded-only recipients; transparent addresses are explicitly labeled non-private. Live Zcash backend transport and production proof/signing implementations are not represented as verified until concrete local scanner/signer integrations are connected and tested. SwapDesk exposes a replaceable provider boundary rather than embedding a custodial exchange; an actual swap provider must be supplied through that boundary. External-signing interfaces and offline packages are implemented, but no specific hardware-wallet vendor adapter is represented as connected or verified until a concrete integration is added and tested. External signing now requires a transaction authorization produced by the protected pre-sign review flow; arbitrary authorization bytes are no longer accepted by the wallet core. Remote network endpoints fail closed to HTTPS, while explicit loopback local-node HTTP remains available; direct, proxy, and Tor routing are represented without claiming direct connections are anonymous.

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

See `docs/architecture/VAULT.md`, `docs/security/VAULT-SECURITY.md`, and `docs/security/SECURITY-TESTING.md`.


## Release security gate

Release-level security checks are documented in `docs/security/RELEASE-AUDIT.md`. CI continuously runs cross-platform correctness checks, adversarial security tests, a RustSec dependency advisory scan, and an unexpected-unsafe-code gate. Production release approval still requires an independent security assessment and remediation of any critical/high findings; the project does not represent its internal review as an external audit.


## Release candidate gate

Demon Vault now has a fail-closed production release gate and signed-artifact verification boundary. The current repository is a **release candidate**, not a production-mainnet approval: independent security assessment, real-node compatibility, physical hardware signing, recovery/migration, installer-matrix, signed-artifact, and updater validation remain explicit blockers. See `docs/release/RELEASE-CANDIDATE.md`.

Mainnet is not enabled merely because automated CI passes. The release layer requires explicit production evidence before a mainnet permit can be issued.


## Production maintenance

The final production process, recovery procedure, vulnerability-response policy, and maintenance requirements are documented in `docs/release/PRODUCTION.md`. The desktop is versioned as `1.0.0-rc.1` while mandatory external and real-world release evidence remains incomplete. This avoids representing an unsigned or incompletely validated build as an approved production release.
