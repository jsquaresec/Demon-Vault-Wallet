# Phase 0 — Architecture and Security Specification

Status: **LOCKED BASELINE**

## Product boundary
Demon Vault is a self-custody desktop wallet. The user controls keys and authorizes every spend. Normal operation does not require a Demon Vault website, VPS, account service, user database, cloud wallet storage, analytics backend, or Demon Vault-operated blockchain node.

Supported desktop targets are currently maintained mainstream **Windows**, **macOS**, and **Linux** environments. macOS targets Apple Silicon and Intel where dependencies remain supportable; Windows and Linux initially target x86-64, with additional architectures only after explicit validation.

## Mandatory network invariant
Default Demon Vault operation requires **zero inbound firewall rules**, **zero router port forwarding**, and **zero UPnP/NAT-PMP port creation**. Normal wallet networking is client-initiated outbound traffic. No feature may silently create a public listener or NAT mapping.

## Custody invariant
Private keys and recovery material are generated and handled locally; signing remains local. Remote nodes, chain backends, SwapDesk, Discord, update infrastructure, clipboard input, QR input, and network responses are untrusted inputs and never receive signing authority.

## Privacy invariant
General-purpose telemetry is disabled by default. Demon Vault does not collect wallet-address, balance, transaction, seed, private-key, password, or device-fingerprint telemetry. Advertising SDKs are prohibited.

The owner-controlled Discord webhook is a narrowly scoped anonymous swap-notification integration, not general telemetry. Its publisher receives only a sanitized event schema and has no interface to wallet secrets.

## Process and trust boundaries
The desktop GUI is presentation and orchestration. Security-sensitive operations live behind a narrow validated Rust-core interface. The GUI must not manipulate raw private keys directly. Chain adapters validate untrusted backend data before it reaches policy/signing components.

## Technology baseline
- Core language: stable Rust, edition 2024.
- Desktop shell candidate: Tauri 2, contingent on Phase 2 implementation validation across Windows/macOS/Linux. The security boundary remains in Rust rather than frontend code.
- GUI frontend: bundled locally; no remote application code is loaded at runtime.
- Networking: Rust HTTPS clients with TLS certificate verification; no silent plaintext fallback.
- Storage: application-owned local files with OS-appropriate restrictive permissions; encrypted secret material is independent of filesystem confidentiality.
- Structured non-secret state may use SQLite when implementation begins. Wallet secret encryption does not depend on SQLite encryption.
- Cryptography: established reviewed primitives/libraries only; no custom cryptographic algorithms.

Exact chain libraries, cryptographic crate versions, and GUI dependencies are pinned when their implementation phase begins so Phase 0 does not freeze stale dependencies before use.

## Repository boundaries
Planned logical modules: `apps/desktop`, `crates/vault-core`, `vault-crypto`, `vault-policy`, `vault-storage`, `vault-network`, `chains/{bitcoin,monero,zcash}`, `integrations/{swapdesk,discord}`, `security/{threat-model,fuzz,audit}`, and platform/integration/security tests.

## Phase gate
Phase 0 passes only when the documents referenced by `docs/PHASE-0-CHECKLIST.md` exist, the CLI validator passes, and the mandatory invariants above are preserved. Phase 1 may then begin; implementation choices may not weaken these invariants without an explicit architecture revision.
