# Phase 1 — Threat Model

Status: **PHASE 1 BASELINE**

This threat model is derived from the locked Phase 0 architecture. It describes what Demon Vault protects, who may attack it, where trust boundaries exist, and which threats must be mitigated in later implementation phases.

## Security objectives

1. Preserve user control of private keys and signing authorization.
2. Prevent unauthorized transaction creation or signing.
3. Prevent disclosure of recovery material, private keys, wallet passwords, integration secrets, and sensitive wallet metadata.
4. Make remote services incapable of becoming custodians.
5. Preserve transaction integrity from user intent through local signing.
6. Preserve the Phase 0 outbound-only network invariant.
7. Prevent a compromised Discord webhook from affecting wallet security.
8. Make updates and dependencies unable to silently bypass the wallet trust boundary without detection and release controls.

## Protected assets

- Recovery phrases and chain-specific private key material.
- Vault-unlock secrets and derived encryption keys.
- Signing authority and transaction-authorization state.
- Encrypted vault contents and integrity metadata.
- SwapDesk credentials if a future API requires per-user secrets.
- Sensitive wallet metadata such as addresses, balances, transaction history, and UTXO/account state.
- Release signing keys and authenticated update metadata.
- User intent: asset, network, recipient, amount, fee, privacy mode, and provider selection.
- Application integrity and the trusted Rust wallet core.
- Discord webhook credential, treated as low-trust application credential whose compromise must not impact wallet funds or secrets.

## Attacker classes

- **Remote network attacker:** can observe, block, delay, replay, or manipulate traffic where transport protections do not prevent it.
- **Malicious/compromised backend:** controls a BTC/XMR/ZEC node or service and returns crafted, stale, inconsistent, or privacy-invasive data.
- **Malicious swap provider or compromised provider account:** manipulates quotes, destinations, status, or metadata.
- **Supply-chain attacker:** compromises a dependency, build action, package registry, release pipeline, signing workflow, or update channel.
- **Local unprivileged attacker:** has access to the user account, files, clipboard, or local process surface without administrator/root control.
- **Local privileged attacker / host malware:** can inspect process memory, inject input, capture screens/keystrokes, alter binaries, or control the OS.
- **Physical thief:** obtains a powered-off or locked device and local wallet files.
- **Social-engineering attacker:** tricks the user into approving the wrong address, network, amount, recovery action, or software package.
- **Curious/reverse-engineering user:** controls their own machine and attempts to extract the embedded Discord webhook.

## Trust assumptions

Demon Vault does not assume the Internet, remote nodes, SwapDesk, Discord, clipboard, QR codes, downloaded update metadata, or GUI input are trustworthy. The operating system and hardware form part of the local trusted computing base, but a fully privileged compromised host can defeat software-only protections. That limitation is explicitly documented rather than hidden.

## Trust boundaries

See `TRUST-BOUNDARIES.md`. Data crossing a trust boundary must be schema-validated, bounded, network/chain checked where applicable, and must not itself authorize signing.

## Risk model

Threats are tracked with qualitative **Likelihood** and **Impact** values: Low, Medium, High, Critical impact where loss of signing authority or recovery material is possible. A threat may remain accepted only when its residual risk and limitation are explicitly documented. "Mitigated" means controls are planned or implemented; it does not mean impossible.

## Phase relationship

Phase 1 defines threats and required controls. Later phases implement and test those controls. No Phase 1 document authorizes mainnet operation.
