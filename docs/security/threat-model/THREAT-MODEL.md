# Threat Model

This document describes what Demon Vault protects, who may attack it, where trust boundaries exist, and which threats require controls.

## Security objectives

1. Preserve user control of private keys and signing authorization.
2. Prevent unauthorized transaction creation or signing.
3. Prevent disclosure of recovery material, private keys, wallet passwords, integration secrets, and sensitive wallet metadata.
4. Make remote services incapable of becoming custodians.
5. Preserve transaction integrity from user intent through local signing.
6. Preserve the outbound-only network invariant.
7. Prevent a compromised Discord webhook from affecting wallet security.
8. Protect the software supply chain from silent trust-boundary bypass.

## Protected assets

- Recovery phrases and chain-specific private key material.
- Vault-unlock secrets and derived encryption keys.
- Signing authority and transaction-authorization state.
- Encrypted vault contents and integrity metadata.
- Provider credentials.
- Sensitive wallet metadata.
- Release signing keys and authenticated update metadata.
- User intent: asset, network, recipient, amount, fee, privacy mode, and provider selection.
- Application integrity and the trusted Rust wallet core.
- Discord webhook credential, whose compromise must not impact wallet funds or secrets.

## Attacker classes

- **Remote network attacker:** observes, blocks, delays, replays, or manipulates traffic where transport protections do not prevent it.
- **Malicious/compromised backend:** controls a blockchain node or service and returns crafted, stale, inconsistent, or privacy-invasive data.
- **Malicious swap provider or compromised provider account:** manipulates quotes, destinations, status, or metadata.
- **Supply-chain attacker:** compromises a dependency, build action, package registry, release pipeline, signing workflow, or update channel.
- **Local unprivileged attacker:** accesses user files, clipboard, or local process surfaces without administrator/root control.
- **Local privileged attacker / host malware:** inspects process memory, injects input, captures screens/keystrokes, alters binaries, or controls the OS.
- **Physical thief:** obtains a powered-off or locked device and local wallet files.
- **Social-engineering attacker:** tricks the user into approving the wrong address, network, amount, recovery action, or software package.
- **Reverse-engineering user:** controls their own machine and attempts to extract embedded application credentials.

## Trust assumptions

The Internet, remote nodes, SwapDesk, Discord, clipboard, QR codes, downloaded update metadata, and GUI input are untrusted. The operating system and hardware are part of the local trusted computing base, but a fully privileged compromised host can defeat software-only protections.

## Trust boundaries

See `TRUST-BOUNDARIES.md`. Data crossing a trust boundary must be schema-validated, bounded, network/chain checked where applicable, and must not itself authorize signing.

## Risk model

Threats use qualitative likelihood and impact. Critical impact includes loss of signing authority or recovery material. A residual risk may be accepted only when its limitation is explicitly documented.
