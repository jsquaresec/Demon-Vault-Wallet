# Release Security Audit

This document records the release-level security review for Demon Vault and the gates that remain mandatory before a production release.

## Reviewed surfaces

The internal review covers the complete security-sensitive workspace:

- cryptographic vault construction, KDF bounds, authenticated encryption, domain separation, secret redaction, and zeroization;
- vault creation, persistence, lock state, and key lifecycle;
- Bitcoin, Monero, and Zcash parsing, scanning, transaction construction boundaries, and network restrictions;
- pre-sign transaction review, exact unsigned-transaction binding, fee limits, expiry, confirmation, and external-signing authorization;
- SwapDesk provider and Discord notification boundaries, including credential isolation and notification failure isolation;
- outbound networking, HTTPS enforcement, proxy/Tor routing, redirect and certificate policy, metadata minimization, and the zero-inbound invariant;
- Tauri command surface and CSP;
- update/supply-chain requirements;
- workspace dependencies, CI, and release process;
- adversarial/property tests and malformed-input handling.

## Internal audit results

The current internal review found no unresolved critical or high-severity issue in the implemented code paths covered by the repository tests.

The following controls are enforced continuously:

1. formatting, Clippy with warnings denied, workspace tests, and workspace checks on Windows, macOS, and Linux;
2. RustSec advisory scanning on the resolved dependency graph;
3. a CI rejection gate for unexpected Rust unsafe blocks, unsafe functions/implementations, or C FFI boundaries;
4. adversarial/property tests for vault envelopes, offline-signing packages, chain address parsers, Monero transaction scanning, URL/proxy/webhook parsing, network policy mutation, and transaction binding;
5. CI rejection of phase-numbered scaffolding in shipping paths.

This statement is an internal engineering assessment, not an independent audit certification.

## Release blockers

A production release is blocked by any unresolved critical/high finding from internal review, dependency advisories that materially affect a reachable Demon Vault code path, or an independent security assessment.

An independent external security assessment has **not** been performed by this repository automation and must not be represented as completed. Before a production release, an independent reviewer should receive the source revision and review at minimum the cryptographic construction, secret lifecycle, transaction authorization, chain-specific code, SwapDesk/webhook isolation, Tauri boundary, networking, updater/release process, and dependency/build supply chain.

All critical/high external findings must be remediated and the affected tests/audit must be rerun before release.

## Remediation and retest policy

Every security finding is tracked with severity, affected revision, affected boundary, remediation commit, and retest evidence. Critical/high findings block release. Medium/low findings require an explicit disposition and must not be silently ignored.

After remediation, the normal cross-platform CI and the security-audit job must both pass on the exact candidate commit. A change to a security boundary invalidates prior review evidence for that boundary.

## Audit evidence

The auditable evidence for a candidate revision is:

- the exact Git commit SHA;
- successful Windows/macOS/Linux CI checks;
- successful security-audit job;
- security regression/property tests in `vault-security-tests`;
- this audit scope and the architecture/security documents under `docs/security`;
- independent assessment report and remediation references when production release approval is sought.

No audit result changes the wallet's core trust model: a privileged attacker controlling the running endpoint can still observe secrets while the vault is unlocked.
