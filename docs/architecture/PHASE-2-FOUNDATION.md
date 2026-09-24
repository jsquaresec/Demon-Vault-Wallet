# Phase 2 — Rust Core and Desktop GUI Foundation

Status: **IMPLEMENTED FOUNDATION**

Phase 2 converts the Phase 0/1 specifications into a compilable cross-platform application skeleton without implementing wallet custody, key generation, transaction signing, chain synchronization, or mainnet behavior.

## Workspace

The repository is a Rust workspace with isolated foundation crates:

- `vault-core`: orchestration boundary and safe foundation status.
- `vault-policy`: deny-by-default policy decisions for security-critical actions not yet implemented.
- `vault-network`: Phase 0 network invariant represented in code.
- `vault-storage`: cross-platform path model without OS-specific literals.
- `apps/desktop/src-tauri`: Tauri desktop shell.
- root package: completed-phase security-gate CLI.

## Desktop framework decision

Tauri 2 is accepted for the desktop shell. The GUI is locally bundled HTML/CSS/JavaScript and does not load remote application code. The trusted security boundary remains Rust-side. Frontend code is not allowed to possess raw keys or become the final authority for transaction validation/signing.

The initial Tauri capability surface is deliberately minimal. No shell, process, filesystem, HTTP, updater, global shortcut, or other plugin is enabled in Phase 2.

## Core security posture

The `vault-core` crate starts locked. Phase 2 does not contain signing functionality. Requests for signing or private-key export are denied by policy. This ensures the foundation cannot accidentally be mistaken for a usable funds wallet before later phases.

## Network posture

`vault-network::NetworkPolicy::default()` encodes:
- no inbound listener;
- no port forwarding;
- no UPnP;
- no NAT-PMP.

The foundation has no chain networking implementation yet. Network clients are added only in their roadmap phases.

## GUI scope

The Phase 2 GUI establishes the visual/navigation system and security-state presentation: overview, wallets, send, receive, swap, activity, Security Center, network, and settings. BTC/XMR/ZEC cards are placeholders; balances are zero and no transaction action is functional.

The UI clearly labels Phase 2 limitations rather than simulating working custody or signing.

## Cross-platform target

The workspace and desktop shell must compile/check on Windows, macOS, and Linux CI. Linux CI installs the documented WebKitGTK/system prerequisites required by Tauri. Packaging/signing remains a later release concern.

## Exit condition

Phase 2 passes only when:
1. the Phase 0 and Phase 1 gates continue to pass;
2. all foundation crate tests pass;
3. the full Rust workspace checks and lints;
4. the Tauri desktop shell compiles/checks on Windows, macOS, and Linux;
5. the Phase 2 CLI validator confirms required files and security invariants.
