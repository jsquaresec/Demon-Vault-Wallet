# Core and Desktop Architecture

Demon Vault is a Rust workspace with isolated components:

- `vault-core`: wallet orchestration and lock state;
- `vault-policy`: deny-by-default authorization decisions;
- `vault-network`: outbound-only network policy;
- `vault-storage`: cross-platform storage and encrypted-vault persistence;
- `vault-crypto`: local cryptographic vault;
- `apps/desktop/src-tauri`: Tauri desktop shell.

The GUI is locally bundled HTML/CSS/JavaScript and does not load remote application code. The trusted security boundary remains Rust-side. Frontend code is not allowed to possess raw keys or become the final authority for transaction validation or signing.

The desktop command surface is deliberately narrow. No shell, process, arbitrary filesystem, updater, or remote-UI capability is enabled.

Core crates and the desktop application forbid project-authored `unsafe` Rust. Third-party dependencies may internally use unsafe code and remain subject to dependency review.

The application starts locked. Transaction signing and raw private-key export are disabled until complete implementations exist.

Cross-platform CI validates the workspace on Windows, macOS, and Linux.
