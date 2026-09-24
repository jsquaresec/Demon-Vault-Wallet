# Phase 0 Validation Checklist

- [x] Product/self-custody boundary documented.
- [x] Zero-inbound networking invariant documented.
- [x] No mandatory Demon Vault infrastructure for normal wallet operation.
- [x] Windows/macOS/Linux target strategy documented.
- [x] Rust core and GUI/core trust boundary documented.
- [x] Chain backend interfaces documented.
- [x] Local storage/data classification documented.
- [x] Cryptographic vault properties documented without inventing cryptography.
- [x] Discord anonymous webhook boundary and compromise containment documented.
- [x] Privacy/telemetry baseline documented.
- [x] Logging restrictions documented.
- [x] Update/release signing and supply-chain requirements documented.
- [x] Platform packaging direction documented.
- [x] CLI validator verifies required Phase 0 documents and top-level invariants.

Phase 0 is complete only after the CI matrix passes format, lint, tests, and the Phase 0 CLI on Windows, macOS, and Linux. Completion authorizes Phase 1 (Threat Model), not mainnet use or production wallet functionality.
