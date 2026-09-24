# Phase 1 Validation Checklist

- [x] Security objectives and protected assets documented.
- [x] Attacker classes documented.
- [x] Trust assumptions documented.
- [x] GUI/core/vault/network/provider/Discord/update/OS trust boundaries documented.
- [x] Threat register created with likelihood, impact, and treatment.
- [x] Attack trees cover unauthorized spend, secret theft, privacy loss, and Discord abuse.
- [x] Abuse cases document hostile clipboard, nodes, swap provider, stolen device, webhook extraction, installer tampering, privileged malware, and interrupted writes.
- [x] Security assumptions and non-goals documented.
- [x] Required controls mapped from threats.
- [x] Phase 0 security/network/privacy invariants remain unchanged.
- [x] CLI validates Phase 0 and Phase 1 required documents/invariants.
- [x] Cross-platform CI executes format, lint, tests, and CLI validation.

Phase 1 is complete only when all validation jobs pass on Windows, macOS, and Linux. Completion authorizes Phase 2 (Rust wallet core + polished GUI/foundation), not mainnet use.
