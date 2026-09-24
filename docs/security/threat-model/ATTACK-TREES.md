# Attack Trees

These trees describe attacker goals, not implementation instructions.

## Goal A — Spend funds without user intent

Possible paths:
- Obtain recovery/private signing material.
  - Steal and crack local vault.
  - Capture secret while unlocked through privileged malware.
  - Compromise future backup/recovery handling.
- Manipulate an authorized transaction.
  - Replace clipboard/QR destination.
  - Cause GUI to display different data than the core signs.
  - Feed malicious SwapDesk destination or wrong-network data.
- Ship malicious code.
  - Compromise dependency/build pipeline.
  - Compromise update/signing workflow.

Required breakpoints: encrypted vault, local signing boundary, exact transaction review/authorization binding, strict parsing, supply-chain signing, and later hardware/offline signing.

## Goal B — Exfiltrate wallet secrets

Possible paths:
- Read plaintext logs/crash output.
- Read vault file and brute-force password.
- Scrape unlocked process memory.
- Abuse GUI/core API to request raw secrets.
- Introduce malicious dependency/update.

Required breakpoints: no-secret logging, memory-hard KDF + AEAD, narrow APIs, minimized plaintext lifetime, dependency/release controls.

## Goal C — De-anonymize user activity

Possible paths:
- Observe remote-node requests.
- Correlate provider activity and timing.
- Add analytics/device identifiers.
- Abuse Discord payload fields.
- Correlate public-chain data.

Required breakpoints: no general telemetry, metadata-minimizing design, accurate privacy warnings, replaceable/local node options, sanitized Discord events.

## Goal D — Abuse Discord webhook

Possible paths:
- Extract credential from distributed application.
- Obtain credential from logs/crash/source.
- Invoke generic publisher with arbitrary content.

Required breakpoints: accept extraction as possible but make it difficult, never commit/log plaintext credential, fixed event schema, rate limiting, rotation ability, and complete isolation from wallet security.
