# Required Security Controls

## Vault and secrets

- Memory-hard KDF, per-vault salt, AEAD, and domain-separated keys.
- Minimal plaintext secret lifetime and no generic secret debugging.
- Automatic locking and safe authentication failure.
- Crash-resistant secret-state persistence.

## Transaction integrity

- Strict chain/network/address parsing.
- Core-side recomputation and validation independent of GUI state.
- Explicit final review of destination, amount, network, fee, and privacy mode.
- Authorization bound to the exact transaction that is signed.

## Remote inputs

- Defensive parsing, bounds, timeouts, and response-schema validation.
- Remote nodes/providers never receive arbitrary signing capability.
- Replaceable backends and visible degraded/error state.

## Integrations

- Swap provider responses are validated and cannot authorize signing.
- Discord receives only a fixed sanitized event structure.
- Discord webhook compromise has zero wallet-security impact.

## Local/platform security

- Restrictive app-data permissions appropriate to each OS.
- No secret logging or crash payloads.
- Clipboard and QR inputs treated as hostile.
- Cross-platform security behavior tested rather than assumed.

## Supply chain

- Locked release dependencies.
- Minimal CI permissions.
- Signed/notarized production artifacts.
- Authenticated update metadata and controlled rollback behavior.
- No runtime remote GUI code.

## Testing obligations

High/Critical threats require mapped tests, fuzz cases, or audit checks before production.
