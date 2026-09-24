# Required Security Controls Derived from Phase 1

## Vault and secrets
- Memory-hard KDF, per-vault salt, AEAD, domain-separated keys.
- Minimal plaintext secret lifetime and no generic secret debugging.
- Automatic locking and safe authentication failure.
- Atomic/durable secret-state writes.

## Transaction integrity
- Strict chain/network/address parsing.
- Core-side recomputation/validation independent of GUI state.
- Explicit final review of destination, amount, network, fee, and privacy mode.
- Authorization bound to the exact transaction that is signed.

## Remote inputs
- Defensive parsing, bounds, timeouts, response schema validation.
- Remote nodes/providers never receive arbitrary signing capability.
- Replaceable backends and visible degraded/error state.

## Integrations
- SwapDesk responses are validated and cannot authorize signing.
- Discord receives only a fixed sanitized event DTO.
- Discord webhook compromise has zero wallet-security impact.

## Local/platform security
- Restrictive app data permissions appropriate to each OS.
- No secret logging/crash payloads.
- Clipboard and QR inputs treated as hostile.
- Cross-platform security behavior tested, not assumed equivalent.

## Supply chain
- Locked/pinned release dependencies.
- Minimal CI permissions.
- Signed/notarized production artifacts.
- Authenticated update metadata and controlled rollback behavior.
- No runtime remote GUI code.

## Testing obligations
High/Critical threats require mapped tests, fuzz cases, or audit checks before production. Phase 12 and Phase 13 must verify the controls rather than relying only on design documentation.
