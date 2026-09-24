# Trust Boundaries

## TB-1 — User ↔ GUI

User-entered addresses, pasted content, QR data, amounts, settings, and authorization gestures are untrusted until validated. The GUI may display data but cannot directly access or mutate raw signing secrets.

Required controls: strict parsing, explicit network/asset labels, final transaction review, protection against clipboard substitution, and clear distinction between display state and signed state.

## TB-2 — GUI ↔ Rust wallet core

This is a narrow typed command/event boundary. The core independently validates security-critical inputs. Frontend state is never sufficient evidence that a transaction is safe to sign.

Required controls: typed schemas, deny-by-default commands, minimal secret-returning APIs, authorization state bound to exact transaction details.

## TB-3 — Core ↔ encrypted vault

Only the vault/crypto subsystem may decrypt wallet secrets. Other components request narrowly scoped operations instead of receiving long-lived raw keys.

Required controls: authenticated encryption, domain separation, minimal plaintext lifetime, atomic writes, lock state, safe failure on authentication errors.

## TB-4 — Chain adapters ↔ remote nodes/services

All remote chain data is hostile input. A backend can lie about state, fees, confirmations, network identity, or availability.

Required controls: chain/network validation, defensive parsing, bounds/timeouts, no remote signing authority, explicit backend status, and later privacy hardening.

## TB-5 — Swap engine ↔ SwapDesk

Quotes, deposit destinations, fees, expiration, pair, and status are untrusted provider data.

Required controls: validate provider response schema, asset/network, destination, amount, fee/expiration policy, bind user authorization to the exact reviewed swap payment, and never expose wallet signing secrets.

## TB-6 — Event sanitizer ↔ Discord publisher

The publisher receives only an allowlisted anonymous event structure. It has no wallet-vault, signing, address, balance, transaction-history, or SwapDesk-secret interface.

Required controls: fixed schema, no arbitrary message API, outbound HTTPS only, rate limiting, no logs containing the webhook URL, compromise containment.

## TB-7 — Release pipeline ↔ installed application

Build systems, package registries, CI actions, release storage, signing systems, and update metadata are supply-chain boundaries.

Required controls: dependency pinning, minimal CI permissions, signed/notarized releases, authenticated update metadata, reproducible-build-oriented procedures, and no remote code-loaded GUI.

## TB-8 — OS/filesystem ↔ application

Local storage, clipboard, process memory, notifications, screenshots, and OS credential facilities depend on platform security.

Required controls: restrictive permissions, no secret logs, best-effort memory hygiene, automatic locking, platform abstraction, and explicit acknowledgement that privileged host malware is outside complete software-only prevention.
