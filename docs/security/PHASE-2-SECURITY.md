# Phase 2 Security Design

## Deny-by-default implementation

Security-critical features that do not belong to Phase 2 are represented as unavailable rather than mocked as successful. The policy engine denies transaction signing and raw private-key export.

## Frontend boundary

The frontend is an untrusted presentation layer relative to the signing boundary. It contains no wallet secrets, no provider secrets, and no embedded Discord webhook. Its content is packaged locally.

The only initial desktop command returns non-secret foundation status. Future commands must be typed, narrow, and independently validated in Rust.

## No secret-bearing state

Phase 2 creates no recovery phrase, private key, wallet password, encrypted vault, or live chain account. This prevents an unfinished cryptographic design from becoming security-critical before Phase 3.

## No network privilege expansion

The desktop foundation enables no network/listener plugin and creates no server. The coded default network policy preserves the Phase 0 zero-inbound requirement.

## Unsafe Rust policy

Foundation crates and the desktop application forbid project-authored `unsafe` Rust. Third-party dependencies may internally use unsafe code; those dependencies remain subject to later dependency/audit controls.

## Webview policy

The application uses a restrictive Content Security Policy and local assets. No remote scripts, remote styles, or remote application UI are required.

## Logging

No logging framework is introduced in Phase 2. Later logging must follow the no-secret logging invariant established in Phase 0.

## Threat-model mapping

- TM-004: memory-safe Rust boundary and later fuzzing path established.
- TM-009: GUI/core separation established so frontend display state is not signing authority.
- TM-018: in-process core retained; no exposed local IPC service introduced.
- TM-019: integration modules are not granted vault access in the foundation.
- TM-021: no analytics/telemetry SDK introduced.
