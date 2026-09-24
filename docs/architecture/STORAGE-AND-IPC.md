# Local Storage and Interface Boundaries

## Data classes
1. Wallet secrets: recovery/key material and signing secrets.
2. Integration secrets: per-user provider credentials if required.
3. Non-secret wallet state: synchronization/cache metadata and user preferences.
4. Logs: operational diagnostics containing no secrets.

Wallet and integration secrets use separate encryption domains derived from the master unlock process. Non-secret storage is still protected with restrictive OS permissions.

## Paths
All paths are resolved through platform APIs. No Windows-only registry/path assumption, Unix-only permission assumption, or macOS-only storage assumption may leak into core business logic.

## GUI/core interface
The GUI uses typed commands/events. Secret-returning APIs are minimized. The frontend never receives a seed or private key merely to render UI. Transaction signing requires validated transaction data plus explicit user authorization.

## IPC
Initial architecture favors an in-process Rust core behind a narrow command boundary, reducing exposed local IPC surface. If process isolation is introduced later, IPC must be authenticated, local-only, permission-restricted, schema-validated, and threat-modeled before use.
