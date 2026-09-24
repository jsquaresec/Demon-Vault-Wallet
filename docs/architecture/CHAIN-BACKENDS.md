# Chain Backend Interfaces

Each chain adapter exposes a narrow capability interface: synchronization/state queries, address/account state required by that chain, fee estimation, transaction construction support, broadcast of already authorized and signed transactions, and health/status reporting.

## Bitcoin
Development begins on test networks. Backend selection must be replaceable so no single third party becomes a custody or architectural dependency. Signing keys remain inside the local wallet core.

## Monero
Connection modes are automatic remote node (default), custom remote node, and user-managed local node. Remote nodes are untrusted and the UI must explain network-metadata tradeoffs.

## Zcash
The adapter must support the selected shielded architecture without misrepresenting transparent transactions as private. Shielded support is validated during Phase 7.

## Common rules
Backends cannot request raw private keys, recovery phrases, vault passwords, or arbitrary signing. Network and chain identity are validated before transaction authorization.
