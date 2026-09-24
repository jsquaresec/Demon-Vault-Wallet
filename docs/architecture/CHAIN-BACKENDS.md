# Chain Backend Interfaces

Each chain adapter exposes a narrow capability interface: synchronization/state queries, address/account state required by that chain, fee estimation, transaction construction support, broadcast of already authorized and signed transactions, and health/status reporting.

## Bitcoin

Bitcoin development is restricted to Testnet, Signet, and Regtest. Mainnet remains unavailable.

The Bitcoin module uses the maintained `rust-bitcoin` library for consensus types and address/network validation. Its backend interface is deliberately narrow: report network identity and tip height, provide bounded fee-rate estimates, and broadcast an already authorized transaction.

Backends cannot access wallet passwords, recovery material, private keys, or signing authority.

Unsigned transaction construction validates the destination and change networks, requires a bounded fee rate, selects known wallet UTXOs, uses opt-in RBF sequences, and fails closed on insufficient funds or arithmetic overflow.

Signing remains disabled at the policy boundary until transaction authorization and key derivation/signing are fully connected.

## Monero

Connection modes are automatic remote node (default), custom remote node, and user-managed local node. Remote nodes are untrusted and the UI must explain network-metadata tradeoffs.

## Zcash

The adapter must support the selected shielded architecture without misrepresenting transparent transactions as private.

## Common rules

Backends cannot request raw private keys, recovery phrases, vault passwords, or arbitrary signing. Network and chain identity are validated before transaction authorization.
