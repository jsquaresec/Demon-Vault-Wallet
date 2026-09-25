# Chain Backend Interfaces

Each chain adapter exposes a narrow capability interface: synchronization/state queries, address/account state required by that chain, fee estimation, transaction-construction support, broadcast of already authorized and signed transactions, and health/status reporting.

## Bitcoin

Bitcoin development is restricted to Testnet, Signet, and Regtest. Mainnet remains unavailable.

The Bitcoin module uses the maintained `rust-bitcoin` library for consensus types and address/network validation. Its backend interface is deliberately narrow: report network identity and tip height, provide bounded fee-rate estimates, and broadcast an already authorized transaction.

Backends cannot access wallet passwords, recovery material, private keys, or signing authority.

Unsigned transaction construction validates the destination and change networks, requires a bounded fee rate, selects known wallet UTXOs, uses opt-in RBF sequences, and fails closed on insufficient funds or arithmetic overflow.

Signing remains disabled at the policy boundary until transaction authorization and key derivation/signing are fully connected.

## Monero

Monero support is implemented in the dedicated `vault-monero` crate using maintained Monero protocol types.

Supported development networks are Stagenet and Testnet. Mainnet is explicitly unavailable until the mainnet release stage.

Connection modes are:

- automatic remote node (default);
- custom remote node;
- user-managed local node bound to loopback.

The automatic selector rejects unreachable nodes, wrong-network nodes, and nodes more than 20 blocks behind the best known height. Eligible nodes are ordered by TLS availability, chain height, and latency.

Local-node mode accepts loopback hosts only and requires no firewall rule, router forwarding, UPnP, or NAT-PMP mapping.

Wallet key material is generated locally from operating-system cryptographic randomness. The private view key is derived deterministically from the private spend key, and both are held in zeroizing byte containers. Address parsing validates checksums and network identity. Mainnet addresses fail closed.

The adapter exposes wallet balance, synchronization, transaction-history, fee-estimation, transfer-intent, health, and broadcast interfaces without giving a remote node wallet secrets. Remote nodes receive no private spend key, private view key, vault password, or signing authority.

A remote node may still observe network metadata associated with wallet synchronization, which is surfaced as a privacy warning.

Transaction signing remains disabled at the global policy boundary until the transaction-authorization/signing stage is implemented.

## Zcash

The adapter must support the selected shielded architecture without misrepresenting transparent transactions as private.

## Common rules

Backends cannot request raw private keys, recovery phrases, vault passwords, or arbitrary signing. Network and chain identity are validated before transaction authorization.
