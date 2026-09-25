# Chain Backend Interfaces

Each chain adapter exposes a narrow capability interface: synchronization/state queries, address/account state required by that chain, fee estimation, transaction construction support, broadcast of already authorized and signed transactions, and health/status reporting.

## Bitcoin

Bitcoin development is restricted to Testnet, Signet, and Regtest. Mainnet remains unavailable.

The Bitcoin module uses the maintained `rust-bitcoin` library for consensus types and address/network validation. Its backend interface is deliberately narrow: report network identity and tip height, provide bounded fee-rate estimates, and broadcast an already authorized transaction.

Backends cannot access wallet passwords, recovery material, private keys, or signing authority.

Unsigned transaction construction validates the destination and change networks, requires a bounded fee rate, selects known wallet UTXOs, uses opt-in RBF sequences, and fails closed on insufficient funds or arithmetic overflow.

Signing remains disabled at the policy boundary until transaction authorization and key derivation/signing are fully connected.

## Monero

Monero supports three node-selection modes: automatic remote node by default, a user-supplied custom remote node, and a user-managed local node. Automatic selection filters for the configured Monero network and selects only healthy candidates. Local-node mode only accepts loopback endpoints.

Remote nodes are untrusted. The backend boundary never receives the wallet seed, private spend key, private view key, vault password, or signing authority. Chain transactions are fetched through the narrow backend interface and ownership scanning is performed locally using the private view key and public spend key.

Wallet identity creation is deterministic from vault-protected seed material and uses separate domain-separated spend and view derivation. Address parsing validates Mainnet, Stagenet, and Testnet identity explicitly.

Synchronization state rejects malformed heights, duplicate outputs, arithmetic overflow, malformed transaction data, undecodable confidential amounts, and unexpectedly deep reorganization reports. Fee estimates are bounded before they can become part of a transaction intent.

Transaction intents bind network, destination, amount, and fee into an exact authorization digest. A signed Monero transaction must match that authorization before broadcast. The signing interface is local-only; remote nodes cannot request arbitrary signatures or access wallet secrets.

## Zcash

Zcash currently operates on Testnet or Regtest; mainnet remains unavailable until release-candidate validation. Address parsing uses the official Zcash address/protocol crates and validates the configured network before an address can enter a transaction intent.

Recipients are classified as transparent or shielded-capable. Shielded-only policy rejects transparent-only recipients rather than presenting them as private. Unified, Sapling, Orchard-capable, and legacy shielded receivers remain distinguishable from transparent-only addresses.

The remote backend is untrusted and exposes only health, network identity, tip height, compact-block retrieval, bounded fee estimates, and broadcast. Compact chain data is handed to a local scanner interface; private viewing material is not part of the backend interface.

Shielded notes, balances, history, synchronization height, duplicate-note detection, and deep-reorganization checks live in the wallet state. Transaction intents bind network, canonical recipient, amount, fee, and privacy policy into an exact authorization digest. The local signer must return a non-empty transaction matching that exact authorization before the backend can broadcast it.

Production shielded proof construction and key derivation remain behind the local signer/scanner boundary and are not represented as verified until concrete protocol implementations are connected and audited.

## Common rules

Backends cannot request raw private keys, recovery phrases, vault passwords, or arbitrary signing. Network and chain identity are validated before transaction authorization.
