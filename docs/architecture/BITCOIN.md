# Bitcoin Wallet Architecture

Demon Vault uses a dedicated Rust Bitcoin adapter built on Bitcoin Dev Kit (BDK) and rust-bitcoin.

## Supported development networks

The Bitcoin wallet currently supports only non-mainnet environments:

- Testnet3
- Testnet4
- Signet
- Regtest

Bitcoin mainnet is not represented by the adapter's public environment enum, preventing accidental selection through the normal API.

## Wallet construction

The adapter accepts 16–64 bytes of locally decrypted seed material and derives a BIP32 master key for a BIP84 native-SegWit wallet. Receive and change keychains are separated through BDK's BIP84 descriptor templates.

Seed material originates from the encrypted local vault and remains local. It is never supplied by a remote backend.

## Address handling

Receive and change addresses are derived locally. Recipient strings are parsed as Bitcoin addresses and must be valid for the configured network before transaction construction.

## Wallet state

The adapter exposes:

- total balance in satoshis;
- unspent-output count;
- application of unconfirmed transaction updates supplied by a chain source;
- BIP84 receive/change derivation;
- transaction construction;
- local signing.

The adapter does not hard-code a third-party backend. Chain-source selection remains replaceable so remote infrastructure never becomes a custody dependency.

## Transaction construction

Payments require:

- a nonzero amount;
- a nonzero fee rate;
- a recipient valid for the selected network;
- sufficient locally known spendable outputs.

BDK performs coin selection and PSBT construction. Signing is local using keys derived from the vault-held seed.

## Mainnet boundary

General mainnet transaction signing remains disabled in the policy layer. The current Bitcoin adapter is deliberately a test-network environment and cannot be configured with `Network::Bitcoin` through its public environment type.
