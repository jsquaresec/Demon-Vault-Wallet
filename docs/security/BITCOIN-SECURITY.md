# Bitcoin Security Controls

The Bitcoin test wallet preserves the existing custody and networking boundaries.

Controls include:

- no Bitcoin mainnet option in the adapter's public environment enum;
- local BIP32/BIP84 key derivation;
- locally generated receive/change addresses;
- network-aware recipient validation;
- zero-amount and zero-fee-rate rejection;
- vault unlock required before the core can construct a Bitcoin test wallet;
- local signing only;
- no private-key export interface;
- no remote signing authority;
- no hard-coded third-party chain backend;
- no inbound listener, port forwarding, UPnP, or NAT-PMP requirement.

Remote chain data remains untrusted. Backend-provided transaction and chain updates must be validated by the wallet/chain libraries before they influence displayed balance or spend selection.

The current environment is for Bitcoin test networks and regtest only. It is not authorization for mainnet use.
