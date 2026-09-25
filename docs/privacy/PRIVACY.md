# Privacy Baseline

Demon Vault is privacy-conscious without promising anonymity.

No general analytics or advertising SDKs. No collection of seeds, private keys, wallet passwords, wallet addresses, balances, transaction histories, or device fingerprints.

BTC UI must explain public-ledger properties. XMR UI explains that a remote node may observe the wallet IP address, connection timing, requested chain ranges, and other network metadata even though spend and view private keys remain local. A local node reduces this remote-node metadata exposure but increases local storage and bandwidth requirements. ZEC UI must distinguish shielded and transparent behavior accurately.

## Anonymous Discord swap event
The owner-controlled webhook is limited to a fixed sanitized schema such as provider, asset pair, and coarse status. Exact amounts are excluded from the maximum-privacy baseline unless the product specification is explicitly revised. Wallet addresses, transaction IDs, balances, IP addresses, device IDs, keys, seeds, passwords, and provider credentials are forbidden.

The webhook URL is treated as an application credential: never committed in plaintext, never logged, never placed in crash output, obfuscated in distributed builds, reconstructed only when needed, and kept outside the wallet-secret trust domain. Obfuscation is defense-in-depth, not a claim that a client-side shared secret is impossible to extract.
