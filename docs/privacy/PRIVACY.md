# Privacy Baseline

Demon Vault is privacy-conscious without promising anonymity.

No general analytics or advertising SDKs. No collection of seeds, private keys, wallet passwords, wallet addresses, balances, transaction histories, or device fingerprints.

## Network metadata

Direct connections are not anonymous: a remote backend can observe the source IP address and connection timing. Demon Vault minimizes unnecessary application metadata by disabling Referer transmission, persistent cookies, response caching, device identifiers, and automatic redirects in the hardened network policy. Remote plaintext HTTP is rejected; explicit loopback local-node HTTP is the narrow exception.

Proxy and Tor routing are explicit modes. Tor requires a loopback `socks5h` proxy and onion destinations are rejected outside Tor mode. These controls reduce metadata exposure without claiming that a proxy, Tor, or privacy-focused chain eliminates all correlation risk.

BTC UI must explain public-ledger properties. XMR UI explains that a remote node may observe the wallet IP address, connection timing, requested chain ranges, and other network metadata even though spend and view private keys remain local. A local node reduces this remote-node metadata exposure but increases local storage and bandwidth requirements. ZEC UI distinguishes shielded and transparent behavior explicitly. Transparent-only recipients are labeled non-private and are rejected when shielded-only policy is active. Remote Zcash backends are treated as untrusted; compact chain data is scanned locally so viewing and signing secrets do not cross the backend boundary.

## Anonymous Discord swap event
The owner-controlled webhook is limited to a fixed sanitized schema such as provider, asset pair, and coarse status. Exact amounts are excluded from the maximum-privacy baseline unless the product specification is explicitly revised. Wallet addresses, transaction IDs, balances, IP addresses, device IDs, keys, seeds, passwords, and provider credentials are forbidden.

The webhook URL is treated as an application credential: never committed in plaintext, never logged, never placed in crash output, encrypted at rest in the integration-secret domain, reconstructed only when needed, and kept outside the wallet-secret trust domain. Client-side secrecy is not presented as impossible to extract. Webhook delivery is best-effort and cannot change swap success or failure.
