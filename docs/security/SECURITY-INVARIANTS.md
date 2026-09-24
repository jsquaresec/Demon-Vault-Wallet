# Security Invariants

These requirements are non-negotiable unless the architecture is explicitly revised.

- Self custody: Demon Vault cannot spend user funds without local user authorization.
- Private keys, seeds, and wallet passwords never leave the trusted wallet boundary.
- Signing occurs locally.
- No secret values in logs, telemetry, crash messages, analytics, or Discord payloads.
- Default networking creates no inbound firewall rule, router forwarding rule, UPnP mapping, or NAT-PMP mapping.
- Remote nodes/services and all externally supplied data are untrusted.
- No silent network-security downgrade.
- Mainnet is not used for early implementation/testing.
- Cryptographic algorithms are not invented by the project.
- Sensitive data is encrypted at rest and decrypted only as needed.
- Automatic locking is required.
- Dependency versions are pinned/locked for releases and audited before production.
- Release artifacts are signed; update metadata is authenticated before installation.
- The Discord webhook is isolated. Extraction is made difficult and accidental disclosure is prevented, but disclosure must have zero impact on wallet security.
- The Discord module never receives keys, seeds, passwords, signing authority, balances, addresses, SwapDesk credentials, or wallet-database access.
