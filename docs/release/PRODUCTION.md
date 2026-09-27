# Production Release and Maintenance

Demon Vault's production architecture keeps wallet custody, signing, and secret material local. Remote nodes, SwapDesk, Discord notifications, update distribution, and blockchain backends remain outside the trusted signing boundary.

## Production release gate

A production release requires all release-readiness evidence to be complete on the exact candidate revision:

- internal security audit;
- independent security assessment;
- real-node compatibility testing for supported chains;
- physical hardware-signing validation for supported devices;
- encrypted backup and fresh-install restore validation;
- migration validation for every supported prior vault format;
- Windows, macOS ARM64/x64, and Linux installer validation;
- signed release validation;
- authenticated update verification validation.

The application remains fail-closed for production mainnet enablement while any mandatory evidence is missing.

## Recovery procedure

1. Create an encrypted recovery backup from the existing local vault.
2. The backup operation authenticates the vault with the supplied password before export.
3. The backup is the authenticated encrypted vault envelope; plaintext seed/private-key material is not exported.
4. Store the backup offline in a user-controlled location.
5. On restore, select a new destination vault path. Existing vault files are never overwritten.
6. Restore authenticates the backup before writing it.
7. Unlock the restored vault with the original password and verify expected wallet identity before attempting a transaction.
8. A production release must exercise this flow on fresh Windows, macOS, and Linux installations.

## Vulnerability response

Security reports should never contain seeds, private keys, passwords, recovery material, webhook credentials, provider credentials, or live signed transactions.

For every reported issue:

- identify the affected revision and security boundary;
- assign severity and exploitability;
- reproduce using synthetic test material;
- add a regression test before or with the fix;
- remediate critical/high findings before release;
- rerun cross-platform CI and the dependency/security audit;
- rotate any affected release/integration credential outside the repository;
- document user action when an update or migration is required.

## Maintenance policy

Maintenance releases preserve the zero-inbound networking invariant and do not silently expand telemetry or remote trust. Dependency/security updates must pass the same cross-platform CI and security-audit gates as feature changes.

Future enhancements must remain behind the existing policy, transaction-review, local-signing, encrypted-vault, and release-verification boundaries rather than bypassing them.
