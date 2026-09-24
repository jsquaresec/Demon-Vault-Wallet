# Update and Supply-Chain Architecture

A compromised update channel can compromise future wallet versions even though normal wallet operation has no Demon Vault backend.

Requirements:

- documented reproducible-build-oriented CI;
- Authenticode signing for production Windows releases;
- Developer ID signing and notarization for production macOS releases;
- cryptographic signatures/checksums for Linux artifacts;
- authenticated update metadata;
- controlled rollback/downgrade behavior;
- no unsigned remote code execution;
- no remotely loaded application UI;
- locked dependencies and minimal feature sets;
- isolated release credentials.

Any future automatic updater must preserve the outbound-only network invariant and fail closed on signature or integrity errors.
