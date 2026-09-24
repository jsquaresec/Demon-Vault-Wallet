# Update and Supply-Chain Architecture

A compromised update channel can compromise future wallet versions even though normal wallet operation has no Demon Vault backend.

## Requirements
- Release artifacts are built through documented reproducible-build-oriented CI.
- Windows binaries are Authenticode-signed for production distribution.
- macOS releases are Developer ID signed and notarized for production distribution.
- Linux release artifacts receive detached cryptographic signatures/checksums and package-specific signing where applicable.
- Update metadata is authenticated and rollback/downgrade behavior is controlled.
- The application never executes unsigned remote code or loads the GUI from a remote website.
- Dependencies use lockfiles, review, automated vulnerability checks, and minimal feature sets.
- Release credentials are isolated from source code and ordinary developer builds.

Automatic updating is not required in Phase 0. Any future updater must preserve the outbound-only network invariant and fail closed on signature or integrity errors.
