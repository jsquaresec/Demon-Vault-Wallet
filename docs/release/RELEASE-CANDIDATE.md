# Release Candidate Gate

Demon Vault can be built as a release candidate, but production mainnet enablement is deliberately fail-closed.

## Mainnet permit

The release layer can issue a `MainnetPermit` only when all of the following evidence is explicitly true:

- internal security audit;
- independent security assessment;
- real-node compatibility validation;
- hardware-signing validation;
- recovery/restore validation;
- migration validation;
- Windows/macOS/Linux installer validation;
- signed-release validation;
- update-verification validation.

The current repository truthfully records only the internal security audit as complete. The remaining real-world and independent gates are false, so production mainnet enablement remains disabled.

No environment variable, UI toggle, network response, or remote provider can manufacture a `MainnetPermit`.

## Signed artifacts

`vault-release` defines a domain-separated canonical release manifest containing:

- monotonically increasing release sequence;
- version;
- platform;
- artifact name;
- SHA-256 artifact digest.

The verifier checks the artifact digest, rejects rollback below a caller-provided minimum sequence, and verifies an Ed25519 signature over the canonical manifest.

The repository does not contain a release private key. Signing keys must remain outside source control and outside normal application runtime.

## Candidate testing

Release-candidate validation must exercise:

1. Windows x64 installation, launch, update, uninstall, and recovery;
2. macOS Apple Silicon and Intel packaging/signing/notarization as applicable;
3. Linux x64 packaging, launch, update, and recovery;
4. BTC/XMR/ZEC against real compatible nodes without weakening zero-inbound networking;
5. supported hardware signing on physical devices;
6. backup creation and restore on fresh installations;
7. migration from every supported prior vault format;
8. signed artifact and update verification, including tamper and rollback rejection;
9. an independent security assessment with all critical/high findings remediated.

Automated CI is necessary evidence but is not a substitute for the physical-device, installer, real-node, recovery, or independent-audit gates above.

## Network invariant

Release-candidate work does not alter the permanent network architecture: default operation requires no inbound listener, firewall exception, router port forwarding, UPnP, or NAT-PMP. Direct outbound mode is not represented as anonymous.
