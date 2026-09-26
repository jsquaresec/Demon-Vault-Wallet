# Continuous Security Testing

Demon Vault keeps adversarial tests in the normal Rust workspace so they run with the same cross-platform CI as the rest of the wallet.

## Property-based fuzz testing

The `vault-security-tests` crate uses property-based randomized inputs against security-sensitive parsing and validation boundaries. Each property executes hundreds of generated cases during the ordinary test suite.

Current fuzz-style targets include:

- encrypted vault envelope decoding;
- offline signing request parsing;
- offline signature parsing;
- outbound URL validation;
- proxy and Tor endpoint validation;
- Discord webhook credential parsing;
- Bitcoin, Monero, and Zcash address/recipient parsers;
- Monero raw transaction scanning;
- unsigned-transaction security bindings.

The primary invariant is panic resistance: attacker-controlled or malformed input must return an error rather than crash the process.

## Mutation and fail-closed tests

Security tests also exercise targeted hostile inputs and mutations:

- credential-bearing and malformed URLs;
- plaintext remote endpoints;
- unsafe redirect and certificate-policy changes;
- empty and oversized unsigned transactions;
- changed transaction bytes, recipient values, and review fields;
- transaction fee-limit enforcement;
- signing package binding mismatches;
- encrypted-vault authentication and tamper detection.

## Continuous execution

The security-test crate is a normal workspace member. The generic CI workflow therefore executes it on Windows, macOS, and Linux through:

`cargo test --workspace`

This avoids a separate phase-specific workflow and keeps the adversarial regression suite active after development work is merged.

## Scope

These tests are designed to catch parser panics, missing bounds, unsafe acceptance paths, authorization mismatches, and common regression classes. They do not replace an independent security audit, platform sandbox review, dependency review, or extended coverage-guided fuzzing performed during audit/release work.
