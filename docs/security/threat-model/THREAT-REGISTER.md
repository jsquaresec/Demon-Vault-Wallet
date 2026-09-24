# Threat Register

| ID | Threat | Likelihood | Impact | Required treatment |
|---|---|---|---|---|
| TM-001 | Host malware captures password, seed, or signing data | Medium | Critical | Minimize secret exposure/lifetime; auto-lock; hardware/offline signing later; document privileged-host limitation |
| TM-002 | Clipboard replacement changes destination address | High | High | Detect paste changes where practical; revalidate; full destination review before signing |
| TM-003 | Malicious remote node lies about state/fees/confirmations | Medium | High | Treat node data as untrusted; validate network/data; provider health/status; no signing authority |
| TM-004 | Crafted RPC/network input exploits parser | Medium | Critical | Memory-safe core, bounded parsers, fuzzing, timeouts/limits, malformed-input tests |
| TM-005 | Malicious dependency compromises wallet | Medium | Critical | Lockfiles, minimized dependencies/features, audit/scanning, review, release controls |
| TM-006 | Compromised update channel ships malicious wallet | Medium | Critical | Signed artifacts, authenticated metadata, notarization/signing, rollback controls |
| TM-007 | Stolen wallet files are brute-forced offline | Medium | Critical | Memory-hard KDF, random salt, AEAD, strong-password guidance, migration-capable vault format |
| TM-008 | Process memory scraping exposes secrets | Medium | Critical | Short plaintext lifetime, zeroization-capable types where reliable, lock behavior, hardware/offline signing later |
| TM-009 | UI/core mismatch causes user to approve different transaction | Medium | Critical | Core recomputes/validates transaction; authorization bound to exact network/recipient/amount/fee |
| TM-010 | Malicious SwapDesk response redirects funds | Medium | Critical | Validate provider response; review exact destination/amount; local construction/signing; status cannot authorize spend |
| TM-011 | Embedded Discord webhook is extracted | High | Low | Obfuscation/short-lived reconstruction; no plaintext logs/source; fixed payload; wallet isolation; rotate on abuse |
| TM-012 | Logs/crash output leak sensitive values | Medium | High | Secret types not generically debug-serializable; redaction; allowlisted logging fields; tests |
| TM-013 | Weak local file permissions expose vault/caches | Medium | High | Platform-specific restrictive permissions plus encryption independent of filesystem secrecy |
| TM-014 | Stale/replayed backend or update data misleads wallet | Medium | High | Freshness/version/chain checks; authenticated update metadata; controlled downgrade behavior |
| TM-015 | Wrong-network/address parsing sends funds incorrectly | Medium | Critical | Chain-specific strict parsing; explicit network display; reject ambiguous/wrong-network destinations |
| TM-016 | Phishing/QR substitution alters destination | High | High | Treat QR as untrusted input; normalized destination review; confirmation ceremony |
| TM-017 | Remote service denial-of-service blocks wallet operation | High | Medium | Timeouts, bounded retries, replaceable backends, clear degraded-state UI |
| TM-018 | Future local IPC is hijacked | Low | Critical | Prefer in-process core; any future IPC requires authentication, local-only scope, permissions, schema validation, threat review |
| TM-019 | Swap/Discord integration accidentally gains secret access | Low | Critical | Compile/module boundary; sanitized DTOs; no vault handles; integration-focused tests |
| TM-020 | Backup/recovery workflow exposes seed | Medium | Critical | Explicit reveal ceremony, no telemetry/logging, verification flow, user warnings, OS protections where available |
| TM-021 | Address/balance metadata leaks through analytics | Low | High | No general telemetry/ads; privacy baseline; fixed Discord schema only |
| TM-022 | Transaction fee manipulation causes excessive fee | Medium | High | Fee-policy bounds, user review, chain-aware sanity checks |
| TM-023 | Corrupt/interrupted write destroys vault state | Medium | High | Atomic/durable writes, authenticated/versioned records, backup/recovery design, corruption tests |
| TM-024 | Build credentials/signing keys are stolen | Low | Critical | Isolated release credentials, least-privilege CI, protected release workflow, rotation/revocation plan |

## Tracking rule

Every High or Critical impact threat must map to at least one planned control and later to a test or audit item before production. New features require adding threats before implementation when they introduce a new trust boundary or secret.
