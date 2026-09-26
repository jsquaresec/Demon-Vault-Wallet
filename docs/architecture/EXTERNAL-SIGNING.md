# External Signing Architecture

Demon Vault supports two external-signing paths: hardware-device signing through a narrow signer interface and offline signing through versioned request/response packages.

External signing never exports the wallet seed, vault password, or raw private keys. The signer receives only the asset, network, unsigned transaction bytes, an exact authorization value, and an expiry. Each request is bound with SHA-256 over a domain-separated canonical representation so a signed response can be rejected if it belongs to a different transaction, network, asset, signing mode, authorization, or expiry.

Offline request packages use a versioned Demon Vault envelope with strict length bounds and a request binding. Imports reject malformed, oversized, unsupported-version, wrong-mode, truncated, trailing-data, and binding-mismatched packages. Offline signature packages contain only the request binding and opaque signed transaction bytes.

Hardware integrations implement the `HardwareSigner` interface. Device metadata is bounded and sanitized before use. A returned signed transaction is accepted only after its request binding matches the exact request. Hardware transport errors and signing failures fail closed.

Preparing or importing an external-signing artifact requires the vault to be unlocked at the policy boundary. Generic in-process transaction signing and raw private-key export remain disabled. A hardware interface being available is not the same as a hardware device being connected; the Security Center reports those states separately.

No inbound listener, router port forwarding, UPnP, NAT-PMP, cloud signing service, or Demon Vault account service is required for external signing.
