# Assumptions and Non-Goals

## Assumptions

- Supported operating systems provide working cryptographic randomness and normal process/filesystem isolation.
- Users obtain production builds through documented release channels and can verify platform signing or provided integrity mechanisms.
- External blockchain networks and providers can be unavailable or malicious; they are not trusted with keys.
- A strong local unlock password materially improves resistance to offline vault guessing.
- Hardware wallets/offline signers are not part of the early phases and therefore cannot be assumed.

## Non-goals / limitations

- Demon Vault cannot guarantee secrecy on a machine fully controlled by privileged malware while the wallet is unlocked.
- It cannot prevent screenshots, cameras, keyloggers, or malicious accessibility tooling under a fully compromised OS.
- It cannot make an embedded shared Discord webhook impossible to extract from software running on an attacker's own machine.
- It cannot make public-chain activity private when the underlying chain/transaction mode exposes it.
- It cannot guarantee remote-node anonymity; network metadata risks must be disclosed and reduced in later privacy hardening.
- It cannot reverse blockchain transactions or recover lost self-custody secrets.
- It does not claim that "audited" or "hardened" means invulnerable.

These limitations are security properties to communicate clearly, not reasons to weaken the controls that are within Demon Vault's control.
