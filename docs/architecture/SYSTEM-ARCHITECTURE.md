# System Architecture

Demon Vault is a self-custody desktop wallet. Users control local wallet secrets and authorize sensitive operations locally.

## Product boundary

Normal operation does not require a Demon Vault account server, user database, cloud wallet, cloud seed backup, analytics backend, or Demon Vault-operated blockchain node.

Supported desktop targets are maintained mainstream Windows, macOS, and Linux environments.

## Network invariant

Default operation requires:

- zero inbound firewall rules;
- zero router port forwarding;
- zero UPnP;
- zero NAT-PMP.

Normal wallet networking is client-initiated outbound traffic. No feature may silently create a public listener or NAT mapping.

## Custody invariant

Private keys and recovery material are generated and handled locally. Remote nodes, chain backends, SwapDesk, Discord, update infrastructure, clipboard input, QR input, and network responses are untrusted and never receive signing authority.

## Privacy invariant

General-purpose telemetry is disabled by default. Demon Vault does not collect wallet addresses, balances, transaction history, seeds, private keys, passwords, or device fingerprints.

## Trust boundary

The desktop GUI is presentation and orchestration. Security-sensitive operations live behind a narrow Rust-core interface. The GUI must not manipulate raw private keys directly. Chain adapters validate untrusted backend data before it reaches authorization or signing components.

## Technology baseline

- Rust core.
- Tauri desktop shell.
- Locally bundled UI assets.
- Authenticated TLS where supported.
- Encrypted local secret storage independent of filesystem secrecy.
- Established cryptographic libraries only; no custom cryptographic primitives.
