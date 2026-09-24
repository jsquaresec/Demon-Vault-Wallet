# Networking Architecture

## Default mode
Demon Vault is an outbound client. It does not require inbound listeners, inbound firewall exceptions, router port forwarding, UPnP, or NAT-PMP. External communication must be initiated by the application over normal client connections.

## Backends
BTC, XMR, and ZEC adapters obtain chain state and broadcast signed transactions through configurable external services or nodes. Advanced local-node configurations are permitted, but the default user experience must retain the zero-inbound invariant.

## Transport rules
Use authenticated TLS where the selected protocol supports it. Certificate errors fail closed; there is no silent downgrade to plaintext. Proxy support and metadata minimization are Phase 10 concerns but interfaces must not prevent them.

## Input validation
All remote responses are untrusted. Chain adapters must parse defensively, apply size/time limits, reject malformed or wrong-network data, and never convert remote data directly into signing authorization.

## Discord
The Discord publisher makes only outbound HTTPS requests. It accepts a fixed sanitized swap event, not arbitrary wallet structures. Webhook compromise must not grant access to wallet secrets or other integrations.
