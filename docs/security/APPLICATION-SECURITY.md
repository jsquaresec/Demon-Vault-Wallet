# Application Security

Security-critical features that are not implemented are denied rather than mocked as successful. Transaction signing and raw private-key export are currently disabled.

The frontend is an untrusted presentation layer relative to the signing boundary. It contains no wallet secrets or provider secrets and is packaged locally.

The desktop shell creates no inbound server and enables no router mapping. The default network policy requires no inbound listener, no port forwarding, no UPnP, and no NAT-PMP.

The application uses a restrictive Content Security Policy and local assets. No remote scripts, styles, or application UI are required.

Logging and crash handling must not expose passwords, recovery material, private keys, provider credentials, wallet addresses, balances, or raw transaction data.
