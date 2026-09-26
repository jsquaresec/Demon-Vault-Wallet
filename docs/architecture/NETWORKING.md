# Networking Architecture

## Default posture

Demon Vault is an outbound-only desktop client. The default policy requires no inbound listener, inbound firewall exception, router port forwarding, UPnP, or NAT-PMP. External communication is initiated by the application over client connections only.

The default privacy route is direct outbound access. Proxy and Tor routes are explicit configuration states rather than silent fallbacks.

## Remote transport

Remote endpoints must use authenticated HTTPS. Remote plaintext HTTP is rejected. Invalid-certificate bypass is disabled and redirects are disabled so an approved endpoint cannot silently redirect the client to a different origin.

Loopback HTTP is permitted only for explicit local-node use. This supports locally managed Bitcoin/Monero/Zcash infrastructure without weakening the remote transport rule.

Onion-service URLs are accepted only when the Tor privacy route is selected. Tor routing requires a loopback `socks5h` proxy so DNS resolution remains on the proxy side and a remote machine cannot be silently configured as the Tor proxy.

## Proxy and Tor routing

The network layer models three routes:

- `Direct`: no proxy is accepted.
- `Proxy`: an explicit HTTPS or `socks5h` proxy is required.
- `Tor`: an explicit loopback `socks5h` proxy is required.

Proxy URLs reject embedded credentials, fragments, control characters, malformed authorities, and oversized values.

## Request bounds

Default transport limits are:

- 15-second connect timeout;
- 45-second request timeout;
- 8 MiB maximum response size policy.

Limits are bounded so configuration cannot silently disable timeouts or permit unbounded remote responses.

## Metadata minimization

The default metadata policy disables Referer transmission, persistent cookies, response caching, and device identifiers. Redirects are disabled. General analytics and advertising telemetry remain absent.

These controls reduce unnecessary network metadata; they do not claim to make direct connections anonymous. A remote server can still observe the source IP address and connection timing unless the user selects an appropriate proxy/Tor route.

## Chain backends

BTC, XMR, and ZEC adapters treat all backend responses as untrusted. Backends do not receive wallet passwords, recovery material, private keys, or signing authority.

Monero automatic and custom remote-node selection now requires HTTPS. Explicit local-node mode remains loopback-only and may use HTTP on loopback.

## Discord

The Discord swap-event publisher is outbound HTTPS only. Its HTTP client disables redirects and Referer generation and applies bounded connect/request timeouts. Notifications accept only the fixed sanitized swap-event schema and webhook compromise does not grant wallet signing authority or access to wallet secrets.

## Desktop boundary

The webview Content Security Policy keeps `connect-src` restricted to `'self'`. Chain/provider networking remains in the Rust trust boundary rather than exposing arbitrary remote fetch capability to frontend JavaScript.
