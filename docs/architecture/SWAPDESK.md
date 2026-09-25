# SwapDesk Security Boundary

SwapDesk is a local orchestration boundary for external swap providers. Providers remain untrusted and never receive wallet seeds, private keys, vault passwords, or signing authority from the SwapDesk interface.

Quotes are bound to the requested asset pair, input amount, provider identity, and expiration before use. Orders are validated against the provider and quote pair. Provider-specific transport is replaceable and intentionally separate from wallet signing.

Optional Discord notifications are outbound HTTPS only and use a fixed coarse event schema: provider identifier, asset pair, and coarse status. Amounts, wallet addresses, refund addresses, provider order references, transaction IDs, balances, device identifiers, IP addresses, seeds, keys, passwords, and provider credentials are excluded.

The webhook credential is encrypted with the existing integration-secret cryptographic domain. Its debug representation is redacted, the URL is validated as a Discord HTTPS webhook, and delivery failures are isolated from the swap path. A webhook outage or compromise must not grant wallet signing authority or alter swap execution.

No inbound listener, UPnP, NAT-PMP, or router port forwarding is introduced by SwapDesk.
