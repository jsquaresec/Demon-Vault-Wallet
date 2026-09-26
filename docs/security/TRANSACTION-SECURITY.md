# Transaction Security Architecture

Demon Vault places a transaction-security boundary between transaction construction and signing.

## Exact transaction binding

Unsigned transaction bytes are hashed with a domain-separated SHA-256 binding that also includes the asset and network. A reviewed authorization is accepted for external signing only when the exact transaction bytes, asset, and network still match.

Changing the destination, amount, fee, network, change outputs, or serialized unsigned transaction invalidates the authorization path.

## Human review

A review request contains:

- asset and network;
- recipient and change outputs;
- atomic-unit amounts;
- fee;
- exact unsigned-transaction binding;
- optional bounded memo;
- expiration time.

Recipient addresses shown in review are bounded and sanitized. Chain-specific address/network validation still occurs in the BTC/XMR/ZEC transaction builders before this generic security layer.

The review digest commits to every displayed security-relevant field. The user-facing confirmation code is derived from that digest, so confirmation is tied to the exact review rather than a generic approval button.

## Fee protection

Transaction authorization supports both an absolute fee limit and a relative fee limit expressed in basis points against recipient value. Exceeding either configured limit creates a blocking finding and authorization fails closed.

Large output counts and multiple change outputs are surfaced as warnings. Arithmetic is checked for overflow.

## Authorization lifetime and replay resistance

Reviews and authorizations expire. A fresh cryptographic nonce is generated for each review and contributes to the resulting authorization value. Reusing an authorization against different transaction bytes or after expiry is rejected.

Authorization values and transaction bindings are redacted from Debug output.

## Signing boundary

Generic unreviewed transaction signing remains disabled by policy. Hardware/offline external signing can proceed only after:

1. the vault is unlocked;
2. the transaction is reviewed;
3. configured blocking checks pass;
4. the displayed confirmation code is supplied;
5. the resulting authorization matches the exact unsigned transaction bytes and remains unexpired.

This preserves the no-raw-private-key-export design while making the signing boundary dependent on a concrete reviewed transaction.

## Threats reduced

The controls are intended to reduce risk from clipboard substitution, UI/backend mismatch, fee manipulation, stale approvals, signing a different transaction than the one reviewed, and accidental approval of materially changed output sets.

They do not replace chain consensus validation, hardware-wallet display verification, or user verification of the intended recipient.
