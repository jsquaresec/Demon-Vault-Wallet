# Abuse Cases

## AC-01 — Pasted address changes
The user copies a legitimate destination but malware replaces clipboard contents. Demon Vault must parse the actual pasted address, visibly show the normalized destination, identify the selected network, and require final authorization of the exact transaction that the core will sign.

## AC-02 — Remote node returns hostile data
A configured node returns malformed or inconsistent responses. The adapter must fail safely, bound input/resource usage, reject wrong-network information, and never let a node directly request a signature.

## AC-03 — Swap provider returns unexpected destination
SwapDesk returns a destination, pair, amount, fee, or expiration inconsistent with the quote/order. Demon Vault must reject inconsistent responses and bind authorization to the reviewed payment details.

## AC-04 — Stolen powered-off laptop
An attacker gets the wallet files but not the unlock password. Sensitive records must remain encrypted/authenticated with a memory-hard password-derived key and random salt. Filesystem permissions are defense-in-depth, not the encryption boundary.

## AC-05 — Discord credential extracted
A user reverse engineers the desktop binary and recovers the webhook. The expected blast radius is limited to webhook abuse. The credential grants no read access, signing authority, wallet secret, balance, address, or provider credential.

## AC-06 — Fake or modified installer
A user receives a tampered package. Production release design must provide OS signing/notarization or cryptographic artifact verification and documentation so modified packages can be detected.

## AC-07 — Privileged host malware
Malware with administrator/root-equivalent control captures input or process memory while the wallet is unlocked. Demon Vault reduces exposure but does not claim software-only prevention against a fully compromised host; hardware/offline signing is the later mitigation for higher-value use.

## AC-08 — Crash during vault write
Power loss or crash interrupts an update. Storage design must use atomic/durable replacement and authenticated versioned records so an interrupted write does not silently become valid corrupted secret state.
