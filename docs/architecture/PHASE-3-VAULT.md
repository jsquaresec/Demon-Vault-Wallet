# Phase 3 — Local Cryptographic Vault

Status: **IMPLEMENTED — VALIDATION REQUIRED**

Phase 3 implements the encrypted local secret vault defined by the Phase 0 architecture and Phase 1 threat model. It does not implement blockchain keys, seed generation, transaction signing, or mainnet use.

## Cryptographic construction

Demon Vault uses maintained RustCrypto primitives and does not implement custom cryptographic algorithms.

Password processing:

1. The user password is processed with Argon2id.
2. Each vault uses a fresh 16-byte random salt.
3. The default KDF parameters are 65,536 KiB memory, 3 iterations, and parallelism 1.
4. The 32-byte Argon2id output is used as input keying material to HKDF-SHA-256.
5. HKDF uses fixed domain labels to derive separate 32-byte keys for wallet secrets and integration secrets.

Encryption:

- XChaCha20-Poly1305 authenticated encryption.
- Fresh 24-byte random nonce for every sealed vault envelope.
- Version, encryption domain, KDF parameters, salt, and nonce are authenticated as associated data.
- Authentication failure returns no plaintext.
- Ciphertext size is bounded before allocation/use.

Randomness is obtained from the operating system through the maintained `getrandom` crate.

## Versioned envelope

The Phase 3 binary vault begins with the `DVLT` magic and format version 1. The envelope contains:

- magic and version;
- encryption domain;
- Argon2id parameters;
- random salt;
- random XChaCha20 nonce;
- ciphertext length;
- AEAD ciphertext and authentication tag.

The format is explicitly versioned so future KDF/AEAD migrations can be introduced without guessing which construction encrypted an existing vault.

## Domain separation

Two cryptographic domains are defined:

- `Wallet` — wallet/recovery/signing secret material.
- `Integration` — provider/API integration secrets.

They use different HKDF context strings. A shared unlock password therefore does not produce the same encryption key for both secret classes.

## Memory handling

Derived Argon2/HKDF key material is zeroized after use. Decrypted secret bytes are held in a `Zeroizing<Vec<u8>>` wrapper and are cleared when dropped to the extent guaranteed by the selected Rust library/platform.

No claim is made that software zeroization defeats privileged process-memory capture or a fully compromised host.

## Core lifecycle

`VaultCore` can:

- create a new local encrypted wallet vault;
- unlock an existing wallet-domain vault using a password;
- keep decrypted bytes only while unlocked;
- lock and drop/zeroize decrypted secret state.

Wrong passwords and authentication failures do not transition the core into the unlocked state.

## Scope boundary

Phase 3 test secrets are synthetic bytes. Real BTC/XMR/ZEC key generation and transaction signing remain in their later roadmap phases.
