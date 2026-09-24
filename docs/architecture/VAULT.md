# Local Cryptographic Vault

Demon Vault uses maintained RustCrypto primitives and does not implement custom cryptographic algorithms.

## Password processing

1. The user password is processed with Argon2id.
2. Each vault uses a fresh 16-byte random salt.
3. Default KDF parameters are 65,536 KiB memory, 3 iterations, and parallelism 1.
4. The 32-byte Argon2id output is used as input keying material to HKDF-SHA-256.
5. HKDF uses fixed domain labels to derive separate 32-byte keys for wallet secrets and integration secrets.

## Encryption

- XChaCha20-Poly1305 authenticated encryption.
- Fresh 24-byte random nonce for every sealed vault envelope.
- Version, encryption domain, KDF parameters, salt, and nonce are authenticated as associated data.
- Authentication failure returns no plaintext.
- Ciphertext size is bounded before allocation/use.
- Randomness comes from the operating system through `getrandom`.

## Versioned envelope

The binary vault begins with the `DVLT` magic and format version 1. It contains the version, encryption domain, Argon2id parameters, salt, XChaCha20 nonce, ciphertext length, ciphertext, and authentication tag.

## Domain separation

Two cryptographic domains are defined:

- `Wallet` — wallet/recovery/signing secret material;
- `Integration` — provider/API integration secrets.

They use different HKDF context strings.

## Memory handling

Derived Argon2/HKDF key material is zeroized after use. Decrypted secret bytes are held in zeroizing containers and cleared on drop to the extent guaranteed by the selected Rust library/platform.

Software zeroization does not defeat privileged process-memory capture or a fully compromised host.

## Core lifecycle

`VaultCore` can create a new local encrypted wallet vault, unlock an existing wallet-domain vault using a password, retain decrypted bytes only while unlocked, and lock by dropping/zeroizing decrypted secret state.

Wrong passwords and authentication failures do not transition the core into the unlocked state.
