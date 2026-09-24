#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::{error::Error, fmt};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 4] = *b"DVLT";
const FORMAT_VERSION: u16 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 2 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 4;
const MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultDomain {
    Wallet = 1,
    Integration = 2,
}

impl VaultDomain {
    fn from_byte(value: u8) -> Result<Self, VaultError> {
        match value {
            1 => Ok(Self::Wallet),
            2 => Ok(Self::Integration),
            _ => Err(VaultError::InvalidFormat("unknown encryption domain")),
        }
    }

    fn hkdf_info(self) -> &'static [u8] {
        match self {
            Self::Wallet => b"demon-vault/v1/wallet-secrets",
            Self::Integration => b"demon-vault/v1/integration-secrets",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    fn validate(self) -> Result<(), VaultError> {
        if self.memory_kib < 19 * 1024 {
            return Err(VaultError::InvalidKdfParams);
        }
        if self.iterations < 2 || self.parallelism == 0 || self.parallelism > 8 {
            return Err(VaultError::InvalidKdfParams);
        }
        Ok(())
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("redacted", &true)
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultEnvelope {
    version: u16,
    domain: VaultDomain,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl fmt::Debug for VaultEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultEnvelope")
            .field("version", &self.version)
            .field("domain", &self.domain)
            .field("kdf", &self.kdf)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl VaultEnvelope {
    pub fn domain(&self) -> VaultDomain {
        self.domain
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    pub fn encode(&self) -> Result<Vec<u8>, VaultError> {
        if self.ciphertext.len() > MAX_CIPHERTEXT_LEN {
            return Err(VaultError::PayloadTooLarge);
        }
        let cipher_len =
            u32::try_from(self.ciphertext.len()).map_err(|_| VaultError::PayloadTooLarge)?;
        let mut output = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&self.version.to_le_bytes());
        output.push(self.domain as u8);
        output.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        output.extend_from_slice(&self.kdf.iterations.to_le_bytes());
        output.extend_from_slice(&self.kdf.parallelism.to_le_bytes());
        output.extend_from_slice(&self.salt);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&cipher_len.to_le_bytes());
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_LEN {
            return Err(VaultError::InvalidFormat("truncated vault"));
        }
        if bytes[..4] != MAGIC {
            return Err(VaultError::InvalidFormat("invalid vault magic"));
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let domain = VaultDomain::from_byte(bytes[6])?;

        let mut cursor = 7;
        let memory_kib = take_u32(bytes, &mut cursor)?;
        let iterations = take_u32(bytes, &mut cursor)?;
        let parallelism = take_u32(bytes, &mut cursor)?;
        let kdf = KdfParams {
            memory_kib,
            iterations,
            parallelism,
        };
        kdf.validate()?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(take(bytes, &mut cursor, SALT_LEN)?);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(take(bytes, &mut cursor, NONCE_LEN)?);

        let cipher_len = usize::try_from(take_u32(bytes, &mut cursor)?)
            .map_err(|_| VaultError::PayloadTooLarge)?;
        if cipher_len > MAX_CIPHERTEXT_LEN {
            return Err(VaultError::PayloadTooLarge);
        }
        if bytes.len() != cursor + cipher_len {
            return Err(VaultError::InvalidFormat("ciphertext length mismatch"));
        }

        Ok(Self {
            version,
            domain,
            kdf,
            salt,
            nonce,
            ciphertext: bytes[cursor..].to_vec(),
        })
    }

    fn aad(&self) -> Vec<u8> {
        make_aad(
            self.version,
            self.domain,
            self.kdf,
            &self.salt,
            &self.nonce,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    AuthenticationFailed,
    InvalidFormat(&'static str),
    UnsupportedVersion(u16),
    InvalidKdfParams,
    RandomnessUnavailable,
    PayloadTooLarge,
    CryptographicFailure,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(formatter, "vault authentication failed"),
            Self::InvalidFormat(message) => write!(formatter, "invalid vault format: {message}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported vault format version: {version}")
            }
            Self::InvalidKdfParams => write!(formatter, "invalid vault KDF parameters"),
            Self::RandomnessUnavailable => write!(formatter, "secure randomness unavailable"),
            Self::PayloadTooLarge => write!(formatter, "vault payload exceeds configured limit"),
            Self::CryptographicFailure => write!(formatter, "cryptographic operation failed"),
        }
    }
}

impl Error for VaultError {}

pub fn seal(
    password: &[u8],
    domain: VaultDomain,
    plaintext: &[u8],
    kdf: KdfParams,
) -> Result<VaultEnvelope, VaultError> {
    kdf.validate()?;
    if plaintext.len() > MAX_CIPHERTEXT_LEN.saturating_sub(16) {
        return Err(VaultError::PayloadTooLarge);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| VaultError::RandomnessUnavailable)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::RandomnessUnavailable)?;

    let mut key = derive_domain_key(password, &salt, kdf, domain)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| VaultError::CryptographicFailure)?;

    let aad = make_aad(FORMAT_VERSION, domain, kdf, &salt, &nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::CryptographicFailure)?;
    key.zeroize();

    Ok(VaultEnvelope {
        version: FORMAT_VERSION,
        domain,
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}

pub fn open(password: &[u8], envelope: &VaultEnvelope) -> Result<SecretBytes, VaultError> {
    if envelope.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(envelope.version));
    }
    envelope.kdf.validate()?;

    let mut key = derive_domain_key(password, &envelope.salt, envelope.kdf, envelope.domain)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| VaultError::CryptographicFailure)?;
    let aad = envelope.aad();
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed);
    key.zeroize();

    plaintext.map(SecretBytes::new)
}

fn derive_domain_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    kdf: KdfParams,
    domain: VaultDomain,
) -> Result<[u8; KEY_LEN], VaultError> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut master)
        .map_err(|_| VaultError::CryptographicFailure)?;

    let hkdf = Hkdf::<Sha256>::new(None, &master);
    let mut key = [0u8; KEY_LEN];
    let result = hkdf
        .expand(domain.hkdf_info(), &mut key)
        .map_err(|_| VaultError::CryptographicFailure);
    master.zeroize();
    result.map(|()| key)
}

fn make_aad(
    version: u16,
    domain: VaultDomain,
    kdf: KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN - 4);
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&version.to_le_bytes());
    aad.push(domain as u8);
    aad.extend_from_slice(&kdf.memory_kib.to_le_bytes());
    aad.extend_from_slice(&kdf.iterations.to_le_bytes());
    aad.extend_from_slice(&kdf.parallelism.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], VaultError> {
    let end = cursor
        .checked_add(len)
        .ok_or(VaultError::InvalidFormat("length overflow"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(VaultError::InvalidFormat("truncated vault"))?;
    *cursor = end;
    Ok(slice)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, VaultError> {
    let raw = take(bytes, cursor, 4)?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn round_trip_wallet_secret() {
        let envelope = seal(
            b"correct horse battery staple",
            VaultDomain::Wallet,
            b"synthetic phase-three secret",
            test_kdf(),
        )
        .unwrap();
        let opened = open(b"correct horse battery staple", &envelope).unwrap();
        assert_eq!(opened.as_slice(), b"synthetic phase-three secret");
    }

    #[test]
    fn wrong_password_fails_closed() {
        let envelope = seal(
            b"right password",
            VaultDomain::Wallet,
            b"secret",
            test_kdf(),
        )
        .unwrap();
        assert_eq!(
            open(b"wrong password", &envelope).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn ciphertext_tampering_is_detected() {
        let mut envelope = seal(
            b"password",
            VaultDomain::Wallet,
            b"secret",
            test_kdf(),
        )
        .unwrap();
        envelope.ciphertext[0] ^= 0x40;
        assert_eq!(
            open(b"password", &envelope).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn header_tampering_is_detected_by_aead() {
        let envelope = seal(
            b"password",
            VaultDomain::Wallet,
            b"secret",
            test_kdf(),
        )
        .unwrap();
        let mut encoded = envelope.encode().unwrap();
        encoded[7] ^= 0x01;
        let decoded = VaultEnvelope::decode(&encoded).unwrap();
        assert_eq!(
            open(b"password", &decoded).unwrap_err(),
            VaultError::AuthenticationFailed
        );
    }

    #[test]
    fn encryption_domains_produce_distinct_keys() {
        let salt = [7u8; SALT_LEN];
        let wallet =
            derive_domain_key(b"password", &salt, test_kdf(), VaultDomain::Wallet).unwrap();
        let integration =
            derive_domain_key(b"password", &salt, test_kdf(), VaultDomain::Integration).unwrap();
        assert_ne!(wallet, integration);
    }

    #[test]
    fn encoded_envelope_round_trips() {
        let envelope = seal(
            b"password",
            VaultDomain::Integration,
            b"provider secret placeholder",
            test_kdf(),
        )
        .unwrap();
        let encoded = envelope.encode().unwrap();
        let decoded = VaultEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.domain(), VaultDomain::Integration);
        assert_eq!(
            open(b"password", &decoded).unwrap().as_slice(),
            b"provider secret placeholder"
        );
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = SecretBytes::new(b"never-print-me".to_vec());
        let debug = format!("{secret:?}");
        assert!(!debug.contains("never-print-me"));
        assert!(debug.contains("redacted"));
    }
}
