#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const MAGIC: &[u8; 4] = b"DVSG";
const VERSION: u16 = 1;
const MAX_NETWORK_LEN: usize = 32;
const MAX_TRANSACTION_BYTES: usize = 1024 * 1024;
const MAX_DEVICE_FIELD_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigningAsset {
    Bitcoin = 1,
    Monero = 2,
    Zcash = 3,
}

impl SigningAsset {
    fn from_byte(value: u8) -> Result<Self, SigningError> {
        match value {
            1 => Ok(Self::Bitcoin),
            2 => Ok(Self::Monero),
            3 => Ok(Self::Zcash),
            _ => Err(SigningError::InvalidPackage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigningMode {
    Hardware = 1,
    Offline = 2,
}

impl SigningMode {
    fn from_byte(value: u8) -> Result<Self, SigningError> {
        match value {
            1 => Ok(Self::Hardware),
            2 => Ok(Self::Offline),
            _ => Err(SigningError::InvalidPackage),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SigningRequest {
    pub asset: SigningAsset,
    pub mode: SigningMode,
    network: String,
    unsigned_transaction: Vec<u8>,
    authorization: [u8; 32],
    expires_at_unix: u64,
}

impl fmt::Debug for SigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningRequest")
            .field("asset", &self.asset)
            .field("mode", &self.mode)
            .field("network", &self.network)
            .field("unsigned_transaction", &"<redacted>")
            .field("authorization", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl SigningRequest {
    pub fn new(
        asset: SigningAsset,
        mode: SigningMode,
        network: &str,
        unsigned_transaction: Vec<u8>,
        authorization: [u8; 32],
        expires_at_unix: u64,
    ) -> Result<Self, SigningError> {
        validate_network(network)?;
        if unsigned_transaction.is_empty() || unsigned_transaction.len() > MAX_TRANSACTION_BYTES {
            return Err(SigningError::InvalidTransaction);
        }
        if authorization.iter().all(|byte| *byte == 0) {
            return Err(SigningError::InvalidAuthorization);
        }
        if expires_at_unix == 0 {
            return Err(SigningError::InvalidExpiry);
        }
        Ok(Self {
            asset,
            mode,
            network: network.to_owned(),
            unsigned_transaction,
            authorization,
            expires_at_unix,
        })
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn unsigned_transaction(&self) -> &[u8] {
        &self.unsigned_transaction
    }

    pub const fn authorization(&self) -> [u8; 32] {
        self.authorization
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn binding(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"demon-vault/external-signing/v1");
        hasher.update([self.asset as u8, self.mode as u8]);
        hasher.update((self.network.len() as u32).to_le_bytes());
        hasher.update(self.network.as_bytes());
        hasher.update((self.unsigned_transaction.len() as u64).to_le_bytes());
        hasher.update(&self.unsigned_transaction);
        hasher.update(self.authorization);
        hasher.update(self.expires_at_unix.to_le_bytes());
        hasher.finalize().into()
    }

    pub fn ensure_fresh(&self, now_unix: u64) -> Result<(), SigningError> {
        if now_unix >= self.expires_at_unix {
            return Err(SigningError::ExpiredRequest);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    pub request_binding: [u8; 32],
    signed_transaction: Vec<u8>,
}

impl fmt::Debug for SignedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTransaction")
            .field("request_binding", &"<redacted>")
            .field("signed_transaction", &"<redacted>")
            .finish()
    }
}

impl SignedTransaction {
    pub fn new(
        request_binding: [u8; 32],
        signed_transaction: Vec<u8>,
    ) -> Result<Self, SigningError> {
        if request_binding.iter().all(|byte| *byte == 0) {
            return Err(SigningError::BindingMismatch);
        }
        if signed_transaction.is_empty() || signed_transaction.len() > MAX_TRANSACTION_BYTES {
            return Err(SigningError::InvalidTransaction);
        }
        Ok(Self {
            request_binding,
            signed_transaction,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.signed_transaction
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareDeviceInfo {
    pub vendor: String,
    pub model: String,
    pub device_id: String,
}

impl HardwareDeviceInfo {
    pub fn new(vendor: &str, model: &str, device_id: &str) -> Result<Self, SigningError> {
        for field in [vendor, model, device_id] {
            if field.is_empty()
                || field.len() > MAX_DEVICE_FIELD_LEN
                || field.chars().any(char::is_control)
            {
                return Err(SigningError::InvalidDeviceInfo);
            }
        }
        Ok(Self {
            vendor: vendor.to_owned(),
            model: model.to_owned(),
            device_id: device_id.to_owned(),
        })
    }
}

pub trait HardwareSigner {
    type Error: Error + Send + Sync + 'static;

    fn device_info(&self) -> Result<HardwareDeviceInfo, Self::Error>;
    fn sign(&self, request: &SigningRequest) -> Result<SignedTransaction, Self::Error>;
}

pub fn sign_with_hardware<S: HardwareSigner>(
    signer: &S,
    request: &SigningRequest,
    now_unix: u64,
) -> Result<SignedTransaction, SigningError> {
    if request.mode != SigningMode::Hardware {
        return Err(SigningError::WrongSigningMode);
    }
    request.ensure_fresh(now_unix)?;
    signer
        .device_info()
        .map_err(|_| SigningError::SignerUnavailable)?;
    let signed = signer
        .sign(request)
        .map_err(|_| SigningError::SigningFailed)?;
    validate_signed_transaction(request, &signed)?;
    Ok(signed)
}

pub fn validate_signed_transaction(
    request: &SigningRequest,
    signed: &SignedTransaction,
) -> Result<(), SigningError> {
    if signed.request_binding != request.binding() {
        return Err(SigningError::BindingMismatch);
    }
    if signed.bytes().is_empty() || signed.bytes().len() > MAX_TRANSACTION_BYTES {
        return Err(SigningError::InvalidTransaction);
    }
    Ok(())
}

pub fn export_offline_request(request: &SigningRequest) -> Result<Vec<u8>, SigningError> {
    if request.mode != SigningMode::Offline {
        return Err(SigningError::WrongSigningMode);
    }
    let network_len =
        u16::try_from(request.network.len()).map_err(|_| SigningError::InvalidPackage)?;
    let tx_len =
        u32::try_from(request.unsigned_transaction.len()).map_err(|_| SigningError::InvalidPackage)?;
    let mut output = Vec::with_capacity(64 + request.network.len() + request.unsigned_transaction.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.push(request.asset as u8);
    output.push(request.mode as u8);
    output.extend_from_slice(&network_len.to_le_bytes());
    output.extend_from_slice(request.network.as_bytes());
    output.extend_from_slice(&tx_len.to_le_bytes());
    output.extend_from_slice(&request.unsigned_transaction);
    output.extend_from_slice(&request.authorization);
    output.extend_from_slice(&request.expires_at_unix.to_le_bytes());
    output.extend_from_slice(&request.binding());
    Ok(output)
}

pub fn import_offline_request(bytes: &[u8]) -> Result<SigningRequest, SigningError> {
    let mut cursor = 0usize;
    if take(bytes, &mut cursor, 4)? != MAGIC {
        return Err(SigningError::InvalidPackage);
    }
    let version = u16::from_le_bytes(take_array::<2>(bytes, &mut cursor)?);
    if version != VERSION {
        return Err(SigningError::UnsupportedVersion);
    }
    let asset = SigningAsset::from_byte(take(bytes, &mut cursor, 1)?[0])?;
    let mode = SigningMode::from_byte(take(bytes, &mut cursor, 1)?[0])?;
    if mode != SigningMode::Offline {
        return Err(SigningError::WrongSigningMode);
    }
    let network_len = u16::from_le_bytes(take_array::<2>(bytes, &mut cursor)?) as usize;
    let network = std::str::from_utf8(take(bytes, &mut cursor, network_len)?)
        .map_err(|_| SigningError::InvalidPackage)?;
    let tx_len = u32::from_le_bytes(take_array::<4>(bytes, &mut cursor)?) as usize;
    if tx_len == 0 || tx_len > MAX_TRANSACTION_BYTES {
        return Err(SigningError::InvalidTransaction);
    }
    let transaction = take(bytes, &mut cursor, tx_len)?.to_vec();
    let authorization = take_array::<32>(bytes, &mut cursor)?;
    let expires_at_unix = u64::from_le_bytes(take_array::<8>(bytes, &mut cursor)?);
    let expected_binding = take_array::<32>(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(SigningError::InvalidPackage);
    }
    let request = SigningRequest::new(
        asset,
        mode,
        network,
        transaction,
        authorization,
        expires_at_unix,
    )?;
    if request.binding() != expected_binding {
        return Err(SigningError::BindingMismatch);
    }
    Ok(request)
}

pub fn export_offline_signature(
    signed: &SignedTransaction,
) -> Result<Vec<u8>, SigningError> {
    let tx_len =
        u32::try_from(signed.signed_transaction.len()).map_err(|_| SigningError::InvalidPackage)?;
    let mut output = Vec::with_capacity(42 + signed.signed_transaction.len());
    output.extend_from_slice(b"DVSR");
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&signed.request_binding);
    output.extend_from_slice(&tx_len.to_le_bytes());
    output.extend_from_slice(&signed.signed_transaction);
    Ok(output)
}

pub fn import_offline_signature(bytes: &[u8]) -> Result<SignedTransaction, SigningError> {
    let mut cursor = 0usize;
    if take(bytes, &mut cursor, 4)? != b"DVSR" {
        return Err(SigningError::InvalidPackage);
    }
    let version = u16::from_le_bytes(take_array::<2>(bytes, &mut cursor)?);
    if version != VERSION {
        return Err(SigningError::UnsupportedVersion);
    }
    let request_binding = take_array::<32>(bytes, &mut cursor)?;
    let tx_len = u32::from_le_bytes(take_array::<4>(bytes, &mut cursor)?) as usize;
    if tx_len == 0 || tx_len > MAX_TRANSACTION_BYTES {
        return Err(SigningError::InvalidTransaction);
    }
    let signed_transaction = take(bytes, &mut cursor, tx_len)?.to_vec();
    if cursor != bytes.len() {
        return Err(SigningError::InvalidPackage);
    }
    SignedTransaction::new(request_binding, signed_transaction)
}

fn validate_network(network: &str) -> Result<(), SigningError> {
    if network.is_empty()
        || network.len() > MAX_NETWORK_LEN
        || !network
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SigningError::InvalidNetwork);
    }
    Ok(())
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], SigningError> {
    let end = cursor.checked_add(len).ok_or(SigningError::InvalidPackage)?;
    let value = bytes.get(*cursor..end).ok_or(SigningError::InvalidPackage)?;
    *cursor = end;
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], SigningError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| SigningError::InvalidPackage)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    InvalidNetwork,
    InvalidTransaction,
    InvalidAuthorization,
    InvalidExpiry,
    ExpiredRequest,
    InvalidDeviceInfo,
    WrongSigningMode,
    BindingMismatch,
    InvalidPackage,
    UnsupportedVersion,
    SignerUnavailable,
    SigningFailed,
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNetwork => write!(formatter, "invalid signing network"),
            Self::InvalidTransaction => write!(formatter, "invalid signing transaction"),
            Self::InvalidAuthorization => write!(formatter, "invalid signing authorization"),
            Self::InvalidExpiry => write!(formatter, "invalid signing request expiry"),
            Self::ExpiredRequest => write!(formatter, "signing request has expired"),
            Self::InvalidDeviceInfo => write!(formatter, "invalid hardware signer information"),
            Self::WrongSigningMode => write!(formatter, "wrong external signing mode"),
            Self::BindingMismatch => write!(formatter, "signed transaction does not match request"),
            Self::InvalidPackage => write!(formatter, "invalid offline signing package"),
            Self::UnsupportedVersion => write!(formatter, "unsupported signing package version"),
            Self::SignerUnavailable => write!(formatter, "hardware signer is unavailable"),
            Self::SigningFailed => write!(formatter, "external signing failed"),
        }
    }
}

impl Error for SigningError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_request() -> SigningRequest {
        SigningRequest::new(
            SigningAsset::Bitcoin,
            SigningMode::Offline,
            "testnet",
            vec![1, 2, 3, 4],
            [7u8; 32],
            2_000,
        )
        .unwrap()
    }

    #[test]
    fn offline_request_round_trips_and_detects_tampering() {
        let request = offline_request();
        let encoded = export_offline_request(&request).unwrap();
        assert_eq!(import_offline_request(&encoded).unwrap(), request);

        let mut tampered = encoded;
        tampered[15] ^= 1;
        assert!(import_offline_request(&tampered).is_err());
    }

    #[test]
    fn expired_requests_fail_closed() {
        let request = offline_request();
        assert!(request.ensure_fresh(1_999).is_ok());
        assert_eq!(
            request.ensure_fresh(2_000).unwrap_err(),
            SigningError::ExpiredRequest
        );
    }

    #[test]
    fn debug_output_redacts_transaction_and_authorization() {
        let request = offline_request();
        let debug = format!("{request:?}");
        assert!(!debug.contains("[1, 2, 3, 4]"));
        assert!(!debug.contains("[7, 7"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn offline_signature_must_match_exact_request() {
        let request = offline_request();
        let signed = SignedTransaction::new(request.binding(), vec![9, 8, 7]).unwrap();
        assert!(validate_signed_transaction(&request, &signed).is_ok());

        let wrong = SignedTransaction::new([3u8; 32], vec![9, 8, 7]).unwrap();
        assert_eq!(
            validate_signed_transaction(&request, &wrong).unwrap_err(),
            SigningError::BindingMismatch
        );
    }

    #[test]
    fn signature_package_round_trips_without_private_material() {
        let request = offline_request();
        let signed = SignedTransaction::new(request.binding(), vec![9, 8, 7]).unwrap();
        let encoded = export_offline_signature(&signed).unwrap();
        let decoded = import_offline_signature(&encoded).unwrap();
        assert_eq!(decoded, signed);
    }

    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock signer error")
        }
    }

    impl Error for MockError {}

    struct MockHardware;

    impl HardwareSigner for MockHardware {
        type Error = MockError;

        fn device_info(&self) -> Result<HardwareDeviceInfo, Self::Error> {
            Ok(HardwareDeviceInfo::new("Mock", "Device", "unit-test").unwrap())
        }

        fn sign(&self, request: &SigningRequest) -> Result<SignedTransaction, Self::Error> {
            Ok(SignedTransaction::new(request.binding(), vec![5, 4, 3]).unwrap())
        }
    }

    #[test]
    fn hardware_signer_receives_only_bounded_request_and_exact_binding_is_verified() {
        let request = SigningRequest::new(
            SigningAsset::Zcash,
            SigningMode::Hardware,
            "testnet",
            vec![1, 2, 3],
            [8u8; 32],
            5_000,
        )
        .unwrap();
        let signed = sign_with_hardware(&MockHardware, &request, 4_000).unwrap();
        assert_eq!(signed.request_binding, request.binding());
    }

    #[test]
    fn hardware_signing_rejects_offline_mode() {
        assert_eq!(
            sign_with_hardware(&MockHardware, &offline_request(), 1_000).unwrap_err(),
            SigningError::WrongSigningMode
        );
    }
}
