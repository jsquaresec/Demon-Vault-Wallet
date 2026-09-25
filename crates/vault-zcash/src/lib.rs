#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{convert::Infallible, error::Error, fmt};
use zcash_address::{
    ConversionError, ToAddress, TryFromAddress, ZcashAddress, unified,
};
use zcash_protocol::{
    PoolType,
    consensus::NetworkType,
};

const MAX_ZAT: u64 = 2_100_000_000_000_000;
const MAX_FEE_ZAT: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZcashNetwork {
    Testnet,
    Regtest,
}

impl ZcashNetwork {
    pub const fn network_type(self) -> NetworkType {
        match self {
            Self::Testnet => NetworkType::Test,
            Self::Regtest => NetworkType::Regtest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientPrivacy {
    Transparent,
    Sapling,
    OrchardCapable,
    MultiShielded,
    ShieldedLegacy,
}

impl RecipientPrivacy {
    pub const fn is_shielded(self) -> bool {
        !matches!(self, Self::Transparent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyPolicy {
    ShieldedRequired,
    ShieldedPreferred,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRecipient {
    pub encoded: String,
    pub privacy: RecipientPrivacy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedNote {
    pub id: String,
    pub value_zat: u64,
    pub received_height: u64,
    pub spent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub txid: String,
    pub height: Option<u64>,
    pub amount_delta_zat: i128,
    pub shielded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletState {
    pub scanned_height: u64,
    pub chain_height: u64,
    pub notes: Vec<ShieldedNote>,
    pub history: Vec<HistoryEntry>,
}

impl WalletState {
    pub fn shielded_balance(&self) -> Result<u64, ZcashError> {
        self.notes
            .iter()
            .filter(|note| !note.spent && note.received_height <= self.chain_height)
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.value_zat)
                    .ok_or(ZcashError::ArithmeticOverflow)
            })
    }

    pub fn apply_snapshot(&mut self, snapshot: ShieldedSyncSnapshot) -> Result<(), ZcashError> {
        validate_snapshot(&snapshot)?;
        if snapshot.chain_height < self.chain_height
            && self.chain_height - snapshot.chain_height > 100
        {
            return Err(ZcashError::SuspiciousReorg);
        }
        self.scanned_height = snapshot.scanned_height;
        self.chain_height = snapshot.chain_height;
        self.notes = snapshot.notes;
        self.history = snapshot.history;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedSyncSnapshot {
    pub network: ZcashNetwork,
    pub scanned_height: u64,
    pub chain_height: u64,
    pub notes: Vec<ShieldedNote>,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlock {
    pub height: u64,
    pub encoded: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub total_zat: u64,
}

impl FeeEstimate {
    pub fn new(total_zat: u64) -> Result<Self, ZcashError> {
        if total_zat == 0 || total_zat > MAX_FEE_ZAT {
            return Err(ZcashError::InvalidFeeEstimate);
        }
        Ok(Self { total_zat })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendIntent {
    pub network: ZcashNetwork,
    pub recipient: ParsedRecipient,
    pub amount_zat: u64,
    pub fee: FeeEstimate,
    pub privacy_policy: PrivacyPolicy,
}

impl SpendIntent {
    pub fn new(
        network: ZcashNetwork,
        recipient: &str,
        amount_zat: u64,
        fee: FeeEstimate,
        privacy_policy: PrivacyPolicy,
    ) -> Result<Self, ZcashError> {
        if amount_zat == 0 || amount_zat > MAX_ZAT {
            return Err(ZcashError::InvalidAmount);
        }
        let recipient = parse_recipient(recipient, network)?;
        if privacy_policy == PrivacyPolicy::ShieldedRequired && !recipient.privacy.is_shielded() {
            return Err(ZcashError::TransparentRecipientRejected);
        }
        Ok(Self {
            network,
            recipient,
            amount_zat,
            fee,
            privacy_policy,
        })
    }

    pub fn authorization_binding(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"demon-vault/zcash/authorization/v1");
        hasher.update([match self.network {
            ZcashNetwork::Testnet => 1,
            ZcashNetwork::Regtest => 2,
        }]);
        hasher.update(self.recipient.encoded.as_bytes());
        hasher.update(self.amount_zat.to_le_bytes());
        hasher.update(self.fee.total_zat.to_le_bytes());
        hasher.update([match self.privacy_policy {
            PrivacyPolicy::ShieldedRequired => 1,
            PrivacyPolicy::ShieldedPreferred => 2,
        }]);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedZcashTransaction {
    pub raw_transaction: Vec<u8>,
}

pub trait ZcashBackend {
    type Error: Error + Send + Sync + 'static;

    fn network(&self) -> Result<ZcashNetwork, Self::Error>;
    fn health(&self) -> Result<bool, Self::Error>;
    fn tip_height(&self) -> Result<u64, Self::Error>;
    fn compact_blocks(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<CompactBlock>, Self::Error>;
    fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error>;
    fn broadcast(&self, transaction: &SignedZcashTransaction) -> Result<(), Self::Error>;
}

pub trait ZcashLocalScanner {
    type Error: Error + Send + Sync + 'static;

    fn scan(
        &self,
        network: ZcashNetwork,
        start_height: u64,
        end_height: u64,
        blocks: &[CompactBlock],
    ) -> Result<ShieldedSyncSnapshot, Self::Error>;
}

pub trait ZcashLocalSigner {
    type Error: Error + Send + Sync + 'static;

    fn sign(
        &self,
        intent: &SpendIntent,
        exact_authorization: [u8; 32],
    ) -> Result<SignedZcashTransaction, Self::Error>;
}

pub struct ZcashWallet {
    network: ZcashNetwork,
    privacy_policy: PrivacyPolicy,
    state: WalletState,
}

impl ZcashWallet {
    pub fn new(network: ZcashNetwork, privacy_policy: PrivacyPolicy) -> Self {
        Self {
            network,
            privacy_policy,
            state: WalletState::default(),
        }
    }

    pub fn network(&self) -> ZcashNetwork {
        self.network
    }

    pub fn privacy_policy(&self) -> PrivacyPolicy {
        self.privacy_policy
    }

    pub fn state(&self) -> &WalletState {
        &self.state
    }

    pub fn shielded_balance(&self) -> Result<u64, ZcashError> {
        self.state.shielded_balance()
    }

    pub fn history(&self) -> &[HistoryEntry] {
        &self.state.history
    }

    pub fn sync<B, S>(&mut self, backend: &B, scanner: &S) -> Result<(), ZcashError>
    where
        B: ZcashBackend,
        S: ZcashLocalScanner,
    {
        if !backend
            .health()
            .map_err(|_| ZcashError::BackendUnavailable)?
        {
            return Err(ZcashError::BackendUnhealthy);
        }

        let reported_network = backend
            .network()
            .map_err(|_| ZcashError::BackendUnavailable)?;
        validate_backend_network(self.network, reported_network)?;

        let tip = backend
            .tip_height()
            .map_err(|_| ZcashError::BackendUnavailable)?;
        let start_height = self.state.scanned_height.saturating_sub(20);
        let blocks = backend
            .compact_blocks(start_height, tip)
            .map_err(|_| ZcashError::BackendUnavailable)?;
        let snapshot = scanner
            .scan(self.network, start_height, tip, &blocks)
            .map_err(|_| ZcashError::ScanFailed)?;
        if snapshot.network != self.network {
            return Err(ZcashError::BackendNetworkMismatch);
        }
        self.state.apply_snapshot(snapshot)
    }

    pub fn prepare_spend<B: ZcashBackend>(
        &self,
        backend: &B,
        recipient: &str,
        amount_zat: u64,
    ) -> Result<SpendIntent, ZcashError> {
        let reported_network = backend
            .network()
            .map_err(|_| ZcashError::BackendUnavailable)?;
        validate_backend_network(self.network, reported_network)?;

        let fee = backend
            .fee_estimate()
            .map_err(|_| ZcashError::BackendUnavailable)?;
        let required = amount_zat
            .checked_add(fee.total_zat)
            .ok_or(ZcashError::ArithmeticOverflow)?;
        if required > self.shielded_balance()? {
            return Err(ZcashError::InsufficientFunds);
        }
        SpendIntent::new(
            self.network,
            recipient,
            amount_zat,
            fee,
            self.privacy_policy,
        )
    }

    pub fn sign_and_broadcast<B, S>(
        &self,
        backend: &B,
        signer: &S,
        intent: &SpendIntent,
    ) -> Result<SignedZcashTransaction, ZcashError>
    where
        B: ZcashBackend,
        S: ZcashLocalSigner,
    {
        validate_backend_network(self.network, intent.network)?;
        let reported_network = backend
            .network()
            .map_err(|_| ZcashError::BackendUnavailable)?;
        validate_backend_network(self.network, reported_network)?;

        let authorization = intent.authorization_binding();
        let signed = signer
            .sign(intent, authorization)
            .map_err(|_| ZcashError::SigningFailed)?;
        validate_authorized_signed_transaction(intent, authorization, &signed)?;
        backend
            .broadcast(&signed)
            .map_err(|_| ZcashError::BackendUnavailable)?;
        Ok(signed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZcashError {
    InvalidAddress,
    WrongNetwork,
    TransparentRecipientRejected,
    InvalidAmount,
    InvalidFeeEstimate,
    InvalidSyncHeight,
    DuplicateNote,
    ArithmeticOverflow,
    SuspiciousReorg,
    BackendNetworkMismatch,
    BackendUnavailable,
    BackendUnhealthy,
    ScanFailed,
    SigningFailed,
    AuthorizationMismatch,
    EmptySignedTransaction,
    InsufficientFunds,
}

impl fmt::Display for ZcashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => write!(formatter, "invalid Zcash address"),
            Self::WrongNetwork => write!(formatter, "Zcash address is for the wrong network"),
            Self::TransparentRecipientRejected => {
                write!(formatter, "transparent Zcash recipient rejected by shielded-only policy")
            }
            Self::InvalidAmount => write!(formatter, "invalid Zcash amount"),
            Self::InvalidFeeEstimate => write!(formatter, "invalid Zcash fee estimate"),
            Self::InvalidSyncHeight => write!(formatter, "invalid Zcash synchronization heights"),
            Self::DuplicateNote => write!(formatter, "duplicate Zcash shielded note"),
            Self::ArithmeticOverflow => write!(formatter, "Zcash amount arithmetic overflow"),
            Self::SuspiciousReorg => write!(formatter, "suspiciously deep Zcash reorganization"),
            Self::BackendNetworkMismatch => write!(formatter, "Zcash backend reported the wrong network"),
            Self::BackendUnavailable => write!(formatter, "Zcash backend is unavailable"),
            Self::BackendUnhealthy => write!(formatter, "Zcash backend reported unhealthy status"),
            Self::ScanFailed => write!(formatter, "local Zcash shielded scanning failed"),
            Self::SigningFailed => write!(formatter, "local Zcash signing failed"),
            Self::AuthorizationMismatch => write!(formatter, "Zcash signing authorization mismatch"),
            Self::EmptySignedTransaction => write!(formatter, "Zcash signer returned an empty transaction"),
            Self::InsufficientFunds => write!(formatter, "insufficient shielded Zcash balance"),
        }
    }
}

impl Error for ZcashError {}

pub fn parse_recipient(
    encoded: &str,
    network: ZcashNetwork,
) -> Result<ParsedRecipient, ZcashError> {
    let address =
        ZcashAddress::try_from_encoded(encoded).map_err(|_| ZcashError::InvalidAddress)?;

    address
        .clone()
        .convert_if_network::<NetworkValidated>(network.network_type())
        .map_err(|_| ZcashError::WrongNetwork)?;

    let privacy = if address.is_transparent_only() {
        RecipientPrivacy::Transparent
    } else {
        let sapling = address.can_receive_as(PoolType::SAPLING);
        let orchard = address.can_receive_as(PoolType::ORCHARD);
        match (sapling, orchard) {
            (true, true) => RecipientPrivacy::MultiShielded,
            (true, false) => RecipientPrivacy::Sapling,
            (false, true) => RecipientPrivacy::OrchardCapable,
            (false, false) => RecipientPrivacy::ShieldedLegacy,
        }
    };

    Ok(ParsedRecipient {
        encoded: address.encode(),
        privacy,
    })
}

pub fn validate_backend_network(
    expected: ZcashNetwork,
    reported: ZcashNetwork,
) -> Result<(), ZcashError> {
    if expected != reported {
        return Err(ZcashError::BackendNetworkMismatch);
    }
    Ok(())
}

pub fn validate_authorized_signed_transaction(
    intent: &SpendIntent,
    authorization: [u8; 32],
    signed: &SignedZcashTransaction,
) -> Result<(), ZcashError> {
    if intent.authorization_binding() != authorization {
        return Err(ZcashError::AuthorizationMismatch);
    }
    if signed.raw_transaction.is_empty() {
        return Err(ZcashError::EmptySignedTransaction);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &ShieldedSyncSnapshot) -> Result<(), ZcashError> {
    if snapshot.scanned_height > snapshot.chain_height {
        return Err(ZcashError::InvalidSyncHeight);
    }

    let mut ids = std::collections::BTreeSet::new();
    for note in &snapshot.notes {
        if note.received_height > snapshot.chain_height {
            return Err(ZcashError::InvalidSyncHeight);
        }
        if note.value_zat > MAX_ZAT {
            return Err(ZcashError::InvalidAmount);
        }
        if !ids.insert(note.id.as_str()) {
            return Err(ZcashError::DuplicateNote);
        }
    }
    Ok(())
}

struct NetworkValidated;

impl TryFromAddress for NetworkValidated {
    type Error = Infallible;

    fn try_from_sprout(
        _net: NetworkType,
        _data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_sapling(
        _net: NetworkType,
        _data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_unified(
        _net: NetworkType,
        _data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }

    fn try_from_tex(
        _net: NetworkType,
        _data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn sapling_address(network: ZcashNetwork) -> String {
        ZcashAddress::from_sapling(network.network_type(), [7u8; 43]).encode()
    }

    fn transparent_address(network: ZcashNetwork) -> String {
        ZcashAddress::from_transparent_p2pkh(network.network_type(), [3u8; 20]).encode()
    }

    #[test]
    fn sapling_recipient_is_classified_as_shielded() {
        let encoded = sapling_address(ZcashNetwork::Testnet);
        let parsed = parse_recipient(&encoded, ZcashNetwork::Testnet).unwrap();
        assert_eq!(parsed.privacy, RecipientPrivacy::Sapling);
        assert!(parsed.privacy.is_shielded());
    }

    #[test]
    fn transparent_recipient_is_not_misrepresented_as_private() {
        let encoded = transparent_address(ZcashNetwork::Testnet);
        let parsed = parse_recipient(&encoded, ZcashNetwork::Testnet).unwrap();
        assert_eq!(parsed.privacy, RecipientPrivacy::Transparent);
        assert!(!parsed.privacy.is_shielded());
    }

    #[test]
    fn wrong_network_is_rejected() {
        let encoded = ZcashAddress::from_sapling(NetworkType::Main, [9u8; 43]).encode();
        assert_eq!(
            parse_recipient(&encoded, ZcashNetwork::Testnet).unwrap_err(),
            ZcashError::WrongNetwork
        );
    }

    #[test]
    fn shielded_required_policy_rejects_transparent_recipient() {
        let encoded = transparent_address(ZcashNetwork::Testnet);
        assert_eq!(
            SpendIntent::new(
                ZcashNetwork::Testnet,
                &encoded,
                100_000,
                FeeEstimate::new(10_000).unwrap(),
                PrivacyPolicy::ShieldedRequired,
            )
            .unwrap_err(),
            ZcashError::TransparentRecipientRejected
        );
    }

    #[test]
    fn wallet_state_rejects_duplicates_and_invalid_heights() {
        let duplicate = ShieldedNote {
            id: "note-1".into(),
            value_zat: 50_000,
            received_height: 10,
            spent: false,
        };
        let mut state = WalletState::default();
        assert_eq!(
            state
                .apply_snapshot(ShieldedSyncSnapshot {
                    network: ZcashNetwork::Testnet,
                    scanned_height: 10,
                    chain_height: 10,
                    notes: vec![duplicate.clone(), duplicate],
                    history: vec![],
                })
                .unwrap_err(),
            ZcashError::DuplicateNote
        );
        assert_eq!(
            state
                .apply_snapshot(ShieldedSyncSnapshot {
                    network: ZcashNetwork::Testnet,
                    scanned_height: 11,
                    chain_height: 10,
                    notes: vec![],
                    history: vec![],
                })
                .unwrap_err(),
            ZcashError::InvalidSyncHeight
        );
    }

    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock error")
        }
    }

    impl Error for MockError {}

    struct MockBackend {
        network: ZcashNetwork,
        healthy: bool,
        broadcast_count: Cell<u32>,
    }

    impl ZcashBackend for MockBackend {
        type Error = MockError;

        fn network(&self) -> Result<ZcashNetwork, Self::Error> {
            Ok(self.network)
        }

        fn health(&self) -> Result<bool, Self::Error> {
            Ok(self.healthy)
        }

        fn tip_height(&self) -> Result<u64, Self::Error> {
            Ok(100)
        }

        fn compact_blocks(
            &self,
            start_height: u64,
            end_height: u64,
        ) -> Result<Vec<CompactBlock>, Self::Error> {
            Ok((start_height..=end_height)
                .map(|height| CompactBlock {
                    height,
                    encoded: vec![1, 2, 3],
                })
                .collect())
        }

        fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error> {
            Ok(FeeEstimate::new(10_000).unwrap())
        }

        fn broadcast(&self, _transaction: &SignedZcashTransaction) -> Result<(), Self::Error> {
            self.broadcast_count.set(self.broadcast_count.get() + 1);
            Ok(())
        }
    }

    struct MockScanner;

    impl ZcashLocalScanner for MockScanner {
        type Error = MockError;

        fn scan(
            &self,
            network: ZcashNetwork,
            _start_height: u64,
            end_height: u64,
            _blocks: &[CompactBlock],
        ) -> Result<ShieldedSyncSnapshot, Self::Error> {
            Ok(ShieldedSyncSnapshot {
                network,
                scanned_height: end_height,
                chain_height: end_height,
                notes: vec![ShieldedNote {
                    id: "note-a".into(),
                    value_zat: 500_000,
                    received_height: end_height,
                    spent: false,
                }],
                history: vec![],
            })
        }
    }

    struct MockSigner {
        empty: bool,
    }

    impl ZcashLocalSigner for MockSigner {
        type Error = MockError;

        fn sign(
            &self,
            _intent: &SpendIntent,
            _exact_authorization: [u8; 32],
        ) -> Result<SignedZcashTransaction, Self::Error> {
            Ok(SignedZcashTransaction {
                raw_transaction: if self.empty { vec![] } else { vec![4, 5, 6] },
            })
        }
    }

    #[test]
    fn shielded_sync_is_local_and_backend_network_is_validated() {
        let mut wallet =
            ZcashWallet::new(ZcashNetwork::Testnet, PrivacyPolicy::ShieldedRequired);
        let backend = MockBackend {
            network: ZcashNetwork::Testnet,
            healthy: true,
            broadcast_count: Cell::new(0),
        };
        wallet.sync(&backend, &MockScanner).unwrap();
        assert_eq!(wallet.state().scanned_height, 100);
        assert_eq!(wallet.shielded_balance().unwrap(), 500_000);

        let wrong = MockBackend {
            network: ZcashNetwork::Regtest,
            healthy: true,
            broadcast_count: Cell::new(0),
        };
        assert_eq!(
            wallet.sync(&wrong, &MockScanner).unwrap_err(),
            ZcashError::BackendNetworkMismatch
        );
    }

    #[test]
    fn signing_requires_exact_authorization_before_broadcast() {
        let mut wallet =
            ZcashWallet::new(ZcashNetwork::Testnet, PrivacyPolicy::ShieldedRequired);
        let backend = MockBackend {
            network: ZcashNetwork::Testnet,
            healthy: true,
            broadcast_count: Cell::new(0),
        };
        wallet.sync(&backend, &MockScanner).unwrap();

        let recipient = sapling_address(ZcashNetwork::Testnet);
        let intent = wallet.prepare_spend(&backend, &recipient, 100_000).unwrap();

        assert_eq!(
            wallet
                .sign_and_broadcast(&backend, &MockSigner { empty: true }, &intent)
                .unwrap_err(),
            ZcashError::EmptySignedTransaction
        );
        assert_eq!(backend.broadcast_count.get(), 0);

        wallet
            .sign_and_broadcast(&backend, &MockSigner { empty: false }, &intent)
            .unwrap();
        assert_eq!(backend.broadcast_count.get(), 1);
    }

    #[test]
    fn authorization_binding_detects_intent_changes() {
        let recipient = sapling_address(ZcashNetwork::Testnet);
        let first = SpendIntent::new(
            ZcashNetwork::Testnet,
            &recipient,
            100_000,
            FeeEstimate::new(10_000).unwrap(),
            PrivacyPolicy::ShieldedRequired,
        )
        .unwrap();
        let second = SpendIntent::new(
            ZcashNetwork::Testnet,
            &recipient,
            100_001,
            FeeEstimate::new(10_000).unwrap(),
            PrivacyPolicy::ShieldedRequired,
        )
        .unwrap();
        assert_ne!(first.authorization_binding(), second.authorization_binding());
    }
}
