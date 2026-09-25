#![forbid(unsafe_code)]

use monero::{
    Address, Hash, KeyPair, Network, PrivateKey, PublicKey, Transaction, ViewPair,
    consensus::deserialize, cryptonote::hash::Hashable,
};
use std::{error::Error, fmt, str::FromStr};

const MIN_FEE_PER_BYTE: u64 = 1;
const MAX_FEE_PER_BYTE: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneroNetwork {
    Mainnet,
    Stagenet,
    Testnet,
}

impl MoneroNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Stagenet => Network::Stagenet,
            Self::Testnet => Network::Testnet,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeMode {
    AutomaticRemote,
    CustomRemote(String),
    LocalNode(String),
}

impl Default for NodeMode {
    fn default() -> Self {
        Self::AutomaticRemote
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCandidate {
    pub endpoint: String,
    pub network: MoneroNetwork,
    pub healthy: bool,
    pub height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSelection {
    pub mode: NodeMode,
    pub endpoint: String,
    pub network: MoneroNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletIdentity {
    network: MoneroNetwork,
    private_spend: PrivateKey,
    private_view: PrivateKey,
    address: Address,
}

impl fmt::Debug for WalletIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletIdentity")
            .field("network", &self.network)
            .field("address", &self.address.to_string())
            .field("private_keys", &"<redacted>")
            .finish()
    }
}

impl WalletIdentity {
    pub fn from_seed(seed: &[u8], network: MoneroNetwork) -> Result<Self, MoneroError> {
        if seed.len() < 32 {
            return Err(MoneroError::InvalidSeed);
        }

        let private_spend = derive_scalar(b"demon-vault/monero/spend", seed)?;
        let private_view = derive_scalar(b"demon-vault/monero/view", private_spend.as_bytes())?;
        Self::from_private_keys(private_spend, private_view, network)
    }

    pub fn from_private_keys(
        private_spend: PrivateKey,
        private_view: PrivateKey,
        network: MoneroNetwork,
    ) -> Result<Self, MoneroError> {
        if private_spend.as_bytes().iter().all(|byte| *byte == 0)
            || private_view.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(MoneroError::InvalidPrivateKey);
        }

        let keys = KeyPair {
            view: private_view,
            spend: private_spend,
        };
        let address = Address::from_keypair(network.network(), &keys);
        Ok(Self {
            network,
            private_spend,
            private_view,
            address,
        })
    }

    pub fn network(&self) -> MoneroNetwork {
        self.network
    }

    pub fn address(&self) -> String {
        self.address.to_string()
    }

    pub fn private_spend_key(&self) -> &PrivateKey {
        &self.private_spend
    }

    pub fn private_view_key(&self) -> &PrivateKey {
        &self.private_view
    }

    pub fn public_spend_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_spend)
    }

    pub fn public_view_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_view)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletOutput {
    pub id: String,
    pub amount_piconero: u64,
    pub unlock_height: u64,
    pub spent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub txid: String,
    pub height: Option<u64>,
    pub amount_delta_piconero: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletState {
    pub scanned_height: u64,
    pub chain_height: u64,
    pub outputs: Vec<WalletOutput>,
    pub history: Vec<HistoryEntry>,
}

impl WalletState {
    pub fn unlocked_balance(&self) -> Result<u64, MoneroError> {
        self.outputs
            .iter()
            .filter(|output| !output.spent && output.unlock_height <= self.chain_height)
            .try_fold(0u64, |sum, output| {
                sum.checked_add(output.amount_piconero)
                    .ok_or(MoneroError::ArithmeticOverflow)
            })
    }

    pub fn apply_snapshot(&mut self, snapshot: SyncSnapshot) -> Result<(), MoneroError> {
        validate_snapshot(&snapshot)?;
        if snapshot.chain_height < self.chain_height
            && self.chain_height - snapshot.chain_height > 100
        {
            return Err(MoneroError::SuspiciousReorg);
        }
        self.scanned_height = snapshot.scanned_height;
        self.chain_height = snapshot.chain_height;
        self.outputs = snapshot.outputs;
        self.history = snapshot.history;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSnapshot {
    pub network: MoneroNetwork,
    pub scanned_height: u64,
    pub chain_height: u64,
    pub outputs: Vec<WalletOutput>,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub atomic_units_per_byte: u64,
}

impl FeeEstimate {
    pub fn new(atomic_units_per_byte: u64) -> Result<Self, MoneroError> {
        if !(MIN_FEE_PER_BYTE..=MAX_FEE_PER_BYTE).contains(&atomic_units_per_byte) {
            return Err(MoneroError::InvalidFeeEstimate);
        }
        Ok(Self {
            atomic_units_per_byte,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendIntent {
    pub network: MoneroNetwork,
    pub destination: String,
    pub amount_piconero: u64,
    pub fee: FeeEstimate,
}

impl SpendIntent {
    pub fn new(
        network: MoneroNetwork,
        destination: &str,
        amount_piconero: u64,
        fee: FeeEstimate,
    ) -> Result<Self, MoneroError> {
        if amount_piconero == 0 {
            return Err(MoneroError::AmountTooSmall);
        }
        parse_address(destination, network)?;
        Ok(Self {
            network,
            destination: destination.to_owned(),
            amount_piconero,
            fee,
        })
    }

    pub fn authorization_binding(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.destination.len() + 40);
        data.extend_from_slice(b"demon-vault/monero/authorization/v1");
        data.push(match self.network {
            MoneroNetwork::Mainnet => 0,
            MoneroNetwork::Stagenet => 1,
            MoneroNetwork::Testnet => 2,
        });
        data.extend_from_slice(self.destination.as_bytes());
        data.extend_from_slice(&self.amount_piconero.to_le_bytes());
        data.extend_from_slice(&self.fee.atomic_units_per_byte.to_le_bytes());
        Hash::new(data).to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMoneroTransaction {
    pub raw_transaction: Vec<u8>,
}

pub trait MoneroLocalSigner {
    type Error: Error + Send + Sync + 'static;

    fn sign(
        &self,
        identity: &WalletIdentity,
        intent: &SpendIntent,
        exact_authorization: [u8; 32],
    ) -> Result<SignedMoneroTransaction, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTransaction {
    pub height: u64,
    pub raw_transaction: Vec<u8>,
}

pub trait MoneroBackend {
    type Error: Error + Send + Sync + 'static;

    fn network(&self) -> Result<MoneroNetwork, Self::Error>;
    fn health(&self) -> Result<bool, Self::Error>;
    fn tip_height(&self) -> Result<u64, Self::Error>;
    fn transactions(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<ChainTransaction>, Self::Error>;
    fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error>;
    fn broadcast(&self, transaction: &SignedMoneroTransaction) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoneroError {
    InvalidSeed,
    InvalidPrivateKey,
    InvalidAddress,
    WrongNetwork,
    InvalidNodeEndpoint,
    NoHealthyRemoteNode,
    BackendNetworkMismatch,
    InvalidFeeEstimate,
    AmountTooSmall,
    DuplicateOutput,
    InvalidSyncHeight,
    SuspiciousReorg,
    ArithmeticOverflow,
    AuthorizationMismatch,
    EmptySignedTransaction,
    MalformedTransaction,
    UndecodableAmount,
}

impl fmt::Display for MoneroError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeed => write!(formatter, "Monero seed material is invalid"),
            Self::InvalidPrivateKey => write!(formatter, "Monero private key is invalid"),
            Self::InvalidAddress => write!(formatter, "invalid Monero address"),
            Self::WrongNetwork => write!(formatter, "Monero address is for the wrong network"),
            Self::InvalidNodeEndpoint => write!(formatter, "invalid Monero node endpoint"),
            Self::NoHealthyRemoteNode => {
                write!(formatter, "no healthy Monero remote node is available")
            }
            Self::BackendNetworkMismatch => {
                write!(formatter, "Monero backend reported the wrong network")
            }
            Self::InvalidFeeEstimate => write!(
                formatter,
                "Monero fee estimate is outside the allowed range"
            ),
            Self::AmountTooSmall => write!(formatter, "Monero amount must be greater than zero"),
            Self::DuplicateOutput => {
                write!(formatter, "Monero sync response contains duplicate outputs")
            }
            Self::InvalidSyncHeight => {
                write!(formatter, "Monero sync response contains invalid heights")
            }
            Self::SuspiciousReorg => write!(
                formatter,
                "Monero backend reported an unexpectedly deep reorganization"
            ),
            Self::ArithmeticOverflow => write!(formatter, "Monero amount arithmetic overflow"),
            Self::AuthorizationMismatch => write!(
                formatter,
                "Monero signing authorization does not match the transaction intent"
            ),
            Self::EmptySignedTransaction => {
                write!(formatter, "Monero signer returned an empty transaction")
            }
            Self::MalformedTransaction => {
                write!(formatter, "Monero backend returned a malformed transaction")
            }
            Self::UndecodableAmount => write!(
                formatter,
                "Monero output amount could not be decoded locally"
            ),
        }
    }
}

impl Error for MoneroError {}

pub fn parse_address(value: &str, network: MoneroNetwork) -> Result<Address, MoneroError> {
    let address = Address::from_str(value).map_err(|_| MoneroError::InvalidAddress)?;
    if address.network != network.network() {
        return Err(MoneroError::WrongNetwork);
    }
    Ok(address)
}

pub fn select_node(
    mode: &NodeMode,
    network: MoneroNetwork,
    candidates: &[NodeCandidate],
) -> Result<NodeSelection, MoneroError> {
    match mode {
        NodeMode::AutomaticRemote => candidates
            .iter()
            .filter(|candidate| candidate.network == network && candidate.healthy)
            .max_by_key(|candidate| candidate.height)
            .map(|candidate| NodeSelection {
                mode: NodeMode::AutomaticRemote,
                endpoint: candidate.endpoint.clone(),
                network,
            })
            .ok_or(MoneroError::NoHealthyRemoteNode),
        NodeMode::CustomRemote(endpoint) => {
            validate_remote_endpoint(endpoint)?;
            Ok(NodeSelection {
                mode: mode.clone(),
                endpoint: endpoint.clone(),
                network,
            })
        }
        NodeMode::LocalNode(endpoint) => {
            validate_local_endpoint(endpoint)?;
            Ok(NodeSelection {
                mode: mode.clone(),
                endpoint: endpoint.clone(),
                network,
            })
        }
    }
}

pub fn scan_transactions_locally(
    identity: &WalletIdentity,
    transactions: &[ChainTransaction],
) -> Result<Vec<WalletOutput>, MoneroError> {
    let view_pair = ViewPair {
        view: *identity.private_view_key(),
        spend: identity.public_spend_key(),
    };
    let mut outputs = Vec::new();

    for item in transactions {
        let transaction: Transaction =
            deserialize(&item.raw_transaction).map_err(|_| MoneroError::MalformedTransaction)?;
        let txid = transaction.hash().to_string();
        let owned = transaction
            .check_outputs(&view_pair, 0..1, 0..100)
            .map_err(|_| MoneroError::MalformedTransaction)?;

        for output in owned {
            let amount = output.amount().ok_or(MoneroError::UndecodableAmount)?;
            outputs.push(WalletOutput {
                id: format!("{txid}:{}", output.index()),
                amount_piconero: amount.as_pico(),
                unlock_height: item.height,
                spent: false,
            });
        }
    }

    Ok(outputs)
}

pub fn validate_backend_network(
    expected: MoneroNetwork,
    reported: MoneroNetwork,
) -> Result<(), MoneroError> {
    if expected != reported {
        return Err(MoneroError::BackendNetworkMismatch);
    }
    Ok(())
}

pub fn validate_authorized_signed_transaction(
    intent: &SpendIntent,
    authorization: [u8; 32],
    signed: &SignedMoneroTransaction,
) -> Result<(), MoneroError> {
    if intent.authorization_binding() != authorization {
        return Err(MoneroError::AuthorizationMismatch);
    }
    if signed.raw_transaction.is_empty() {
        return Err(MoneroError::EmptySignedTransaction);
    }
    Ok(())
}

fn derive_scalar(domain: &[u8], material: &[u8]) -> Result<PrivateKey, MoneroError> {
    let mut data = Vec::with_capacity(domain.len() + material.len());
    data.extend_from_slice(domain);
    data.extend_from_slice(material);
    let scalar = Hash::hash_to_scalar(data);
    if scalar.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(MoneroError::InvalidPrivateKey);
    }
    Ok(scalar)
}

fn validate_snapshot(snapshot: &SyncSnapshot) -> Result<(), MoneroError> {
    if snapshot.scanned_height > snapshot.chain_height {
        return Err(MoneroError::InvalidSyncHeight);
    }
    for (index, output) in snapshot.outputs.iter().enumerate() {
        if snapshot.outputs[..index]
            .iter()
            .any(|existing| existing.id == output.id)
        {
            return Err(MoneroError::DuplicateOutput);
        }
    }
    Ok(())
}

fn validate_remote_endpoint(endpoint: &str) -> Result<(), MoneroError> {
    let endpoint = endpoint.trim();
    let valid_scheme = endpoint.starts_with("https://") || endpoint.starts_with("http://");
    let has_host = endpoint
        .split_once("://")
        .map(|(_, rest)| !rest.is_empty() && !rest.starts_with('/'))
        .unwrap_or(false);
    let no_credentials = endpoint
        .split_once("://")
        .map(|(_, rest)| !rest.split('/').next().unwrap_or_default().contains('@'))
        .unwrap_or(false);
    if valid_scheme && has_host && no_credentials {
        Ok(())
    } else {
        Err(MoneroError::InvalidNodeEndpoint)
    }
}

fn validate_local_endpoint(endpoint: &str) -> Result<(), MoneroError> {
    validate_remote_endpoint(endpoint)?;
    let lower = endpoint.to_ascii_lowercase();
    if lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("http://[::1]")
        || lower.starts_with("https://127.0.0.1")
        || lower.starts_with("https://localhost")
        || lower.starts_with("https://[::1]")
    {
        Ok(())
    } else {
        Err(MoneroError::InvalidNodeEndpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(network: MoneroNetwork) -> WalletIdentity {
        WalletIdentity::from_seed(&[7u8; 32], network).unwrap()
    }

    #[test]
    fn deterministic_wallet_identity_round_trips() {
        let first = identity(MoneroNetwork::Stagenet);
        let second = identity(MoneroNetwork::Stagenet);
        assert_eq!(first.address(), second.address());
        assert_eq!(
            parse_address(&first.address(), MoneroNetwork::Stagenet)
                .unwrap()
                .network,
            Network::Stagenet
        );
        assert!(!format!("{first:?}").contains(&first.private_spend_key().to_string()));
    }

    #[test]
    fn wrong_network_address_is_rejected() {
        let address = identity(MoneroNetwork::Mainnet).address();
        assert_eq!(
            parse_address(&address, MoneroNetwork::Stagenet).unwrap_err(),
            MoneroError::WrongNetwork
        );
    }

    #[test]
    fn automatic_remote_prefers_healthy_highest_node() {
        let candidates = vec![
            NodeCandidate {
                endpoint: "https://node-a.example".into(),
                network: MoneroNetwork::Mainnet,
                healthy: true,
                height: 100,
            },
            NodeCandidate {
                endpoint: "https://node-b.example".into(),
                network: MoneroNetwork::Mainnet,
                healthy: true,
                height: 110,
            },
            NodeCandidate {
                endpoint: "https://node-c.example".into(),
                network: MoneroNetwork::Mainnet,
                healthy: false,
                height: 120,
            },
        ];
        assert_eq!(
            select_node(
                &NodeMode::AutomaticRemote,
                MoneroNetwork::Mainnet,
                &candidates
            )
            .unwrap()
            .endpoint,
            "https://node-b.example"
        );
    }

    #[test]
    fn local_mode_requires_loopback() {
        assert!(
            select_node(
                &NodeMode::LocalNode("http://127.0.0.1:18081".into()),
                MoneroNetwork::Mainnet,
                &[]
            )
            .is_ok()
        );
        assert_eq!(
            select_node(
                &NodeMode::LocalNode("https://remote.example:18081".into()),
                MoneroNetwork::Mainnet,
                &[]
            )
            .unwrap_err(),
            MoneroError::InvalidNodeEndpoint
        );
    }

    #[test]
    fn duplicate_outputs_fail_closed() {
        let output = WalletOutput {
            id: "same-output".into(),
            amount_piconero: 1,
            unlock_height: 0,
            spent: false,
        };
        let snapshot = SyncSnapshot {
            network: MoneroNetwork::Mainnet,
            scanned_height: 10,
            chain_height: 10,
            outputs: vec![output.clone(), output],
            history: vec![],
        };
        let mut state = WalletState::default();
        assert_eq!(
            state.apply_snapshot(snapshot).unwrap_err(),
            MoneroError::DuplicateOutput
        );
    }

    #[test]
    fn invalid_and_deep_reorg_states_fail_closed() {
        let mut state = WalletState {
            chain_height: 1_000,
            scanned_height: 1_000,
            ..WalletState::default()
        };
        let snapshot = SyncSnapshot {
            network: MoneroNetwork::Mainnet,
            scanned_height: 800,
            chain_height: 800,
            outputs: vec![],
            history: vec![],
        };
        assert_eq!(
            state.apply_snapshot(snapshot).unwrap_err(),
            MoneroError::SuspiciousReorg
        );

        let invalid = SyncSnapshot {
            network: MoneroNetwork::Mainnet,
            scanned_height: 11,
            chain_height: 10,
            outputs: vec![],
            history: vec![],
        };
        assert_eq!(
            WalletState::default().apply_snapshot(invalid).unwrap_err(),
            MoneroError::InvalidSyncHeight
        );
    }

    #[test]
    fn spend_intent_binds_exact_authorization() {
        let destination = identity(MoneroNetwork::Stagenet).address();
        let intent = SpendIntent::new(
            MoneroNetwork::Stagenet,
            &destination,
            5_000_000_000,
            FeeEstimate::new(20).unwrap(),
        )
        .unwrap();
        let authorization = intent.authorization_binding();
        let signed = SignedMoneroTransaction {
            raw_transaction: vec![1, 2, 3],
        };
        assert!(validate_authorized_signed_transaction(&intent, authorization, &signed).is_ok());

        let mut wrong = authorization;
        wrong[0] ^= 1;
        assert_eq!(
            validate_authorized_signed_transaction(&intent, wrong, &signed).unwrap_err(),
            MoneroError::AuthorizationMismatch
        );
    }

    #[test]
    fn backend_interface_never_receives_wallet_secrets() {
        fn assert_backend_shape<B: MoneroBackend>(_backend: &B) {}
        let _ = assert_backend_shape::<MockBackend>;
    }

    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock error")
        }
    }

    impl Error for MockError {}

    struct MockBackend;

    impl MoneroBackend for MockBackend {
        type Error = MockError;

        fn network(&self) -> Result<MoneroNetwork, Self::Error> {
            Ok(MoneroNetwork::Stagenet)
        }

        fn health(&self) -> Result<bool, Self::Error> {
            Ok(true)
        }

        fn tip_height(&self) -> Result<u64, Self::Error> {
            Ok(1)
        }

        fn transactions(
            &self,
            _start_height: u64,
            _end_height: u64,
        ) -> Result<Vec<ChainTransaction>, Self::Error> {
            Ok(vec![])
        }

        fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error> {
            FeeEstimate::new(20).map_err(|_| MockError)
        }

        fn broadcast(&self, _transaction: &SignedMoneroTransaction) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn fee_estimates_are_bounded() {
        assert!(FeeEstimate::new(0).is_err());
        assert!(FeeEstimate::new(MIN_FEE_PER_BYTE).is_ok());
        assert!(FeeEstimate::new(MAX_FEE_PER_BYTE).is_ok());
        assert!(FeeEstimate::new(MAX_FEE_PER_BYTE + 1).is_err());
    }
}
