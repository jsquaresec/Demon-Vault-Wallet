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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NodeMode {
    #[default]
    AutomaticRemote,
    CustomRemote(String),
    LocalNode(String),
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

#[derive(Clone, PartialEq, Eq)]
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

pub struct MoneroWallet {
    identity: WalletIdentity,
    node_mode: NodeMode,
    state: WalletState,
}

impl MoneroWallet {
    pub fn from_seed(
        seed: &[u8],
        network: MoneroNetwork,
        node_mode: NodeMode,
    ) -> Result<Self, MoneroError> {
        Ok(Self {
            identity: WalletIdentity::from_seed(seed, network)?,
            node_mode,
            state: WalletState::default(),
        })
    }

    pub fn import_private_keys(
        private_spend: PrivateKey,
        private_view: PrivateKey,
        network: MoneroNetwork,
        node_mode: NodeMode,
    ) -> Result<Self, MoneroError> {
        Ok(Self {
            identity: WalletIdentity::from_private_keys(private_spend, private_view, network)?,
            node_mode,
            state: WalletState::default(),
        })
    }

    pub fn address(&self) -> String {
        self.identity.address()
    }

    pub fn network(&self) -> MoneroNetwork {
        self.identity.network()
    }

    pub fn node_mode(&self) -> &NodeMode {
        &self.node_mode
    }

    pub fn state(&self) -> &WalletState {
        &self.state
    }

    pub fn balance(&self) -> Result<u64, MoneroError> {
        self.state.unlocked_balance()
    }

    pub fn history(&self) -> &[HistoryEntry] {
        &self.state.history
    }

    pub fn sync<B: MoneroBackend>(&mut self, backend: &B) -> Result<(), MoneroError> {
        if !backend
            .health()
            .map_err(|_| MoneroError::BackendUnavailable)?
        {
            return Err(MoneroError::BackendUnhealthy);
        }

        let reported_network = backend
            .network()
            .map_err(|_| MoneroError::BackendUnavailable)?;
        validate_backend_network(self.network(), reported_network)?;

        let tip = backend
            .tip_height()
            .map_err(|_| MoneroError::BackendUnavailable)?;
        let start_height = self.state.scanned_height.saturating_sub(20);
        let transactions = backend
            .transactions(start_height, tip)
            .map_err(|_| MoneroError::BackendUnavailable)?;
        let newly_scanned = scan_transactions_locally(&self.identity, &transactions)?;

        let mut outputs = self
            .state
            .outputs
            .iter()
            .filter(|output| output.unlock_height < start_height)
            .cloned()
            .collect::<Vec<_>>();
        outputs.extend(newly_scanned);
        outputs.sort_by(|left, right| left.id.cmp(&right.id));
        outputs.dedup_by(|left, right| left.id == right.id);

        let mut history_by_tx = std::collections::BTreeMap::<String, i128>::new();
        for output in &outputs {
            let txid = output
                .id
                .split_once(':')
                .map(|(txid, _)| txid)
                .unwrap_or(output.id.as_str())
                .to_owned();
            let amount = i128::from(output.amount_piconero);
            let entry = history_by_tx.entry(txid).or_default();
            *entry = entry
                .checked_add(amount)
                .ok_or(MoneroError::ArithmeticOverflow)?;
        }
        let history = history_by_tx
            .into_iter()
            .map(|(txid, amount_delta_piconero)| HistoryEntry {
                txid,
                height: None,
                amount_delta_piconero,
            })
            .collect();

        self.state.apply_snapshot(SyncSnapshot {
            network: self.network(),
            scanned_height: tip,
            chain_height: tip,
            outputs,
            history,
        })
    }

    pub fn prepare_spend<B: MoneroBackend>(
        &self,
        backend: &B,
        destination: &str,
        amount_piconero: u64,
    ) -> Result<SpendIntent, MoneroError> {
        let reported_network = backend
            .network()
            .map_err(|_| MoneroError::BackendUnavailable)?;
        validate_backend_network(self.network(), reported_network)?;

        if amount_piconero > self.balance()? {
            return Err(MoneroError::InsufficientFunds);
        }
        let fee = backend
            .fee_estimate()
            .map_err(|_| MoneroError::BackendUnavailable)?;
        SpendIntent::new(self.network(), destination, amount_piconero, fee)
    }

    pub fn sign_and_broadcast<B, S>(
        &self,
        backend: &B,
        signer: &S,
        intent: &SpendIntent,
    ) -> Result<SignedMoneroTransaction, MoneroError>
    where
        B: MoneroBackend,
        S: MoneroLocalSigner,
    {
        validate_backend_network(self.network(), intent.network)?;
        let reported_network = backend
            .network()
            .map_err(|_| MoneroError::BackendUnavailable)?;
        validate_backend_network(self.network(), reported_network)?;

        let authorization = intent.authorization_binding();
        let signed = signer
            .sign(&self.identity, intent, authorization)
            .map_err(|_| MoneroError::SigningFailed)?;
        validate_authorized_signed_transaction(intent, authorization, &signed)?;
        backend
            .broadcast(&signed)
            .map_err(|_| MoneroError::BackendUnavailable)?;
        Ok(signed)
    }
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
    BackendUnavailable,
    BackendUnhealthy,
    SigningFailed,
    InsufficientFunds,
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
            Self::BackendUnavailable => write!(formatter, "Monero backend is unavailable"),
            Self::BackendUnhealthy => write!(formatter, "Monero backend reported unhealthy status"),
            Self::SigningFailed => write!(formatter, "Monero local signing failed"),
            Self::InsufficientFunds => write!(formatter, "insufficient unlocked Monero balance"),
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
            .filter(|candidate| {
                candidate.network == network
                    && candidate.healthy
                    && validate_remote_endpoint(&candidate.endpoint).is_ok()
            })
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
    if endpoint.is_empty()
        || endpoint.len() > 2_048
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('#')
        || !endpoint.starts_with("https://")
    {
        return Err(MoneroError::InvalidNodeEndpoint);
    }

    let authority = endpoint
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?']).next())
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or(MoneroError::InvalidNodeEndpoint)?;
    if authority.starts_with(':') {
        return Err(MoneroError::InvalidNodeEndpoint);
    }
    Ok(())
}

fn validate_local_endpoint(endpoint: &str) -> Result<(), MoneroError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty()
        || endpoint.len() > 2_048
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('#')
        || endpoint.contains('@')
    {
        return Err(MoneroError::InvalidNodeEndpoint);
    }

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
    fn remote_nodes_require_https_and_automatic_selection_ignores_plaintext() {
        assert_eq!(
            select_node(
                &NodeMode::CustomRemote("http://remote.example:18081".into()),
                MoneroNetwork::Mainnet,
                &[]
            )
            .unwrap_err(),
            MoneroError::InvalidNodeEndpoint
        );

        let candidates = vec![
            NodeCandidate {
                endpoint: "http://faster.example".into(),
                network: MoneroNetwork::Mainnet,
                healthy: true,
                height: 200,
            },
            NodeCandidate {
                endpoint: "https://secure.example".into(),
                network: MoneroNetwork::Mainnet,
                healthy: true,
                height: 150,
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
            "https://secure.example"
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

    struct EmptySigner {
        empty: bool,
    }

    impl MoneroLocalSigner for EmptySigner {
        type Error = MockError;

        fn sign(
            &self,
            _identity: &WalletIdentity,
            _intent: &SpendIntent,
            _exact_authorization: [u8; 32],
        ) -> Result<SignedMoneroTransaction, Self::Error> {
            Ok(SignedMoneroTransaction {
                raw_transaction: if self.empty { vec![] } else { vec![1, 2, 3] },
            })
        }
    }

    struct GateBackend {
        network: MoneroNetwork,
        healthy: bool,
        broadcast_count: std::cell::Cell<u32>,
    }

    impl MoneroBackend for GateBackend {
        type Error = MockError;

        fn network(&self) -> Result<MoneroNetwork, Self::Error> {
            Ok(self.network)
        }

        fn health(&self) -> Result<bool, Self::Error> {
            Ok(self.healthy)
        }

        fn tip_height(&self) -> Result<u64, Self::Error> {
            Ok(42)
        }

        fn transactions(
            &self,
            _start_height: u64,
            _end_height: u64,
        ) -> Result<Vec<ChainTransaction>, Self::Error> {
            Ok(vec![])
        }

        fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error> {
            Ok(FeeEstimate::new(20).unwrap())
        }

        fn broadcast(&self, _transaction: &SignedMoneroTransaction) -> Result<(), Self::Error> {
            self.broadcast_count.set(self.broadcast_count.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn wallet_sync_validates_backend_identity_and_health() {
        let mut wallet = MoneroWallet::from_seed(
            &[9u8; 32],
            MoneroNetwork::Stagenet,
            NodeMode::AutomaticRemote,
        )
        .unwrap();
        let healthy = GateBackend {
            network: MoneroNetwork::Stagenet,
            healthy: true,
            broadcast_count: std::cell::Cell::new(0),
        };
        wallet.sync(&healthy).unwrap();
        assert_eq!(wallet.state().scanned_height, 42);

        let wrong_network = GateBackend {
            network: MoneroNetwork::Mainnet,
            healthy: true,
            broadcast_count: std::cell::Cell::new(0),
        };
        assert_eq!(
            wallet.sync(&wrong_network).unwrap_err(),
            MoneroError::BackendNetworkMismatch
        );

        let unhealthy = GateBackend {
            network: MoneroNetwork::Stagenet,
            healthy: false,
            broadcast_count: std::cell::Cell::new(0),
        };
        assert_eq!(
            wallet.sync(&unhealthy).unwrap_err(),
            MoneroError::BackendUnhealthy
        );
    }

    #[test]
    fn broadcast_occurs_only_after_local_signing_and_exact_authorization() {
        let wallet = MoneroWallet::from_seed(
            &[11u8; 32],
            MoneroNetwork::Stagenet,
            NodeMode::AutomaticRemote,
        )
        .unwrap();
        let backend = GateBackend {
            network: MoneroNetwork::Stagenet,
            healthy: true,
            broadcast_count: std::cell::Cell::new(0),
        };
        let destination = identity(MoneroNetwork::Stagenet).address();
        let intent = SpendIntent::new(
            MoneroNetwork::Stagenet,
            &destination,
            1,
            FeeEstimate::new(20).unwrap(),
        )
        .unwrap();

        assert_eq!(
            wallet
                .sign_and_broadcast(&backend, &EmptySigner { empty: true }, &intent)
                .unwrap_err(),
            MoneroError::EmptySignedTransaction
        );
        assert_eq!(backend.broadcast_count.get(), 0);

        wallet
            .sign_and_broadcast(&backend, &EmptySigner { empty: false }, &intent)
            .unwrap();
        assert_eq!(backend.broadcast_count.get(), 1);
    }

    #[test]
    fn fee_estimates_are_bounded() {
        assert!(FeeEstimate::new(0).is_err());
        assert!(FeeEstimate::new(MIN_FEE_PER_BYTE).is_ok());
        assert!(FeeEstimate::new(MAX_FEE_PER_BYTE).is_ok());
        assert!(FeeEstimate::new(MAX_FEE_PER_BYTE + 1).is_err());
    }
}
