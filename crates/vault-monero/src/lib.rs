#![forbid(unsafe_code)]

use curve25519_dalek::scalar::Scalar;
use monero::{Address, KeyPair, Network, PrivateKey, PublicKey, Transaction};
use std::{error::Error, fmt, net::IpAddr, ops::Range, str::FromStr};
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;

const MAX_NODE_HOST_LEN: usize = 253;
const MAX_ACCEPTABLE_LAG: u64 = 20;
const MAX_FEE_PER_BYTE_PICONERO: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoneroNetwork {
    Stagenet,
    Testnet,
}

impl MoneroNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Stagenet => Network::Stagenet,
            Self::Testnet => Network::Testnet,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Stagenet => "stagenet",
            Self::Testnet => "testnet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    AutomaticRemote,
    CustomRemote,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEndpoint {
    pub mode: NodeMode,
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl NodeEndpoint {
    pub fn automatic_remote(
        host: impl Into<String>,
        port: u16,
        tls: bool,
    ) -> Result<Self, MoneroError> {
        Self::new(NodeMode::AutomaticRemote, host, port, tls)
    }

    pub fn custom_remote(
        host: impl Into<String>,
        port: u16,
        tls: bool,
    ) -> Result<Self, MoneroError> {
        Self::new(NodeMode::CustomRemote, host, port, tls)
    }

    pub fn local(host: impl Into<String>, port: u16) -> Result<Self, MoneroError> {
        Self::new(NodeMode::Local, host, port, false)
    }

    fn new(
        mode: NodeMode,
        host: impl Into<String>,
        port: u16,
        tls: bool,
    ) -> Result<Self, MoneroError> {
        let host = host.into();
        validate_host(&host)?;
        if port == 0 {
            return Err(MoneroError::InvalidNodeEndpoint);
        }
        if mode == NodeMode::Local && !is_loopback_host(&host) {
            return Err(MoneroError::LocalNodeMustBeLoopback);
        }

        Ok(Self {
            mode,
            host,
            port,
            tls,
        })
    }

    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub endpoint: NodeEndpoint,
    pub network: MoneroNetwork,
    pub reachable: bool,
    pub height: u64,
    pub latency_ms: u32,
}

pub fn select_automatic_node(
    expected_network: MoneroNetwork,
    best_known_height: u64,
    candidates: &[NodeHealth],
) -> Option<NodeEndpoint> {
    let minimum_height = best_known_height.saturating_sub(MAX_ACCEPTABLE_LAG);
    let mut eligible = candidates
        .iter()
        .filter(|candidate| {
            candidate.endpoint.mode == NodeMode::AutomaticRemote
                && candidate.reachable
                && candidate.network == expected_network
                && candidate.height >= minimum_height
        })
        .collect::<Vec<_>>();

    eligible.sort_by(|left, right| {
        right
            .endpoint
            .tls
            .cmp(&left.endpoint.tls)
            .then_with(|| right.height.cmp(&left.height))
            .then_with(|| left.latency_ms.cmp(&right.latency_ms))
            .then_with(|| left.endpoint.authority().cmp(&right.endpoint.authority()))
    });

    eligible.first().map(|health| health.endpoint.clone())
}

pub const fn remote_node_privacy_notice() -> &'static str {
    "Remote Monero nodes cannot spend wallet funds, but may observe network metadata related to wallet synchronization."
}

pub struct MoneroWalletKeys {
    spend: Zeroizing<[u8; 32]>,
    view: Zeroizing<[u8; 32]>,
}

impl MoneroWalletKeys {
    pub fn generate() -> Result<Self, MoneroError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| MoneroError::RandomnessUnavailable)?;

        let spend = PrivateKey::from_scalar(Scalar::from_bytes_mod_order(*entropy));
        if spend.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(MoneroError::InvalidPrivateKey);
        }

        let spend_bytes = spend.to_bytes();
        let view = derive_view_private_key(&spend_bytes);

        Ok(Self {
            spend: Zeroizing::new(spend_bytes),
            view: Zeroizing::new(view.to_bytes()),
        })
    }

    pub fn from_spend_key(spend_key: [u8; 32]) -> Result<Self, MoneroError> {
        let spend =
            PrivateKey::from_slice(&spend_key).map_err(|_| MoneroError::InvalidPrivateKey)?;
        if spend.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(MoneroError::InvalidPrivateKey);
        }
        let view = derive_view_private_key(&spend_key);

        Ok(Self {
            spend: Zeroizing::new(spend_key),
            view: Zeroizing::new(view.to_bytes()),
        })
    }

    pub fn from_keys(spend_key: [u8; 32], view_key: [u8; 32]) -> Result<Self, MoneroError> {
        let spend =
            PrivateKey::from_slice(&spend_key).map_err(|_| MoneroError::InvalidPrivateKey)?;
        let view = PrivateKey::from_slice(&view_key).map_err(|_| MoneroError::InvalidPrivateKey)?;
        if spend.as_bytes().iter().all(|byte| *byte == 0)
            || view.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(MoneroError::InvalidPrivateKey);
        }

        Ok(Self {
            spend: Zeroizing::new(spend_key),
            view: Zeroizing::new(view_key),
        })
    }

    pub fn primary_address(&self, network: MoneroNetwork) -> Result<String, MoneroError> {
        let keys = self.keypair()?;
        Ok(Address::from_keypair(network.network(), &keys).to_string())
    }

    pub fn view_pair(&self) -> Result<monero::ViewPair, MoneroError> {
        let spend = self.spend_private_key()?;
        let view = self.view_private_key()?;
        Ok(monero::ViewPair {
            view,
            spend: PublicKey::from_private_key(&spend),
        })
    }

    fn keypair(&self) -> Result<KeyPair, MoneroError> {
        Ok(KeyPair {
            spend: self.spend_private_key()?,
            view: self.view_private_key()?,
        })
    }

    fn spend_private_key(&self) -> Result<PrivateKey, MoneroError> {
        PrivateKey::from_slice(self.spend.as_slice()).map_err(|_| MoneroError::InvalidPrivateKey)
    }

    fn view_private_key(&self) -> Result<PrivateKey, MoneroError> {
        PrivateKey::from_slice(self.view.as_slice()).map_err(|_| MoneroError::InvalidPrivateKey)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedOutput {
    pub output_index: usize,
    pub account_index: u32,
    pub subaddress_index: u32,
    pub amount_piconero: Option<u64>,
}

pub fn scan_transaction(
    transaction: &Transaction,
    keys: &MoneroWalletKeys,
    account_range: Range<u32>,
    subaddress_range: Range<u32>,
) -> Result<Vec<ReceivedOutput>, MoneroError> {
    let view_pair = keys.view_pair()?;
    transaction
        .check_outputs(&view_pair, account_range, subaddress_range)
        .map_err(|_| MoneroError::ScanFailed)?
        .into_iter()
        .map(|output| {
            let index = output.sub_index();
            Ok(ReceivedOutput {
                output_index: output.index(),
                account_index: index.major,
                subaddress_index: index.minor,
                amount_piconero: output.amount().map(|amount| amount.as_pico()),
            })
        })
        .collect()
}

pub fn parse_address(value: &str, network: MoneroNetwork) -> Result<Address, MoneroError> {
    let address = Address::from_str(value).map_err(|_| MoneroError::InvalidAddress)?;
    if address.network == Network::Mainnet {
        return Err(MoneroError::MainnetDisabled);
    }
    if address.network != network.network() {
        return Err(MoneroError::WrongNetwork);
    }
    Ok(address)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub piconero_per_byte: u64,
    pub estimated_weight: u64,
}

impl FeeEstimate {
    pub fn total(self) -> Result<u64, MoneroError> {
        if self.piconero_per_byte == 0
            || self.piconero_per_byte > MAX_FEE_PER_BYTE_PICONERO
            || self.estimated_weight == 0
        {
            return Err(MoneroError::InvalidFee);
        }
        self.piconero_per_byte
            .checked_mul(self.estimated_weight)
            .ok_or(MoneroError::ArithmeticOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferIntent {
    pub network: MoneroNetwork,
    pub destination: String,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
}

pub fn prepare_transfer(
    network: MoneroNetwork,
    destination: &str,
    amount_piconero: u64,
    fee: FeeEstimate,
) -> Result<TransferIntent, MoneroError> {
    if amount_piconero == 0 {
        return Err(MoneroError::AmountTooSmall);
    }
    parse_address(destination, network)?;
    let fee_piconero = fee.total()?;
    if fee_piconero >= amount_piconero {
        return Err(MoneroError::FeeExceedsAmount);
    }

    Ok(TransferIntent {
        network,
        destination: destination.to_owned(),
        amount_piconero,
        fee_piconero,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletBalance {
    pub total_piconero: u64,
    pub unlocked_piconero: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRecord {
    pub txid: String,
    pub direction: TransactionDirection,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub height: Option<u64>,
    pub confirmations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncState {
    pub scanned_height: u64,
    pub target_height: u64,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletSnapshot {
    pub balance: WalletBalance,
    pub sync: SyncState,
    pub transactions: Vec<TransactionRecord>,
}

pub trait MoneroBackend {
    type Error: Error + Send + Sync + 'static;

    fn network(&self) -> Result<MoneroNetwork, Self::Error>;
    fn health(&self) -> Result<NodeHealth, Self::Error>;
    fn snapshot(&self) -> Result<WalletSnapshot, Self::Error>;
    fn fee_estimate(&self) -> Result<FeeEstimate, Self::Error>;
    fn broadcast(&self, signed_transaction: &[u8]) -> Result<String, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoneroError {
    MainnetDisabled,
    WrongNetwork,
    InvalidAddress,
    InvalidPrivateKey,
    InvalidNodeEndpoint,
    LocalNodeMustBeLoopback,
    RandomnessUnavailable,
    InvalidFee,
    FeeExceedsAmount,
    AmountTooSmall,
    ArithmeticOverflow,
    ScanFailed,
}

impl fmt::Display for MoneroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MainnetDisabled => "Monero mainnet is disabled",
            Self::WrongNetwork => "Monero address is for the wrong network",
            Self::InvalidAddress => "invalid Monero address",
            Self::InvalidPrivateKey => "invalid Monero private key",
            Self::InvalidNodeEndpoint => "invalid Monero node endpoint",
            Self::LocalNodeMustBeLoopback => "local Monero nodes must use a loopback host",
            Self::RandomnessUnavailable => "secure operating-system randomness is unavailable",
            Self::InvalidFee => "invalid Monero fee estimate",
            Self::FeeExceedsAmount => "Monero fee exceeds or equals transfer amount",
            Self::AmountTooSmall => "Monero amount must be greater than zero",
            Self::ArithmeticOverflow => "Monero amount arithmetic overflow",
            Self::ScanFailed => "Monero transaction scan failed",
        };
        f.write_str(message)
    }
}

impl Error for MoneroError {}

fn derive_view_private_key(spend_key: &[u8; 32]) -> PrivateKey {
    let mut digest = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(spend_key);
    hasher.finalize(&mut digest);
    PrivateKey::from_scalar(Scalar::from_bytes_mod_order(digest))
}

fn validate_host(host: &str) -> Result<(), MoneroError> {
    if host.is_empty()
        || host.len() > MAX_NODE_HOST_LEN
        || host.contains('/')
        || host.contains('@')
        || host.contains(char::is_whitespace)
    {
        return Err(MoneroError::InvalidNodeEndpoint);
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_keys() -> MoneroWalletKeys {
        let spend = PrivateKey::from_scalar(Scalar::from(7u64)).to_bytes();
        MoneroWalletKeys::from_spend_key(spend).unwrap()
    }

    #[test]
    fn generated_wallet_uses_selected_non_mainnet_network() {
        let keys = deterministic_keys();
        let stage = keys.primary_address(MoneroNetwork::Stagenet).unwrap();
        let test = keys.primary_address(MoneroNetwork::Testnet).unwrap();

        assert_eq!(
            parse_address(&stage, MoneroNetwork::Stagenet)
                .unwrap()
                .network,
            Network::Stagenet
        );
        assert_eq!(
            parse_address(&test, MoneroNetwork::Testnet)
                .unwrap()
                .network,
            Network::Testnet
        );
        assert_ne!(stage, test);
    }

    #[test]
    fn mainnet_address_is_rejected() {
        let address = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
        assert_eq!(
            parse_address(address, MoneroNetwork::Stagenet).unwrap_err(),
            MoneroError::MainnetDisabled
        );
    }

    #[test]
    fn wrong_non_mainnet_network_is_rejected() {
        let keys = deterministic_keys();
        let address = keys.primary_address(MoneroNetwork::Stagenet).unwrap();
        assert_eq!(
            parse_address(&address, MoneroNetwork::Testnet).unwrap_err(),
            MoneroError::WrongNetwork
        );
    }

    #[test]
    fn local_node_must_be_loopback() {
        assert!(NodeEndpoint::local("127.0.0.1", 38081).is_ok());
        assert!(NodeEndpoint::local("localhost", 38081).is_ok());
        assert_eq!(
            NodeEndpoint::local("node.example.org", 38081).unwrap_err(),
            MoneroError::LocalNodeMustBeLoopback
        );
    }

    #[test]
    fn automatic_selection_filters_wrong_network_stale_and_unreachable_nodes() {
        let candidates = vec![
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("fast.example", 443, true).unwrap(),
                network: MoneroNetwork::Stagenet,
                reachable: true,
                height: 1_000,
                latency_ms: 90,
            },
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("stale.example", 443, true).unwrap(),
                network: MoneroNetwork::Stagenet,
                reachable: true,
                height: 900,
                latency_ms: 5,
            },
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("wrong.example", 443, true).unwrap(),
                network: MoneroNetwork::Testnet,
                reachable: true,
                height: 1_001,
                latency_ms: 1,
            },
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("offline.example", 443, true).unwrap(),
                network: MoneroNetwork::Stagenet,
                reachable: false,
                height: 1_001,
                latency_ms: 1,
            },
        ];

        let selected = select_automatic_node(MoneroNetwork::Stagenet, 1_001, &candidates).unwrap();
        assert_eq!(selected.host, "fast.example");
    }

    #[test]
    fn automatic_selection_prefers_tls_then_height_then_latency() {
        let candidates = vec![
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("plain.example", 38081, false).unwrap(),
                network: MoneroNetwork::Stagenet,
                reachable: true,
                height: 2_000,
                latency_ms: 10,
            },
            NodeHealth {
                endpoint: NodeEndpoint::automatic_remote("tls.example", 443, true).unwrap(),
                network: MoneroNetwork::Stagenet,
                reachable: true,
                height: 1_999,
                latency_ms: 80,
            },
        ];

        let selected = select_automatic_node(MoneroNetwork::Stagenet, 2_000, &candidates).unwrap();
        assert_eq!(selected.host, "tls.example");
    }

    #[test]
    fn transfer_intent_validates_address_amount_and_fee() {
        let keys = deterministic_keys();
        let address = keys.primary_address(MoneroNetwork::Stagenet).unwrap();
        let transfer = prepare_transfer(
            MoneroNetwork::Stagenet,
            &address,
            5_000_000,
            FeeEstimate {
                piconero_per_byte: 20,
                estimated_weight: 1_000,
            },
        )
        .unwrap();

        assert_eq!(transfer.amount_piconero, 5_000_000);
        assert_eq!(transfer.fee_piconero, 20_000);
        assert_eq!(transfer.network, MoneroNetwork::Stagenet);
    }

    #[test]
    fn unreasonable_fee_is_rejected() {
        assert_eq!(
            FeeEstimate {
                piconero_per_byte: MAX_FEE_PER_BYTE_PICONERO + 1,
                estimated_weight: 1_000,
            }
            .total()
            .unwrap_err(),
            MoneroError::InvalidFee
        );
    }

    #[test]
    fn malformed_transaction_scan_fails_closed() {
        let keys = deterministic_keys();
        assert_eq!(
            scan_transaction(&Transaction::default(), &keys, 0..1, 0..20).unwrap_err(),
            MoneroError::ScanFailed
        );
    }

    #[test]
    fn remote_node_notice_is_explicit_about_metadata_risk() {
        let notice = remote_node_privacy_notice();
        assert!(notice.contains("cannot spend"));
        assert!(notice.contains("network metadata"));
    }
}
