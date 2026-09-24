#![forbid(unsafe_code)]

use std::str::FromStr;

use bdk_wallet::{
    KeychainKind, SignOptions, Wallet,
    bitcoin::{
        Address, Amount, FeeRate, Network, Psbt, Transaction, address::NetworkUnchecked,
        bip32::Xpriv,
    },
    template::Bip84,
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinTestNetwork {
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl BitcoinTestNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Testnet => Network::Testnet,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("seed must contain between 16 and 64 bytes")]
    InvalidSeedLength,
    #[error("bitcoin key derivation failed")]
    KeyDerivation,
    #[error("bitcoin wallet creation failed")]
    WalletCreation,
    #[error("invalid bitcoin address")]
    InvalidAddress,
    #[error("bitcoin address is not valid for the configured test network")]
    WrongNetwork,
    #[error("amount must be greater than zero")]
    InvalidAmount,
    #[error("fee rate must be greater than zero")]
    InvalidFeeRate,
    #[error("fee rate exceeds the test-wallet safety limit")]
    ExcessiveFeeRate,
    #[error("transaction construction failed")]
    BuildTransaction,
    #[error("transaction signing failed")]
    SignTransaction,
    #[error("transaction could not be finalized")]
    NotFinalized,
}

pub struct BitcoinTestWallet {
    network: BitcoinTestNetwork,
    wallet: Wallet,
    seed: Zeroizing<Vec<u8>>,
}

impl BitcoinTestWallet {
    pub fn from_seed(network: BitcoinTestNetwork, seed: &[u8]) -> Result<Self, BitcoinError> {
        if !(16..=64).contains(&seed.len()) {
            return Err(BitcoinError::InvalidSeedLength);
        }

        let protected_seed = Zeroizing::new(seed.to_vec());
        let root = Xpriv::new_master(network.network(), protected_seed.as_slice())
            .map_err(|_| BitcoinError::KeyDerivation)?;

        let wallet = Wallet::create(
            Bip84(root, KeychainKind::External),
            Bip84(root, KeychainKind::Internal),
        )
        .network(network.network())
        .create_wallet_no_persist()
        .map_err(|_| BitcoinError::WalletCreation)?;

        Ok(Self {
            network,
            wallet,
            seed: protected_seed,
        })
    }

    pub const fn network(&self) -> BitcoinTestNetwork {
        self.network
    }

    pub fn next_receive_address(&mut self) -> Address {
        self.wallet
            .reveal_next_address(KeychainKind::External)
            .address
    }

    pub fn next_change_address(&mut self) -> Address {
        self.wallet
            .reveal_next_address(KeychainKind::Internal)
            .address
    }

    pub fn validate_recipient(&self, address: &str) -> Result<Address, BitcoinError> {
        let unchecked = Address::<NetworkUnchecked>::from_str(address)
            .map_err(|_| BitcoinError::InvalidAddress)?;
        unchecked
            .require_network(self.network.network())
            .map_err(|_| BitcoinError::WrongNetwork)
    }

    pub fn balance_sats(&self) -> u64 {
        self.wallet.balance().total().to_sat()
    }

    pub fn list_unspent_count(&self) -> usize {
        self.wallet.list_unspent().count()
    }

    pub fn apply_unconfirmed_transactions(
        &mut self,
        transactions: impl IntoIterator<Item = (Transaction, u64)>,
    ) {
        self.wallet.apply_unconfirmed_txs(transactions);
    }

    pub fn build_payment(
        &mut self,
        recipient: &str,
        amount_sats: u64,
        sat_per_vbyte: u64,
    ) -> Result<Psbt, BitcoinError> {
        if amount_sats == 0 {
            return Err(BitcoinError::InvalidAmount);
        }
        if sat_per_vbyte == 0 {
            return Err(BitcoinError::InvalidFeeRate);
        }
        if sat_per_vbyte > 100 {
            return Err(BitcoinError::ExcessiveFeeRate);
        }

        let recipient = self.validate_recipient(recipient)?;
        let fee_rate =
            FeeRate::from_sat_per_vb(sat_per_vbyte).ok_or(BitcoinError::InvalidFeeRate)?;

        let mut builder = self.wallet.build_tx();
        builder
            .add_recipient(recipient.script_pubkey(), Amount::from_sat(amount_sats))
            .fee_rate(fee_rate);

        builder.finish().map_err(|_| BitcoinError::BuildTransaction)
    }

    #[allow(deprecated)]
    pub fn sign_payment(&self, psbt: &mut Psbt) -> Result<(), BitcoinError> {
        let finalized = self
            .wallet
            .sign(psbt, SignOptions::default())
            .map_err(|_| BitcoinError::SignTransaction)?;

        if !finalized {
            return Err(BitcoinError::NotFinalized);
        }
        Ok(())
    }

    pub fn seed_is_loaded(&self) -> bool {
        !self.seed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{TxOut, absolute::LockTime, transaction::Version};

    const TEST_SEED: [u8; 32] = [0x42; 32];
    const OTHER_SEED: [u8; 32] = [0x24; 32];

    fn funded_wallet() -> BitcoinTestWallet {
        let mut wallet =
            BitcoinTestWallet::from_seed(BitcoinTestNetwork::Regtest, &TEST_SEED).unwrap();
        let receive = wallet.next_receive_address();

        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: receive.script_pubkey(),
            }],
        };

        wallet.apply_unconfirmed_transactions([(funding, 1)]);
        wallet
    }

    #[test]
    fn every_supported_environment_is_non_mainnet() {
        for network in [
            BitcoinTestNetwork::Testnet,
            BitcoinTestNetwork::Testnet4,
            BitcoinTestNetwork::Signet,
            BitcoinTestNetwork::Regtest,
        ] {
            assert_ne!(network.network(), Network::Bitcoin);
        }
    }

    #[test]
    fn deterministic_seed_derives_network_valid_receive_addresses() {
        for network in [
            BitcoinTestNetwork::Testnet,
            BitcoinTestNetwork::Testnet4,
            BitcoinTestNetwork::Signet,
            BitcoinTestNetwork::Regtest,
        ] {
            let mut wallet = BitcoinTestWallet::from_seed(network, &TEST_SEED).unwrap();
            let address = wallet.next_receive_address();
            let validated = wallet
                .validate_recipient(&address.to_string())
                .expect("derived address must validate for its test network");
            assert_eq!(validated, address);
            assert!(wallet.seed_is_loaded());
        }
    }

    #[test]
    fn mainnet_recipient_is_rejected() {
        let wallet = BitcoinTestWallet::from_seed(BitcoinTestNetwork::Regtest, &TEST_SEED).unwrap();
        assert!(matches!(
            wallet.validate_recipient("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
            Err(BitcoinError::WrongNetwork) | Err(BitcoinError::InvalidAddress)
        ));
    }

    #[test]
    fn funding_update_produces_balance_and_utxo() {
        let wallet = funded_wallet();
        assert_eq!(wallet.balance_sats(), 150_000);
        assert_eq!(wallet.list_unspent_count(), 1);
    }

    #[test]
    fn builds_and_locally_signs_regtest_payment() {
        let mut wallet = funded_wallet();
        let mut recipient =
            BitcoinTestWallet::from_seed(BitcoinTestNetwork::Regtest, &OTHER_SEED).unwrap();
        let recipient = recipient.next_receive_address().to_string();

        let mut psbt = wallet.build_payment(&recipient, 50_000, 2).unwrap();
        wallet.sign_payment(&mut psbt).unwrap();

        let tx = psbt.extract_tx().unwrap();
        assert!(!tx.input.is_empty());
        assert!(
            tx.output
                .iter()
                .any(|output| output.value == Amount::from_sat(50_000))
        );
    }

    #[test]
    fn refuses_zero_amount_and_zero_fee_rate() {
        let mut wallet = funded_wallet();
        let mut recipient =
            BitcoinTestWallet::from_seed(BitcoinTestNetwork::Regtest, &OTHER_SEED).unwrap();
        let recipient = recipient.next_receive_address().to_string();

        assert!(matches!(
            wallet.build_payment(&recipient, 0, 2),
            Err(BitcoinError::InvalidAmount)
        ));
        assert!(matches!(
            wallet.build_payment(&recipient, 50_000, 0),
            Err(BitcoinError::InvalidFeeRate)
        ));
        assert!(matches!(
            wallet.build_payment(&recipient, 50_000, 101),
            Err(BitcoinError::ExcessiveFeeRate)
        ));
    }
}
