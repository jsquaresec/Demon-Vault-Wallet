#![forbid(unsafe_code)]

use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, absolute::LockTime,
    transaction::Version,
};
use std::{error::Error, fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    pub const fn network(self) -> Network {
        match self {
            Self::Testnet => Network::Testnet,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendableUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeRateSatVb(u64);

impl FeeRateSatVb {
    pub fn new(sat_per_vb: u64) -> Result<Self, BitcoinError> {
        if !(1..=1_000).contains(&sat_per_vb) {
            return Err(BitcoinError::InvalidFeeRate);
        }
        Ok(Self(sat_per_vb))
    }

    pub const fn as_sat_per_vb(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedSpend {
    pub transaction: Transaction,
    pub selected_value: Amount,
    pub send_value: Amount,
    pub fee: Amount,
    pub change: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinError {
    MainnetDisabled,
    InvalidAddress,
    WrongNetwork,
    InvalidFeeRate,
    AmountTooSmall,
    InsufficientFunds,
    ArithmeticOverflow,
}

impl fmt::Display for BitcoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MainnetDisabled => write!(f, "Bitcoin mainnet is disabled"),
            Self::InvalidAddress => write!(f, "invalid Bitcoin address"),
            Self::WrongNetwork => write!(f, "Bitcoin address is for the wrong network"),
            Self::InvalidFeeRate => write!(f, "fee rate is outside the allowed test-wallet range"),
            Self::AmountTooSmall => write!(f, "amount must be greater than zero"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::ArithmeticOverflow => write!(f, "Bitcoin amount arithmetic overflow"),
        }
    }
}

impl Error for BitcoinError {}

pub fn parse_address(
    value: &str,
    network: BitcoinNetwork,
) -> Result<Address, BitcoinError> {
    let unchecked = Address::from_str(value).map_err(|_| BitcoinError::InvalidAddress)?;
    unchecked
        .require_network(network.network())
        .map_err(|_| BitcoinError::WrongNetwork)
}

pub fn build_unsigned_spend(
    network: BitcoinNetwork,
    destination: &str,
    change_address: &str,
    amount: Amount,
    fee_rate: FeeRateSatVb,
    utxos: &[SpendableUtxo],
) -> Result<UnsignedSpend, BitcoinError> {
    if network.network() == Network::Bitcoin {
        return Err(BitcoinError::MainnetDisabled);
    }
    if amount == Amount::ZERO {
        return Err(BitcoinError::AmountTooSmall);
    }

    let destination = parse_address(destination, network)?;
    let change_address = parse_address(change_address, network)?;

    let mut selected = Vec::new();
    let mut selected_sat = 0u64;
    let amount_sat = amount.to_sat();

    for utxo in utxos {
        selected_sat = selected_sat
            .checked_add(utxo.value.to_sat())
            .ok_or(BitcoinError::ArithmeticOverflow)?;
        selected.push(utxo);

        let estimated_vbytes = estimate_vbytes(selected.len(), 2)?;
        let fee_sat = estimated_vbytes
            .checked_mul(fee_rate.as_sat_per_vb())
            .ok_or(BitcoinError::ArithmeticOverflow)?;
        if selected_sat >= amount_sat.saturating_add(fee_sat) {
            break;
        }
    }

    if selected.is_empty() {
        return Err(BitcoinError::InsufficientFunds);
    }

    let two_output_fee = estimate_vbytes(selected.len(), 2)?
        .checked_mul(fee_rate.as_sat_per_vb())
        .ok_or(BitcoinError::ArithmeticOverflow)?;
    let one_output_fee = estimate_vbytes(selected.len(), 1)?
        .checked_mul(fee_rate.as_sat_per_vb())
        .ok_or(BitcoinError::ArithmeticOverflow)?;

    let (fee_sat, change_sat) = if selected_sat >= amount_sat.saturating_add(two_output_fee) {
        let change = selected_sat - amount_sat - two_output_fee;
        if change >= 546 {
            (two_output_fee, change)
        } else if selected_sat >= amount_sat.saturating_add(one_output_fee) {
            (selected_sat - amount_sat, 0)
        } else {
            return Err(BitcoinError::InsufficientFunds);
        }
    } else if selected_sat >= amount_sat.saturating_add(one_output_fee) {
        (selected_sat - amount_sat, 0)
    } else {
        return Err(BitcoinError::InsufficientFunds);
    };

    let inputs = selected
        .iter()
        .map(|utxo| TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        })
        .collect();

    let mut outputs = vec![TxOut {
        value: amount,
        script_pubkey: destination.script_pubkey(),
    }];
    if change_sat > 0 {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sat),
            script_pubkey: change_address.script_pubkey(),
        });
    }

    Ok(UnsignedSpend {
        transaction: Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        },
        selected_value: Amount::from_sat(selected_sat),
        send_value: amount,
        fee: Amount::from_sat(fee_sat),
        change: Amount::from_sat(change_sat),
    })
}

fn estimate_vbytes(inputs: usize, outputs: usize) -> Result<u64, BitcoinError> {
    let inputs = u64::try_from(inputs).map_err(|_| BitcoinError::ArithmeticOverflow)?;
    let outputs = u64::try_from(outputs).map_err(|_| BitcoinError::ArithmeticOverflow)?;
    10u64
        .checked_add(inputs.checked_mul(68).ok_or(BitcoinError::ArithmeticOverflow)?)
        .and_then(|v| v.checked_add(outputs.checked_mul(31)?))
        .ok_or(BitcoinError::ArithmeticOverflow)
}

pub trait BitcoinBackend {
    type Error: Error + Send + Sync + 'static;

    fn network(&self) -> Result<BitcoinNetwork, Self::Error>;
    fn tip_height(&self) -> Result<u64, Self::Error>;
    fn fee_rate(&self) -> Result<FeeRateSatVb, Self::Error>;
    fn broadcast(&self, transaction: &Transaction) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Txid, hashes::Hash};

    const TESTNET_DEST: &str = "tb1qfm7k4zd4h6h2j8f5y6q7q0w6n0s4x5w2w7s4xq";

    #[test]
    fn fee_rate_is_bounded() {
        assert!(FeeRateSatVb::new(0).is_err());
        assert!(FeeRateSatVb::new(1).is_ok());
        assert!(FeeRateSatVb::new(1_000).is_ok());
        assert!(FeeRateSatVb::new(1_001).is_err());
    }

    #[test]
    fn mainnet_address_is_rejected_for_testnet() {
        assert!(matches!(
            parse_address("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", BitcoinNetwork::Testnet),
            Err(BitcoinError::WrongNetwork)
        ));
    }

    #[test]
    fn malformed_address_is_rejected() {
        assert_eq!(
            parse_address("not-an-address", BitcoinNetwork::Regtest).unwrap_err(),
            BitcoinError::InvalidAddress
        );
    }

    #[test]
    fn insufficient_funds_fail_closed() {
        let utxo = SpendableUtxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            value: Amount::from_sat(500),
            script_pubkey: ScriptBuf::new(),
        };
        let result = build_unsigned_spend(
            BitcoinNetwork::Testnet,
            TESTNET_DEST,
            TESTNET_DEST,
            Amount::from_sat(10_000),
            FeeRateSatVb::new(2).unwrap(),
            &[utxo],
        );
        assert_eq!(result.unwrap_err(), BitcoinError::InsufficientFunds);
    }
}
