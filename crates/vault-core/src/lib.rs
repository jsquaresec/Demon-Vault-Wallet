#![forbid(unsafe_code)]

use std::{error::Error, fmt, path::Path};

use demon_vault_bitcoin::{BitcoinError, BitcoinTestNetwork, BitcoinTestWallet};
use vault_crypto::{KdfParams, SecretBytes, VaultDomain, VaultError, open, seal};
use vault_network::NetworkPolicy;
use vault_policy::{Asset, CoreAction, CoreDecision, PolicyEngine};
use vault_storage::{StorageError, read_envelope, write_new_envelope_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLockState {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreStatus {
    pub lock_state: VaultLockState,
    pub network_policy: NetworkPolicy,
    pub supported_assets: [Asset; 3],
}

pub struct VaultCore {
    lock_state: VaultLockState,
    policy: PolicyEngine,
    network_policy: NetworkPolicy,
    unlocked_wallet_secret: Option<SecretBytes>,
}

impl Default for VaultCore {
    fn default() -> Self {
        Self {
            lock_state: VaultLockState::Locked,
            policy: PolicyEngine,
            network_policy: NetworkPolicy::default(),
            unlocked_wallet_secret: None,
        }
    }
}

impl VaultCore {
    pub fn status(&self) -> CoreStatus {
        CoreStatus {
            lock_state: self.lock_state,
            network_policy: self.network_policy,
            supported_assets: [Asset::Bitcoin, Asset::Monero, Asset::Zcash],
        }
    }

    pub fn authorize(&self, action: CoreAction) -> CoreDecision {
        self.policy
            .evaluate(action, self.lock_state == VaultLockState::Unlocked)
    }

    pub fn create_local_vault(
        &self,
        path: &Path,
        password: &[u8],
        initial_wallet_secret: &[u8],
    ) -> Result<(), CoreVaultError> {
        let envelope = seal(
            password,
            VaultDomain::Wallet,
            initial_wallet_secret,
            KdfParams::default(),
        )?;
        write_new_envelope_atomic(path, &envelope)?;
        Ok(())
    }

    pub fn unlock_local_vault(
        &mut self,
        path: &Path,
        password: &[u8],
    ) -> Result<(), CoreVaultError> {
        let envelope = read_envelope(path)?;
        if envelope.domain() != VaultDomain::Wallet {
            return Err(CoreVaultError::WrongDomain);
        }

        let secret = open(password, &envelope)?;
        self.unlocked_wallet_secret = Some(secret);
        self.lock_state = VaultLockState::Unlocked;
        Ok(())
    }

    pub fn bitcoin_test_wallet(
        &self,
        network: BitcoinTestNetwork,
    ) -> Result<BitcoinTestWallet, CoreVaultError> {
        if self.authorize(CoreAction::SignBitcoinTestTransaction) != CoreDecision::Allowed {
            return Err(CoreVaultError::Locked);
        }

        let seed = self
            .unlocked_wallet_secret
            .as_ref()
            .ok_or(CoreVaultError::Locked)?;
        Ok(BitcoinTestWallet::from_seed(network, seed.as_slice())?)
    }

    pub fn lock(&mut self) {
        self.unlocked_wallet_secret = None;
        self.lock_state = VaultLockState::Locked;
    }

    pub fn wallet_secret(&self) -> Option<&[u8]> {
        self.unlocked_wallet_secret
            .as_ref()
            .map(SecretBytes::as_slice)
    }
}

#[derive(Debug)]
pub enum CoreVaultError {
    Crypto(VaultError),
    Storage(StorageError),
    Bitcoin(BitcoinError),
    WrongDomain,
    Locked,
}

impl fmt::Display for CoreVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "vault cryptographic error: {error}"),
            Self::Storage(error) => write!(formatter, "vault storage error: {error}"),
            Self::Bitcoin(error) => write!(formatter, "bitcoin wallet error: {error}"),
            Self::WrongDomain => write!(formatter, "vault contains the wrong encryption domain"),
            Self::Locked => write!(formatter, "vault is locked"),
        }
    }
}

impl Error for CoreVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Bitcoin(error) => Some(error),
            Self::WrongDomain | Self::Locked => None,
        }
    }
}

impl From<VaultError> for CoreVaultError {
    fn from(error: VaultError) -> Self {
        Self::Crypto(error)
    }
}

impl From<StorageError> for CoreVaultError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<BitcoinError> for CoreVaultError {
    fn from(error: BitcoinError) -> Self {
        Self::Bitcoin(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_vault_path() -> std::path::PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("demon-vault-core-{}-{now}", std::process::id()))
            .join("wallet.dvlt")
    }

    #[test]
    fn core_starts_locked_and_outbound_only() {
        let core = VaultCore::default();
        let status = core.status();
        assert_eq!(status.lock_state, VaultLockState::Locked);
        assert!(status.network_policy.outbound_only());
        assert_eq!(status.supported_assets.len(), 3);
    }

    #[test]
    fn mainnet_signing_is_disabled() {
        let core = VaultCore::default();
        assert!(matches!(
            core.authorize(CoreAction::SignTransaction),
            CoreDecision::Denied(_)
        ));
    }

    #[test]
    fn bitcoin_test_wallet_requires_unlock() {
        let core = VaultCore::default();
        assert!(matches!(
            core.bitcoin_test_wallet(BitcoinTestNetwork::Regtest),
            Err(CoreVaultError::Locked)
        ));
    }

    #[test]
    fn unlocked_vault_can_derive_bitcoin_test_wallet() {
        let path = unique_vault_path();
        let mut core = VaultCore::default();
        core.create_local_vault(
            &path,
            b"correct horse battery staple",
            &[0x42; 32],
        )
        .unwrap();
        core.unlock_local_vault(&path, b"correct horse battery staple")
            .unwrap();

        let mut wallet = core
            .bitcoin_test_wallet(BitcoinTestNetwork::Regtest)
            .unwrap();
        let address = wallet.next_receive_address();
        assert!(address.is_valid_for_network(
            BitcoinTestNetwork::Regtest.network()
        ));

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn local_vault_unlocks_and_locks_without_exposing_via_status() {
        let path = unique_vault_path();
        let mut core = VaultCore::default();
        core.create_local_vault(
            &path,
            b"correct horse battery staple",
            &[0x33; 32],
        )
        .unwrap();

        assert_eq!(core.status().lock_state, VaultLockState::Locked);
        core.unlock_local_vault(&path, b"correct horse battery staple")
            .unwrap();
        assert_eq!(core.status().lock_state, VaultLockState::Unlocked);

        core.lock();
        assert_eq!(core.status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
