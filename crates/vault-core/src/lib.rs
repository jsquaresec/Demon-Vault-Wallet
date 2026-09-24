#![forbid(unsafe_code)]

use std::{error::Error, fmt, path::Path};
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
pub struct FoundationStatus {
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
    pub fn foundation_status(&self) -> FoundationStatus {
        FoundationStatus {
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
    WrongDomain,
}

impl fmt::Display for CoreVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "vault cryptographic error: {error}"),
            Self::Storage(error) => write!(formatter, "vault storage error: {error}"),
            Self::WrongDomain => write!(formatter, "vault contains the wrong encryption domain"),
        }
    }
}

impl Error for CoreVaultError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::WrongDomain => None,
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
        let status = core.foundation_status();
        assert_eq!(status.lock_state, VaultLockState::Locked);
        assert!(status.network_policy.outbound_only());
        assert_eq!(status.supported_assets.len(), 3);
    }

    #[test]
    fn signing_is_not_available_in_phase_three() {
        let core = VaultCore::default();
        assert_eq!(
            core.authorize(CoreAction::SignTransaction),
            CoreDecision::Denied("signing is not implemented in Phase 2")
        );
    }

    #[test]
    fn local_vault_unlocks_and_locks_without_exposing_via_status() {
        let path = unique_vault_path();
        let mut core = VaultCore::default();
        core.create_local_vault(
            &path,
            b"correct horse battery staple",
            b"synthetic-wallet-secret",
        )
        .unwrap();

        assert_eq!(core.foundation_status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        core.unlock_local_vault(&path, b"correct horse battery staple")
            .unwrap();
        assert_eq!(core.foundation_status().lock_state, VaultLockState::Unlocked);
        assert_eq!(core.wallet_secret().unwrap(), b"synthetic-wallet-secret");

        core.lock();
        assert_eq!(core.foundation_status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn wrong_password_does_not_unlock_core() {
        let path = unique_vault_path();
        let mut core = VaultCore::default();
        core.create_local_vault(&path, b"right-password", b"secret")
            .unwrap();

        assert!(core.unlock_local_vault(&path, b"wrong-password").is_err());
        assert_eq!(core.foundation_status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
