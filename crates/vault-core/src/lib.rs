#![forbid(unsafe_code)]

use std::{error::Error, fmt, path::Path};
use vault_crypto::{KdfParams, SecretBytes, VaultDomain, VaultError, open, seal};
use vault_monero::{MoneroNetwork, NodeMode, remote_node_privacy_notice};
use vault_network::NetworkPolicy;
use vault_policy::{Asset, CoreAction, CoreDecision, PolicyEngine};
use vault_storage::{StorageError, read_envelope, write_new_envelope_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLockState {
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assurance {
    Configured,
    Detected,
    Verified,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityCategory {
    Vault,
    Network,
    Privacy,
    Application,
    Backup,
    TransactionProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub category: SecurityCategory,
    pub control: &'static str,
    pub assurance: Assurance,
    pub detail: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReport {
    pub findings: Vec<SecurityFinding>,
}

impl SecurityReport {
    pub fn verified_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.assurance == Assurance::Verified)
            .count()
    }

    pub fn unknown_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.assurance == Assurance::Unknown)
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoneroSupportStatus {
    pub default_network: MoneroNetwork,
    pub node_modes: [NodeMode; 3],
    pub mainnet_enabled: bool,
    pub transaction_signing_enabled: bool,
    pub remote_node_privacy_notice: &'static str,
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

    pub fn monero_status(&self) -> MoneroSupportStatus {
        MoneroSupportStatus {
            default_network: MoneroNetwork::Stagenet,
            node_modes: [
                NodeMode::AutomaticRemote,
                NodeMode::CustomRemote,
                NodeMode::Local,
            ],
            mainnet_enabled: false,
            transaction_signing_enabled: false,
            remote_node_privacy_notice: remote_node_privacy_notice(),
        }
    }

    pub fn security_report(&self) -> SecurityReport {
        let outbound = self.network_policy.outbound_only();
        SecurityReport {
            findings: vec![
                SecurityFinding {
                    category: SecurityCategory::Vault,
                    control: "Vault encryption",
                    assurance: Assurance::Verified,
                    detail: "Authenticated local cryptographic vault is implemented",
                },
                SecurityFinding {
                    category: SecurityCategory::Vault,
                    control: "Vault lock state",
                    assurance: Assurance::Detected,
                    detail: if self.lock_state == VaultLockState::Locked {
                        "Vault is locked"
                    } else {
                        "Vault is unlocked"
                    },
                },
                SecurityFinding {
                    category: SecurityCategory::Vault,
                    control: "Automatic lock",
                    assurance: Assurance::Unknown,
                    detail: "Automatic lock policy is not configured",
                },
                SecurityFinding {
                    category: SecurityCategory::Network,
                    control: "Outbound-only policy",
                    assurance: if outbound {
                        Assurance::Verified
                    } else {
                        Assurance::Detected
                    },
                    detail: if outbound {
                        "Application policy requires no inbound listener or NAT mapping"
                    } else {
                        "Network policy permits an inbound capability"
                    },
                },
                SecurityFinding {
                    category: SecurityCategory::Network,
                    control: "Monero node modes",
                    assurance: Assurance::Configured,
                    detail: "Automatic remote, custom remote, and loopback local-node modes are available",
                },
                SecurityFinding {
                    category: SecurityCategory::Network,
                    control: "Active backend",
                    assurance: Assurance::Unknown,
                    detail: "No live chain backend is connected",
                },
                SecurityFinding {
                    category: SecurityCategory::Privacy,
                    control: "Application telemetry",
                    assurance: Assurance::Configured,
                    detail: "No analytics or usage telemetry subsystem is configured",
                },
                SecurityFinding {
                    category: SecurityCategory::Application,
                    control: "Release signature",
                    assurance: Assurance::Unknown,
                    detail: "Runtime release-signature verification is not implemented",
                },
                SecurityFinding {
                    category: SecurityCategory::Application,
                    control: "Update verification",
                    assurance: Assurance::Unknown,
                    detail: "Authenticated update verification is not implemented",
                },
                SecurityFinding {
                    category: SecurityCategory::Backup,
                    control: "Recovery backup",
                    assurance: Assurance::Unknown,
                    detail: "Backup state has not been verified",
                },
                SecurityFinding {
                    category: SecurityCategory::Backup,
                    control: "Recovery verification",
                    assurance: Assurance::Unknown,
                    detail: "Recovery material has not been verified",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Transaction signing",
                    assurance: Assurance::Configured,
                    detail: "Transaction signing is disabled by policy",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Transaction review",
                    assurance: Assurance::Unknown,
                    detail: "Pre-sign transaction review is not implemented",
                },
            ],
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
        let status = core.status();
        assert_eq!(status.lock_state, VaultLockState::Locked);
        assert!(status.network_policy.outbound_only());
        assert_eq!(status.supported_assets.len(), 3);
    }

    #[test]
    fn security_report_is_truthful_about_verified_and_unknown_controls() {
        let report = VaultCore::default().security_report();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.control == "Vault encryption" && f.assurance == Assurance::Verified)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.control == "Outbound-only policy" && f.assurance == Assurance::Verified)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.control == "Recovery backup" && f.assurance == Assurance::Unknown)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.control == "Release signature" && f.assurance == Assurance::Unknown)
        );
        assert_eq!(report.verified_count(), 2);
        assert!(report.unknown_count() >= 1);
    }

    #[test]
    fn monero_support_is_non_mainnet_and_outbound_client_only() {
        let status = VaultCore::default().monero_status();
        assert_eq!(status.default_network, MoneroNetwork::Stagenet);
        assert_eq!(
            status.node_modes,
            [
                NodeMode::AutomaticRemote,
                NodeMode::CustomRemote,
                NodeMode::Local
            ]
        );
        assert!(!status.mainnet_enabled);
        assert!(!status.transaction_signing_enabled);
        assert!(
            status
                .remote_node_privacy_notice
                .contains("network metadata")
        );
    }

    #[test]
    fn signing_is_disabled() {
        let core = VaultCore::default();
        assert_eq!(
            core.authorize(CoreAction::SignTransaction),
            CoreDecision::Denied("transaction signing is disabled")
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

        assert_eq!(core.status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        core.unlock_local_vault(&path, b"correct horse battery staple")
            .unwrap();
        assert_eq!(core.status().lock_state, VaultLockState::Unlocked);
        assert_eq!(core.wallet_secret().unwrap(), b"synthetic-wallet-secret");

        core.lock();
        assert_eq!(core.status().lock_state, VaultLockState::Locked);
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
        assert_eq!(core.status().lock_state, VaultLockState::Locked);
        assert!(core.wallet_secret().is_none());

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
