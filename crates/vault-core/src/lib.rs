#![forbid(unsafe_code)]

use std::{error::Error, fmt, path::Path};
use vault_crypto::{KdfParams, SecretBytes, VaultDomain, VaultError, open, seal};
use vault_monero::{MoneroNetwork, NodeMode};
use vault_network::NetworkPolicy;
use vault_policy::{Asset, CoreAction, CoreDecision, PolicyEngine};
use vault_storage::{StorageError, read_envelope, write_new_envelope_atomic};
use vault_zcash::{PrivacyPolicy, ZcashNetwork};

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
pub struct CoreStatus {
    pub lock_state: VaultLockState,
    pub network_policy: NetworkPolicy,
    pub supported_assets: [Asset; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapDeskStatus {
    pub provider_boundary_ready: bool,
    pub webhook_transport_ready: bool,
    pub webhook_configured: bool,
    pub anonymous_schema_enforced: bool,
}

pub struct VaultCore {
    lock_state: VaultLockState,
    policy: PolicyEngine,
    network_policy: NetworkPolicy,
    monero_network: MoneroNetwork,
    monero_node_mode: NodeMode,
    zcash_network: ZcashNetwork,
    zcash_privacy_policy: PrivacyPolicy,
    unlocked_wallet_secret: Option<SecretBytes>,
}

impl Default for VaultCore {
    fn default() -> Self {
        Self {
            lock_state: VaultLockState::Locked,
            policy: PolicyEngine,
            network_policy: NetworkPolicy::default(),
            monero_network: MoneroNetwork::Mainnet,
            monero_node_mode: NodeMode::default(),
            zcash_network: ZcashNetwork::Testnet,
            zcash_privacy_policy: PrivacyPolicy::ShieldedRequired,
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

    pub fn monero_network(&self) -> MoneroNetwork {
        self.monero_network
    }

    pub fn monero_node_mode(&self) -> &NodeMode {
        &self.monero_node_mode
    }

    pub fn zcash_network(&self) -> ZcashNetwork {
        self.zcash_network
    }

    pub fn zcash_privacy_policy(&self) -> PrivacyPolicy {
        self.zcash_privacy_policy
    }

    pub fn swapdesk_status(&self) -> SwapDeskStatus {
        SwapDeskStatus {
            provider_boundary_ready: true,
            webhook_transport_ready: true,
            webhook_configured: false,
            anonymous_schema_enforced: true,
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
                    category: SecurityCategory::Privacy,
                    control: "Monero remote-node trust",
                    assurance: Assurance::Configured,
                    detail: "Remote Monero nodes are untrusted and receive no wallet private keys",
                },
                SecurityFinding {
                    category: SecurityCategory::Privacy,
                    control: "Zcash shielded recipient policy",
                    assurance: Assurance::Configured,
                    detail: "Zcash defaults to shielded-only recipients and labels transparent addresses as non-private",
                },
                SecurityFinding {
                    category: SecurityCategory::Privacy,
                    control: "Swap notification privacy",
                    assurance: Assurance::Verified,
                    detail: "Discord swap events are restricted to provider, asset pair, and coarse status",
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
    fn monero_defaults_to_automatic_remote_without_changing_network_posture() {
        let core = VaultCore::default();
        assert_eq!(core.monero_network(), MoneroNetwork::Mainnet);
        assert_eq!(core.monero_node_mode(), &NodeMode::AutomaticRemote);
        assert!(core.status().network_policy.outbound_only());
    }

    #[test]
    fn zcash_defaults_to_testnet_and_shielded_only_policy() {
        let core = VaultCore::default();
        assert_eq!(core.zcash_network(), ZcashNetwork::Testnet);
        assert_eq!(core.zcash_privacy_policy(), PrivacyPolicy::ShieldedRequired);
        assert!(core.status().network_policy.outbound_only());
    }

    #[test]
    fn swapdesk_defaults_to_private_disabled_notification_state() {
        let status = VaultCore::default().swapdesk_status();
        assert!(status.provider_boundary_ready);
        assert!(status.webhook_transport_ready);
        assert!(status.anonymous_schema_enforced);
        assert!(!status.webhook_configured);
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
