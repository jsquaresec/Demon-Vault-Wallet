#![forbid(unsafe_code)]

use std::{error::Error, fmt, path::Path};
use vault_crypto::{KdfParams, SecretBytes, VaultDomain, VaultError, open, seal};
use vault_monero::{MoneroNetwork, NodeMode};
use vault_network::{NetworkPolicy, NetworkPrivacyConfig, PrivacyRoute};
use vault_policy::{Asset, CoreAction, CoreDecision, PolicyEngine};
use vault_signing::{SignedTransaction, SigningAsset, SigningError, SigningMode, SigningRequest};
use vault_storage::{StorageError, read_envelope, write_new_envelope_atomic};
use vault_transaction::{
    FeePolicy, TransactionAuthorization, TransactionReview, TransactionReviewRequest,
    TransactionSecurityError, TransactionAsset, authorize_review, bind_unsigned_transaction,
    review_transaction,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSigningStatus {
    pub hardware_boundary_ready: bool,
    pub offline_packages_ready: bool,
    pub private_key_export_enabled: bool,
    pub live_device_connected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionSecurityStatus {
    pub pre_sign_review_ready: bool,
    pub fee_limits_ready: bool,
    pub exact_binding_ready: bool,
    pub typed_confirmation_required: bool,
}

pub struct VaultCore {
    lock_state: VaultLockState,
    policy: PolicyEngine,
    network_policy: NetworkPolicy,
    network_privacy: NetworkPrivacyConfig,
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
            network_privacy: NetworkPrivacyConfig::default(),
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

    pub fn network_privacy(&self) -> &NetworkPrivacyConfig {
        &self.network_privacy
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

    pub fn external_signing_status(&self) -> ExternalSigningStatus {
        ExternalSigningStatus {
            hardware_boundary_ready: true,
            offline_packages_ready: true,
            private_key_export_enabled: false,
            live_device_connected: false,
        }
    }

    pub fn transaction_security_status(&self) -> TransactionSecurityStatus {
        TransactionSecurityStatus {
            pre_sign_review_ready: true,
            fee_limits_ready: true,
            exact_binding_ready: true,
            typed_confirmation_required: true,
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
                    control: "TLS fail-closed",
                    assurance: if self.network_privacy.tls_fail_closed() {
                        Assurance::Verified
                    } else {
                        Assurance::Detected
                    },
                    detail: if self.network_privacy.tls_fail_closed() {
                        "Remote plaintext and invalid-certificate bypass are disabled"
                    } else {
                        "Network transport permits an unsafe certificate policy"
                    },
                },
                SecurityFinding {
                    category: SecurityCategory::Privacy,
                    control: "Network metadata minimization",
                    assurance: if self.network_privacy.privacy_hardened() {
                        Assurance::Verified
                    } else {
                        Assurance::Detected
                    },
                    detail: if self.network_privacy.privacy_hardened() {
                        "Referer, persistent cookies, response cache, device identifiers, and redirects are disabled"
                    } else {
                        "A network metadata-minimization control is disabled"
                    },
                },
                SecurityFinding {
                    category: SecurityCategory::Network,
                    control: "Privacy route",
                    assurance: Assurance::Configured,
                    detail: match self.network_privacy.route {
                        PrivacyRoute::Direct => "Direct outbound routing is configured",
                        PrivacyRoute::Proxy => "Explicit proxy routing is configured",
                        PrivacyRoute::Tor => "Tor routing is configured",
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
                    control: "External signing boundary",
                    assurance: Assurance::Verified,
                    detail: "Hardware and offline signing requests are cryptographically bound and exclude private-key export",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Live hardware signer",
                    assurance: Assurance::Unknown,
                    detail: "No hardware device is currently connected or verified",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Transaction review",
                    assurance: Assurance::Verified,
                    detail: "Pre-sign review binds recipients, amounts, fees, network, transaction bytes, expiry, and explicit confirmation",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Fee safety limits",
                    assurance: Assurance::Verified,
                    detail: "Absolute and relative fee limits can block authorization before signing",
                },
                SecurityFinding {
                    category: SecurityCategory::TransactionProtection,
                    control: "Transaction signing",
                    assurance: Assurance::Configured,
                    detail: "Generic unreviewed signing remains disabled; reviewed external signing is authorized through the transaction-security boundary",
                },
            ],
        }
    }

    pub fn authorize(&self, action: CoreAction) -> CoreDecision {
        self.policy
            .evaluate(action, self.lock_state == VaultLockState::Unlocked)
    }

    pub fn review_transaction(
        &self,
        request: TransactionReviewRequest,
        fee_policy: FeePolicy,
        now_unix: u64,
    ) -> Result<TransactionReview, CoreTransactionError> {
        match self.authorize(CoreAction::ReviewTransaction) {
            CoreDecision::Allowed => {}
            CoreDecision::Denied(reason) => return Err(CoreTransactionError::PolicyDenied(reason)),
        }
        review_transaction(request, fee_policy, now_unix).map_err(CoreTransactionError::Security)
    }

    pub fn authorize_transaction_review(
        &self,
        review: &TransactionReview,
        typed_confirmation: &str,
        now_unix: u64,
    ) -> Result<TransactionAuthorization, CoreTransactionError> {
        match self.authorize(CoreAction::AuthorizeReviewedTransaction) {
            CoreDecision::Allowed => {}
            CoreDecision::Denied(reason) => return Err(CoreTransactionError::PolicyDenied(reason)),
        }
        authorize_review(review, typed_confirmation, now_unix).map_err(CoreTransactionError::Security)
    }

    pub fn prepare_external_signing(
        &self,
        asset: SigningAsset,
        mode: SigningMode,
        network: &str,
        unsigned_transaction: Vec<u8>,
        authorization: &TransactionAuthorization,
        now_unix: u64,
    ) -> Result<SigningRequest, CoreSigningError> {
        match self.authorize(CoreAction::PrepareExternalSigning) {
            CoreDecision::Allowed => {}
            CoreDecision::Denied(reason) => return Err(CoreSigningError::PolicyDenied(reason)),
        }

        let review_asset = match asset {
            SigningAsset::Bitcoin => TransactionAsset::Bitcoin,
            SigningAsset::Monero => TransactionAsset::Monero,
            SigningAsset::Zcash => TransactionAsset::Zcash,
        };
        let transaction_binding =
            bind_unsigned_transaction(review_asset, network, &unsigned_transaction)
                .map_err(CoreSigningError::TransactionSecurity)?;
        authorization
            .validate_for(transaction_binding, now_unix)
            .map_err(CoreSigningError::TransactionSecurity)?;

        SigningRequest::new(
            asset,
            mode,
            network,
            unsigned_transaction,
            authorization.value(),
            authorization.expires_at_unix,
        )
        .map_err(CoreSigningError::Signing)
    }

    pub fn import_external_signature(
        &self,
        request: &SigningRequest,
        package: &[u8],
        now_unix: u64,
    ) -> Result<SignedTransaction, CoreSigningError> {
        match self.authorize(CoreAction::ImportExternalSignature) {
            CoreDecision::Allowed => {}
            CoreDecision::Denied(reason) => return Err(CoreSigningError::PolicyDenied(reason)),
        }
        request
            .ensure_fresh(now_unix)
            .map_err(CoreSigningError::Signing)?;
        let signed =
            vault_signing::import_offline_signature(package).map_err(CoreSigningError::Signing)?;
        vault_signing::validate_signed_transaction(request, &signed)
            .map_err(CoreSigningError::Signing)?;
        Ok(signed)
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
pub enum CoreSigningError {
    PolicyDenied(&'static str),
    Signing(SigningError),
    TransactionSecurity(TransactionSecurityError),
}

impl fmt::Display for CoreSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied(reason) => write!(formatter, "external signing denied: {reason}"),
            Self::Signing(error) => write!(formatter, "external signing error: {error}"),
            Self::TransactionSecurity(error) => {
                write!(formatter, "transaction security error: {error}")
            }
        }
    }
}

impl Error for CoreSigningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Signing(error) => Some(error),
            Self::TransactionSecurity(error) => Some(error),
            Self::PolicyDenied(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum CoreTransactionError {
    PolicyDenied(&'static str),
    Security(TransactionSecurityError),
}

impl fmt::Display for CoreTransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied(reason) => write!(formatter, "transaction review denied: {reason}"),
            Self::Security(error) => write!(formatter, "transaction security error: {error}"),
        }
    }
}

impl Error for CoreTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::PolicyDenied(_) => None,
        }
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
        assert!(report.findings.iter().any(|f| {
            f.control == "Swap notification privacy" && f.assurance == Assurance::Verified
        }));
        assert!(report.verified_count() >= 3);
        assert!(report.unknown_count() >= 1);
    }

    #[test]
    fn network_privacy_defaults_are_hardened() {
        let core = VaultCore::default();
        assert_eq!(core.network_privacy().route, PrivacyRoute::Direct);
        assert!(core.network_privacy().tls_fail_closed());
        assert!(core.network_privacy().privacy_hardened());
        assert!(core.network_privacy().validate().is_ok());
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
    fn transaction_security_boundary_is_ready() {
        let status = VaultCore::default().transaction_security_status();
        assert!(status.pre_sign_review_ready);
        assert!(status.fee_limits_ready);
        assert!(status.exact_binding_ready);
        assert!(status.typed_confirmation_required);
    }

    #[test]
    fn external_signing_boundary_is_ready_without_enabling_key_export() {
        let status = VaultCore::default().external_signing_status();
        assert!(status.hardware_boundary_ready);
        assert!(status.offline_packages_ready);
        assert!(!status.private_key_export_enabled);
        assert!(!status.live_device_connected);
    }

    #[test]
    fn reviewed_transaction_authorization_is_required_for_external_signing() {
        let unsigned = vec![1, 2, 3];
        let binding =
            bind_unsigned_transaction(TransactionAsset::Bitcoin, "testnet", &unsigned).unwrap();
        let review_request = TransactionReviewRequest::new(
            TransactionAsset::Bitcoin,
            "testnet",
            vec![vault_transaction::ReviewOutput::new(
                vault_transaction::OutputKind::Recipient,
                "tb1qrecipient",
                100_000,
            )
            .unwrap()],
            500,
            binding,
            None,
            5_000,
        )
        .unwrap();

        let locked = VaultCore::default();
        assert!(matches!(
            locked.review_transaction(review_request.clone(), FeePolicy::conservative_default(), 1),
            Err(CoreTransactionError::PolicyDenied(_))
        ));

        let core = VaultCore {
            lock_state: VaultLockState::Unlocked,
            ..VaultCore::default()
        };
        let review = core
            .review_transaction(review_request, FeePolicy::conservative_default(), 1)
            .unwrap();
        let authorization = core
            .authorize_transaction_review(&review, &review.confirmation_code(), 2)
            .unwrap();

        let request = core
            .prepare_external_signing(
                SigningAsset::Bitcoin,
                SigningMode::Offline,
                "testnet",
                unsigned,
                &authorization,
                3,
            )
            .unwrap();
        let signed = SignedTransaction::new(request.binding(), vec![4, 5, 6]).unwrap();
        let package = vault_signing::export_offline_signature(&signed).unwrap();
        assert_eq!(
            core.import_external_signature(&request, &package, 4_000)
                .unwrap(),
            signed
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
