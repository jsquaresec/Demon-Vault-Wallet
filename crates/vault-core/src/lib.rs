#![forbid(unsafe_code)]

use vault_network::NetworkPolicy;
use vault_policy::{Asset, CoreAction, CoreDecision, PolicyEngine};

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
}

impl Default for VaultCore {
    fn default() -> Self {
        Self {
            lock_state: VaultLockState::Locked,
            policy: PolicyEngine,
            network_policy: NetworkPolicy::default(),
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
        self.policy.evaluate(action, self.lock_state == VaultLockState::Unlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_starts_locked_and_outbound_only() {
        let core = VaultCore::default();
        let status = core.foundation_status();
        assert_eq!(status.lock_state, VaultLockState::Locked);
        assert!(status.network_policy.outbound_only());
        assert_eq!(status.supported_assets.len(), 3);
    }

    #[test]
    fn signing_is_not_available_in_foundation() {
        let core = VaultCore::default();
        assert_eq!(
            core.authorize(CoreAction::SignTransaction),
            CoreDecision::Denied("signing is not implemented in Phase 2")
        );
    }
}
