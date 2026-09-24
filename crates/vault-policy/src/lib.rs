#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Bitcoin,
    Monero,
    Zcash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreAction {
    ViewStatus,
    SignBitcoinTestTransaction,
    SignTransaction,
    ExportPrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreDecision {
    Allowed,
    Denied(&'static str),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(&self, action: CoreAction, vault_unlocked: bool) -> CoreDecision {
        match action {
            CoreAction::ViewStatus => CoreDecision::Allowed,
            CoreAction::SignBitcoinTestTransaction if vault_unlocked => CoreDecision::Allowed,
            CoreAction::SignBitcoinTestTransaction => {
                CoreDecision::Denied("vault must be unlocked for bitcoin test signing")
            }
            CoreAction::SignTransaction => CoreDecision::Denied("mainnet transaction signing is disabled"),
            CoreAction::ExportPrivateKey => {
                CoreDecision::Denied("raw private-key export is disabled")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_test_signing_requires_unlocked_vault() {
        let engine = PolicyEngine;
        assert_eq!(
            engine.evaluate(CoreAction::SignBitcoinTestTransaction, false),
            CoreDecision::Denied("vault must be unlocked for bitcoin test signing")
        );
        assert_eq!(
            engine.evaluate(CoreAction::SignBitcoinTestTransaction, true),
            CoreDecision::Allowed
        );
    }

    #[test]
    fn mainnet_signing_and_key_export_remain_denied() {
        let engine = PolicyEngine;
        assert!(matches!(
            engine.evaluate(CoreAction::SignTransaction, true),
            CoreDecision::Denied(_)
        ));
        assert!(matches!(
            engine.evaluate(CoreAction::ExportPrivateKey, true),
            CoreDecision::Denied(_)
        ));
    }

    #[test]
    fn status_is_available_without_unlocking() {
        let engine = PolicyEngine;
        assert_eq!(
            engine.evaluate(CoreAction::ViewStatus, false),
            CoreDecision::Allowed
        );
    }
}
