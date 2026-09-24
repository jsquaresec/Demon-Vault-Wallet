#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Bitcoin,
    Monero,
    Zcash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreAction {
    ViewFoundationStatus,
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
    pub fn evaluate(&self, action: CoreAction, _vault_unlocked: bool) -> CoreDecision {
        match action {
            CoreAction::ViewFoundationStatus => CoreDecision::Allowed,
            CoreAction::SignTransaction => {
                CoreDecision::Denied("signing is not implemented in Phase 2")
            }
            CoreAction::ExportPrivateKey => {
                CoreDecision::Denied("raw private-key export is outside the Phase 2 foundation")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_two_denies_signing_and_key_export() {
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
}
