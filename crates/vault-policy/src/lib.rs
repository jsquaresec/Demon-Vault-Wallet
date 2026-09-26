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
    ReviewTransaction,
    AuthorizeReviewedTransaction,
    PrepareExternalSigning,
    ImportExternalSignature,
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
            CoreAction::ViewStatus => CoreDecision::Allowed,
            CoreAction::ReviewTransaction
            | CoreAction::AuthorizeReviewedTransaction
            | CoreAction::PrepareExternalSigning
            | CoreAction::ImportExternalSignature => {
                if _vault_unlocked {
                    CoreDecision::Allowed
                } else {
                    CoreDecision::Denied("vault must be unlocked for protected transaction operations")
                }
            }
            CoreAction::SignTransaction => CoreDecision::Denied("transaction signing is disabled"),
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
    fn sensitive_unavailable_operations_are_denied() {
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
    fn transaction_review_and_authorization_require_unlocked_vault() {
        let engine = PolicyEngine;
        assert_eq!(
            engine.evaluate(CoreAction::ReviewTransaction, false),
            CoreDecision::Denied("vault must be unlocked for protected transaction operations")
        );
        assert_eq!(
            engine.evaluate(CoreAction::ReviewTransaction, true),
            CoreDecision::Allowed
        );
        assert_eq!(
            engine.evaluate(CoreAction::AuthorizeReviewedTransaction, true),
            CoreDecision::Allowed
        );
    }

    #[test]
    fn external_signing_requires_unlocked_vault() {
        let engine = PolicyEngine;
        assert_eq!(
            engine.evaluate(CoreAction::PrepareExternalSigning, false),
            CoreDecision::Denied("vault must be unlocked for protected transaction operations")
        );
        assert_eq!(
            engine.evaluate(CoreAction::PrepareExternalSigning, true),
            CoreDecision::Allowed
        );
        assert_eq!(
            engine.evaluate(CoreAction::ImportExternalSignature, true),
            CoreDecision::Allowed
        );
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
