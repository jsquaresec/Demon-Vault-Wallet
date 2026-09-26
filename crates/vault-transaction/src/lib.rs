#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const MAX_NETWORK_LEN: usize = 32;
const MAX_ADDRESS_LEN: usize = 256;
const MAX_OUTPUTS: usize = 64;
const MAX_MEMO_LEN: usize = 256;
const MAX_FEE_BPS: u64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionAsset {
    Bitcoin = 1,
    Monero = 2,
    Zcash = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputKind {
    Recipient = 1,
    Change = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewOutput {
    pub kind: OutputKind,
    pub address: String,
    pub amount_atomic: u64,
}

impl ReviewOutput {
    pub fn new(
        kind: OutputKind,
        address: &str,
        amount_atomic: u64,
    ) -> Result<Self, TransactionSecurityError> {
        if address.is_empty()
            || address.len() > MAX_ADDRESS_LEN
            || address.chars().any(char::is_control)
            || address.trim() != address
        {
            return Err(TransactionSecurityError::InvalidAddress);
        }
        if amount_atomic == 0 {
            return Err(TransactionSecurityError::InvalidAmount);
        }
        Ok(Self {
            kind,
            address: address.to_owned(),
            amount_atomic,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicy {
    pub max_absolute_atomic: u64,
    pub max_fee_basis_points: u64,
}

impl FeePolicy {
    pub fn new(
        max_absolute_atomic: u64,
        max_fee_basis_points: u64,
    ) -> Result<Self, TransactionSecurityError> {
        if max_absolute_atomic == 0 || max_fee_basis_points == 0 || max_fee_basis_points > MAX_FEE_BPS
        {
            return Err(TransactionSecurityError::InvalidFeePolicy);
        }
        Ok(Self {
            max_absolute_atomic,
            max_fee_basis_points,
        })
    }

    pub fn conservative_default() -> Self {
        Self {
            max_absolute_atomic: u64::MAX,
            max_fee_basis_points: 1_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionReviewRequest {
    pub asset: TransactionAsset,
    pub network: String,
    pub outputs: Vec<ReviewOutput>,
    pub fee_atomic: u64,
    pub transaction_binding: [u8; 32],
    pub memo: Option<String>,
    pub expires_at_unix: u64,
}

impl TransactionReviewRequest {
    pub fn new(
        asset: TransactionAsset,
        network: &str,
        outputs: Vec<ReviewOutput>,
        fee_atomic: u64,
        transaction_binding: [u8; 32],
        memo: Option<&str>,
        expires_at_unix: u64,
    ) -> Result<Self, TransactionSecurityError> {
        validate_network(network)?;
        if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
            return Err(TransactionSecurityError::InvalidOutputs);
        }
        if !outputs.iter().any(|output| output.kind == OutputKind::Recipient) {
            return Err(TransactionSecurityError::MissingRecipient);
        }
        if transaction_binding.iter().all(|byte| *byte == 0) {
            return Err(TransactionSecurityError::InvalidBinding);
        }
        if expires_at_unix == 0 {
            return Err(TransactionSecurityError::InvalidExpiry);
        }
        let memo = memo.map(str::to_owned);
        if memo.as_ref().is_some_and(|value| {
            value.len() > MAX_MEMO_LEN || value.chars().any(char::is_control)
        }) {
            return Err(TransactionSecurityError::InvalidMemo);
        }
        Ok(Self {
            asset,
            network: network.to_owned(),
            outputs,
            fee_atomic,
            transaction_binding,
            memo,
            expires_at_unix,
        })
    }

    pub fn recipient_total(&self) -> Result<u64, TransactionSecurityError> {
        self.outputs
            .iter()
            .filter(|output| output.kind == OutputKind::Recipient)
            .try_fold(0u64, |total, output| {
                total
                    .checked_add(output.amount_atomic)
                    .ok_or(TransactionSecurityError::ArithmeticOverflow)
            })
    }

    pub fn change_total(&self) -> Result<u64, TransactionSecurityError> {
        self.outputs
            .iter()
            .filter(|output| output.kind == OutputKind::Change)
            .try_fold(0u64, |total, output| {
                total
                    .checked_add(output.amount_atomic)
                    .ok_or(TransactionSecurityError::ArithmeticOverflow)
            })
    }

    pub fn ensure_fresh(&self, now_unix: u64) -> Result<(), TransactionSecurityError> {
        if now_unix >= self.expires_at_unix {
            return Err(TransactionSecurityError::ExpiredReview);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewSeverity {
    Info,
    Warning,
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewFinding {
    pub severity: ReviewSeverity,
    pub code: &'static str,
    pub detail: &'static str,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransactionReview {
    request: TransactionReviewRequest,
    fee_basis_points: u64,
    findings: Vec<ReviewFinding>,
    review_digest: [u8; 32],
    approval_nonce: [u8; 32],
}

impl fmt::Debug for TransactionReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionReview")
            .field("asset", &self.request.asset)
            .field("network", &self.request.network)
            .field("output_count", &self.request.outputs.len())
            .field("fee_atomic", &self.request.fee_atomic)
            .field("fee_basis_points", &self.fee_basis_points)
            .field("findings", &self.findings)
            .field("review_digest", &"<redacted>")
            .field("approval_nonce", &"<redacted>")
            .finish()
    }
}

impl TransactionReview {
    pub fn request(&self) -> &TransactionReviewRequest {
        &self.request
    }

    pub const fn fee_basis_points(&self) -> u64 {
        self.fee_basis_points
    }

    pub fn findings(&self) -> &[ReviewFinding] {
        &self.findings
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.review_digest
    }

    pub fn has_blocking_findings(&self) -> bool {
        let mut index = 0;
        while index < self.findings.len() {
            if matches!(self.findings[index].severity, ReviewSeverity::Blocking) {
                return true;
            }
            index += 1;
        }
        false
    }

    pub fn confirmation_code(&self) -> String {
        hex_prefix(&self.review_digest, 8)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransactionAuthorization {
    pub transaction_binding: [u8; 32],
    pub review_digest: [u8; 32],
    authorization: [u8; 32],
    pub expires_at_unix: u64,
}

impl fmt::Debug for TransactionAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionAuthorization")
            .field("transaction_binding", &"<redacted>")
            .field("review_digest", &"<redacted>")
            .field("authorization", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl TransactionAuthorization {
    pub const fn value(&self) -> [u8; 32] {
        self.authorization
    }

    pub fn validate_for(
        &self,
        transaction_binding: [u8; 32],
        now_unix: u64,
    ) -> Result<(), TransactionSecurityError> {
        if now_unix >= self.expires_at_unix {
            return Err(TransactionSecurityError::ExpiredAuthorization);
        }
        if transaction_binding != self.transaction_binding {
            return Err(TransactionSecurityError::AuthorizationMismatch);
        }
        Ok(())
    }
}

pub fn bind_unsigned_transaction(
    asset: TransactionAsset,
    network: &str,
    unsigned_transaction: &[u8],
) -> Result<[u8; 32], TransactionSecurityError> {
    validate_network(network)?;
    if unsigned_transaction.is_empty() || unsigned_transaction.len() > 1024 * 1024 {
        return Err(TransactionSecurityError::InvalidTransaction);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"demon-vault/unsigned-transaction/v1");
    hasher.update([asset as u8]);
    hasher.update((network.len() as u32).to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.update((unsigned_transaction.len() as u64).to_le_bytes());
    hasher.update(unsigned_transaction);
    Ok(hasher.finalize().into())
}

pub fn review_transaction(
    request: TransactionReviewRequest,
    fee_policy: FeePolicy,
    now_unix: u64,
) -> Result<TransactionReview, TransactionSecurityError> {
    request.ensure_fresh(now_unix)?;
    let recipient_total = request.recipient_total()?;
    if recipient_total == 0 {
        return Err(TransactionSecurityError::InvalidAmount);
    }

    let fee_basis_points = request
        .fee_atomic
        .checked_mul(10_000)
        .ok_or(TransactionSecurityError::ArithmeticOverflow)?
        .checked_div(recipient_total)
        .ok_or(TransactionSecurityError::ArithmeticOverflow)?;

    let mut findings = Vec::new();
    if request.fee_atomic > fee_policy.max_absolute_atomic {
        findings.push(ReviewFinding {
            severity: ReviewSeverity::Blocking,
            code: "fee-absolute-limit",
            detail: "fee exceeds the configured absolute safety limit",
        });
    }
    if fee_basis_points > fee_policy.max_fee_basis_points {
        findings.push(ReviewFinding {
            severity: ReviewSeverity::Blocking,
            code: "fee-relative-limit",
            detail: "fee exceeds the configured relative safety limit",
        });
    }
    if request.outputs.len() > 8 {
        findings.push(ReviewFinding {
            severity: ReviewSeverity::Warning,
            code: "many-outputs",
            detail: "transaction contains an unusually large number of outputs",
        });
    }
    if request
        .outputs
        .iter()
        .filter(|output| output.kind == OutputKind::Change)
        .count()
        > 1
    {
        findings.push(ReviewFinding {
            severity: ReviewSeverity::Warning,
            code: "multiple-change-outputs",
            detail: "transaction contains multiple change outputs",
        });
    }
    if findings.is_empty() {
        findings.push(ReviewFinding {
            severity: ReviewSeverity::Info,
            code: "review-ready",
            detail: "transaction passed configured pre-sign safety checks",
        });
    }

    let review_digest = review_digest(&request, fee_basis_points)?;
    let mut approval_nonce = [0u8; 32];
    getrandom::fill(&mut approval_nonce).map_err(|_| TransactionSecurityError::RandomnessUnavailable)?;

    Ok(TransactionReview {
        request,
        fee_basis_points,
        findings,
        review_digest,
        approval_nonce,
    })
}

pub fn authorize_review(
    review: &TransactionReview,
    typed_confirmation: &str,
    now_unix: u64,
) -> Result<TransactionAuthorization, TransactionSecurityError> {
    review.request.ensure_fresh(now_unix)?;
    if review.has_blocking_findings() {
        return Err(TransactionSecurityError::BlockedByPolicy);
    }
    if typed_confirmation != review.confirmation_code() {
        return Err(TransactionSecurityError::ConfirmationMismatch);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"demon-vault/transaction-authorization/v1");
    hasher.update(review.request.transaction_binding);
    hasher.update(review.review_digest);
    hasher.update(review.approval_nonce);
    hasher.update(review.request.expires_at_unix.to_le_bytes());
    let authorization: [u8; 32] = hasher.finalize().into();

    Ok(TransactionAuthorization {
        transaction_binding: review.request.transaction_binding,
        review_digest: review.review_digest,
        authorization,
        expires_at_unix: review.request.expires_at_unix,
    })
}

fn review_digest(
    request: &TransactionReviewRequest,
    fee_basis_points: u64,
) -> Result<[u8; 32], TransactionSecurityError> {
    let mut hasher = Sha256::new();
    hasher.update(b"demon-vault/transaction-review/v1");
    hasher.update([request.asset as u8]);
    hasher.update((request.network.len() as u32).to_le_bytes());
    hasher.update(request.network.as_bytes());
    hasher.update((request.outputs.len() as u32).to_le_bytes());
    for output in &request.outputs {
        hasher.update([output.kind as u8]);
        hasher.update((output.address.len() as u32).to_le_bytes());
        hasher.update(output.address.as_bytes());
        hasher.update(output.amount_atomic.to_le_bytes());
    }
    hasher.update(request.fee_atomic.to_le_bytes());
    hasher.update(fee_basis_points.to_le_bytes());
    hasher.update(request.transaction_binding);
    if let Some(memo) = &request.memo {
        hasher.update([1]);
        hasher.update((memo.len() as u32).to_le_bytes());
        hasher.update(memo.as_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.update(request.expires_at_unix.to_le_bytes());
    Ok(hasher.finalize().into())
}

fn validate_network(network: &str) -> Result<(), TransactionSecurityError> {
    if network.is_empty()
        || network.len() > MAX_NETWORK_LEN
        || !network
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(TransactionSecurityError::InvalidNetwork);
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .take(count)
        .flat_map(|byte| {
            let high = HEX[(byte >> 4) as usize] as char;
            let low = HEX[(byte & 0x0f) as usize] as char;
            [high, low]
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionSecurityError {
    InvalidNetwork,
    InvalidAddress,
    InvalidAmount,
    InvalidTransaction,
    InvalidOutputs,
    MissingRecipient,
    InvalidBinding,
    InvalidExpiry,
    InvalidMemo,
    InvalidFeePolicy,
    ArithmeticOverflow,
    ExpiredReview,
    BlockedByPolicy,
    ConfirmationMismatch,
    ExpiredAuthorization,
    AuthorizationMismatch,
    RandomnessUnavailable,
}

impl fmt::Display for TransactionSecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNetwork => write!(formatter, "invalid transaction network"),
            Self::InvalidAddress => write!(formatter, "invalid transaction review address"),
            Self::InvalidAmount => write!(formatter, "invalid transaction amount"),
            Self::InvalidTransaction => write!(formatter, "invalid unsigned transaction"),
            Self::InvalidOutputs => write!(formatter, "invalid transaction outputs"),
            Self::MissingRecipient => write!(formatter, "transaction has no recipient output"),
            Self::InvalidBinding => write!(formatter, "invalid transaction binding"),
            Self::InvalidExpiry => write!(formatter, "invalid transaction review expiry"),
            Self::InvalidMemo => write!(formatter, "invalid transaction memo"),
            Self::InvalidFeePolicy => write!(formatter, "invalid fee safety policy"),
            Self::ArithmeticOverflow => write!(formatter, "transaction arithmetic overflow"),
            Self::ExpiredReview => write!(formatter, "transaction review has expired"),
            Self::BlockedByPolicy => write!(formatter, "transaction is blocked by safety policy"),
            Self::ConfirmationMismatch => write!(formatter, "transaction confirmation does not match review"),
            Self::ExpiredAuthorization => write!(formatter, "transaction authorization has expired"),
            Self::AuthorizationMismatch => write!(formatter, "transaction authorization does not match"),
            Self::RandomnessUnavailable => write!(formatter, "secure randomness unavailable"),
        }
    }
}

impl Error for TransactionSecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(fee: u64) -> TransactionReviewRequest {
        TransactionReviewRequest::new(
            TransactionAsset::Bitcoin,
            "testnet",
            vec![
                ReviewOutput::new(OutputKind::Recipient, "tb1qrecipient", 100_000).unwrap(),
                ReviewOutput::new(OutputKind::Change, "tb1qchange", 50_000).unwrap(),
            ],
            fee,
            [9u8; 32],
            None,
            10_000,
        )
        .unwrap()
    }

    #[test]
    fn unsigned_transaction_binding_changes_with_transaction_or_network() {
        let first = bind_unsigned_transaction(
            TransactionAsset::Bitcoin,
            "testnet",
            &[1, 2, 3],
        )
        .unwrap();
        let second = bind_unsigned_transaction(
            TransactionAsset::Bitcoin,
            "testnet",
            &[1, 2, 4],
        )
        .unwrap();
        let other_network = bind_unsigned_transaction(
            TransactionAsset::Bitcoin,
            "regtest",
            &[1, 2, 3],
        )
        .unwrap();
        assert_ne!(first, second);
        assert_ne!(first, other_network);
    }

    #[test]
    fn review_digest_changes_when_recipient_changes() {
        let first = review_transaction(request(500), FeePolicy::conservative_default(), 1).unwrap();
        let mut second_request = request(500);
        second_request.outputs[0].address = "tb1qother".into();
        let second =
            review_transaction(second_request, FeePolicy::conservative_default(), 1).unwrap();
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn excessive_fee_blocks_authorization() {
        let review = review_transaction(
            request(20_000),
            FeePolicy::new(5_000, 1_000).unwrap(),
            1,
        )
        .unwrap();
        assert!(review.has_blocking_findings());
        assert_eq!(
            authorize_review(&review, &review.confirmation_code(), 2).unwrap_err(),
            TransactionSecurityError::BlockedByPolicy
        );
    }

    #[test]
    fn approval_requires_exact_displayed_confirmation() {
        let review = review_transaction(request(500), FeePolicy::conservative_default(), 1).unwrap();
        assert_eq!(
            authorize_review(&review, "wrong", 2).unwrap_err(),
            TransactionSecurityError::ConfirmationMismatch
        );
        let authorization =
            authorize_review(&review, &review.confirmation_code(), 2).unwrap();
        assert!(authorization.validate_for([9u8; 32], 3).is_ok());
        assert_eq!(
            authorization.validate_for([8u8; 32], 3).unwrap_err(),
            TransactionSecurityError::AuthorizationMismatch
        );
    }

    #[test]
    fn expired_reviews_and_authorizations_fail_closed() {
        let review =
            review_transaction(request(500), FeePolicy::conservative_default(), 9_999).unwrap();
        assert_eq!(
            authorize_review(&review, &review.confirmation_code(), 10_000).unwrap_err(),
            TransactionSecurityError::ExpiredReview
        );

        let authorization =
            authorize_review(&review, &review.confirmation_code(), 9_999).unwrap();
        assert_eq!(
            authorization.validate_for([9u8; 32], 10_000).unwrap_err(),
            TransactionSecurityError::ExpiredAuthorization
        );
    }

    #[test]
    fn debug_output_does_not_expose_bindings_or_nonce() {
        let review = review_transaction(request(500), FeePolicy::conservative_default(), 1).unwrap();
        let debug = format!("{review:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("[9, 9"));
    }
}
