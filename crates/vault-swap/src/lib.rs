#![forbid(unsafe_code)]

mod integration;
pub use integration::*;

use std::{error::Error, fmt};

const MAX_PROVIDER_ID_LEN: usize = 32;
const MAX_REFERENCE_LEN: usize = 128;
const MAX_ADDRESS_LEN: usize = 256;
const DISCORD_WEBHOOK_PREFIX: &str = "https://discord.com/api/webhooks/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapAsset {
    Bitcoin,
    Monero,
    Zcash,
}

impl SwapAsset {
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Bitcoin => "BTC",
            Self::Monero => "XMR",
            Self::Zcash => "ZEC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapPair {
    pub from: SwapAsset,
    pub to: SwapAsset,
}

impl SwapPair {
    pub fn new(from: SwapAsset, to: SwapAsset) -> Result<Self, SwapError> {
        if from == to {
            return Err(SwapError::SameAssetPair);
        }
        Ok(Self { from, to })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProviderId(String);

impl fmt::Debug for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProviderId").field(&self.0).finish()
    }
}

impl ProviderId {
    pub fn new(value: &str) -> Result<Self, SwapError> {
        if value.is_empty()
            || value.len() > MAX_PROVIDER_ID_LEN
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SwapError::InvalidProviderId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: &str, max_len: usize) -> Result<Self, SwapError> {
        if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
            return Err(SwapError::InvalidSensitiveValue);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicAmount(u64);

impl AtomicAmount {
    pub fn new(value: u64) -> Result<Self, SwapError> {
        if value == 0 {
            return Err(SwapError::AmountTooSmall);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct QuoteRequest {
    pub pair: SwapPair,
    pub amount: AtomicAmount,
}

impl fmt::Debug for QuoteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuoteRequest")
            .field("pair", &self.pair)
            .field("amount", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SwapQuote {
    pub provider: ProviderId,
    pub pair: SwapPair,
    pub input_amount: AtomicAmount,
    pub expected_output: AtomicAmount,
    pub expires_at_unix: u64,
    reference: SensitiveString,
}

impl fmt::Debug for SwapQuote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwapQuote")
            .field("provider", &self.provider)
            .field("pair", &self.pair)
            .field("input_amount", &"<redacted>")
            .field("expected_output", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("reference", &"<redacted>")
            .finish()
    }
}

impl SwapQuote {
    pub fn new(
        provider: ProviderId,
        pair: SwapPair,
        input_amount: AtomicAmount,
        expected_output: AtomicAmount,
        expires_at_unix: u64,
        reference: &str,
    ) -> Result<Self, SwapError> {
        Ok(Self {
            provider,
            pair,
            input_amount,
            expected_output,
            expires_at_unix,
            reference: SensitiveString::new(reference, MAX_REFERENCE_LEN)?,
        })
    }

    pub fn reference(&self) -> &str {
        self.reference.expose()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SwapOrderRequest {
    pub quote: SwapQuote,
    destination_address: SensitiveString,
    refund_address: SensitiveString,
}

impl fmt::Debug for SwapOrderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwapOrderRequest")
            .field("quote", &self.quote)
            .field("destination_address", &"<redacted>")
            .field("refund_address", &"<redacted>")
            .finish()
    }
}

impl SwapOrderRequest {
    pub fn new(
        quote: SwapQuote,
        destination_address: &str,
        refund_address: &str,
    ) -> Result<Self, SwapError> {
        Ok(Self {
            quote,
            destination_address: SensitiveString::new(destination_address, MAX_ADDRESS_LEN)?,
            refund_address: SensitiveString::new(refund_address, MAX_ADDRESS_LEN)?,
        })
    }

    pub fn destination_address(&self) -> &str {
        self.destination_address.expose()
    }

    pub fn refund_address(&self) -> &str {
        self.refund_address.expose()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapStatus {
    Requested,
    AwaitingDeposit,
    Exchanging,
    Sending,
    Completed,
    Failed,
    Expired,
    Refunding,
    Refunded,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SwapOrder {
    pub provider: ProviderId,
    pub pair: SwapPair,
    pub status: SwapStatus,
    reference: SensitiveString,
}

impl fmt::Debug for SwapOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwapOrder")
            .field("provider", &self.provider)
            .field("pair", &self.pair)
            .field("status", &self.status)
            .field("reference", &"<redacted>")
            .finish()
    }
}

impl SwapOrder {
    pub fn new(
        provider: ProviderId,
        pair: SwapPair,
        status: SwapStatus,
        reference: &str,
    ) -> Result<Self, SwapError> {
        Ok(Self {
            provider,
            pair,
            status,
            reference: SensitiveString::new(reference, MAX_REFERENCE_LEN)?,
        })
    }

    pub fn reference(&self) -> &str {
        self.reference.expose()
    }
}

pub trait SwapProvider {
    type Error: Error + Send + Sync + 'static;

    fn provider_id(&self) -> ProviderId;
    fn quote(&self, request: &QuoteRequest) -> Result<SwapQuote, Self::Error>;
    fn create_order(&self, request: &SwapOrderRequest) -> Result<SwapOrder, Self::Error>;
    fn order_status(&self, order_reference: &str) -> Result<SwapStatus, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoarseSwapStatus {
    Started,
    InProgress,
    Completed,
    Failed,
}

impl CoarseSwapStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::InProgress => "in-progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl From<SwapStatus> for CoarseSwapStatus {
    fn from(value: SwapStatus) -> Self {
        match value {
            SwapStatus::Requested | SwapStatus::AwaitingDeposit => Self::Started,
            SwapStatus::Exchanging | SwapStatus::Sending | SwapStatus::Refunding => {
                Self::InProgress
            }
            SwapStatus::Completed | SwapStatus::Refunded => Self::Completed,
            SwapStatus::Failed | SwapStatus::Expired => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousSwapEvent {
    pub provider: ProviderId,
    pub pair: SwapPair,
    pub status: CoarseSwapStatus,
}

impl AnonymousSwapEvent {
    pub fn from_order(order: &SwapOrder) -> Self {
        Self {
            provider: order.provider.clone(),
            pair: order.pair,
            status: order.status.into(),
        }
    }

    pub fn discord_content(&self) -> String {
        format!(
            "Demon Vault swap | provider={} | pair={}->{} | status={}",
            self.provider.as_str(),
            self.pair.from.symbol(),
            self.pair.to.symbol(),
            self.status.as_str()
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DiscordWebhookCredential(SensitiveString);

impl fmt::Debug for DiscordWebhookCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscordWebhookCredential(<redacted>)")
    }
}

impl DiscordWebhookCredential {
    pub fn new(value: &str) -> Result<Self, SwapError> {
        if !value.starts_with(DISCORD_WEBHOOK_PREFIX) {
            return Err(SwapError::InvalidWebhookUrl);
        }
        let suffix = &value[DISCORD_WEBHOOK_PREFIX.len()..];
        let mut parts = suffix.split('/');
        let id = parts.next().unwrap_or_default();
        let token = parts.next().unwrap_or_default();
        if id.is_empty()
            || token.is_empty()
            || parts.next().is_some()
            || !id.bytes().all(|byte| byte.is_ascii_digit())
            || token.chars().any(char::is_control)
        {
            return Err(SwapError::InvalidWebhookUrl);
        }
        Ok(Self(SensitiveString::new(value, 512)?))
    }

    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

pub trait WebhookTransport {
    type Error: Error + Send + Sync + 'static;

    fn post_discord(
        &self,
        credential: &DiscordWebhookCredential,
        content: &str,
    ) -> Result<(), Self::Error>;
}

pub fn notify_anonymous_swap<T: WebhookTransport>(
    transport: &T,
    credential: &DiscordWebhookCredential,
    event: &AnonymousSwapEvent,
) -> Result<(), SwapError> {
    let content = event.discord_content();
    if content.len() > 256 || content.chars().any(char::is_control) {
        return Err(SwapError::UnsafeNotification);
    }
    transport
        .post_discord(credential, &content)
        .map_err(|_| SwapError::NotificationFailed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapError {
    SameAssetPair,
    InvalidProviderId,
    InvalidSensitiveValue,
    InvalidWebhookUrl,
    AmountTooSmall,
    UnsafeNotification,
    NotificationFailed,
    InvalidProviderResponse,
    ExpiredQuote,
}

impl fmt::Display for SwapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameAssetPair => write!(formatter, "swap input and output assets must differ"),
            Self::InvalidProviderId => write!(formatter, "invalid swap provider identifier"),
            Self::InvalidSensitiveValue => write!(formatter, "invalid sensitive swap value"),
            Self::InvalidWebhookUrl => write!(formatter, "invalid Discord webhook URL"),
            Self::AmountTooSmall => write!(formatter, "swap amount must be greater than zero"),
            Self::UnsafeNotification => {
                write!(formatter, "swap notification failed privacy validation")
            }
            Self::NotificationFailed => write!(formatter, "swap notification transport failed"),
            Self::InvalidProviderResponse => write!(formatter, "swap provider returned data that does not match the request"),
            Self::ExpiredQuote => write!(formatter, "swap quote is expired"),
        }
    }
}

impl Error for SwapError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn sample_order() -> SwapOrder {
        SwapOrder::new(
            ProviderId::new("provider_one").unwrap(),
            SwapPair::new(SwapAsset::Bitcoin, SwapAsset::Monero).unwrap(),
            SwapStatus::Exchanging,
            "provider-order-123",
        )
        .unwrap()
    }

    #[test]
    fn identical_asset_pair_is_rejected() {
        assert_eq!(
            SwapPair::new(SwapAsset::Bitcoin, SwapAsset::Bitcoin).unwrap_err(),
            SwapError::SameAssetPair
        );
    }

    #[test]
    fn provider_ids_are_bounded_and_sanitized() {
        assert!(ProviderId::new("provider_1").is_ok());
        assert!(ProviderId::new("provider name").is_err());
        assert!(ProviderId::new("provider/one").is_err());
    }

    #[test]
    fn sensitive_values_are_redacted_from_debug_output() {
        let quote = SwapQuote::new(
            ProviderId::new("provider").unwrap(),
            SwapPair::new(SwapAsset::Bitcoin, SwapAsset::Zcash).unwrap(),
            AtomicAmount::new(10).unwrap(),
            AtomicAmount::new(20).unwrap(),
            1234,
            "private-quote-reference",
        )
        .unwrap();
        let request =
            SwapOrderRequest::new(quote, "destination-address", "refund-address").unwrap();
        let debug = format!("{request:?}");
        assert!(!debug.contains("destination-address"));
        assert!(!debug.contains("refund-address"));
        assert!(!debug.contains("private-quote-reference"));
        assert!(!debug.contains("AtomicAmount(10)"));
    }

    #[test]
    fn anonymous_event_contains_only_fixed_sanitized_fields() {
        let event = AnonymousSwapEvent::from_order(&sample_order());
        let content = event.discord_content();
        assert_eq!(
            content,
            "Demon Vault swap | provider=provider_one | pair=BTC->XMR | status=in-progress"
        );
        assert!(!content.contains("provider-order-123"));
        assert!(!content.chars().any(char::is_control));
    }

    #[test]
    fn discord_webhook_credentials_are_validated_and_redacted() {
        let value = "https://discord.com/api/webhooks/123456/token_value";
        let credential = DiscordWebhookCredential::new(value).unwrap();
        assert_eq!(credential.expose(), value);
        assert!(!format!("{credential:?}").contains("token_value"));
        assert!(DiscordWebhookCredential::new("http://discord.com/api/webhooks/1/x").is_err());
        assert!(DiscordWebhookCredential::new("https://example.com/api/webhooks/1/x").is_err());
    }

    struct RecordingTransport {
        payloads: RefCell<Vec<String>>,
    }

    #[derive(Debug)]
    struct MockTransportError;

    impl fmt::Display for MockTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock transport error")
        }
    }

    impl Error for MockTransportError {}

    impl WebhookTransport for RecordingTransport {
        type Error = MockTransportError;

        fn post_discord(
            &self,
            _credential: &DiscordWebhookCredential,
            content: &str,
        ) -> Result<(), Self::Error> {
            self.payloads.borrow_mut().push(content.to_owned());
            Ok(())
        }
    }

    #[test]
    fn notification_transport_receives_no_order_reference_or_wallet_data() {
        let transport = RecordingTransport {
            payloads: RefCell::new(Vec::new()),
        };
        let credential =
            DiscordWebhookCredential::new("https://discord.com/api/webhooks/123456/token_value")
                .unwrap();
        let event = AnonymousSwapEvent::from_order(&sample_order());
        notify_anonymous_swap(&transport, &credential, &event).unwrap();
        let payload = transport.payloads.borrow();
        assert_eq!(payload.len(), 1);
        assert!(!payload[0].contains("provider-order-123"));
        assert!(!payload[0].contains("token_value"));
    }
}
