use crate::{
    AnonymousSwapEvent, DiscordWebhookCredential, SwapError, SwapOrder, SwapProvider, SwapQuote,
    WebhookTransport,
};
use std::{error::Error, fmt, path::Path};
use vault_crypto::{KdfParams, VaultDomain, VaultError, open, seal};
use vault_storage::{StorageError, read_envelope, write_new_envelope_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationOutcome {
    Sent,
    Disabled,
    Failed,
}

pub fn notify_anonymous_swap_best_effort<T: WebhookTransport>(
    transport: &T,
    credential: Option<&DiscordWebhookCredential>,
    event: &AnonymousSwapEvent,
) -> NotificationOutcome {
    let Some(credential) = credential else {
        return NotificationOutcome::Disabled;
    };
    match crate::notify_anonymous_swap(transport, credential, event) {
        Ok(()) => NotificationOutcome::Sent,
        Err(_) => NotificationOutcome::Failed,
    }
}

#[derive(Debug, Default, Clone)]
pub struct ReqwestWebhookTransport {
    client: reqwest::blocking::Client,
}

impl WebhookTransport for ReqwestWebhookTransport {
    type Error = reqwest::Error;

    fn post_discord(
        &self,
        credential: &DiscordWebhookCredential,
        content: &str,
    ) -> Result<(), Self::Error> {
        self.client
            .post(credential.expose())
            .json(&serde_json::json!({
                "content": content,
                "allowed_mentions": { "parse": [] }
            }))
            .send()?
            .error_for_status()?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum IntegrationSecretError {
    Crypto(VaultError),
    Storage(StorageError),
    WrongDomain,
    InvalidCredential,
}

impl fmt::Display for IntegrationSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => write!(
                formatter,
                "integration credential cryptographic error: {error}"
            ),
            Self::Storage(error) => {
                write!(formatter, "integration credential storage error: {error}")
            }
            Self::WrongDomain => write!(
                formatter,
                "integration credential has the wrong encryption domain"
            ),
            Self::InvalidCredential => {
                write!(formatter, "stored integration credential is invalid")
            }
        }
    }
}

impl Error for IntegrationSecretError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

pub fn store_webhook_credential(
    path: &Path,
    password: &[u8],
    credential: &DiscordWebhookCredential,
) -> Result<(), IntegrationSecretError> {
    let envelope = seal(
        password,
        VaultDomain::Integration,
        credential.expose().as_bytes(),
        KdfParams::default(),
    )
    .map_err(IntegrationSecretError::Crypto)?;
    write_new_envelope_atomic(path, &envelope).map_err(IntegrationSecretError::Storage)
}

pub fn load_webhook_credential(
    path: &Path,
    password: &[u8],
) -> Result<DiscordWebhookCredential, IntegrationSecretError> {
    let envelope = read_envelope(path).map_err(IntegrationSecretError::Storage)?;
    if envelope.domain() != VaultDomain::Integration {
        return Err(IntegrationSecretError::WrongDomain);
    }
    let plaintext = open(password, &envelope).map_err(IntegrationSecretError::Crypto)?;
    let value = std::str::from_utf8(plaintext.as_slice())
        .map_err(|_| IntegrationSecretError::InvalidCredential)?;
    DiscordWebhookCredential::new(value).map_err(|_| IntegrationSecretError::InvalidCredential)
}

pub fn validate_provider_quote(
    provider: &impl SwapProvider,
    requested_pair: crate::SwapPair,
    requested_amount: crate::AtomicAmount,
    quote: &SwapQuote,
    now_unix: u64,
) -> Result<(), SwapError> {
    if quote.provider != provider.provider_id()
        || quote.pair != requested_pair
        || quote.input_amount != requested_amount
    {
        return Err(SwapError::InvalidProviderResponse);
    }
    if quote.expires_at_unix <= now_unix {
        return Err(SwapError::ExpiredQuote);
    }
    Ok(())
}

pub fn validate_provider_order(
    provider: &impl SwapProvider,
    quote: &SwapQuote,
    order: &SwapOrder,
) -> Result<(), SwapError> {
    if order.provider != provider.provider_id() || order.pair != quote.pair {
        return Err(SwapError::InvalidProviderResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AtomicAmount, CoarseSwapStatus, ProviderId, QuoteRequest, SwapAsset, SwapOrderRequest,
        SwapPair, SwapStatus,
    };
    use std::{
        cell::RefCell,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug)]
    struct MockError;
    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock error")
        }
    }
    impl Error for MockError {}

    struct FailingTransport;
    impl WebhookTransport for FailingTransport {
        type Error = MockError;
        fn post_discord(
            &self,
            _credential: &DiscordWebhookCredential,
            _content: &str,
        ) -> Result<(), Self::Error> {
            Err(MockError)
        }
    }

    struct MockProvider {
        id: ProviderId,
        status_calls: RefCell<u32>,
    }

    impl SwapProvider for MockProvider {
        type Error = MockError;
        fn provider_id(&self) -> ProviderId {
            self.id.clone()
        }
        fn quote(&self, request: &QuoteRequest) -> Result<SwapQuote, Self::Error> {
            Ok(SwapQuote::new(
                self.id.clone(),
                request.pair,
                request.amount,
                AtomicAmount::new(20).unwrap(),
                10_000,
                "quote-ref",
            )
            .unwrap())
        }
        fn create_order(&self, request: &SwapOrderRequest) -> Result<SwapOrder, Self::Error> {
            Ok(SwapOrder::new(
                self.id.clone(),
                request.quote.pair,
                SwapStatus::Requested,
                "order-ref",
            )
            .unwrap())
        }
        fn order_status(&self, _order_reference: &str) -> Result<SwapStatus, Self::Error> {
            *self.status_calls.borrow_mut() += 1;
            Ok(SwapStatus::Completed)
        }
    }

    fn pair() -> SwapPair {
        SwapPair::new(SwapAsset::Bitcoin, SwapAsset::Monero).unwrap()
    }

    #[test]
    fn webhook_failure_is_isolated_from_swap_state() {
        let credential =
            DiscordWebhookCredential::new("https://discord.com/api/webhooks/123456/token_value")
                .unwrap();
        let order = SwapOrder::new(
            ProviderId::new("provider").unwrap(),
            pair(),
            SwapStatus::Completed,
            "private-order-ref",
        )
        .unwrap();
        let event = AnonymousSwapEvent::from_order(&order);
        assert_eq!(event.status, CoarseSwapStatus::Completed);
        assert_eq!(
            notify_anonymous_swap_best_effort(&FailingTransport, Some(&credential), &event),
            NotificationOutcome::Failed
        );
        assert_eq!(
            notify_anonymous_swap_best_effort(&FailingTransport, None, &event),
            NotificationOutcome::Disabled
        );
    }

    #[test]
    fn webhook_credential_round_trips_only_through_integration_domain() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "demon-vault-integration-{}-{now}",
            std::process::id()
        ));
        let path = root.join("discord-webhook.dvlt");
        let credential =
            DiscordWebhookCredential::new("https://discord.com/api/webhooks/123456/token_value")
                .unwrap();

        store_webhook_credential(&path, b"integration-password", &credential).unwrap();
        let envelope = read_envelope(&path).unwrap();
        assert_eq!(envelope.domain(), VaultDomain::Integration);
        let encoded = envelope.encode().unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("token_value"));

        let loaded = load_webhook_credential(&path, b"integration-password").unwrap();
        assert_eq!(loaded.expose(), credential.expose());
        assert!(load_webhook_credential(&path, b"wrong-password").is_err());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_responses_are_bound_to_requested_quote() {
        let provider = MockProvider {
            id: ProviderId::new("provider").unwrap(),
            status_calls: RefCell::new(0),
        };
        let request = QuoteRequest {
            pair: pair(),
            amount: AtomicAmount::new(10).unwrap(),
        };
        let quote = provider.quote(&request).unwrap();
        assert!(
            validate_provider_quote(&provider, request.pair, request.amount, &quote, 1).is_ok()
        );

        let expired = SwapQuote::new(
            provider.provider_id(),
            request.pair,
            request.amount,
            AtomicAmount::new(20).unwrap(),
            1,
            "expired",
        )
        .unwrap();
        assert_eq!(
            validate_provider_quote(&provider, request.pair, request.amount, &expired, 1)
                .unwrap_err(),
            SwapError::ExpiredQuote
        );
    }
}
