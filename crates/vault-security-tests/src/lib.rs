#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use vault_crypto::VaultEnvelope;
    use vault_network::{NetworkPrivacyConfig, OutboundTarget, PrivacyRoute, ProxyEndpoint};
    use vault_signing::{import_offline_request, import_offline_signature};
    use vault_swap::DiscordWebhookCredential;
    use vault_transaction::{
        FeePolicy, OutputKind, ReviewOutput, TransactionAsset, TransactionReviewRequest,
        bind_unsigned_transaction, review_transaction,
    };

    const MAX_FUZZ_BYTES: usize = 16 * 1024;

    fn no_panic<T>(call: impl FnOnce() -> T) {
        assert!(catch_unwind(AssertUnwindSafe(call)).is_ok());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_vault_envelopes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..MAX_FUZZ_BYTES)) {
            no_panic(|| {
                let _ = VaultEnvelope::decode(&bytes);
            });
        }

        #[test]
        fn arbitrary_offline_signing_requests_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..MAX_FUZZ_BYTES)) {
            no_panic(|| {
                let _ = import_offline_request(&bytes);
            });
        }

        #[test]
        fn arbitrary_offline_signatures_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..MAX_FUZZ_BYTES)) {
            no_panic(|| {
                let _ = import_offline_signature(&bytes);
            });
        }

        #[test]
        fn arbitrary_outbound_targets_never_panic(value in ".{0,4096}") {
            no_panic(|| {
                let _ = OutboundTarget::new(&value, PrivacyRoute::Direct, true);
            });
        }

        #[test]
        fn arbitrary_proxy_targets_never_panic(value in ".{0,1024}") {
            no_panic(|| {
                let _ = ProxyEndpoint::new(&value, PrivacyRoute::Proxy);
                let _ = ProxyEndpoint::new(&value, PrivacyRoute::Tor);
            });
        }

        #[test]
        fn arbitrary_webhook_credentials_never_panic(value in ".{0,4096}") {
            no_panic(|| {
                let _ = DiscordWebhookCredential::new(&value);
            });
        }

        #[test]
        fn arbitrary_transaction_bindings_never_panic(
            network in ".{0,64}",
            bytes in prop::collection::vec(any::<u8>(), 0..4096)
        ) {
            no_panic(|| {
                let _ = bind_unsigned_transaction(TransactionAsset::Bitcoin, &network, &bytes);
                let _ = bind_unsigned_transaction(TransactionAsset::Monero, &network, &bytes);
                let _ = bind_unsigned_transaction(TransactionAsset::Zcash, &network, &bytes);
            });
        }
    }

    #[test]
    fn corpus_of_hostile_urls_fails_closed_without_panics() {
        let inputs = [
            "",
            "http://example.com",
            "https://user:pass@example.com",
            "https://example.com#fragment",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://",
            "https://:443",
            "https://example.com:bad",
            "http://[::1",
            "https://exa\nmple.com",
            "socks5://127.0.0.1:9050",
            "socks5h://10.0.0.5:9050",
        ];

        for input in inputs {
            no_panic(|| {
                let _ = OutboundTarget::new(input, PrivacyRoute::Direct, true);
                let _ = ProxyEndpoint::new(input, PrivacyRoute::Proxy);
                let _ = ProxyEndpoint::new(input, PrivacyRoute::Tor);
            });
        }
    }

    #[test]
    fn hardened_network_defaults_reject_unsafe_policy_mutations() {
        let mut config = NetworkPrivacyConfig::default();
        config.allow_redirects = true;
        assert!(config.validate().is_err());

        let mut config = NetworkPrivacyConfig::default();
        config.accept_invalid_certificates = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn transaction_review_mutations_change_binding_or_fail_review() {
        let tx = [1u8, 2, 3, 4];
        let binding =
            bind_unsigned_transaction(TransactionAsset::Bitcoin, "testnet", &tx).unwrap();

        let base = TransactionReviewRequest::new(
            TransactionAsset::Bitcoin,
            "testnet",
            vec![
                ReviewOutput::new(OutputKind::Recipient, "tb1qrecipient", 100_000).unwrap(),
                ReviewOutput::new(OutputKind::Change, "tb1qchange", 50_000).unwrap(),
            ],
            500,
            binding,
            None,
            10_000,
        )
        .unwrap();

        let original =
            review_transaction(base.clone(), FeePolicy::new(10_000, 1_000).unwrap(), 1).unwrap();

        let mut changed = base;
        changed.outputs[0].amount_atomic = 99_999;
        let changed_review =
            review_transaction(changed, FeePolicy::new(10_000, 1_000).unwrap(), 1).unwrap();
        assert_ne!(original.digest(), changed_review.digest());

        let mutated_binding =
            bind_unsigned_transaction(TransactionAsset::Bitcoin, "testnet", &[1, 2, 3, 5])
                .unwrap();
        assert_ne!(binding, mutated_binding);
    }

    #[test]
    fn oversized_and_empty_unsigned_transactions_fail_closed() {
        assert!(
            bind_unsigned_transaction(TransactionAsset::Bitcoin, "testnet", &[]).is_err()
        );
        let oversized = vec![0u8; 1024 * 1024 + 1];
        assert!(
            bind_unsigned_transaction(TransactionAsset::Bitcoin, "testnet", &oversized).is_err()
        );
    }
}
