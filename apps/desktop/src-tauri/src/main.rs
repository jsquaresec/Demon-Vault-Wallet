#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use vault_core::{Assurance, SecurityCategory, VaultCore};
use vault_monero::{MoneroNetwork, NodeMode};
use vault_zcash::{PrivacyPolicy, ZcashNetwork};

fn assurance(value: Assurance) -> &'static str {
    match value {
        Assurance::Configured => "configured",
        Assurance::Detected => "detected",
        Assurance::Verified => "verified",
        Assurance::Unknown => "unknown",
    }
}

fn category(value: SecurityCategory) -> &'static str {
    match value {
        SecurityCategory::Vault => "vault",
        SecurityCategory::Network => "network",
        SecurityCategory::Privacy => "privacy",
        SecurityCategory::Application => "application",
        SecurityCategory::Backup => "backup",
        SecurityCategory::TransactionProtection => "transaction",
    }
}

#[tauri::command]
fn monero_status() -> String {
    let core = VaultCore::default();
    let network = match core.monero_network() {
        MoneroNetwork::Mainnet => "mainnet",
        MoneroNetwork::Stagenet => "stagenet",
        MoneroNetwork::Testnet => "testnet",
    };
    let mode = match core.monero_node_mode() {
        NodeMode::AutomaticRemote => "automatic-remote",
        NodeMode::CustomRemote(_) => "custom-remote",
        NodeMode::LocalNode(_) => "local-node",
    };
    format!(
        "network={network};mode={mode};keys=local-only;remote-trust=untrusted;privacy=remote-node-may-observe-network-metadata"
    )
}

#[tauri::command]
fn zcash_status() -> String {
    let core = VaultCore::default();
    let network = match core.zcash_network() {
        ZcashNetwork::Testnet => "testnet",
        ZcashNetwork::Regtest => "regtest",
    };
    let privacy = match core.zcash_privacy_policy() {
        PrivacyPolicy::ShieldedRequired => "shielded-required",
        PrivacyPolicy::ShieldedPreferred => "shielded-preferred",
    };
    format!(
        "network={network};privacy={privacy};transparent=not-private;scanner=local-only;signer=local-only;backend=untrusted"
    )
}

#[tauri::command]
fn security_status() -> String {
    VaultCore::default()
        .security_report()
        .findings
        .into_iter()
        .map(|f| {
            format!(
                "{}|{}|{}|{}",
                category(f.category),
                f.control,
                assurance(f.assurance),
                f.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![security_status, monero_status, zcash_status])
        .run(tauri::generate_context!())
        .expect("failed to run Demon Vault desktop application");
}
