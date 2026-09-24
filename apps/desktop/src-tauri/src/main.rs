#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use vault_core::{Assurance, SecurityCategory, VaultCore};

fn assurance(value: Assurance) -> &'static str {
    match value { Assurance::Configured => "configured", Assurance::Detected => "detected", Assurance::Verified => "verified", Assurance::Unknown => "unknown" }
}
fn category(value: SecurityCategory) -> &'static str {
    match value { SecurityCategory::Vault => "vault", SecurityCategory::Network => "network", SecurityCategory::Privacy => "privacy", SecurityCategory::Application => "application", SecurityCategory::Backup => "backup", SecurityCategory::TransactionProtection => "transaction" }
}

#[tauri::command]
fn security_status() -> String {
    VaultCore::default().security_report().findings.into_iter().map(|f| {
        format!("{}|{}|{}|{}", category(f.category), f.control, assurance(f.assurance), f.detail)
    }).collect::<Vec<_>>().join("\n")
}

fn main() {
    tauri::Builder::default().invoke_handler(tauri::generate_handler![security_status]).run(tauri::generate_context!()).expect("failed to run Demon Vault desktop application");
}
