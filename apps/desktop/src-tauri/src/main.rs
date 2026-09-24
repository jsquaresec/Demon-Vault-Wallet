#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use vault_core::{VaultCore, VaultLockState};

#[tauri::command]
fn foundation_status() -> String {
    let status = VaultCore::default().foundation_status();
    let lock = match status.lock_state {
        VaultLockState::Locked => "locked",
        VaultLockState::Unlocked => "unlocked",
    };
    format!(
        "phase=2;vault={lock};network=outbound-only;assets=BTC,XMR,ZEC;signing=disabled"
    )
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![foundation_status])
        .run(tauri::generate_context!())
        .expect("failed to run Demon Vault desktop foundation");
}
