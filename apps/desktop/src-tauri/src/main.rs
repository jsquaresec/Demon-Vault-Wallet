#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use vault_core::{VaultCore, VaultLockState};

#[tauri::command]
fn security_status() -> String {
    let status = VaultCore::default().status();
    let lock = match status.lock_state {
        VaultLockState::Locked => "locked",
        VaultLockState::Unlocked => "unlocked",
    };
    format!(
        "vault={lock};crypto-vault=implemented;network=outbound-only;assets=BTC,XMR,ZEC;btc-testnet=available;btc-mainnet=disabled"
    )
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![security_status])
        .run(tauri::generate_context!())
        .expect("failed to run Demon Vault desktop application");
}
