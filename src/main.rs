use std::{env, fs, path::Path};

const PHASE0_DOCS: &[&str] = &[
    "docs/architecture/PHASE-0.md",
    "docs/architecture/NETWORKING.md",
    "docs/architecture/CHAIN-BACKENDS.md",
    "docs/architecture/STORAGE-AND-IPC.md",
    "docs/security/SECURITY-INVARIANTS.md",
    "docs/security/CRYPTOGRAPHIC-VAULT.md",
    "docs/security/UPDATE-SUPPLY-CHAIN.md",
    "docs/privacy/PRIVACY.md",
    "docs/platform/CROSS-PLATFORM.md",
    "docs/PHASE-0-CHECKLIST.md",
];

const PHASE0_INVARIANTS: &[&str] = &[
    "zero inbound firewall rules",
    "zero router port forwarding",
    "zero UPnP/NAT-PMP port creation",
    "signing remains local",
    "telemetry is disabled by default",
    "Windows",
    "macOS",
    "Linux",
];

const PHASE1_DOCS: &[&str] = &[
    "docs/security/threat-model/THREAT-MODEL.md",
    "docs/security/threat-model/TRUST-BOUNDARIES.md",
    "docs/security/threat-model/THREAT-REGISTER.md",
    "docs/security/threat-model/ATTACK-TREES.md",
    "docs/security/threat-model/ABUSE-CASES.md",
    "docs/security/threat-model/ASSUMPTIONS-AND-NONGOALS.md",
    "docs/security/threat-model/REQUIRED-CONTROLS.md",
    "docs/PHASE-1-CHECKLIST.md",
];

const PHASE1_REQUIRED_CONCEPTS: &[&str] = &[
    "Protected assets",
    "Attacker classes",
    "Trust assumptions",
    "Trust boundaries",
    "Risk model",
    "Phase relationship",
];

const PHASE2_DOCS: &[&str] = &[
    "docs/architecture/PHASE-2-FOUNDATION.md",
    "docs/security/PHASE-2-SECURITY.md",
    "docs/platform/PHASE-2-DESKTOP.md",
    "docs/PHASE-2-CHECKLIST.md",
];

const PHASE3_DOCS: &[&str] = &[
    "docs/architecture/PHASE-3-VAULT.md",
    "docs/security/PHASE-3-SECURITY.md",
    "docs/PHASE-3-CHECKLIST.md",
];

const PHASE3_FILES: &[&str] = &[
    "crates/vault-crypto/Cargo.toml",
    "crates/vault-crypto/src/lib.rs",
    "crates/vault-storage/src/lib.rs",
    "crates/vault-core/src/lib.rs",
    ".github/workflows/phase3.yml",
];

const PHASE2_FILES: &[&str] = &[
    "crates/vault-core/Cargo.toml",
    "crates/vault-core/src/lib.rs",
    "crates/vault-policy/Cargo.toml",
    "crates/vault-policy/src/lib.rs",
    "crates/vault-network/Cargo.toml",
    "crates/vault-network/src/lib.rs",
    "crates/vault-storage/Cargo.toml",
    "crates/vault-storage/src/lib.rs",
    "apps/desktop/src-tauri/Cargo.toml",
    "apps/desktop/src-tauri/src/main.rs",
    "apps/desktop/src-tauri/tauri.conf.json",
    "apps/desktop/src-tauri/icons/icon.png",
    "apps/desktop/src-tauri/icons/icon.ico",
    "apps/desktop/ui/index.html",
    "apps/desktop/ui/styles.css",
    "apps/desktop/ui/app.js",
];

fn require_files(root: &Path, files: &[&str], phase: &str) -> Result<(), String> {
    for rel in files {
        if !root.join(rel).is_file() {
            return Err(format!("missing required {phase} file: {rel}"));
        }
    }
    Ok(())
}

fn read(root: &Path, rel: &str) -> Result<String, String> {
    fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

fn validate_phase0(root: &Path) -> Result<(), String> {
    require_files(root, PHASE0_DOCS, "Phase 0")?;
    let phase0 = read(root, "docs/architecture/PHASE-0.md")?;
    for invariant in PHASE0_INVARIANTS {
        if !phase0.contains(invariant) {
            return Err(format!("Phase 0 invariant missing: {invariant}"));
        }
    }
    Ok(())
}

fn validate_phase1(root: &Path) -> Result<(), String> {
    validate_phase0(root)?;
    require_files(root, PHASE1_DOCS, "Phase 1")?;

    let model = read(root, "docs/security/threat-model/THREAT-MODEL.md")?;
    for concept in PHASE1_REQUIRED_CONCEPTS {
        if !model.contains(concept) {
            return Err(format!("Phase 1 threat-model concept missing: {concept}"));
        }
    }

    let register = read(root, "docs/security/threat-model/THREAT-REGISTER.md")?;
    for number in 1..=24 {
        let id = format!("TM-{number:03}");
        if !register.contains(&id) {
            return Err(format!("Phase 1 threat register missing: {id}"));
        }
    }

    let boundaries = read(root, "docs/security/threat-model/TRUST-BOUNDARIES.md")?;
    for number in 1..=8 {
        let id = format!("TB-{number}");
        if !boundaries.contains(&id) {
            return Err(format!("Phase 1 trust boundary missing: {id}"));
        }
    }

    let abuse = read(root, "docs/security/threat-model/ABUSE-CASES.md")?;
    for number in 1..=8 {
        let id = format!("AC-{number:02}");
        if !abuse.contains(&id) {
            return Err(format!("Phase 1 abuse case missing: {id}"));
        }
    }

    Ok(())
}

fn validate_phase2(root: &Path) -> Result<(), String> {
    validate_phase1(root)?;
    require_files(root, PHASE2_DOCS, "Phase 2")?;
    require_files(root, PHASE2_FILES, "Phase 2")?;

    let core = read(root, "crates/vault-core/src/lib.rs")?;
    for required in ["VaultLockState::Locked", "SignTransaction", "VaultCore"] {
        if !core.contains(required) {
            return Err(format!("Phase 2 core foundation missing: {required}"));
        }
    }

    let network = read(root, "crates/vault-network/src/lib.rs")?;
    for required in [
        "inbound_listener",
        "port_forwarding",
        "upnp",
        "nat_pmp",
        "Default",
        "outbound_only",
    ] {
        if !network.contains(required) {
            return Err(format!("Phase 2 network invariant missing: {required}"));
        }
    }

    let policy = read(root, "crates/vault-policy/src/lib.rs")?;
    for required in [
        "signing is not implemented in Phase 2",
        "raw private-key export is outside the Phase 2 foundation",
    ] {
        if !policy.contains(required) {
            return Err(format!(
                "Phase 2 deny-by-default policy missing: {required}"
            ));
        }
    }

    let tauri = read(root, "apps/desktop/src-tauri/tauri.conf.json")?;
    if !tauri.contains("frontendDist") || !tauri.contains("../ui") {
        return Err("Phase 2 desktop assets are not configured as local frontend content".into());
    }
    if tauri.contains("http://") {
        return Err("Phase 2 Tauri config contains an insecure remote URL".into());
    }

    let desktop_manifest = read(root, "apps/desktop/src-tauri/Cargo.toml")?;
    if !desktop_manifest.contains("tauri = { version =") || !desktop_manifest.contains("=2.11.5") {
        return Err("Phase 2 Tauri runtime is not pinned to the validated version".into());
    }

    Ok(())
}

fn validate_phase3(root: &Path) -> Result<(), String> {
    validate_phase2(root)?;
    require_files(root, PHASE3_DOCS, "Phase 3")?;
    require_files(root, PHASE3_FILES, "Phase 3")?;

    let manifest = read(root, "crates/vault-crypto/Cargo.toml")?;
    for required in [
        "argon2 = { version = \"=0.6.0\"",
        "chacha20poly1305 = { version = \"=0.11.0\"",
        "getrandom = \"=0.4.3\"",
        "hkdf = \"=0.13.0\"",
        "sha2 = \"=0.11.0\"",
        "zeroize = { version = \"=1.9.0\"",
    ] {
        if !manifest.contains(required) {
            return Err(format!(
                "Phase 3 crypto dependency is not pinned: {required}"
            ));
        }
    }

    let crypto = read(root, "crates/vault-crypto/src/lib.rs")?;
    for required in [
        "Algorithm::Argon2id",
        "XChaCha20Poly1305",
        "Hkdf::<Sha256>",
        "Zeroizing<Vec<u8>>",
        "FORMAT_VERSION: u16 = 1",
        "memory_kib: 65_536",
        "demon-vault/v1/wallet-secrets",
        "demon-vault/v1/integration-secrets",
        "AuthenticationFailed",
        "ciphertext_tampering_is_detected",
        "header_tampering_is_detected_by_aead",
    ] {
        if !crypto.contains(required) {
            return Err(format!(
                "Phase 3 cryptographic invariant missing: {required}"
            ));
        }
    }

    let storage = read(root, "crates/vault-storage/src/lib.rs")?;
    for required in [
        "write_new_envelope_atomic",
        "create_new(true)",
        "sync_all()",
        "fs::rename",
        "AlreadyExists",
    ] {
        if !storage.contains(required) {
            return Err(format!("Phase 3 storage invariant missing: {required}"));
        }
    }

    let core = read(root, "crates/vault-core/src/lib.rs")?;
    for required in [
        "create_local_vault",
        "unlock_local_vault",
        "pub fn lock",
        "unlocked_wallet_secret: Option<SecretBytes>",
        "WrongDomain",
    ] {
        if !core.contains(required) {
            return Err(format!("Phase 3 core vault lifecycle missing: {required}"));
        }
    }

    Ok(())
}

fn print_help() {
    println!("Demon Vault security-gate validator");
    println!("Usage: cargo run -- [all|phase0|phase1|phase2|phase3]");
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mode = env::args().nth(1).unwrap_or_else(|| "all".to_string());

    let result = match mode.as_str() {
        "phase0" => validate_phase0(root).map(|()| println!("Demon Vault Phase 0 CLI: PASS")),
        "phase1" => validate_phase1(root).map(|()| println!("Demon Vault Phase 1 CLI: PASS")),
        "phase2" => validate_phase2(root).map(|()| println!("Demon Vault Phase 2 CLI: PASS")),
        "phase3" | "all" => validate_phase3(root).map(|()| {
            println!("Demon Vault Phase 0 CLI: PASS");
            println!("Demon Vault Phase 1 CLI: PASS");
            println!("Demon Vault Phase 2 CLI: PASS");
            println!("Demon Vault Phase 3 CLI: PASS");
            println!("Demon Vault security gates: PASS");
        }),
        "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown validation mode: {other}")),
    };

    if let Err(error) = result {
        eprintln!("Demon Vault security gates: FAIL: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_zero_spec_is_complete() {
        validate_phase0(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }

    #[test]
    fn phase_one_threat_model_is_complete() {
        validate_phase1(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }

    #[test]
    fn phase_two_foundation_is_complete() {
        validate_phase2(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }

    #[test]
    fn phase_three_vault_is_complete() {
        validate_phase3(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }
}
