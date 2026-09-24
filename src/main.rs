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

fn require_files(root: &Path, files: &[&str], phase: &str) -> Result<(), String> {
    for rel in files {
        if !root.join(rel).is_file() {
            return Err(format!("missing required {phase} document: {rel}"));
        }
    }
    Ok(())
}

fn validate_phase0(root: &Path) -> Result<(), String> {
    require_files(root, PHASE0_DOCS, "Phase 0")?;
    let phase0 =
        fs::read_to_string(root.join("docs/architecture/PHASE-0.md")).map_err(|e| e.to_string())?;
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

    let model = fs::read_to_string(root.join("docs/security/threat-model/THREAT-MODEL.md"))
        .map_err(|e| e.to_string())?;
    for concept in PHASE1_REQUIRED_CONCEPTS {
        if !model.contains(concept) {
            return Err(format!("Phase 1 threat-model concept missing: {concept}"));
        }
    }

    let register = fs::read_to_string(root.join("docs/security/threat-model/THREAT-REGISTER.md"))
        .map_err(|e| e.to_string())?;
    for number in 1..=24 {
        let id = format!("TM-{number:03}");
        if !register.contains(&id) {
            return Err(format!("Phase 1 threat register missing: {id}"));
        }
    }

    let boundaries =
        fs::read_to_string(root.join("docs/security/threat-model/TRUST-BOUNDARIES.md"))
            .map_err(|e| e.to_string())?;
    for number in 1..=8 {
        let id = format!("TB-{number}");
        if !boundaries.contains(&id) {
            return Err(format!("Phase 1 trust boundary missing: {id}"));
        }
    }

    let abuse = fs::read_to_string(root.join("docs/security/threat-model/ABUSE-CASES.md"))
        .map_err(|e| e.to_string())?;
    for number in 1..=8 {
        let id = format!("AC-{number:02}");
        if !abuse.contains(&id) {
            return Err(format!("Phase 1 abuse case missing: {id}"));
        }
    }

    Ok(())
}

fn print_help() {
    println!("Demon Vault security-gate validator");
    println!("Usage: cargo run -- [all|phase0|phase1]");
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mode = env::args().nth(1).unwrap_or_else(|| "all".to_string());

    let result = match mode.as_str() {
        "phase0" => validate_phase0(root).map(|()| {
            println!("Demon Vault Phase 0 CLI: PASS");
        }),
        "phase1" => validate_phase1(root).map(|()| {
            println!("Demon Vault Phase 1 CLI: PASS");
        }),
        "all" => validate_phase1(root).map(|()| {
            println!("Demon Vault Phase 0 CLI: PASS");
            println!("Demon Vault Phase 1 CLI: PASS");
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
}
