use std::{fs, path::Path};

const REQUIRED_DOCS: &[&str] = &[
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

const REQUIRED_INVARIANTS: &[&str] = &[
    "zero inbound firewall rules",
    "zero router port forwarding",
    "zero UPnP/NAT-PMP port creation",
    "signing remains local",
    "telemetry is disabled by default",
    "Windows",
    "macOS",
    "Linux",
];

fn validate(root: &Path) -> Result<(), String> {
    for rel in REQUIRED_DOCS {
        if !root.join(rel).is_file() {
            return Err(format!("missing required Phase 0 document: {rel}"));
        }
    }
    let phase0 =
        fs::read_to_string(root.join("docs/architecture/PHASE-0.md")).map_err(|e| e.to_string())?;
    for invariant in REQUIRED_INVARIANTS {
        if !phase0.contains(invariant) {
            return Err(format!("Phase 0 invariant missing: {invariant}"));
        }
    }
    Ok(())
}

fn main() {
    match validate(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        Ok(()) => println!("Demon Vault Phase 0 CLI: PASS"),
        Err(e) => {
            eprintln!("Demon Vault Phase 0 CLI: FAIL: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_zero_spec_is_complete() {
        validate(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }
}
