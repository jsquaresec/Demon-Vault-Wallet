#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

const MAX_VERSION_LEN: usize = 64;
const MAX_ARTIFACT_NAME_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleasePlatform {
    WindowsX64,
    MacOsArm64,
    MacOsX64,
    LinuxX64,
}

impl ReleasePlatform {
    const fn as_byte(self) -> u8 {
        match self {
            Self::WindowsX64 => 1,
            Self::MacOsArm64 => 2,
            Self::MacOsX64 => 3,
            Self::LinuxX64 => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReleaseGateEvidence {
    pub internal_security_audit: bool,
    pub independent_security_assessment: bool,
    pub real_node_compatibility: bool,
    pub hardware_signing_validation: bool,
    pub recovery_restore_validation: bool,
    pub migration_validation: bool,
    pub installer_matrix_validation: bool,
    pub signed_release_validation: bool,
    pub update_verification_validation: bool,
}

impl ReleaseGateEvidence {
    pub const fn mainnet_eligible(self) -> bool {
        self.internal_security_audit
            && self.independent_security_assessment
            && self.real_node_compatibility
            && self.hardware_signing_validation
            && self.recovery_restore_validation
            && self.migration_validation
            && self.installer_matrix_validation
            && self.signed_release_validation
            && self.update_verification_validation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MainnetPermit {
    _private: (),
}

impl MainnetPermit {
    pub fn issue(evidence: ReleaseGateEvidence) -> Result<Self, ReleaseError> {
        if !evidence.mainnet_eligible() {
            return Err(ReleaseError::ReleaseGateIncomplete);
        }
        Ok(Self { _private: () })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub sequence: u64,
    pub version: String,
    pub artifact_name: String,
    pub platform: ReleasePlatform,
    pub sha256: [u8; 32],
}

impl ReleaseManifest {
    pub fn new(
        sequence: u64,
        version: &str,
        artifact_name: &str,
        platform: ReleasePlatform,
        artifact: &[u8],
    ) -> Result<Self, ReleaseError> {
        if sequence == 0 {
            return Err(ReleaseError::InvalidSequence);
        }
        validate_text(version, MAX_VERSION_LEN).map_err(|_| ReleaseError::InvalidVersion)?;
        validate_text(artifact_name, MAX_ARTIFACT_NAME_LEN)
            .map_err(|_| ReleaseError::InvalidArtifactName)?;
        if artifact.is_empty() {
            return Err(ReleaseError::EmptyArtifact);
        }

        Ok(Self {
            sequence,
            version: version.to_owned(),
            artifact_name: artifact_name.to_owned(),
            platform,
            sha256: Sha256::digest(artifact).into(),
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            32 + self.version.len() + self.artifact_name.len() + self.sha256.len(),
        );
        bytes.extend_from_slice(b"demon-vault/release-manifest/v1");
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.push(self.platform.as_byte());
        bytes.extend_from_slice(&(self.version.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.version.as_bytes());
        bytes.extend_from_slice(&(self.artifact_name.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.artifact_name.as_bytes());
        bytes.extend_from_slice(&self.sha256);
        bytes
    }
}

pub fn verify_release_artifact(
    manifest: &ReleaseManifest,
    artifact: &[u8],
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8; 32],
    minimum_sequence: u64,
) -> Result<(), ReleaseError> {
    if manifest.sequence < minimum_sequence {
        return Err(ReleaseError::RollbackRejected);
    }
    if Sha256::digest(artifact).as_slice() != manifest.sha256 {
        return Err(ReleaseError::ArtifactHashMismatch);
    }

    let key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| ReleaseError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature_bytes);
    key.verify_strict(&manifest.canonical_bytes(), &signature)
        .map_err(|_| ReleaseError::InvalidSignature)
}

fn validate_text(value: &str, max_len: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_len
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    ReleaseGateIncomplete,
    InvalidSequence,
    InvalidVersion,
    InvalidArtifactName,
    EmptyArtifact,
    RollbackRejected,
    ArtifactHashMismatch,
    InvalidPublicKey,
    InvalidSignature,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReleaseGateIncomplete => write!(formatter, "mainnet release gate is incomplete"),
            Self::InvalidSequence => write!(formatter, "invalid release sequence"),
            Self::InvalidVersion => write!(formatter, "invalid release version"),
            Self::InvalidArtifactName => write!(formatter, "invalid release artifact name"),
            Self::EmptyArtifact => write!(formatter, "release artifact is empty"),
            Self::RollbackRejected => write!(formatter, "release rollback was rejected"),
            Self::ArtifactHashMismatch => write!(formatter, "release artifact hash mismatch"),
            Self::InvalidPublicKey => write!(formatter, "invalid release public key"),
            Self::InvalidSignature => write!(formatter, "invalid release signature"),
        }
    }
}

impl Error for ReleaseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn complete_evidence() -> ReleaseGateEvidence {
        ReleaseGateEvidence {
            internal_security_audit: true,
            independent_security_assessment: true,
            real_node_compatibility: true,
            hardware_signing_validation: true,
            recovery_restore_validation: true,
            migration_validation: true,
            installer_matrix_validation: true,
            signed_release_validation: true,
            update_verification_validation: true,
        }
    }

    #[test]
    fn mainnet_permit_fails_closed_until_every_gate_passes() {
        assert!(MainnetPermit::issue(ReleaseGateEvidence::default()).is_err());
        assert!(MainnetPermit::issue(complete_evidence()).is_ok());

        let mut missing = complete_evidence();
        missing.independent_security_assessment = false;
        assert_eq!(
            MainnetPermit::issue(missing).unwrap_err(),
            ReleaseError::ReleaseGateIncomplete
        );
    }

    #[test]
    fn signed_release_verification_binds_manifest_and_artifact() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let artifact = b"demon-vault-rc";
        let manifest = ReleaseManifest::new(
            7,
            "0.1.0-rc.1",
            "DemonVault-Setup-x64.exe",
            ReleasePlatform::WindowsX64,
            artifact,
        )
        .unwrap();
        let signature = signing.sign(&manifest.canonical_bytes()).to_bytes();

        assert!(
            verify_release_artifact(&manifest, artifact, &signature, verifying.as_bytes(), 7).is_ok()
        );
        assert_eq!(
            verify_release_artifact(
                &manifest,
                b"tampered",
                &signature,
                verifying.as_bytes(),
                7
            )
            .unwrap_err(),
            ReleaseError::ArtifactHashMismatch
        );
    }

    #[test]
    fn rollback_and_manifest_tampering_are_rejected() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let verifying = signing.verifying_key();
        let artifact = b"artifact";
        let mut manifest = ReleaseManifest::new(
            2,
            "0.1.0-rc.2",
            "DemonVault.AppImage",
            ReleasePlatform::LinuxX64,
            artifact,
        )
        .unwrap();
        let signature = signing.sign(&manifest.canonical_bytes()).to_bytes();

        assert_eq!(
            verify_release_artifact(
                &manifest,
                artifact,
                &signature,
                verifying.as_bytes(),
                3
            )
            .unwrap_err(),
            ReleaseError::RollbackRejected
        );

        manifest.version = "0.1.0-rc.3".into();
        assert_eq!(
            verify_release_artifact(
                &manifest,
                artifact,
                &signature,
                verifying.as_bytes(),
                1
            )
            .unwrap_err(),
            ReleaseError::InvalidSignature
        );
    }
}
