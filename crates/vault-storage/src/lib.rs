#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use vault_crypto::{VaultEnvelope, VaultError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    root: PathBuf,
}

impl AppPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    pub fn vault_dir(&self) -> PathBuf {
        self.root.join("vault")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn wallet_vault(&self) -> PathBuf {
        self.vault_dir().join("wallet.dvlt")
    }
}

#[derive(Debug)]
pub enum StorageError {
    AlreadyExists,
    Io(io::Error),
    InvalidVault(VaultError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(formatter, "vault file already exists"),
            Self::Io(error) => write!(formatter, "vault storage error: {error}"),
            Self::InvalidVault(error) => write!(formatter, "invalid encrypted vault: {error}"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyExists => None,
            Self::Io(error) => Some(error),
            Self::InvalidVault(error) => Some(error),
        }
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<VaultError> for StorageError {
    fn from(error: VaultError) -> Self {
        Self::InvalidVault(error)
    }
}

pub fn write_new_envelope_atomic(
    path: &Path,
    envelope: &VaultEnvelope,
) -> Result<(), StorageError> {
    if path.exists() {
        return Err(StorageError::AlreadyExists);
    }

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vault path has no parent"))?;
    fs::create_dir_all(parent)?;

    let encoded = envelope.encode()?;
    let temp = temporary_sibling(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    let write_result = (|| -> Result<(), StorageError> {
        let mut file = options.open(&temp)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        sync_parent_if_supported(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

pub fn read_envelope(path: &Path) -> Result<VaultEnvelope, StorageError> {
    let bytes = fs::read(path)?;
    VaultEnvelope::decode(&bytes).map_err(StorageError::InvalidVault)
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wallet.dvlt");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), now))
}

#[cfg(unix)]
fn sync_parent_if_supported(parent: &Path) -> Result<(), StorageError> {
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_if_supported(_parent: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_crypto::{KdfParams, VaultDomain, seal};

    fn unique_test_dir(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("demon-vault-{label}-{}-{now}", std::process::id()))
    }

    fn test_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn paths_are_joined_without_os_specific_literals() {
        let paths = AppPaths::new(PathBuf::from("demon-vault-test"));
        assert_eq!(paths.state_dir(), paths.root().join("state"));
        assert_eq!(paths.vault_dir(), paths.root().join("vault"));
        assert_eq!(paths.logs_dir(), paths.root().join("logs"));
        assert_eq!(paths.wallet_vault(), paths.vault_dir().join("wallet.dvlt"));
    }

    #[test]
    fn encrypted_envelope_is_created_atomically_and_read_back() {
        let root = unique_test_dir("atomic");
        let path = AppPaths::new(&root).wallet_vault();
        let envelope = seal(
            b"phase-three-test",
            VaultDomain::Wallet,
            b"synthetic-secret",
            test_kdf(),
        )
        .unwrap();

        write_new_envelope_atomic(&path, &envelope).unwrap();
        let loaded = read_envelope(&path).unwrap();
        assert_eq!(loaded, envelope);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_vault_is_never_silently_overwritten() {
        let root = unique_test_dir("no-overwrite");
        let path = AppPaths::new(&root).wallet_vault();
        let envelope = seal(
            b"phase-three-test",
            VaultDomain::Wallet,
            b"synthetic-secret",
            test_kdf(),
        )
        .unwrap();

        write_new_envelope_atomic(&path, &envelope).unwrap();
        assert!(matches!(
            write_new_envelope_atomic(&path, &envelope),
            Err(StorageError::AlreadyExists)
        ));

        fs::remove_dir_all(root).unwrap();
    }
}
