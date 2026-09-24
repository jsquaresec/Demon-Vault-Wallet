#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use vault_crypto::{VaultEnvelope, VaultError};

const MAX_VAULT_FILE_BYTES: u64 = 20 * 1024 * 1024;

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
    TooLarge,
    Io(io::Error),
    InvalidVault(VaultError),
    RandomnessUnavailable,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => write!(formatter, "vault file already exists"),
            Self::TooLarge => write!(formatter, "vault file exceeds configured size limit"),
            Self::Io(error) => write!(formatter, "vault storage error: {error}"),
            Self::InvalidVault(error) => write!(formatter, "invalid encrypted vault: {error}"),
            Self::RandomnessUnavailable => write!(formatter, "secure randomness unavailable"),
        }
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidVault(error) => Some(error),
            _ => None,
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
    if encoded.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    let temp = temporary_sibling(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let result = (|| -> Result<(), StorageError> {
        let mut file = options.open(&temp)?;
        file.write_all(&encoded)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        match fs::hard_link(&temp, path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StorageError::AlreadyExists);
            }
            Err(error) => return Err(StorageError::Io(error)),
        }

        sync_parent_if_supported(parent)?;
        fs::remove_file(&temp)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub fn read_envelope(path: &Path) -> Result<VaultEnvelope, StorageError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    let capacity = usize::try_from(metadata.len()).map_err(|_| StorageError::TooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(MAX_VAULT_FILE_BYTES + 1);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::TooLarge);
    }

    VaultEnvelope::decode(&bytes).map_err(StorageError::InvalidVault)
}

fn temporary_sibling(path: &Path) -> Result<PathBuf, StorageError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("wallet.dvlt");

    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| StorageError::RandomnessUnavailable)?;
    let suffix = u64::from_be_bytes(random);
    Ok(parent.join(format!(".{name}.{suffix:016x}.tmp")))
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
    use vault_crypto::{seal, KdfParams, VaultDomain};

    fn unique_test_dir(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).unwrap();
        std::env::temp_dir().join(format!(
            "demon-vault-{label}-{:016x}",
            u64::from_be_bytes(random)
        ))
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
    fn encrypted_envelope_is_created_and_read_back() {
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
    fn existing_vault_is_never_overwritten() {
        let root = unique_test_dir("no-overwrite");
        let path = AppPaths::new(&root).wallet_vault();
        let first = seal(
            b"phase-three-test",
            VaultDomain::Wallet,
            b"first-secret",
            test_kdf(),
        )
        .unwrap();
        let second = seal(
            b"phase-three-test",
            VaultDomain::Wallet,
            b"second-secret",
            test_kdf(),
        )
        .unwrap();

        write_new_envelope_atomic(&path, &first).unwrap();
        assert!(matches!(
            write_new_envelope_atomic(&path, &second),
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(read_envelope(&path).unwrap(), first);

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_test_dir("mode");
        let path = AppPaths::new(&root).wallet_vault();
        let envelope = seal(
            b"phase-three-test",
            VaultDomain::Wallet,
            b"synthetic-secret",
            test_kdf(),
        )
        .unwrap();

        write_new_envelope_atomic(&path, &envelope).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::remove_dir_all(root).unwrap();
    }
}
