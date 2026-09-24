#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_joined_without_os_specific_literals() {
        let paths = AppPaths::new(PathBuf::from("demon-vault-test"));
        assert_eq!(paths.state_dir(), paths.root().join("state"));
        assert_eq!(paths.vault_dir(), paths.root().join("vault"));
        assert_eq!(paths.logs_dir(), paths.root().join("logs"));
    }
}
