//! The local vault: device-only, encrypted storage for secrets (`vl secret`)
//! and backups of isolated files (`.env` & co).
//!
//! Sealed under the `local` scope, whose key is derived from the identity
//! secret and never written anywhere. The vault lives in `.veil/local/`,
//! which is never synchronised.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    builder::BuildReport,
    crypto::Envelope,
    error::Result,
    keychain::LOCAL_SCOPE,
    repo::Repo,
    vfs::StorageBackend,
    vpath::VPath,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// Isolated file path → hex-encoded content.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

fn vault_path() -> VPath {
    VPath::new(".veil/local/vault.sealed").unwrap()
}

impl Repo {
    pub fn vault_load(&self) -> Result<VaultData> {
        let Some(raw) = self.backend.read_opt(&vault_path())? else {
            return Ok(VaultData::default());
        };
        let key = self.keys().require(LOCAL_SCOPE)?;
        let plain = Envelope::from_bytes(&raw)?.open(&key)?;
        Ok(serde_json::from_slice(&plain)?)
    }

    pub fn vault_save(&self, data: &VaultData) -> Result<()> {
        let key = self.keys().require(LOCAL_SCOPE)?;
        let env = Envelope::seal(&key, LOCAL_SCOPE, &serde_json::to_vec(data)?, false)?;
        self.backend.write(&vault_path(), &env.to_bytes())
    }

    /// Back up local-only files reported by a snapshot into the vault, so
    /// they can be injected into virtual workspaces (`vl ws exec
    /// --with-isolated`) without ever entering history.
    pub fn capture_local_files(&self, fs: &dyn StorageBackend, report: &BuildReport) -> Result<bool> {
        if self.identity().is_none() {
            return Ok(false);
        }
        let mut vault = self.vault_load()?;
        let before = vault.files.clone();
        let local = report.local_only();
        for p in &local {
            if let Some(data) = fs.read_opt(p)? {
                vault.files.insert(p.as_str().to_string(), hex::encode(data));
            }
        }
        let keep: std::collections::HashSet<&str> = local.iter().map(|p| p.as_str()).collect();
        vault.files.retain(|p, _| keep.contains(p.as_str()));
        if vault.files != before {
            self.vault_save(&vault)?;
            return Ok(true);
        }
        Ok(false)
    }
}
