//! The local vault: device-only, encrypted storage for secrets (`vl secret`)
//! and backups of isolated files (`.env` & co).
//!
//! Sealed under the `local` scope, whose key is derived from the identity
//! secret and never written anywhere. The vault lives in `.veil/local/`,
//! which is never synchronised.
//!
//! **Replacing the identity** (`vl identity new --force`) changes the `local`
//! key, so a vault sealed by the previous identity can no longer be opened.
//! That never stops the repository from working:
//!
//! * snapshots skip backing up isolated files into a vault they cannot open
//!   ([`Repo::capture_local_files`]), and leave it untouched;
//! * only commands that need the vault's content (`vl secret`, `vl run`,
//!   `vl ws exec --with-isolated`) fail, with an error explaining why;
//! * [`Repo::vault_rekey`] re-seals the vault under the current identity
//!   given the previous one. `vl identity new --force` keeps the replaced
//!   identity for this, and `vl identity recover-vault` uses it.
//!
//! Every read-modify-write of the vault holds the repository lock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    builder::BuildReport,
    crypto::{Envelope, Key},
    error::{Result, VeilError},
    identity::Identity,
    keychain::LOCAL_SCOPE,
    lock::RepoLock,
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

pub const VAULT_PATH: &str = ".veil/local/vault.sealed";

fn vault_path() -> VPath {
    VPath::new(VAULT_PATH).unwrap()
}

/// What is on disk.
enum Stored {
    Absent,
    Open(VaultData),
    /// Present, but this identity's key does not open it.
    Unreadable,
}

fn unreadable() -> VeilError {
    VeilError::Crypto(format!(
        "the local vault ({VAULT_PATH}) cannot be opened with this identity's key: it was sealed by \
         another identity (was the identity replaced with `vl identity new --force`?) or is damaged. \
         Run `vl identity recover-vault` to re-key it from the previous identity, or delete the file \
         to start an empty vault"
    ))
}

impl Repo {
    fn local_key(&self) -> Result<Key> {
        self.keys().require(LOCAL_SCOPE)
    }

    fn vault_read(&self, key: &Key) -> Result<Stored> {
        let Some(raw) = self.backend.read_opt(&vault_path())? else {
            return Ok(Stored::Absent);
        };
        let Ok(plain) = Envelope::from_bytes(&raw).and_then(|e| e.open(key)) else {
            return Ok(Stored::Unreadable);
        };
        Ok(Stored::Open(serde_json::from_slice(&plain)?))
    }

    fn vault_write(&self, key: &Key, data: &VaultData) -> Result<()> {
        let env = Envelope::seal(key, LOCAL_SCOPE, &serde_json::to_vec(data)?, false)?;
        self.backend.write(&vault_path(), &env.to_bytes())
    }

    /// The vault's content (empty if there is none yet). Fails with an
    /// explanation if the vault was sealed by another identity.
    pub fn vault_load(&self) -> Result<VaultData> {
        match self.vault_read(&self.local_key()?)? {
            Stored::Absent => Ok(VaultData::default()),
            Stored::Open(v) => Ok(v),
            Stored::Unreadable => Err(unreadable()),
        }
    }

    /// Whether a vault exists that this identity cannot open.
    pub fn vault_unreadable(&self) -> Result<bool> {
        let Ok(key) = self.local_key() else {
            return Ok(false);
        };
        Ok(matches!(self.vault_read(&key)?, Stored::Unreadable))
    }

    /// Replace the vault's content.
    pub fn vault_save(&self, data: &VaultData) -> Result<()> {
        let _lock = RepoLock::acquire_reentrant(self.backend.clone())?;
        self.vault_write(&self.local_key()?, data)
    }

    /// Read, modify and write the vault under the repository lock. The
    /// vault is only written if `f` changed it. Fails without calling `f`
    /// if the vault cannot be opened (it is never overwritten).
    pub fn vault_update<T>(&self, f: impl FnOnce(&mut VaultData) -> Result<T>) -> Result<T> {
        let _lock = RepoLock::acquire_reentrant(self.backend.clone())?;
        let key = self.local_key()?;
        let before = match self.vault_read(&key)? {
            Stored::Absent => VaultData::default(),
            Stored::Open(v) => v,
            Stored::Unreadable => return Err(unreadable()),
        };
        let mut vault = before.clone();
        let out = f(&mut vault)?;
        if vault != before {
            self.vault_write(&key, &vault)?;
        }
        Ok(out)
    }

    /// Re-seal a vault sealed by `previous` (an identity this one replaced)
    /// under the current identity. Returns `false`, changing nothing, if
    /// there is no vault, it already opens, or `previous` does not open it.
    pub fn vault_rekey(&self, previous: &Identity) -> Result<bool> {
        let _lock = RepoLock::acquire_reentrant(self.backend.clone())?;
        let key = self.local_key()?;
        if !matches!(self.vault_read(&key)?, Stored::Unreadable) {
            return Ok(false);
        }
        let Stored::Open(data) = self.vault_read(&previous.local_key(self.repo_id()))? else {
            return Ok(false);
        };
        self.vault_write(&key, &data)?;
        Ok(true)
    }

    /// Back up local-only files reported by a snapshot into the vault, so
    /// they can be injected into virtual workspaces (`vl ws exec
    /// --with-isolated`) without ever entering history. A vault this
    /// identity cannot open is left alone (see the module documentation):
    /// nothing is backed up and `false` is returned.
    pub fn capture_local_files(&self, fs: &dyn StorageBackend, report: &BuildReport) -> Result<bool> {
        if self.identity().is_none() {
            return Ok(false);
        }
        let local = report.local_only();
        let mut contents = BTreeMap::new();
        for p in &local {
            if let Some(data) = fs.read_opt(p)? {
                contents.insert(p.as_str().to_string(), hex::encode(data));
            }
        }
        let keep: std::collections::HashSet<&str> = local.iter().map(|p| p.as_str()).collect();
        let res = self.vault_update(|vault| {
            let before = vault.files.clone();
            vault.files.retain(|p, _| keep.contains(p.as_str()));
            vault.files.extend(contents);
            Ok(vault.files != before)
        });
        match res {
            Err(_) if self.vault_unreadable()? => Ok(false),
            r => r,
        }
    }
}
