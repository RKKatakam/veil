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
    /// Backups of isolated files that are no longer in the working copy,
    /// kept for [`REMOVED_RETENTION_MS`] after they were first seen missing
    /// (`vl secret recover` writes one back). Whoever removed the file (the
    /// user, a tool, a checkout), the backup is the last copy of content
    /// that is in no snapshot, so it is not dropped at the next snapshot.
    /// Never injected into sandboxes: the file is gone from the working copy.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub removed: BTreeMap<String, RemovedFile>,
}

/// The backup of an isolated file that disappeared from the working copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedFile {
    /// Hex-encoded content.
    pub content: String,
    /// When a snapshot first found the file missing (ms since the epoch).
    pub removed_at: i64,
}

/// How long the backup of a vanished isolated file is kept: 30 days.
pub const REMOVED_RETENTION_MS: i64 = 30 * 24 * 3600 * 1000;

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
        // A backup whose file is still there (no longer local-only, say) is
        // not the last copy; one whose file is gone is kept for a while.
        let mut gone = std::collections::HashSet::new();
        let read = self.vault_read(&self.local_key()?)?;
        if let Stored::Open(v) = &read {
            for p in v.files.keys().filter(|p| !keep.contains(p.as_str())) {
                let vanished = match VPath::new(p) {
                    Ok(vp) => !fs.exists(&vp)?,
                    Err(_) => false,
                };
                if vanished {
                    gone.insert(p.clone());
                }
            }
        }
        let now = crate::now_millis();
        let apply = |vault: &mut VaultData| {
            let before = vault.clone();
            let dropped: Vec<(String, String)> = std::mem::take(&mut vault.files)
                .into_iter()
                .filter_map(|(p, c)| {
                    if keep.contains(p.as_str()) {
                        vault.files.insert(p, c);
                        None
                    } else {
                        Some((p, c))
                    }
                })
                .collect();
            for (p, content) in dropped {
                if gone.contains(&p) {
                    vault.removed.insert(p, RemovedFile { content, removed_at: now });
                }
            }
            vault.removed.retain(|p, r| !keep.contains(p.as_str()) && now - r.removed_at < REMOVED_RETENTION_MS);
            vault.files.extend(contents.clone());
            *vault != before
        };
        // Every command snapshots, so this runs every time: the lock (a
        // read-modify-write of the vault) is only taken when the backup
        // changes. The vault is replaced atomically, so reading it without
        // the lock sees one version or the other.
        let unchanged = match &read {
            Stored::Open(v) => !apply(&mut v.clone()),
            Stored::Absent => !apply(&mut VaultData::default()),
            Stored::Unreadable => return Ok(false),
        };
        if unchanged {
            return Ok(false);
        }
        let res = self.vault_update(|vault| Ok(apply(vault)));
        match res {
            Err(_) if self.vault_unreadable()? => Ok(false),
            r => r,
        }
    }

    /// Write the vault's backup of the isolated file `path` back into the
    /// working copy `fs` (the latest backup, or the one kept after the file
    /// vanished). Refuses if anything exists at `path`: a backup never
    /// overwrites. Returns whether there was a backup.
    pub fn vault_recover_file(&self, fs: &dyn StorageBackend, path: &VPath) -> Result<bool> {
        let vault = self.vault_load()?;
        let key = path.as_str();
        let Some(hexdata) = vault.files.get(key).or_else(|| vault.removed.get(key).map(|r| &r.content)) else {
            return Ok(false);
        };
        if fs.metadata(path)?.is_some() || crate::checkout::behind_special(fs, path)? {
            return Err(VeilError::AlreadyExists(format!(
                "{key} exists in the working copy; move it away first (the backup never overwrites)"
            )));
        }
        let data = hex::decode(hexdata).map_err(|e| VeilError::Corrupt(VAULT_PATH.into(), e.to_string()))?;
        fs.write(path, &data)?;
        Ok(true)
    }
}
