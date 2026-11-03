//! Scope keys, identity rings and embargo records.
//!
//! Shared, publishable metadata lives under `.veil/meta/`:
//!
//! * `keyrings/<scope>.json` — the scope key wrapped to each member identity.
//! * `embargoes/<id>.json`   — an embargo key wrapped under a scope key, plus
//!   its release condition; on release the plaintext key is published.
//!
//! The special scope `local` is derived from the identity secret and the
//! repository id; it never exists anywhere on disk and therefore cannot be
//! synchronised.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{random_bytes, random_key, Envelope, Key},
    error::{Result, VeilError},
    identity::{format_public_key, parse_public_key, wrap_key, Identity, WrappedKey},
    vfs::StorageBackend,
    vpath::VPath,
};

pub const LOCAL_SCOPE: &str = "local";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRing {
    pub scope: String,
    /// Fingerprint of the scope key. Two rings for the same scope name but
    /// different keys (independently created) are never merged.
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub members: BTreeMap<String, RingMember>,
}

/// Public fingerprint of a scope key.
pub fn key_fingerprint(key: &Key) -> String {
    hex::encode(&blake3::derive_key("veil 2026 key-fingerprint v1", key)[..8])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingMember {
    pub name: String,
    pub wrapped: WrappedKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbargoRecord {
    pub id: String,
    /// Scope whose members may read the embargoed content before release.
    pub scope: String,
    pub wrapped: Envelope,
    /// Automatic release time (ms since epoch); `None` = manual release.
    pub until: Option<i64>,
    pub released_key: Option<String>,
    pub released_at: Option<i64>,
    pub created: i64,
    pub description: String,
}

impl EmbargoRecord {
    pub fn is_released(&self) -> bool {
        self.released_key.is_some()
    }
}

pub fn validate_scope_name(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s != LOCAL_SCOPE
        && !s.starts_with("embargo")
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(VeilError::Policy(format!(
            "invalid scope name '{s}' (use lowercase letters, digits, '-' or '_'; 'local' and 'embargo*' are reserved)"
        )))
    }
}

#[derive(Debug)]
pub struct Keychain {
    backend: Arc<dyn StorageBackend>,
    identity: Option<Identity>,
    repo_id: String,
    cache: RwLock<HashMap<String, Option<Key>>>,
}

impl Keychain {
    pub fn new(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, repo_id: String) -> Self {
        Keychain {
            backend,
            identity,
            repo_id,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Forget cached keys (after pulling new rings or embargo records).
    pub fn invalidate(&self) {
        self.cache.write().unwrap().clear();
    }

    /// The key for `scope`, if this identity can obtain it.
    pub fn key(&self, scope: &str) -> Option<Key> {
        if let Some(k) = self.cache.read().unwrap().get(scope) {
            return *k;
        }
        let k = self.resolve(scope);
        self.cache.write().unwrap().insert(scope.to_string(), k);
        k
    }

    pub fn has(&self, scope: &str) -> bool {
        self.key(scope).is_some()
    }

    pub fn require(&self, scope: &str) -> Result<Key> {
        self.key(scope).ok_or_else(|| VeilError::Redacted {
            scope: scope.to_string(),
        })
    }

    fn resolve(&self, scope: &str) -> Option<Key> {
        if scope == LOCAL_SCOPE {
            return self.identity.as_ref().map(|i| i.local_key(&self.repo_id));
        }
        if let Some(id) = scope.strip_prefix("embargo/") {
            let rec = self.load_embargo(id).ok()??;
            if let Some(k) = &rec.released_key {
                return crate::crypto::parse_key_hex(k).ok();
            }
            let scope_key = self.key(&rec.scope)?;
            return rec.wrapped.open(&scope_key).ok()?.try_into().ok();
        }
        let ident = self.identity.as_ref()?;
        let ring = self.load_ring(scope).ok()??;
        let member = ring.members.get(&ident.public_hex())?;
        let key = ident.unwrap_key(&member.wrapped, scope).ok()?;
        (ring.key_id.is_empty() || ring.key_id == key_fingerprint(&key)).then_some(key)
    }

    // ---- key rings -------------------------------------------------------

    fn ring_path(scope: &str) -> VPath {
        VPath::new(&format!(".veil/meta/keyrings/{scope}.json")).unwrap()
    }

    pub fn load_ring(&self, scope: &str) -> Result<Option<KeyRing>> {
        match self.backend.read_opt(&Self::ring_path(scope))? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    pub fn save_ring(&self, ring: &KeyRing) -> Result<()> {
        self.backend
            .write(&Self::ring_path(&ring.scope), &serde_json::to_vec_pretty(ring)?)?;
        self.invalidate();
        Ok(())
    }

    pub fn rings(&self) -> Result<Vec<KeyRing>> {
        let dir = VPath::new(".veil/meta/keyrings")?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            if let Some(scope) = e.name.strip_suffix(".json") {
                if let Some(r) = self.load_ring(scope)? {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }

    fn me(&self) -> Result<&Identity> {
        self.identity
            .as_ref()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))
    }

    /// Create a new scope whose only member is the current identity.
    pub fn create_scope(&self, scope: &str) -> Result<()> {
        validate_scope_name(scope)?;
        if self.load_ring(scope)?.is_some() {
            return Err(VeilError::AlreadyExists(format!("scope '{scope}'")));
        }
        let me = self.me()?;
        let key = random_key();
        let mut ring = KeyRing {
            scope: scope.to_string(),
            key_id: key_fingerprint(&key),
            members: BTreeMap::new(),
        };
        ring.members.insert(
            me.public_hex(),
            RingMember {
                name: me.name.clone(),
                wrapped: wrap_key(&me.public_key(), &key, scope)?,
            },
        );
        self.save_ring(&ring)
    }

    /// Wrap the scope key for another identity.
    pub fn grant(&self, scope: &str, public_key: &str, name: &str) -> Result<()> {
        let key = self.key(scope).ok_or_else(|| {
            VeilError::Policy(format!("you are not a member of scope '{scope}', so you cannot grant it"))
        })?;
        let pk = parse_public_key(public_key)?;
        let mut ring = self.load_ring(scope)?.unwrap_or_default();
        ring.scope = scope.to_string();
        ring.key_id = key_fingerprint(&key);
        ring.members.insert(
            format_public_key(&pk),
            RingMember {
                name: name.to_string(),
                wrapped: wrap_key(&pk, &key, scope)?,
            },
        );
        self.save_ring(&ring)
    }

    /// Remove a member. Note: like any revocation, this cannot claw back
    /// content the member already decrypted; rotate secrets accordingly.
    pub fn revoke(&self, scope: &str, public_key: &str) -> Result<bool> {
        let pk = format_public_key(&parse_public_key(public_key)?);
        let Some(mut ring) = self.load_ring(scope)? else {
            return Ok(false);
        };
        let removed = ring.members.remove(&pk).is_some();
        if removed {
            self.save_ring(&ring)?;
        }
        Ok(removed)
    }

    // ---- embargoes -------------------------------------------------------

    fn embargo_path(id: &str) -> VPath {
        VPath::new(&format!(".veil/meta/embargoes/{id}.json")).unwrap()
    }

    pub fn load_embargo(&self, id: &str) -> Result<Option<EmbargoRecord>> {
        match self.backend.read_opt(&Self::embargo_path(id))? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    pub fn save_embargo(&self, rec: &EmbargoRecord) -> Result<()> {
        self.backend
            .write(&Self::embargo_path(&rec.id), &serde_json::to_vec_pretty(rec)?)?;
        self.invalidate();
        Ok(())
    }

    pub fn embargoes(&self) -> Result<Vec<EmbargoRecord>> {
        let dir = VPath::new(".veil/meta/embargoes")?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            if let Some(id) = e.name.strip_suffix(".json") {
                if let Some(r) = self.load_embargo(id)? {
                    out.push(r);
                }
            }
        }
        out.sort_by_key(|r| r.created);
        Ok(out)
    }

    pub fn embargo_released(&self, id: &str) -> bool {
        self.load_embargo(id).ok().flatten().is_some_and(|r| r.is_released())
    }

    pub fn create_embargo(&self, scope: &str, until: Option<i64>, description: &str) -> Result<String> {
        let scope_key = self.key(scope).ok_or_else(|| {
            VeilError::Policy(format!("an embargo needs a scope you belong to; you have no key for '{scope}'"))
        })?;
        let id = hex::encode(random_bytes::<5>());
        let key = random_key();
        let rec = EmbargoRecord {
            id: id.clone(),
            scope: scope.to_string(),
            wrapped: Envelope::seal(&scope_key, &format!("embargo-wrap:{id}"), &key, false)?,
            until,
            released_key: None,
            released_at: None,
            created: crate::now_millis(),
            description: description.to_string(),
        };
        self.save_embargo(&rec)?;
        Ok(id)
    }

    /// Publish the embargo key, making the embargoed content readable to all.
    pub fn release_embargo(&self, id: &str) -> Result<()> {
        let mut rec = self
            .load_embargo(id)?
            .ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
        if rec.is_released() {
            return Ok(());
        }
        let key = self
            .key(&format!("embargo/{id}"))
            .ok_or_else(|| VeilError::Policy(format!("you do not hold the key for embargo '{id}'")))?;
        rec.released_key = Some(hex::encode(key));
        rec.released_at = Some(crate::now_millis());
        self.save_embargo(&rec)
    }
}
