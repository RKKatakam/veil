//! Portable Web Worker secret decryption helpers (`docs/HUB.md` §13.40;
//! `docs/design/server/phase-4-agent-scale.md` §4.12, milestone S26).
//!
//! This module runs inside a dedicated Web Worker WASM binary
//! (`examples/web_secret_worker.rs`) that is served **only** when a project
//! admin has turned browser secrets on (`project.web_secrets = true`).
//!
//! Invariants enforced here:
//! 1. **Separate browser device:** a browser device identity is generated
//!    fresh in WASM (`hub::web::seal_new_browser_device`) and sealed under a
//!    key derived from the person's WebAuthn passkey PRF output
//!    (`HUB_WEB_PRF_KEY`). Plain private keys never leave WASM memory.
//! 2. **Verified key rings & project binding:** every key ring is verified
//!    (`KeyRing::verify`) and checked against the expected project fingerprint
//!    before any key is unwrapped.
//! 3. **Content-addressed verification:** sealed object bytes are checked
//!    against their `ObjectId` before decryption.
//! 4. **Scope-only envelopes:** only repository file envelopes (`<scope>` or
//!    `<scope>#<key-id>`) may be opened; `local`, `vault:`, `share:`, `wrap:`,
//!    `prev-key:`, and `web-device:` labels are refused.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        domains::{GENERATION_SEPARATOR, LOCAL_LABEL},
        Envelope, Key,
    },
    error::{Result, VeilError},
    hub::{
        encoding,
        web::{browser_device_label, derive_prf_wrapping_key, MAX_WEB_DIFF_BYTES},
        wire::{device_fingerprint, normalize_fingerprint},
    },
    identity::{parse_public_identity, Identity, WrappedKey},
    keychain::{key_fingerprint, project_fingerprint, KeyRing, RingOp, Rotation},
    object::Object,
    ObjectId,
};

/// Public metadata of an unsealed browser device, returned to verify a stored
/// IndexedDB record without exposing private keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDevicePublic {
    pub public_identity: String,
    pub signing_key: String,
    pub member_id: String,
    pub fingerprint: String,
}

/// Decrypted secret file payload returned from the Web Worker on an explicit
/// "Show" action. Never cached in storage or sent over the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedBrowserSecret {
    pub scope: String,
    pub key_id: String,
    pub binary: bool,
    pub size: usize,
    pub text: Option<String>,
}

const MAX_WORKER_OBJECT_BYTES: u64 = (MAX_WEB_DIFF_BYTES + 65_536) as u64;

fn unseal_identity_in_worker(credential_id: &str, prf_output: &[u8], sealed_identity_hex: &str) -> Result<Identity> {
    let wrap_key = derive_prf_wrapping_key(prf_output)?;
    let expected_label = browser_device_label(credential_id)?;
    let raw_env = hex::decode(sealed_identity_hex.trim())
        .map_err(|_| VeilError::Corrupt("sealed-browser-device".into(), "invalid hex encoding".into()))?;
    let env = Envelope::from_bytes(&raw_env)?;
    if env.scope != expected_label {
        return Err(VeilError::Crypto(
            "sealed browser device label does not match passkey credential".into(),
        ));
    }
    let plain_bytes = Zeroizing::new(env.open(&wrap_key)?);
    let plain_str = std::str::from_utf8(&plain_bytes)
        .map_err(|_| VeilError::Corrupt("sealed-browser-device".into(), "invalid UTF-8".into()))?;
    Identity::from_json(plain_str)
}

/// Verify that `sealed_identity_hex` decrypts cleanly under `(credential_id, prf_output)`
/// and return only its public identity and device fingerprint.
pub fn verify_sealed_browser_device(
    credential_id: &str,
    prf_output: &[u8],
    sealed_identity_hex: &str,
) -> Result<BrowserDevicePublic> {
    let id = unseal_identity_in_worker(credential_id, prf_output, sealed_identity_hex)?;
    let public_identity = id.public_id();
    let parsed = parse_public_identity(&public_identity)?;
    let fingerprint = device_fingerprint(&parsed)
        .ok_or_else(|| VeilError::Corrupt("browser-device".into(), "invalid public identity".into()))?;
    Ok(BrowserDevicePublic {
        public_identity,
        signing_key: id.verifying_hex(),
        member_id: id.public_hex(),
        fingerprint,
    })
}

fn split_secret_file_label(label: &str) -> Result<(&str, Option<&str>)> {
    let (scope, kid) = match label.split_once(GENERATION_SEPARATOR) {
        Some((s, k)) if !k.is_empty() => (s, Some(k)),
        Some(_) => return Err(VeilError::Corrupt("envelope-label".into(), "empty key generation id".into())),
        None => (label, None),
    };
    if scope.is_empty() || scope == LOCAL_LABEL || scope.contains(':') || scope.contains('/') {
        return Err(VeilError::Policy(format!(
            "refusing non-repository secret label '{scope}' in browser worker"
        )));
    }
    Ok((scope, kid))
}

fn parse_ring_entry(scope: &str, val: &serde_json::Value) -> Result<KeyRing> {
    let ring: KeyRing = match val {
        serde_json::Value::String(s) => serde_json::from_str(s)
            .map_err(|e| VeilError::Corrupt(format!("ring:{scope}"), e.to_string()))?,
        other => serde_json::from_value(other.clone())
            .map_err(|e| VeilError::Corrupt(format!("ring:{scope}"), e.to_string()))?,
    };
    if ring.scope != scope {
        return Err(VeilError::Corrupt(
            format!("ring:{scope}"),
            format!("ring scope mismatch: '{}'", ring.scope),
        ));
    }
    Ok(ring)
}

fn derive_ring_keys(
    me: &Identity,
    ring: &KeyRing,
    expected_project_fp: Option<&str>,
) -> Result<(String, BTreeMap<String, Zeroizing<Key>>)> {
    let state = ring
        .verify()
        .map_err(|e| VeilError::Corrupt(format!("ring:{}", ring.scope), e))?;

    if let Some(raw_fp) = expected_project_fp.map(str::trim).filter(|s| !s.is_empty()) {
        let want_fp = normalize_fingerprint(raw_fp)
            .ok_or_else(|| VeilError::Corrupt("project-fingerprint".into(), "invalid project fingerprint".into()))?;
        let Some(proj_id) = state.project.as_deref() else {
            return Err(VeilError::Policy(
                "key ring is not bound to a project and cannot verify project fingerprint".into(),
            ));
        };
        if project_fingerprint(proj_id) != want_fp {
            return Err(VeilError::Policy(format!(
                "key ring for '{}' does not match confirmed project fingerprint {want_fp}",
                ring.scope
            )));
        }
    }

    let mut keys: BTreeMap<String, Zeroizing<Key>> = BTreeMap::new();
    let my_id = me.public_hex();
    let scope = ring.scope.as_str();

    if ring.is_legacy() {
        if let Some(m) = ring.members.get(&my_id) {
            if let Ok(k) = me.unwrap_key(&m.wrapped, scope) {
                let fp = key_fingerprint(&k);
                if ring.key_id.is_empty() || ring.key_id == fp {
                    keys.insert(fp.clone(), Zeroizing::new(k));
                    return Ok((fp, keys));
                }
            }
        }
        return Ok((state.genesis_key_id().to_string(), keys));
    }

    let mut candidates: Vec<(u32, &WrappedKey)> = Vec::new();
    let mut rotations: BTreeMap<u32, &Rotation> = BTreeMap::new();
    for c in &ring.log {
        match &c.op {
            RingOp::Genesis { members, .. } => {
                candidates.extend(members.iter().filter(|m| m.id == my_id).map(|m| (0, &m.wrapped)));
            }
            RingOp::Grant { member } | RingOp::Share { member, .. } if member.id == my_id => {
                candidates.push((member.generation, &member.wrapped));
            }
            RingOp::Grant { .. } | RingOp::Share { .. } | RingOp::Invite { .. } | RingOp::Uninvite { .. } => {}
            RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => {
                rotations.insert(rotation.generation, rotation);
                if let Some(w) = rotation.wrapped.get(&my_id) {
                    candidates.push((rotation.generation, w));
                }
            }
        }
    }
    candidates.sort_by_key(|(g, _)| std::cmp::Reverse(*g));

    let mut newest = None;
    for (g, w) in candidates {
        let Some(kid) = state.generations.get(g as usize) else { continue };
        if let Ok(k) = me.unwrap_key(w, scope) {
            if key_fingerprint(&k) == *kid {
                newest = Some((g, Zeroizing::new(k)));
                break;
            }
        }
    }

    let genesis_kid = state.genesis_key_id().to_string();
    let Some((mut g, mut key)) = newest else {
        return Ok((genesis_kid, keys));
    };
    keys.insert(state.generations[g as usize].clone(), key.clone());

    while g > 0 {
        let Some(rot) = rotations.get(&g) else { break };
        let want = &state.generations[g as usize - 1];
        let mut next = None;
        for p in &rot.previous {
            let Ok(raw) = p.sealed.open(&key).map(Zeroizing::new) else { continue };
            let Ok(k) = <Key>::try_from(raw.as_slice()) else { continue };
            if key_fingerprint(&k) != p.key_id {
                continue;
            }
            if p.key_id == *want {
                next = Some(Zeroizing::new(k));
            }
            keys.insert(p.key_id.clone(), Zeroizing::new(k));
        }
        match next {
            Some(k) => key = k,
            None => break,
        }
        g -= 1;
    }

    Ok((genesis_kid, keys))
}

/// Unseal the browser device identity under `prf_output`, verify the scope's
/// `KeyRing` and optional project fingerprint, verify the ciphertext's
/// content-addressed `ObjectId`, and open one sealed secret file inside WASM
/// memory.
pub fn open_secret_in_worker(
    credential_id: &str,
    prf_output: &[u8],
    sealed_identity_hex: &str,
    rings_json: &str,
    expected_project_fp: Option<&str>,
    expected_object_id: Option<&str>,
    encoded_object: &[u8],
) -> Result<OpenedBrowserSecret> {
    let me = unseal_identity_in_worker(credential_id, prf_output, sealed_identity_hex)?;

    let raw_cow = match expected_object_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(oid_hex) => {
            let oid = ObjectId::from_hex(oid_hex)?;
            encoding::decode(&oid, encoded_object, MAX_WORKER_OBJECT_BYTES)?
        }
        None => {
            if encoded_object.len() as u64 > MAX_WORKER_OBJECT_BYTES {
                return Err(VeilError::Corrupt("sealed-object".into(), "object exceeds browser worker limit".into()));
            }
            std::borrow::Cow::Borrowed(encoded_object)
        }
    };

    let env = match Object::decode(&raw_cow)? {
        Object::Sealed(env) => env,
        _ => return Err(VeilError::Corrupt("sealed-object".into(), "expected a sealed secret object".into())),
    };

    let (scope, kid_opt) = split_secret_file_label(&env.scope)?;

    let ring_map: BTreeMap<String, serde_json::Value> = serde_json::from_str(rings_json)
        .map_err(|e| VeilError::Corrupt("rings-json".into(), e.to_string()))?;
    let ring_val = ring_map
        .get(scope)
        .ok_or_else(|| VeilError::Redacted { scope: scope.to_string() })?;
    let ring = parse_ring_entry(scope, ring_val)?;

    let (genesis_kid, keys) = derive_ring_keys(&me, &ring, expected_project_fp)?;
    let want_kid = kid_opt.unwrap_or(&genesis_kid);
    let key = keys
        .get(want_kid)
        .ok_or_else(|| VeilError::Redacted { scope: env.scope.clone() })?;

    let decrypted = Zeroizing::new(env.open(key)?);
    let plain = match Object::decode(&decrypted)? {
        Object::Blob(b) => Zeroizing::new(b),
        o => {
            return Err(VeilError::Corrupt(
                "sealed-object".into(),
                format!("expected blob inside sealed secret, found {}", o.kind_name()),
            ));
        }
    };
    let size = plain.len();
    if plain.contains(&0) || size > MAX_WEB_DIFF_BYTES {
        return Ok(OpenedBrowserSecret {
            scope: scope.to_string(),
            key_id: want_kid.to_string(),
            binary: true,
            size,
            text: None,
        });
    }
    match std::str::from_utf8(&plain) {
        Ok(s) => Ok(OpenedBrowserSecret {
            scope: scope.to_string(),
            key_id: want_kid.to_string(),
            binary: false,
            size,
            text: Some(s.to_owned()),
        }),
        Err(_) => Ok(OpenedBrowserSecret {
            scope: scope.to_string(),
            key_id: want_kid.to_string(),
            binary: true,
            size,
            text: None,
        }),
    }
}
