//! Person-to-person secret shares (`vl secret share PATH --with PERSON`,
//! `docs/HUB.md` §13.14, `docs/CRYPTO.md` C14).
//!
//! A share is a **copy of one secret file**, sealed for the confirmed
//! devices of one person (and the sharing device), signed by the sharing
//! device. It opens nothing else: not the access line's key, not another
//! file under it.
//!
//! * Each version has its own random 32-byte key `K`. The file is sealed
//!   under `K` with the random-nonce envelope (C2), label
//!   `share:<share id>#<version>`, and `K` is wrapped with HPKE (C3) to
//!   each device, bound to the same label. So a device left out of a version
//!   (removed, or no longer the person's) cannot open it or any later one.
//! * The record (project, path, sharer, recipient, version, time, signing
//!   key, the sealed file and every wrap) is signed by the sharing device
//!   (Ed25519, context `hub-share`). Whether that device is the sharer's is
//!   decided by the reader against the project's key rings, never by the
//!   server.
//! * The server stores records and decides who may write and read them (the
//!   sharer's access to the path, the recipient's part in the project). It
//!   cannot open them, and a record it changes no longer verifies.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{domains, random_key, Envelope},
    error::{Result, VeilError},
    identity::{verify_signature, wrap_key, Identity, WrappedKey},
    policy::{Policy, Tier},
    vpath::VPath,
};

/// The record format this build writes and reads.
pub const SHARE_FORMAT: u32 = 1;
/// The largest secret file a share carries.
pub const MAX_SHARE_BYTES: usize = 64 << 10;
/// The most devices one version is wrapped for.
pub const MAX_SHARE_DEVICES: usize = 64;
/// The most shares one person keeps in one project (active or ended).
pub const MAX_SHARES_PER_SHARER: i64 = 256;

/// Names of personal private keys: never shared, whatever the policy says
/// (`docs/VISIBILITY.md`, "Personal private keys never leave your machine").
pub fn personal_key(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(name.as_str(), "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519")
}

/// May the file at `path` be shared under `policy`? Only a secret file the
/// policy seals (`cloak`), never a personal key, never code (code is shared
/// with `vl access`). `Err` says why not.
pub fn shareable(policy: &Policy, path: &str) -> std::result::Result<VPath, String> {
    let vp = VPath::new(path).ok().filter(|v| !v.as_str().split('/').any(crate::object::is_reserved_name));
    let vp = vp.ok_or_else(|| format!("'{path}' is not a path in the project"))?;
    if personal_key(path) {
        return Err(format!("'{path}' is a personal private key: it never leaves your device"));
    }
    match policy.classify(&vp, false).tier {
        Tier::Cloaked(_) => Ok(vp),
        Tier::Isolated => Err(format!(
            "'{path}' stays on this device by the project's policy (a personal key or credential): it is never shared"
        )),
        _ => Err(format!(
            "'{path}' is not a secret file (.env, .env.*, …): only secrets are shared this way; code is shared with `vl access`"
        )),
    }
}

/// The share's id: which (project, path, sharer, recipient) it is, as 32
/// hex digits. Part of every label, so a sealed file or a wrapped key
/// cannot be moved from one share to another.
pub fn share_id(project: &str, path: &str, sharer: &str, recipient: &str) -> String {
    let mut h = blake3::Hasher::new_derive_key(domains::HUB_SHARE_ID);
    for f in [project, path, sharer, recipient] {
        h.update(&(f.len() as u64).to_le_bytes());
        h.update(f.as_bytes());
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// One device's wrap of a version's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareWrap {
    /// The device's member id (`veil1` and its X25519 public key, hex).
    pub device: String,
    pub key: WrappedKey,
}

/// One version of a share, as stored on the server (`docs/FORMAT.md`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRecord {
    pub format: u32,
    /// The project's id (its `team` ring's genesis hash, 32 hex digits).
    pub project: String,
    pub path: String,
    pub sharer: String,
    pub recipient: String,
    /// Starts at 1; every change on the server (a new version, an unshare)
    /// moves it forward.
    pub version: u64,
    /// When this version was sealed (ms since the epoch, the sharer's clock).
    pub at: i64,
    /// The sharing device's Ed25519 key (hex).
    pub signer: String,
    /// The file, sealed under the version's key (C2 envelope bytes, hex).
    pub sealed: String,
    pub wraps: Vec<ShareWrap>,
    /// Ed25519 by `signer`, context `hub-share`, over [`ShareRecord::signing_body`].
    pub signature: String,
}

/// The signed fields, in this order (never change it: signatures are over
/// its exact JSON).
#[derive(Serialize)]
struct Body<'a> {
    format: u32,
    project: &'a str,
    path: &'a str,
    sharer: &'a str,
    recipient: &'a str,
    version: u64,
    at: i64,
    signer: &'a str,
    sealed: &'a str,
    wraps: &'a [ShareWrap],
}

/// What a share is sealed for: everything but the content and devices.
pub struct ShareTarget<'a> {
    pub project: &'a str,
    pub path: &'a str,
    pub sharer: &'a str,
    pub recipient: &'a str,
    pub version: u64,
}

impl ShareRecord {
    /// Seal `content` for `devices` (member ids, `veil1…`), signed by
    /// `signer`. Each call makes a fresh key.
    pub fn seal(signer: &Identity, t: &ShareTarget<'_>, at: i64, content: &[u8], devices: &[String]) -> Result<ShareRecord> {
        if content.len() > MAX_SHARE_BYTES {
            return Err(VeilError::Policy(format!(
                "{} is {} bytes; a share carries at most {} KiB",
                t.path,
                content.len(),
                MAX_SHARE_BYTES >> 10
            )));
        }
        if devices.is_empty() || devices.len() > MAX_SHARE_DEVICES {
            return Err(VeilError::Policy(format!("a share is sealed for 1 to {MAX_SHARE_DEVICES} devices")));
        }
        let label = share_label(&share_id(t.project, t.path, t.sharer, t.recipient), t.version);
        let key = zeroize::Zeroizing::new(random_key());
        let sealed = hex::encode(Envelope::seal_random(&key, &label, content)?.to_bytes());
        let mut wraps = Vec::new();
        for d in devices {
            let pk = crate::identity::parse_public_key(d)?;
            wraps.push(ShareWrap {
                device: d.clone(),
                key: wrap_key(&pk, &key, &label)?,
            });
        }
        let mut r = ShareRecord {
            format: SHARE_FORMAT,
            project: t.project.to_string(),
            path: t.path.to_string(),
            sharer: t.sharer.to_string(),
            recipient: t.recipient.to_string(),
            version: t.version,
            at,
            signer: signer.verifying_hex(),
            sealed,
            wraps,
            signature: String::new(),
        };
        r.signature = signer.sign(domains::SIG_CONTEXT_HUB_SHARE, &r.signing_body());
        Ok(r)
    }

    /// The exact bytes the signature is over.
    pub fn signing_body(&self) -> Vec<u8> {
        serde_json::to_vec(&Body {
            format: self.format,
            project: &self.project,
            path: &self.path,
            sharer: &self.sharer,
            recipient: &self.recipient,
            version: self.version,
            at: self.at,
            signer: &self.signer,
            sealed: &self.sealed,
            wraps: &self.wraps,
        })
        .expect("serialising a share body")
    }

    /// Well-formed, of a format this build reads, and signed by `signer`.
    /// Who `signer` is, is the reader's question (the key rings).
    pub fn verify(&self) -> std::result::Result<(), String> {
        if self.format != SHARE_FORMAT {
            return Err(format!("share record format {} (this vl reads {SHARE_FORMAT})", self.format));
        }
        if self.version == 0 || self.wraps.is_empty() || self.wraps.len() > MAX_SHARE_DEVICES {
            return Err("malformed share record".into());
        }
        if self.sealed.len() > 2 * (MAX_SHARE_BYTES + 4096) || VPath::new(&self.path).is_err() || self.path.split('/').any(crate::object::is_reserved_name) {
            return Err("malformed share record".into());
        }
        if !verify_signature(&self.signer, domains::SIG_CONTEXT_HUB_SHARE, &self.signing_body(), &self.signature) {
            return Err("the share's signature does not verify".into());
        }
        Ok(())
    }

    /// The devices (member ids) this version is wrapped for.
    pub fn devices(&self) -> Vec<String> {
        self.wraps.iter().map(|w| w.device.clone()).collect()
    }

    /// Open this version with `me`'s key: the file. Fails unless it is
    /// wrapped for `me` and every label is this share's.
    pub fn open(&self, me: &Identity) -> Result<Vec<u8>> {
        let label = share_label(&share_id(&self.project, &self.path, &self.sharer, &self.recipient), self.version);
        let w = self
            .wraps
            .iter()
            .find(|w| w.device == me.public_hex())
            .ok_or_else(|| VeilError::Crypto("this share is not sealed for this device".into()))?;
        let key = zeroize::Zeroizing::new(me.unwrap_key(&w.key, &label)?);
        let raw = hex::decode(&self.sealed).map_err(|_| VeilError::Crypto("malformed share".into()))?;
        let env = Envelope::from_bytes(&raw)?;
        if env.scope != label {
            return Err(VeilError::Crypto("the sealed file belongs to another share".into()));
        }
        env.open(&key)
    }
}

fn share_label(id: &str, version: u64) -> String {
    format!("{}{id}{}{version}", domains::SHARE_LABEL_PREFIX, domains::GENERATION_SEPARATOR)
}

// ---- the server's API -------------------------------------------------------------------

/// `POST /v1/projects/{p}/shares`: a new version of a share. `expect` is
/// the version the sender built on (0: none yet); the record's version is
/// `expect + 1`. `reshare` (an explicit `vl secret share`) may start again
/// a share that was ended; a background update never does.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharePut {
    pub expect: u64,
    pub reshare: bool,
    pub record: ShareRecord,
}

/// `POST /v1/projects/{p}/shares/remove`: the sharer ends a share.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRemove {
    pub path: String,
    pub recipient: String,
}

/// One share, as the server lists it (`GET /v1/projects/{p}/shares`):
/// admins see every share of the project, others the ones they made or
/// receive. Never the content; the record (ciphertext) only for its sharer
/// and recipient while it is active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareInfo {
    pub path: String,
    pub sharer: String,
    pub recipient: String,
    pub version: u64,
    pub created_at: i64,
    pub updated_at: i64,
    /// When the sharer ended it.
    #[serde(default)]
    pub unshared_at: Option<i64>,
    /// Served to the recipient now: not ended, the sharer may still read
    /// the path, and the recipient still takes part in the project.
    pub active: bool,
    /// Why it is not active, if it is not.
    #[serde(default)]
    pub paused: Option<String>,
    #[serde(default)]
    pub record: Option<ShareRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(version: u64) -> ShareTarget<'static> {
        ShareTarget {
            project: "0123456789abcdef0123456789abcdef",
            path: "billing/.env",
            sharer: "alice",
            recipient: "bob",
            version,
        }
    }

    #[test]
    fn only_the_devices_sealed_for_open_a_share() {
        let (alice, bob, eve) = (Identity::generate("alice"), Identity::generate("bob"), Identity::generate("eve"));
        let r = ShareRecord::seal(&alice, &target(1), 5, b"KEY=1\n", &[bob.public_hex(), alice.public_hex()]).unwrap();
        r.verify().unwrap();
        assert_eq!(r.open(&bob).unwrap(), b"KEY=1\n");
        assert_eq!(r.open(&alice).unwrap(), b"KEY=1\n");
        assert!(r.open(&eve).is_err());
        // Eve's key listed under Bob's device id does not open it either.
        let mut moved = r.clone();
        moved.wraps[0].device = eve.public_hex();
        assert!(moved.open(&eve).is_err());
        assert!(moved.verify().is_err());
    }

    #[test]
    fn any_change_breaks_the_signature() {
        let (alice, bob, eve) = (Identity::generate("alice"), Identity::generate("bob"), Identity::generate("eve"));
        let r = ShareRecord::seal(&alice, &target(2), 5, b"KEY=1\n", &[bob.public_hex()]).unwrap();
        type Edit = Box<dyn Fn(&mut ShareRecord)>;
        let edits: Vec<Edit> = vec![
            Box::new(|r| r.path = "infra/.env".into()),
            Box::new(|r| r.recipient = "eve".into()),
            Box::new(|r| r.sharer = "carol".into()),
            Box::new(|r| r.version = 9),
            Box::new(|r| r.project = "f".repeat(32)),
            Box::new(|r| r.at = 6),
            Box::new(|r| r.wraps.clear()),
        ];
        for e in edits {
            let mut t = r.clone();
            e(&mut t);
            assert!(t.verify().is_err(), "{t:?}");
        }
        // An extra wrap for Eve's device, made with a key of Eve's own: the
        // signature fails (and the wrap opens a key that is not this one).
        let other = ShareRecord::seal(&eve, &target(2), 5, b"X", &[eve.public_hex()]).unwrap();
        let mut t = r.clone();
        t.wraps.push(other.wraps[0].clone());
        assert!(t.verify().is_err());
        // Re-signed by another device: it verifies as Eve's, never as
        // Alice's (the reader checks `signer` against the key rings).
        let mut t = r.clone();
        t.signer = eve.verifying_hex();
        t.signature = eve.sign(domains::SIG_CONTEXT_HUB_SHARE, &t.signing_body());
        t.verify().unwrap();
        assert_ne!(t.signer, alice.verifying_hex());
    }

    #[test]
    fn a_sealed_file_or_wrap_cannot_move_between_shares_or_versions() {
        let (alice, bob) = (Identity::generate("alice"), Identity::generate("bob"));
        let a = ShareRecord::seal(&alice, &target(1), 5, b"A", &[bob.public_hex()]).unwrap();
        let b = ShareRecord::seal(&alice, &ShareTarget { path: "infra/.env", ..target(1) }, 5, b"B", &[bob.public_hex()]).unwrap();
        let mut t = a.clone();
        t.sealed = b.sealed.clone();
        assert!(t.open(&bob).is_err());
        let mut t = a.clone();
        t.wraps = b.wraps.clone();
        assert!(t.open(&bob).is_err());
        let mut t = a.clone();
        t.version = 2;
        assert!(t.open(&bob).is_err());
    }

    #[test]
    fn the_signed_body_never_changes() {
        let alice = Identity::generate("alice");
        let mut r = ShareRecord::seal(&alice, &target(1), 5, b"A", &[alice.public_hex()]).unwrap();
        r.signer = "s".into();
        r.sealed = "c".into();
        r.wraps = vec![];
        assert_eq!(
            String::from_utf8(r.signing_body()).unwrap(),
            r#"{"format":1,"project":"0123456789abcdef0123456789abcdef","path":"billing/.env","sharer":"alice","recipient":"bob","version":1,"at":5,"signer":"s","sealed":"c","wraps":[]}"#
        );
    }

    #[test]
    fn only_sealed_secrets_are_shareable() {
        let p = Policy::parse(crate::policy::SYNCED_SECRETS_POLICY);
        assert!(shareable(&p, "billing/.env").is_ok());
        assert!(shareable(&p, ".env.prod").is_ok());
        assert!(shareable(&p, "src/main.rs").is_err());
        assert!(shareable(&p, "deploy/id_ed25519").is_err());
        assert!(shareable(&p, "deploy/server.pem").is_err());
        assert!(shareable(&p, "../x/.env").is_err());
        assert!(shareable(&p, ".veil/local/.env").is_err());
        assert!(shareable(&p, "a/.VEIL/.env").is_err());
        let p = Policy::parse("id_rsa cloak team\n");
        assert!(shareable(&p, "id_rsa").is_err());
    }

    #[test]
    fn size_and_device_limits() {
        let alice = Identity::generate("alice");
        assert!(ShareRecord::seal(&alice, &target(1), 5, &vec![0; MAX_SHARE_BYTES + 1], &[alice.public_hex()]).is_err());
        assert!(ShareRecord::seal(&alice, &target(1), 5, b"x", &[]).is_err());
    }
}
