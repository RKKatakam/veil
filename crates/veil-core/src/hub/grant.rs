//! Read grants and the chain check (`docs/HUB.md` §13.13; design:
//! `docs/design/server/phase-2-thin-clients.md` §4.3–§4.5).
//!
//! **A grant** is the server's decision, in a form any layer can check by
//! itself: "this device may read what is reachable from projected root
//! tree `root` of `project`, until `expires`, unless an access change newer
//! than `epoch` reached its person or project". It is **signed, not
//! encrypted**: an Ed25519 signature by the server's grant key, context
//! [`SIG_CONTEXT_HUB_GRANT`], over the grant's JSON body exactly as it is
//! sent (the receiver verifies those bytes, then parses them; nothing is
//! re-encoded).
//!
//! **Reachability is the authority.** A projected tree holds exactly what
//! its viewer may read (`hub::project`), so every object reachable from a
//! grant's root is one its holder may read, and nothing else is. A request
//! names, with each object, the **chain** of tree ids from the grant's root
//! to the tree that names it ([`Chains::allows`]). The check reads only
//! objects it has already reached from the root, so it never looks up an
//! object it would refuse, and "not allowed" and "not there" cannot be told
//! apart.
//!
//! **Requests are signed by the grant's device** (context
//! [`SIG_CONTEXT_HUB_REQUEST`], [`request_message`]): a grant copied to
//! another machine is useless without the device key. A grant of anyone on
//! Earth (the public view) names no device and needs no signature.
//!
//! Pure functions, no I/O and no clock (callers pass `now`): the server, the
//! Veil daemon and regional caches share them, and they build for WASM.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::domains::{SIG_CONTEXT_HUB_GRANT, SIG_CONTEXT_HUB_REQUEST},
    error::Result,
    id::ObjectId,
    identity::{verify_signature, SeedSigner},
    object::{EntryKind, Tree},
    tree::MAX_TREE_DEPTH,
};

/// How long a grant lasts.
pub const GRANT_TTL_MS: i64 = 10 * 60 * 1000;
/// How far a signed request's time may be from the receiver's clock.
pub const REQUEST_SKEW_MS: i64 = 5 * 60 * 1000;
/// Most ids in a chain: the root, one tree per directory level, and a
/// conflict object.
pub const MAX_CHAIN: usize = MAX_TREE_DEPTH + 2;
/// Longest grant token accepted (a real one is under 1 KiB).
pub const MAX_GRANT_TOKEN: usize = 4096;

/// What a grant says. Unknown fields are refused, so a layer that does not
/// know a later restriction refuses the grant instead of ignoring it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBody {
    /// The project's name (as in the routes) and id (as in the store).
    pub project: String,
    pub project_id: i64,
    /// Who it was issued to: a person's id and their device's Ed25519 key
    /// (hex); both `None` for anyone on Earth.
    pub person: Option<i64>,
    pub device: Option<String>,
    /// The viewer's view key (`hub::access::View::key`).
    pub view: String,
    /// The viewer's projected root tree of one snapshot.
    pub root: ObjectId,
    /// The server's access epoch when the grant was made: an access change
    /// of its project or person with a newer epoch voids it.
    pub epoch: i64,
    /// Unix milliseconds.
    pub expires: i64,
}

/// A grant whose signature verified.
#[derive(Clone, Debug)]
pub struct Grant {
    pub body: GrantBody,
    raw: Vec<u8>,
}

impl Grant {
    /// Sign `body` with the server's grant key: the token `hex(body).sig`.
    pub fn issue(key: &SeedSigner, body: &GrantBody) -> String {
        let raw = serde_json::to_vec(body).expect("a grant body serialises");
        format!("{}.{}", hex::encode(&raw), key.sign(SIG_CONTEXT_HUB_GRANT, &raw))
    }

    /// The grant in `token` if its signature verifies under `grant_key`
    /// (hex). Says nothing of its expiry, epoch or project: see
    /// [`Grant::usable`].
    pub fn verify(token: &str, grant_key: &str) -> Option<Grant> {
        let (raw, sig) = split(token)?;
        if !verify_signature(grant_key, SIG_CONTEXT_HUB_GRANT, &raw, sig) {
            return None;
        }
        let body = serde_json::from_slice(&raw).ok()?;
        Some(Grant { body, raw })
    }

    /// What a token says, **unverified**: for a client reading its own
    /// grant (its root). Never an authority.
    pub fn read_unverified(token: &str) -> Option<GrantBody> {
        serde_json::from_slice(&split(token)?.0).ok()
    }

    /// The hash a request signature names the grant by.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&self.raw).as_bytes()
    }

    /// May the grant be used now, for `project`, when the newest access
    /// epoch of its project and person known to the checker is `newest`?
    pub fn usable(&self, project: &str, now: i64, newest: i64) -> bool {
        self.body.project == project && now < self.body.expires && newest <= self.body.epoch
    }
}

fn split(token: &str) -> Option<(Vec<u8>, &str)> {
    if token.len() > MAX_GRANT_TOKEN {
        return None;
    }
    let (body, sig) = token.split_once('.')?;
    Some((hex::decode(body).ok()?, sig))
}

/// What a device signs to use grant `grant` at time `ts` (unix ms) for
/// `ids`: the grant's hash ‖ `ts` (i64 big-endian) ‖ BLAKE3 of the ids'
/// bytes, in order. 72 bytes.
pub fn request_message(grant: &Grant, ts: i64, ids: &[ObjectId]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    for id in ids {
        h.update(&id.0);
    }
    let mut m = grant.hash().to_vec();
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(h.finalize().as_bytes());
    m
}

/// Sign a request for `ids` under `grant` with the device `identity`.
pub fn sign_request(identity: &crate::Identity, grant: &Grant, ts: i64, ids: &[ObjectId]) -> String {
    identity.sign(SIG_CONTEXT_HUB_REQUEST, &request_message(grant, ts, ids))
}

/// Is a request for `ids` at `ts` made by the grant's device? A grant that
/// names no device (anyone on Earth's) needs no signature.
pub fn request_signed(grant: &Grant, ts: i64, ids: &[ObjectId], signature: Option<&str>, now: i64) -> bool {
    let Some(device) = &grant.body.device else { return true };
    let Some(sig) = signature else { return false };
    ts.abs_diff(now) <= REQUEST_SKEW_MS as u64 && verify_signature(device, SIG_CONTEXT_HUB_REQUEST, &request_message(grant, ts, ids), sig)
}

/// Where a chain check reads objects. Each answer must be the object with
/// that id (hash-checked by the source).
pub trait ChainSource {
    /// The tree `id`; `None` if it is not held or not a tree.
    fn tree(&self, id: &ObjectId) -> Result<Option<Arc<Tree>>>;
    /// The ids conflict object `id` names (its terms and their fallbacks);
    /// `None` if it is not held or not a conflict.
    fn conflict_terms(&self, id: &ObjectId) -> Result<Option<Vec<ObjectId>>>;
}

/// The ids one tree names, by role.
#[derive(Default)]
struct Names {
    /// Directory entries: a chain may go on through them.
    dirs: HashSet<ObjectId>,
    /// Conflict entries: a chain may end with one, naming one of its terms.
    conflicts: HashSet<ObjectId>,
    /// Every entry's object and fallback: what the tree lets be served.
    named: HashSet<ObjectId>,
}

/// Checks chains from one grant's root, remembering the trees it read (one
/// request's worth).
pub struct Chains<'a> {
    src: &'a dyn ChainSource,
    root: ObjectId,
    trees: HashMap<ObjectId, Option<Arc<Names>>>,
    terms: HashMap<ObjectId, Option<Arc<HashSet<ObjectId>>>>,
}

impl<'a> Chains<'a> {
    pub fn new(src: &'a dyn ChainSource, root: ObjectId) -> Chains<'a> {
        Chains {
            src,
            root,
            trees: HashMap::new(),
            terms: HashMap::new(),
        }
    }

    /// May object `id` be served to the holder of a grant for this root,
    /// met at the end of `chain`?
    ///
    /// * An empty chain names the root itself.
    /// * Otherwise `chain[0]` is the root; each tree `chain[i]` has a
    ///   directory entry naming `chain[i + 1]`; and the last tree has an
    ///   entry whose object or fallback is `id`. The last element may
    ///   instead be a conflict object, named by a conflict entry of the
    ///   tree before it, with `id` one of its terms.
    ///
    /// Only objects already reached from the root are read.
    pub fn allows(&mut self, chain: &[ObjectId], id: &ObjectId) -> Result<bool> {
        let Some(last) = chain.len().checked_sub(1) else {
            return Ok(*id == self.root);
        };
        if chain.len() > MAX_CHAIN || chain[0] != self.root {
            return Ok(false);
        }
        for i in 0..last {
            let Some(names) = self.names(&chain[i])? else { return Ok(false) };
            let next = &chain[i + 1];
            if names.dirs.contains(next) {
                continue;
            }
            if i + 1 == last && names.conflicts.contains(next) {
                return Ok(self.terms(next)?.is_some_and(|t| t.contains(id)));
            }
            return Ok(false);
        }
        Ok(self.names(&chain[last])?.is_some_and(|n| n.named.contains(id)))
    }

    fn names(&mut self, tree: &ObjectId) -> Result<Option<Arc<Names>>> {
        if let Some(n) = self.trees.get(tree) {
            return Ok(n.clone());
        }
        let n = self.src.tree(tree)?.map(|t| {
            let mut n = Names::default();
            for e in &t.entries {
                match e.kind {
                    EntryKind::Dir => n.dirs.insert(e.id),
                    EntryKind::Conflict => n.conflicts.insert(e.id),
                    EntryKind::File | EntryKind::Symlink => false,
                };
                n.named.insert(e.id);
                n.named.extend(e.fallback);
            }
            Arc::new(n)
        });
        self.trees.insert(*tree, n.clone());
        Ok(n)
    }

    fn terms(&mut self, conflict: &ObjectId) -> Result<Option<Arc<HashSet<ObjectId>>>> {
        if let Some(t) = self.terms.get(conflict) {
            return Ok(t.clone());
        }
        let t = self.src.conflict_terms(conflict)?.map(|v| Arc::new(v.into_iter().collect::<HashSet<_>>()));
        self.terms.insert(*conflict, t.clone());
        Ok(t)
    }
}

/// One object of a batch: its id, and the chain where the client met it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainWant {
    #[serde(default)]
    pub chain: Vec<ObjectId>,
    pub id: ObjectId,
}

/// `POST /v1/objects/{project}:batch`: objects under one grant, as object
/// frames; what is not served (not reachable, or not there) is left out,
/// and the client asks again for what did not arrive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRequest {
    pub grant: String,
    /// Unix ms, as signed.
    pub ts: i64,
    /// The device's signature ([`sign_request`]) over the ids in order;
    /// absent for anyone on Earth's grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub wants: Vec<ChainWant>,
}

/// `GET /v1/epochs?since=N`: the access epochs newer than `N`, oldest
/// first, and the epoch to ask from next.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Epochs {
    pub now: i64,
    pub changes: Vec<EpochChange>,
}

/// One access change: of a project's policy (`project`), or of a person's
/// groups or devices (`person`). A grant of that project or person with an
/// older epoch is void.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<i64>,
    pub epoch: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Object, TreeEntry};

    #[derive(Default)]
    struct Store {
        trees: HashMap<ObjectId, Arc<Tree>>,
        conflicts: HashMap<ObjectId, Vec<ObjectId>>,
        reads: std::cell::RefCell<Vec<ObjectId>>,
    }

    impl ChainSource for Store {
        fn tree(&self, id: &ObjectId) -> Result<Option<Arc<Tree>>> {
            self.reads.borrow_mut().push(*id);
            Ok(self.trees.get(id).cloned())
        }
        fn conflict_terms(&self, id: &ObjectId) -> Result<Option<Vec<ObjectId>>> {
            self.reads.borrow_mut().push(*id);
            Ok(self.conflicts.get(id).cloned())
        }
    }

    fn entry(name: &str, kind: EntryKind, id: ObjectId) -> TreeEntry {
        TreeEntry {
            name: name.into(),
            kind,
            id,
            size: 0,
            executable: false,
            visibility: Default::default(),
            fallback: None,
        }
    }

    fn put(s: &mut Store, mut entries: Vec<TreeEntry>) -> ObjectId {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let t = Tree { entries };
        let id = ObjectId::hash(&Object::Tree(t.clone()).encode());
        s.trees.insert(id, Arc::new(t));
        id
    }

    fn blob(x: &str) -> ObjectId {
        ObjectId::hash(format!("veil:blob\n{x}").as_bytes())
    }

    #[test]
    fn chains_reach_only_what_the_root_reaches() {
        let mut s = Store::default();
        let (a, b, fb, hidden, term) = (blob("a"), blob("b"), blob("fallback"), blob("hidden"), blob("term"));
        let conflict = ObjectId::hash(b"veil:conflict\n{}");
        s.conflicts.insert(conflict, vec![term]);
        let mut with_fb = entry("b", EntryKind::File, b);
        with_fb.fallback = Some(fb);
        let sub = put(&mut s, vec![entry("a", EntryKind::File, a), with_fb, entry("c", EntryKind::Conflict, conflict)]);
        let root = put(&mut s, vec![entry("src", EntryKind::Dir, sub), entry("x", EntryKind::File, a)]);
        // Another root (the admin's), which also holds `hidden`.
        let secret = put(&mut s, vec![entry("h", EntryKind::File, hidden)]);
        let other = put(&mut s, vec![entry("src", EntryKind::Dir, sub), entry("billing", EntryKind::Dir, secret)]);
        let mut c = Chains::new(&s, root);
        assert!(c.allows(&[], &root).unwrap());
        assert!(c.allows(&[root], &sub).unwrap() && c.allows(&[root], &a).unwrap());
        assert!(c.allows(&[root, sub], &a).unwrap() && c.allows(&[root, sub], &b).unwrap());
        assert!(c.allows(&[root, sub], &fb).unwrap(), "a fallback is served at its entry");
        assert!(c.allows(&[root, sub], &conflict).unwrap() && c.allows(&[root, sub, conflict], &term).unwrap());
        s.reads.borrow_mut().clear();
        // Refused: another root, a chain through a tree the root does not
        // reach, a tree that does not name the next, a file as a step.
        for (chain, id) in [
            (vec![], other),
            (vec![], a),
            (vec![other], secret),
            (vec![other, secret], hidden),
            (vec![root, secret], hidden),
            (vec![root, sub, secret], hidden),
            (vec![secret], hidden),
            (vec![root], hidden),
            (vec![root, a], hidden),
            (vec![root, sub], term),
            (vec![root, conflict], term),
            (vec![root, sub, conflict, sub], a),
            (vec![root, sub, conflict], hidden),
        ] {
            assert!(!c.allows(&chain, &id).unwrap(), "{chain:?} → {id:?}");
        }
        // It never read an object it had not reached from the root.
        assert!(s.reads.borrow().iter().all(|r| [root, sub, conflict].contains(r)), "{:?}", s.reads.borrow());
        assert!(!Chains::new(&s, root).allows(&vec![root; MAX_CHAIN + 1], &a).unwrap());
    }

    fn body(device: Option<String>) -> GrantBody {
        GrantBody {
            project: "acme".into(),
            project_id: 7,
            person: device.as_ref().map(|_| 3),
            device,
            view: "v".into(),
            root: blob("root"),
            epoch: 41,
            expires: 1_000_000,
        }
    }

    #[test]
    fn grants_verify_only_under_their_key_and_context() {
        let key = SeedSigner::from_seed(&[7; 32]);
        let other = SeedSigner::from_seed(&[8; 32]);
        let dev = crate::Identity::generate("alice");
        let token = Grant::issue(&key, &body(Some(dev.verifying_hex())));
        let g = Grant::verify(&token, &key.verifying_hex()).unwrap();
        assert_eq!(g.body, body(Some(dev.verifying_hex())));
        assert_eq!(Grant::read_unverified(&token).unwrap(), g.body);
        assert!(Grant::verify(&token, &other.verifying_hex()).is_none());
        // The same body signed in another context, or tampered with.
        let raw = serde_json::to_vec(&g.body).unwrap();
        let login = format!("{}.{}", hex::encode(&raw), key.sign(crate::crypto::domains::SIG_CONTEXT_HUB_LOGIN, &raw));
        assert!(Grant::verify(&login, &key.verifying_hex()).is_none());
        let mut t = token.clone().into_bytes();
        t[5] ^= 1;
        assert!(Grant::verify(std::str::from_utf8(&t).unwrap(), &key.verifying_hex()).is_none());
        // An unknown field is refused even when signed.
        let mut v = serde_json::to_value(&g.body).unwrap();
        v["only"] = "src".into();
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(Grant::verify(&format!("{}.{}", hex::encode(&raw), key.sign(SIG_CONTEXT_HUB_GRANT, &raw)), &key.verifying_hex()).is_none());
        for junk in ["", ".", "zz.zz", &"a".repeat(MAX_GRANT_TOKEN + 1)] {
            assert!(Grant::verify(junk, &key.verifying_hex()).is_none());
        }
        // Expiry, epoch, project.
        assert!(g.usable("acme", 999_999, 41) && g.usable("acme", 0, 0));
        assert!(!g.usable("acme", 1_000_000, 41) && !g.usable("acme", 0, 42) && !g.usable("acme2", 0, 0));
    }

    #[test]
    fn requests_are_signed_by_the_grants_device() {
        let key = SeedSigner::from_seed(&[7; 32]);
        let dev = crate::Identity::generate("alice");
        let thief = crate::Identity::generate("mal");
        let g = Grant::verify(&Grant::issue(&key, &body(Some(dev.verifying_hex()))), &key.verifying_hex()).unwrap();
        let ids = [blob("a"), blob("b")];
        let now = 5_000_000;
        let sig = sign_request(&dev, &g, now, &ids);
        assert!(request_signed(&g, now, &ids, Some(&sig), now + 1000));
        assert!(!request_signed(&g, now, &ids, None, now));
        assert!(!request_signed(&g, now, &ids, Some(&sign_request(&thief, &g, now, &ids)), now));
        assert!(!request_signed(&g, now, &[ids[1], ids[0]], Some(&sig), now), "other ids");
        assert!(!request_signed(&g, now + 1, &ids, Some(&sig), now), "another time");
        assert!(!request_signed(&g, now, &ids, Some(&sig), now + REQUEST_SKEW_MS + 1), "too old");
        assert_eq!(request_message(&g, now, &ids).len(), 72);
        // Anyone on Earth's grant: no device, no signature needed.
        let public = Grant::verify(&Grant::issue(&key, &body(None)), &key.verifying_hex()).unwrap();
        assert!(request_signed(&public, 0, &ids, None, now));
    }
}
