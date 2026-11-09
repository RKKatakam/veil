//! Read grants and the chain check (`docs/HUB.md` §13.16; design:
//! `docs/design/server/phase-2-thin-clients.md` §4.3–§4.5).
//!
//! **A grant** is the server's decision, in a form any layer can check by
//! itself: "this device may read what is reachable from projected root
//! tree `root` of `project`, until `expires`, while the access epochs of
//! its project and person are still `epoch` and `person_epoch`". It is
//! **signed, not
//! encrypted**: an Ed25519 signature by the server's grant key, context
//! [`SIG_CONTEXT_HUB_GRANT`], over the grant's JSON body exactly as it is
//! sent (the receiver verifies those bytes, then parses them; nothing is
//! re-encoded). It holds nothing its holder could not see otherwise: no
//! view key (an unkeyed hash of every access line, hidden ones included,
//! BUG-1080), and epochs that are random values compared only for equality,
//! never counts or times (BUG-1081).
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
    collections::HashMap,
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::domains::{SIG_CONTEXT_HUB_GRANT, SIG_CONTEXT_HUB_REQUEST},
    error::Result,
    id::ObjectId,
    identity::{verify_signature, SeedSigner},
    object::{EntryKind, Tree, TreeEntry},
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
    /// The project's name (as in the routes). No database id: ids are
    /// sequential, and would count the server's projects and people
    /// (BUG-1088); the server looks them up when it checks the grant.
    pub project: String,
    /// The device it was issued to: its Ed25519 key (hex); `None` for
    /// anyone on Earth.
    pub device: Option<String>,
    /// The viewer's projected root tree of one snapshot.
    pub root: ObjectId,
    /// The access epochs of the project and of the person (0 for anyone on
    /// Earth) the grant's view was built under: random values, new at every
    /// access change of that project or person (BUG-1081). A grant holds
    /// only while both are still current.
    pub epoch: i64,
    pub person_epoch: i64,
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

    /// May the grant be used now, for `project`, when the current access
    /// epochs of its project and person are `epoch` and `person_epoch`?
    /// Epochs are compared for equality: a layer that knows other values
    /// than the grant's (newer or older) does not serve under it.
    pub fn usable(&self, project: &str, now: i64, epoch: i64, person_epoch: i64) -> bool {
        self.body.project == project && now < self.body.expires && epoch == self.body.epoch && person_epoch == self.body.person_epoch
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
    /// The ids conflict object `id` names (its terms), with the sizes the
    /// terms record; `None` if it is not held or not a conflict.
    fn conflict_terms(&self, id: &ObjectId) -> Result<Option<Vec<(ObjectId, u64)>>>;
}

/// What one tree's entries say of one id.
#[derive(Clone, Copy, Default)]
struct Hit {
    /// A directory entry names it: a chain may go on through it.
    dir: bool,
    /// A conflict entry names it: a chain may end with it, naming a term.
    conflict: bool,
    /// An entry's object is it (may be served), with the size the entry
    /// records.
    size: Option<u64>,
}

impl Hit {
    fn add(&mut self, e: &TreeEntry, id: &ObjectId) {
        if e.id == *id {
            self.dir |= e.kind == EntryKind::Dir;
            self.conflict |= e.kind == EntryKind::Conflict;
            self.size = Some(e.size);
        }
    }
}

/// A tree a check has read: scanned for its first few lookups (one object
/// costs no index of a large folder), indexed from [`INDEX_AFTER`] on.
enum Seen {
    Scanned(Arc<Tree>, u32),
    Indexed(HashMap<ObjectId, Hit>),
}

/// The lookup in one tree from which it is indexed.
const INDEX_AFTER: u32 = 4;

/// Checks chains from one grant's root, remembering the trees it read (one
/// request's worth).
pub struct Chains<'a> {
    src: &'a dyn ChainSource,
    root: ObjectId,
    trees: HashMap<ObjectId, Option<Seen>>,
    terms: HashMap<ObjectId, Option<Arc<HashMap<ObjectId, u64>>>>,
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
    ///   entry whose object is `id`. The last element may
    ///   instead be a conflict object, named by a conflict entry of the
    ///   tree before it, with `id` one of its terms.
    ///
    /// Only objects already reached from the root are read.
    pub fn allows(&mut self, chain: &[ObjectId], id: &ObjectId) -> Result<bool> {
        Ok(self.check(chain, id)?.is_some())
    }

    /// [`Chains::allows`], with the size the naming entry records when it
    /// allows (0 when it records none: a tree, a conflict's
    /// term). A server bounds what it reads ahead by it.
    pub fn check(&mut self, chain: &[ObjectId], id: &ObjectId) -> Result<Option<u64>> {
        let Some(last) = chain.len().checked_sub(1) else {
            return Ok((*id == self.root).then_some(0));
        };
        if chain.len() > MAX_CHAIN || chain[0] != self.root {
            return Ok(None);
        }
        for i in 0..last {
            let next = &chain[i + 1];
            let hit = self.lookup(&chain[i], next)?;
            if hit.dir {
                continue;
            }
            if i + 1 == last && hit.conflict {
                return Ok(self.terms(next)?.and_then(|t| t.get(id).copied()));
            }
            return Ok(None);
        }
        Ok(self.lookup(&chain[last], id)?.size)
    }

    /// What tree `tree` (already reached) says of `id`; nothing if the
    /// tree is not held.
    fn lookup(&mut self, tree: &ObjectId, id: &ObjectId) -> Result<Hit> {
        if !self.trees.contains_key(tree) {
            let t = self.src.tree(tree)?;
            self.trees.insert(*tree, t.map(|t| Seen::Scanned(t, 0)));
        }
        let Some(Some(seen)) = self.trees.get_mut(tree) else { return Ok(Hit::default()) };
        let index = match seen {
            Seen::Indexed(ix) => return Ok(ix.get(id).copied().unwrap_or_default()),
            Seen::Scanned(t, n) => {
                *n += 1;
                if *n < INDEX_AFTER {
                    let mut h = Hit::default();
                    t.entries.iter().for_each(|e| h.add(e, id));
                    return Ok(h);
                }
                let mut ix: HashMap<ObjectId, Hit> = HashMap::with_capacity(t.entries.len());
                for e in &t.entries {
                    ix.entry(e.id).or_default().add(e, &e.id);
                }
                ix
            }
        };
        let h = index.get(id).copied().unwrap_or_default();
        *seen = Seen::Indexed(index);
        Ok(h)
    }

    fn terms(&mut self, conflict: &ObjectId) -> Result<Option<Arc<HashMap<ObjectId, u64>>>> {
        if let Some(t) = self.terms.get(conflict) {
            return Ok(t.clone());
        }
        let t = self.src.conflict_terms(conflict)?.map(|v| Arc::new(v.into_iter().collect::<HashMap<_, _>>()));
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
    /// Ids of `wants` not to send: a regional cache forwarding a signed
    /// request (whose signature covers every want) names those it served
    /// itself. Unsigned: it can only make the answer smaller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skip: Vec<ObjectId>,
}

/// `GET /v1/grant-key` (S6): the server's grant key (hex), for the Veil
/// daemon, which checks grants under the key it fetched itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantKey {
    pub grant_key: String,
}

/// `GET /v1/epochs?projects=a,b` (signed in): the current access epochs
/// of the caller (`person`) and of each named project the caller can see
/// (`projects`, by name); a project left out cannot be seen by the caller,
/// so their grants of it are void. Every key's current epoch is listed
/// (there is no paging, so no change is passed over: BUG-1082).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Epochs {
    pub person: i64,
    pub projects: std::collections::BTreeMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Object;

    #[derive(Default)]
    struct Store {
        trees: HashMap<ObjectId, Arc<Tree>>,
        conflicts: HashMap<ObjectId, Vec<(ObjectId, u64)>>,
        reads: std::cell::RefCell<Vec<ObjectId>>,
    }

    impl ChainSource for Store {
        fn tree(&self, id: &ObjectId) -> Result<Option<Arc<Tree>>> {
            self.reads.borrow_mut().push(*id);
            Ok(self.trees.get(id).cloned())
        }
        fn conflict_terms(&self, id: &ObjectId) -> Result<Option<Vec<(ObjectId, u64)>>> {
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
        let (a, b, hidden, term) = (blob("a"), blob("b"), blob("hidden"), blob("term"));
        let conflict = ObjectId::hash(b"veil:conflict\n{}");
        s.conflicts.insert(conflict, vec![(term, 5)]);
        let sub = put(&mut s, vec![entry("a", EntryKind::File, a), entry("b", EntryKind::File, b), entry("c", EntryKind::Conflict, conflict)]);
        let root = put(&mut s, vec![entry("src", EntryKind::Dir, sub), entry("x", EntryKind::File, a)]);
        // Another root (the admin's), which also holds `hidden`.
        let secret = put(&mut s, vec![entry("h", EntryKind::File, hidden)]);
        let other = put(&mut s, vec![entry("src", EntryKind::Dir, sub), entry("billing", EntryKind::Dir, secret)]);
        let mut c = Chains::new(&s, root);
        assert!(c.allows(&[], &root).unwrap());
        assert!(c.allows(&[root], &sub).unwrap() && c.allows(&[root], &a).unwrap());
        assert!(c.allows(&[root, sub], &a).unwrap() && c.allows(&[root, sub], &b).unwrap());
        assert!(c.allows(&[root, sub], &conflict).unwrap() && c.allows(&[root, sub, conflict], &term).unwrap());
        assert_eq!(c.check(&[root, sub, conflict], &term).unwrap(), Some(5), "a term's recorded size");
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
        // A tree's first lookups scan it, later ones use its index: the
        // same answers, sizes included.
        let mut indexed = Chains::new(&s, root);
        for _ in 0..INDEX_AFTER {
            indexed.check(&[root, sub], &a).unwrap();
        }
        for id in [a, b, conflict, term, hidden, sub, secret, root] {
            for chain in [vec![root], vec![root, sub]] {
                assert_eq!(Chains::new(&s, root).check(&chain, &id).unwrap(), indexed.check(&chain, &id).unwrap(), "{chain:?} {id:?}");
            }
        }
    }

    fn body(device: Option<String>) -> GrantBody {
        GrantBody {
            project: "acme".into(),
            person_epoch: if device.is_some() { -9 } else { 0 },
            device,
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
        assert!(g.usable("acme", 999_999, 41, -9) && g.usable("acme", 0, 41, -9));
        assert!(!g.usable("acme", 1_000_000, 41, -9) && !g.usable("acme2", 0, 41, -9));
        // Any other epoch, newer or older, of the project or the person.
        for (e, pe) in [(42, -9), (40, -9), (0, -9), (41, -8), (41, 0)] {
            assert!(!g.usable("acme", 0, e, pe), "{e} {pe}");
        }
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
