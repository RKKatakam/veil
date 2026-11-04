//! The object model stored in the CAS.
//!
//! Four object kinds, each encoded as `tag || payload` and addressed by the
//! BLAKE3 hash of the whole encoding:
//!
//! * `Blob`     — raw file bytes.
//! * `Tree`     — sorted directory listing ([`TreeEntry`]s). Only the
//!   canonical encoding is accepted on decode (see [`Tree::validate`]):
//!   entry names are valid path components, strictly sorted (hence
//!   unique), and never the reserved `.veil`.
//! * `Snapshot` — immutable node of the history DAG.
//! * `Sealed`   — a [`crate::crypto::Envelope`] wrapping the encoding of any
//!   other object. Sealed objects are self-describing: the envelope names the
//!   scope whose key opens it.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::Envelope,
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    identity::{Identity, Signature},
};

/// Signature context for snapshots (see [`Snapshot::sign`]).
pub const SNAPSHOT_SIG_CONTEXT: &str = "snapshot";

const BLOB_TAG: &[u8] = b"veil:blob\n";
const TREE_TAG: &[u8] = b"veil:tree\n";
const SNAP_TAG: &[u8] = b"veil:snap\n";
const SEAL_TAG: &[u8] = b"veil:seal\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

/// How a node may be seen and synchronised.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "lowercase")]
pub enum Visibility {
    /// Plaintext, synchronised everywhere.
    #[default]
    Public,
    /// Encrypted under a scope key; plaintext only for scope members.
    Cloaked { scope: String },
    /// Encrypted under a one-off embargo key until released (delayed-visibility
    /// merge). Readers without the key see the entry's `fallback` instead.
    Embargoed { embargo: String },
}

impl Visibility {
    pub fn is_public(&self) -> bool {
        matches!(self, Visibility::Public)
    }

    /// Name of the key scope required to read content with this visibility.
    pub fn key_scope(&self) -> Option<String> {
        match self {
            Visibility::Public => None,
            Visibility::Cloaked { scope } => Some(scope.clone()),
            Visibility::Embargoed { embargo } => Some(format!("embargo/{embargo}")),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Visibility::Public => "public".into(),
            Visibility::Cloaked { scope } => format!("cloaked:{scope}"),
            Visibility::Embargoed { embargo } => format!("embargo:{embargo}"),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    pub kind: EntryKind,
    pub id: ObjectId,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Visibility::is_public")]
    pub visibility: Visibility,
    /// For embargoed entries: the pre-merge object shown to readers who do
    /// not (yet) hold the embargo key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ObjectId>,
}

impl TreeEntry {
    /// Equal in everything but the name.
    pub fn same_content(&self, other: &TreeEntry) -> bool {
        self.kind == other.kind
            && self.id == other.id
            && self.executable == other.executable
            && self.visibility == other.visibility
            && self.fallback == other.fallback
    }

    pub fn dir(name: &str, id: ObjectId) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: EntryKind::Dir,
            id,
            size: 0,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        }
    }
}

/// Directory name reserved for repository metadata. Like Git's `.git`, it
/// is refused as a tree entry name at every depth, in every spelling that
/// names the same directory on a macOS filesystem: any ASCII case (`.VEIL`)
/// and with HFS+-ignorable code points inserted anywhere (`.v\u{200C}eil`),
/// as Git's `is_hfs_dotgit` does.
pub const RESERVED_NAME: &str = ".veil";

/// Is `name` an alias of the reserved metadata directory name?
///
/// No other spellings need catching: no non-ASCII character case-folds or
/// canonically decomposes to `.`, `v`, `e`, `i` or `l`.
pub fn is_reserved_name(name: &str) -> bool {
    if name.is_ascii() {
        return name.eq_ignore_ascii_case(RESERVED_NAME);
    }
    let mut folded = name.chars().filter(|c| !crate::vpath::is_hfs_ignorable(*c));
    RESERVED_NAME
        .chars()
        .all(|r| folded.next().is_some_and(|c| c.eq_ignore_ascii_case(&r)))
        && folded.next().is_none()
}

/// Check that `name` is a single, safe path component for a tree entry: not
/// empty, not `.` or `..`, no `/` or NUL, and not [`RESERVED_NAME`].
pub fn validate_entry_name(name: &str) -> Result<()> {
    let why = if name.is_empty() {
        "empty name"
    } else if name == "." || name == ".." {
        "relative path component"
    } else if name.contains('/') {
        "contains '/'"
    } else if name.contains('\0') {
        "contains NUL"
    } else if is_reserved_name(name) {
        "reserved for repository metadata"
    } else {
        return Ok(());
    };
    Err(VeilError::Corrupt(
        "tree".into(),
        format!("invalid entry name {:?} ({why})", truncate_for_error(name)),
    ))
}

fn truncate_for_error(s: &str) -> &str {
    match s.char_indices().nth(64) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        self.entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.entries[i])
    }

    pub fn insert(&mut self, entry: TreeEntry) {
        match self.entries.binary_search_by(|e| e.name.cmp(&entry.name)) {
            Ok(i) => self.entries[i] = entry,
            Err(i) => self.entries.insert(i, entry),
        }
    }

    pub fn remove(&mut self, name: &str) -> Option<TreeEntry> {
        self.entries
            .binary_search_by(|e| e.name.as_str().cmp(name))
            .ok()
            .map(|i| self.entries.remove(i))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Structural validity: every name passes [`validate_entry_name`] and
    /// the entries are strictly sorted by name (so no duplicates). Lookups
    /// use binary search, so an unsorted tree would show different files to
    /// `walk_files` and to `lookup`/`diff_trees`/checkout.
    pub fn validate(&self) -> Result<()> {
        let mut prev: Option<&str> = None;
        for e in &self.entries {
            validate_entry_name(&e.name)?;
            if let Some(p) = prev {
                if p >= e.name.as_str() {
                    return Err(VeilError::Corrupt(
                        "tree".into(),
                        format!(
                            "entries are not sorted and unique ({:?} before {:?})",
                            truncate_for_error(p),
                            truncate_for_error(&e.name)
                        ),
                    ));
                }
            }
            prev = Some(&e.name);
        }
        Ok(())
    }
}

/// Descriptions may themselves be cloaked (snapshots on cloaked branches).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Text {
    Plain(String),
    Sealed(Envelope),
}

impl Default for Text {
    fn default() -> Self {
        Text::Plain(String::new())
    }
}

/// An immutable node of the history DAG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub parents: Vec<ObjectId>,
    pub change_id: ChangeId,
    pub tree: ObjectId,
    pub description: Text,
    pub author: String,
    /// Milliseconds since the Unix epoch.
    pub timestamp: i64,
    /// Snapshots this one replaced (evolution log: amend, describe, rebase).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predecessors: Vec<ObjectId>,
    /// Paths that still contain unresolved conflict markers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
    /// Set on snapshots of a cloaked line of work: every file and the
    /// description are sealed under this scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloak: Option<String>,
    /// Embargo introduced by this (merge) snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embargo: Option<String>,
    /// Ed25519 signature of whoever *produced this exact snapshot* (the
    /// signer), over [`Snapshot::unsigned_id`]. The signer may differ from
    /// `author`: an automatic rebase of Alice's change by Bob yields a
    /// snapshot signed by Bob whose `predecessors` names Alice's original.
    /// Because the signature is part of the encoding, the snapshot id
    /// commits to it: stripping or swapping a signature changes the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl Snapshot {
    /// The universal root: every repository shares the same root id, so
    /// unrelated repositories can still exchange history.
    pub fn root(empty_tree: ObjectId) -> Snapshot {
        Snapshot {
            parents: vec![],
            change_id: ChangeId::ROOT,
            tree: empty_tree,
            description: Text::default(),
            author: String::new(),
            timestamp: 0,
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        }
    }

    /// Id this snapshot would have without its signature. This is the value
    /// that is signed, so a signature commits to every other field (parents,
    /// tree, change id, author, description, ...).
    pub fn unsigned_id(&self) -> ObjectId {
        if self.signature.is_none() {
            return ObjectId::hash(&Object::Snapshot(self.clone()).encode());
        }
        let mut s = self.clone();
        s.signature = None;
        ObjectId::hash(&Object::Snapshot(s).encode())
    }

    /// Replace any existing signature with one by `identity`.
    pub fn sign(&mut self, identity: &Identity) {
        self.signature = None;
        let id = self.unsigned_id();
        self.signature = Some(Signature::create(identity, SNAPSHOT_SIG_CONTEXT, &id.0));
    }

    /// `None` if unsigned, otherwise whether the signature is
    /// cryptographically valid (says nothing about who the key belongs to).
    pub fn signature_valid(&self) -> Option<bool> {
        let sig = self.signature.as_ref()?;
        Some(sig.verify(SNAPSHOT_SIG_CONTEXT, &self.unsigned_id().0))
    }
}

// Snapshots are decoded transiently; boxing them is not worth the churn.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Blob(Vec<u8>),
    Tree(Tree),
    Snapshot(Snapshot),
    Sealed(Envelope),
}

impl Object {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, body): (&[u8], Vec<u8>) = match self {
            Object::Blob(b) => (BLOB_TAG, b.clone()),
            Object::Tree(t) => (TREE_TAG, serde_json::to_vec(t).unwrap()),
            Object::Snapshot(s) => (SNAP_TAG, serde_json::to_vec(s).unwrap()),
            Object::Sealed(e) => (SEAL_TAG, e.to_bytes()),
        };
        let mut out = Vec::with_capacity(tag.len() + body.len());
        out.extend_from_slice(tag);
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Object> {
        let corrupt = |m: &str| VeilError::Corrupt("object".into(), m.to_string());
        if let Some(b) = raw.strip_prefix(BLOB_TAG) {
            Ok(Object::Blob(b.to_vec()))
        } else if let Some(b) = raw.strip_prefix(TREE_TAG) {
            // Trees come from remotes and from `.veil/`: both are hostile.
            // Only the canonical form is accepted, so that every reader
            // (listing, lookup, diff, checkout) sees the same entries and
            // one logical tree has exactly one id.
            let t: Tree = serde_json::from_slice(b)?;
            t.validate()?;
            if serde_json::to_vec(&t)? != b {
                return Err(corrupt("tree is not in canonical encoding"));
            }
            Ok(Object::Tree(t))
        } else if let Some(b) = raw.strip_prefix(SNAP_TAG) {
            Ok(Object::Snapshot(serde_json::from_slice(b)?))
        } else if let Some(b) = raw.strip_prefix(SEAL_TAG) {
            Ok(Object::Sealed(Envelope::from_bytes(b)?))
        } else {
            Err(corrupt("unknown object tag"))
        }
    }

    /// Id a blob with this content would have, without copying it.
    pub fn blob_id(data: &[u8]) -> ObjectId {
        let mut h = blake3::Hasher::new();
        h.update(BLOB_TAG);
        h.update(data);
        ObjectId(*h.finalize().as_bytes())
    }

    /// Scope of a raw sealed object, `None` for plaintext objects.
    pub fn sealed_scope(raw: &[u8]) -> Option<String> {
        raw.strip_prefix(SEAL_TAG).and_then(Envelope::peek_scope)
    }

    pub fn is_blob_raw(raw: &[u8]) -> bool {
        raw.starts_with(BLOB_TAG)
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Object::Blob(_) => "blob",
            Object::Tree(_) => "tree",
            Object::Snapshot(_) => "snapshot",
            Object::Sealed(_) => "sealed",
        }
    }
}
