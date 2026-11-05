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
//! * `Conflict` — an unresolved file conflict ([`Conflict`]): the versions
//!   of a file that a merge could not combine, as jj records them (adds and
//!   removes), each with its own visibility. Referenced by tree entries of
//!   kind [`EntryKind::Conflict`] (repository format 4).
//! * `Atag`     — an annotated (optionally signed) tag ([`crate::tag_object::Atag`],
//!   `veil:atag`, repository format 5), named by `oplog::Tag::annotation`.
//! * `Sealed`   — a [`crate::crypto::Envelope`] wrapping the encoding of any
//!   other object. Sealed objects are self-describing: the envelope names the
//!   scope whose key opens it. Two tags: `veil:seal` (XChaCha20-Poly1305,
//!   formats 1–2) and `veil:sea2` (AES-SIV, format 3; see `docs/CRYPTO.md`).
//!
//! # Encodings and their evolution
//!
//! The first payload byte after the tag of a structured object (tree,
//! snapshot) is its **encoding version**: `{` is the format-1 JSON
//! encoding, `0x02` the binary tree encoding ([`TreeEncoding::Binary`]),
//! and `0x03..=0x1F` are reserved for later versions. A reader that meets a
//! reserved version, a reserved flag bit or an unknown `veil:xxxx` tag
//! fails with [`VeilError::Unsupported`] ("needs a newer vl"), never with a
//! silent misreading. There are no ignorable fields: anything a reader
//! cannot represent exactly would be lost when it rewrites the object, so
//! every addition is a new version. Every version is canonical (one logical
//! object, one byte string), and the empty tree always uses the format-1
//! encoding, so the universal root snapshot keeps its id forever. See
//! `docs/FORMAT.md`.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::Envelope,
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    identity::{Identity, Signature},
    tag_object::Atag,
};

/// Signature context for snapshots (see [`Snapshot::sign`]).
pub const SNAPSHOT_SIG_CONTEXT: &str = "snapshot";

const BLOB_TAG: &[u8] = b"veil:blob\n";
const TREE_TAG: &[u8] = b"veil:tree\n";
const SNAP_TAG: &[u8] = b"veil:snap\n";
/// Conflict object (repository format 4).
const CONF_TAG: &[u8] = b"veil:conf\n";
/// Annotated tag object (repository format 5).
pub(crate) const ATAG_TAG: &[u8] = b"veil:atag\n";
const SEAL_TAG: &[u8] = b"veil:seal\n";
/// Sealed object, AES-SIV envelope (repository format 3).
const SEAL_AES_SIV_TAG: &[u8] = b"veil:sea2\n";

/// Lowest repository format that may store `veil:sea2` (AES-SIV) objects.
pub const AES_SIV_REPO_FORMAT: u32 = 3;
/// Lowest repository format that may store conflict objects (`veil:conf`)
/// and trees with conflict entries.
pub const CONFLICT_REPO_FORMAT: u32 = 4;
/// Lowest repository format that may store the format-5 additions:
/// symlink tree entries (and conflict terms), annotated tag objects
/// (`veil:atag`), `Tag::annotation` and `View::remote_release_tags`.
pub const GIT_PARITY_REPO_FORMAT: u32 = 5;
/// First payload byte of the conflict object encoding.
pub const ENCODING_CONFLICT: u8 = 0x04;
/// Most removes (bases) a conflict object may hold: a conflict of more than
/// this many sides is refused as hostile. Real conflicts have one or two.
pub const MAX_CONFLICT_REMOVES: usize = 64;

/// First payload byte of the format-1 JSON encodings (trees and snapshots).
pub const ENCODING_JSON: u8 = b'{';
/// First payload byte of the binary tree encoding (repository format 2).
pub const ENCODING_BINARY_TREE: u8 = 0x02;
/// Encoding version bytes reserved for later formats.
pub const ENCODING_RESERVED: std::ops::RangeInclusive<u8> = 0x03..=0x1F;

/// How tree objects are written. Reading accepts every encoding this build
/// knows; which one is *written* is chosen by the repository format (see
/// [`crate::repo::RepoConfig::format`] and [`crate::store::ObjectStore::set_format`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TreeEncoding {
    /// Format 1: `veil:tree\n{"entries":[…]}` exactly as `serde_json` writes
    /// it. Always used for the empty tree.
    Json,
    /// Format 2: compact binary, see [`Tree::encode_binary`].
    Binary,
}

impl TreeEncoding {
    /// The encoding a repository of `format` writes.
    pub fn for_repo_format(format: u32) -> TreeEncoding {
        if format >= 2 {
            TreeEncoding::Binary
        } else {
            TreeEncoding::Json
        }
    }

    /// Lowest repository format that may store trees in this encoding.
    pub fn min_repo_format(self) -> u32 {
        match self {
            TreeEncoding::Json => 1,
            TreeEncoding::Binary => 2,
        }
    }
}

fn unsupported_encoding(kind: &str, v: u8) -> VeilError {
    VeilError::Unsupported(format!(
        "{kind} object uses encoding version {v}, which vl {} cannot read; this repository needs a newer vl",
        env!("CARGO_PKG_VERSION")
    ))
}

/// Does `tag` look like an object tag (`veil:` + 4 lowercase alphanumerics +
/// newline)? Unknown ones are kinds introduced by a later format.
fn tag_shaped(raw: &[u8]) -> Option<&str> {
    let t = raw.get(..10)?;
    (t.starts_with(b"veil:") && t[9] == b'\n' && t[5..9].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
        .then(|| std::str::from_utf8(&t[5..9]).unwrap())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    /// An unresolved file conflict: `id` names a [`Conflict`] object. The
    /// entry itself is always public, not executable, with no size or
    /// fallback (its terms carry their own); repository format 4.
    Conflict,
    /// A symbolic link: `id` names the (plaintext or sealed) blob of the
    /// link's target bytes, sealed like file content under the policy of
    /// the link's own path. Never executable; repository format 5.
    Symlink,
}

impl EntryKind {
    /// A file or a conflicted file: something checkout writes as a file.
    pub fn is_file_like(self) -> bool {
        matches!(self, EntryKind::File | EntryKind::Conflict)
    }

    /// A symlink (repository format 5): its object holds content (a
    /// target) that is not a file's bytes.
    pub fn is_special(self) -> bool {
        matches!(self, EntryKind::Symlink)
    }

    /// A file or symlink: an entry whose `id` names a blob (or its sealed
    /// form), sealed, withheld and published by the same rules.
    pub fn holds_blob(self) -> bool {
        matches!(self, EntryKind::File | EntryKind::Symlink)
    }

    /// Name of the kind as JSON trees and messages spell it.
    pub fn name(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Conflict => "conflict",
            EntryKind::Symlink => "symlink",
        }
    }

    /// The error for reading a format-5 entry where this build does not
    /// support it yet (checkout, the builder, …). The
    /// entry itself is kept: merges, diffs, gc, fsck and sync carry it.
    pub fn not_supported_yet(self, path: &str) -> VeilError {
        VeilError::Unsupported(format!(
            "{path:?} is a {} entry, which vl {} cannot check out or record yet",
            self.name(),
            env!("CARGO_PKG_VERSION"),
        ))
    }
}

/// The kind of one version of a file in a [`Conflict`] (repository format 5
/// adds links: a link/file or link/link conflict).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TermKind {
    #[default]
    File,
    Symlink,
}

impl TermKind {
    fn is_file(&self) -> bool {
        *self == TermKind::File
    }

    /// The term kind of an entry kind (`None` for directories and
    /// conflicts, which are never terms).
    pub fn of(kind: EntryKind) -> Option<TermKind> {
        match kind {
            EntryKind::File => Some(TermKind::File),
            EntryKind::Symlink => Some(TermKind::Symlink),
            EntryKind::Dir | EntryKind::Conflict => None,
        }
    }

    /// The entry kind holding a term of this kind.
    pub fn entry_kind(self) -> EntryKind {
        match self {
            TermKind::File => EntryKind::File,
            TermKind::Symlink => EntryKind::Symlink,
        }
    }
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
    /// The object shown to readers who cannot read `id`: for embargoed
    /// entries the pre-merge version (until they hold the embargo key); for
    /// a public file sealed only because it was edited on a cloaked line,
    /// its last public version (ARCHITECTURE §4, rule 5).
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

    /// A conflict entry naming the [`Conflict`] object `id`.
    pub fn conflict(name: &str, id: ObjectId) -> TreeEntry {
        TreeEntry {
            kind: EntryKind::Conflict,
            ..TreeEntry::dir(name, id)
        }
    }

    /// A conflict entry carries nothing but its name and object id.
    fn conflict_fields_valid(&self) -> bool {
        self.kind != EntryKind::Conflict
            || (self.size == 0 && !self.executable && self.visibility.is_public() && self.fallback.is_none())
    }

    /// A symlink is never executable.
    fn special_fields_valid(&self) -> bool {
        !self.kind.is_special() || !self.executable
    }
}

/// One version of a file in a [`Conflict`]: what a tree entry of kind
/// [`EntryKind::File`] holds, without the name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConflictTerm {
    /// File (the default, omitted) or symlink (format 5).
    #[serde(default, skip_serializing_if = "TermKind::is_file")]
    pub kind: TermKind,
    pub id: ObjectId,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable: bool,
    #[serde(default, skip_serializing_if = "Visibility::is_public")]
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<ObjectId>,
}

impl ConflictTerm {
    /// The term of a file or symlink entry (a directory or
    /// conflict entry is never a term; callers check, and get a file term).
    pub fn of(e: &TreeEntry) -> ConflictTerm {
        debug_assert!(TermKind::of(e.kind).is_some(), "{:?} is not a conflict term", e.kind);
        ConflictTerm {
            kind: TermKind::of(e.kind).unwrap_or_default(),
            id: e.id,
            size: e.size,
            executable: e.executable,
            visibility: e.visibility.clone(),
            fallback: e.fallback,
        }
    }

    /// The entry `name` holding this term (a file, or in format 5 a
    /// symlink).
    pub fn entry(&self, name: &str) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: self.kind.entry_kind(),
            id: self.id,
            size: self.size,
            executable: self.executable,
            visibility: self.visibility.clone(),
            fallback: self.fallback,
        }
    }

    /// Same version: equal in everything but the (claimed) size.
    pub fn same(&self, other: &ConflictTerm) -> bool {
        self.kind == other.kind && self.id == other.id && self.executable == other.executable && self.visibility == other.visibility && self.fallback == other.fallback
    }
}

/// An unresolved conflict between versions of one file, recorded as data
/// rather than as markers in the file (repository format 4).
///
/// As in Jujutsu, a conflict is an alternating sum: `adds[0] - removes[0] +
/// adds[1] - removes[1] + … + adds[n]`. A three-way merge of `base`, `ours`
/// and `theirs` that did not resolve is `adds = [ours, theirs]`, `removes =
/// [base]`. `None` is an absent file (added on one side only, or deleted).
/// Each term keeps the visibility it had: a conflict never moves content to
/// another audience, and a public conflict may name a sealed term that
/// readers without its key cannot open (they see it redacted).
///
/// Invariant: `adds.len() == removes.len() + 1`, at least two adds and at
/// most [`MAX_CONFLICT_REMOVES`] removes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Conflict {
    pub adds: Vec<Option<ConflictTerm>>,
    pub removes: Vec<Option<ConflictTerm>>,
}

fn conflict_corrupt(m: impl Into<String>) -> VeilError {
    VeilError::Corrupt("conflict".into(), m.into())
}

impl Conflict {
    /// Check the shape invariant (see [`Conflict`]).
    pub fn validate(&self) -> Result<()> {
        if self.adds.len() != self.removes.len() + 1 {
            return Err(conflict_corrupt("a conflict needs exactly one more add than removes"));
        }
        if self.removes.is_empty() {
            return Err(conflict_corrupt("a conflict needs at least two sides"));
        }
        if self.removes.len() > MAX_CONFLICT_REMOVES {
            return Err(conflict_corrupt(format!("more than {MAX_CONFLICT_REMOVES} removes")));
        }
        if self.interleaved().flatten().any(|t| t.kind != TermKind::File && t.executable) {
            return Err(conflict_corrupt("a symlink term is executable"));
        }
        Ok(())
    }

    /// Does a term hold a symlink (repository format 5)?
    pub fn has_special_terms(&self) -> bool {
        self.interleaved().flatten().any(|t| t.kind != TermKind::File)
    }

    /// Every term, adds and removes interleaved as stored: `add0, remove0,
    /// add1, …, addN`.
    pub fn interleaved(&self) -> impl Iterator<Item = &Option<ConflictTerm>> {
        let n = self.removes.len();
        (0..=2 * n).map(move |i| if i % 2 == 0 { &self.adds[i / 2] } else { &self.removes[i / 2] })
    }

    /// Every object id the conflict references (term ids and fallbacks).
    pub fn referenced_ids(&self) -> Vec<ObjectId> {
        let mut out = Vec::new();
        for t in self.interleaved().flatten() {
            out.push(t.id);
            if let Some(fb) = t.fallback {
                out.push(fb);
            }
        }
        out
    }

    /// The payload (without the tag): version byte `0x04`, the number of
    /// removes, then every term in [`Conflict::interleaved`] order:
    ///
    /// ```text
    /// conflict = 0x04 | removes uvarint (>= 1) | term{2·removes + 1}
    /// term     = 0x00                                   (absent)
    ///          | flags u8 | id [32] | size uvarint      if flags.SIZE
    ///            | label_len uvarint | label            if tier != public
    ///            | fallback [32]                        if flags.FALLBACK
    /// flags    = bit 0 PRESENT (set) · bit 1 EXECUTABLE · bit 2 SIZE ·
    ///            bit 3 FALLBACK · bits 4–5 tier as in trees ·
    ///            bits 6–7 term kind (format 5): 0 file, 1 symlink,
    ///            2 and 3 reserved; EXECUTABLE clear unless a file
    /// ```
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = vec![ENCODING_CONFLICT];
        put_uvarint(&mut out, self.removes.len() as u64);
        for t in self.interleaved() {
            let Some(t) = t else {
                out.push(0);
                continue;
            };
            let (tier, label) = tier_of(&t.visibility);
            let mut flags = C_PRESENT | (tier << TIER_SHIFT) | (term_kind_bits(t.kind) << C_KIND_SHIFT);
            if t.executable {
                flags |= C_EXEC;
            }
            if t.size != 0 {
                flags |= C_SIZE;
            }
            if t.fallback.is_some() {
                flags |= C_FALLBACK;
            }
            out.push(flags);
            out.extend_from_slice(&t.id.0);
            if t.size != 0 {
                put_uvarint(&mut out, t.size);
            }
            if let Some(l) = label {
                put_uvarint(&mut out, l.len() as u64);
                out.extend_from_slice(l.as_bytes());
            }
            if let Some(fb) = &t.fallback {
                out.extend_from_slice(&fb.0);
            }
        }
        out
    }

    /// Decode a payload written by [`Conflict::encode_payload`]; accepts
    /// exactly those bytes (canonical without re-encoding).
    pub fn decode_payload(payload: &[u8]) -> Result<Conflict> {
        let mut r = BinReader { b: payload, at: 0 };
        let corrupt = |e: VeilError| match e {
            VeilError::Corrupt(_, m) => conflict_corrupt(m),
            e => e,
        };
        if r.byte().map_err(corrupt)? != ENCODING_CONFLICT {
            return Err(conflict_corrupt("not a conflict object"));
        }
        let n = r.uvarint().map_err(corrupt)?;
        if n == 0 || n > MAX_CONFLICT_REMOVES as u64 {
            return Err(conflict_corrupt(format!("{n} removes (1 to {MAX_CONFLICT_REMOVES} allowed)")));
        }
        let n = n as usize;
        let mut terms = Vec::with_capacity(2 * n + 1);
        for _ in 0..=2 * n {
            let flags = r.byte().map_err(corrupt)?;
            if flags == 0 {
                terms.push(None);
                continue;
            }
            if flags & C_PRESENT == 0 {
                return Err(conflict_corrupt("absent term with flags set"));
            }
            let kind = match (flags & C_KIND_MASK) >> C_KIND_SHIFT {
                0 => TermKind::File,
                1 => TermKind::Symlink,
                _ => {
                    return Err(VeilError::Unsupported(format!(
                        "conflict term uses flags {flags:#04x} that vl {} does not know; this repository needs a newer vl",
                        env!("CARGO_PKG_VERSION")
                    )))
                }
            };
            if kind != TermKind::File && flags & C_EXEC != 0 {
                return Err(conflict_corrupt("a symlink term is executable"));
            }
            let id = r.id().map_err(corrupt)?;
            let size = if flags & C_SIZE != 0 {
                match r.uvarint().map_err(corrupt)? {
                    0 => return Err(conflict_corrupt("explicit zero size")),
                    n => n,
                }
            } else {
                0
            };
            let visibility = match (flags & TIER_MASK) >> TIER_SHIFT {
                TIER_PUBLIC => Visibility::Public,
                TIER_CLOAKED => Visibility::Cloaked { scope: r.string().map_err(corrupt)? },
                TIER_EMBARGOED => Visibility::Embargoed { embargo: r.string().map_err(corrupt)? },
                t => {
                    return Err(VeilError::Unsupported(format!(
                        "conflict term uses visibility tier {t}, which vl {} does not know; this repository needs a newer vl",
                        env!("CARGO_PKG_VERSION")
                    )))
                }
            };
            let fallback = if flags & C_FALLBACK != 0 { Some(r.id().map_err(corrupt)?) } else { None };
            terms.push(Some(ConflictTerm {
                kind,
                id,
                size,
                executable: flags & C_EXEC != 0,
                visibility,
                fallback,
            }));
        }
        if r.at != payload.len() {
            return Err(conflict_corrupt("trailing bytes after the last term"));
        }
        let mut adds = Vec::with_capacity(n + 1);
        let mut removes = Vec::with_capacity(n);
        for (i, t) in terms.into_iter().enumerate() {
            if i % 2 == 0 {
                adds.push(t);
            } else {
                removes.push(t);
            }
        }
        let c = Conflict { adds, removes };
        c.validate()?;
        Ok(c)
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

    /// Does the tree hold a conflict entry (repository format 4)?
    pub fn has_conflicts(&self) -> bool {
        self.entries.iter().any(|e| e.kind == EntryKind::Conflict)
    }

    /// Does the tree hold a symlink entry (repository format 5)?
    pub fn has_special_entries(&self) -> bool {
        self.entries.iter().any(|e| e.kind.is_special())
    }

    /// Structural validity: every name passes [`validate_entry_name`] and
    /// the entries are strictly sorted by name (so no duplicates). Lookups
    /// use binary search, so an unsorted tree would show different files to
    /// `walk_files` and to `lookup`/`diff_trees`/checkout.
    pub fn validate(&self) -> Result<()> {
        let mut prev: Option<&str> = None;
        for e in &self.entries {
            validate_entry_name(&e.name)?;
            if !e.conflict_fields_valid() {
                return Err(VeilError::Corrupt(
                    "tree".into(),
                    format!("conflict entry {:?} carries file fields", truncate_for_error(&e.name)),
                ));
            }
            if !e.special_fields_valid() {
                return Err(VeilError::Corrupt(
                    "tree".into(),
                    format!("{} entry {:?} is executable", e.kind.name(), truncate_for_error(&e.name)),
                ));
            }
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

// ---- binary tree encoding (format 2) --------------------------------------
//
//   tree    = 0x02 | count uvarint (>= 1) | entry{count}
//   entry   = name_len uvarint | name (UTF-8) | flags u8 | id [32]
//             | size uvarint            if flags & SIZE  (and then size != 0)
//             | label_len uvarint | label (UTF-8)  if tier != public
//             | fallback [32]           if flags & FALLBACK
//   flags   = bit 0 DIR, bit 1 EXECUTABLE, bit 2 SIZE, bit 3 FALLBACK,
//             bits 4-5 tier (0 public, 1 cloaked, 2 embargoed, 3 reserved),
//             bit 6 CONFLICT (format 4: `id` names a conflict object; every
//             other bit clear), bit 7 KIND (format 5: a `kind` byte follows
//             the flags, 1 symlink; 2 is reserved, never reused; DIR,
//             EXECUTABLE and CONFLICT clear)
//   entry  += kind u8 (right after flags)  if flags & KIND
//
// `uvarint` is unsigned LEB128 in its shortest form. Canonical by
// construction: every field has exactly one representation, defaults are
// omitted (flag clear) and never written explicitly, entries are strictly
// sorted, and nothing may follow the last entry.

const F_DIR: u8 = 1 << 0;
const F_EXEC: u8 = 1 << 1;
const F_SIZE: u8 = 1 << 2;
const F_FALLBACK: u8 = 1 << 3;
const TIER_SHIFT: u8 = 4;
const TIER_MASK: u8 = 0b11 << TIER_SHIFT;
const F_CONFLICT: u8 = 1 << 6;
/// Format 5: a kind byte follows the flags.
const F_KIND: u8 = 1 << 7;
/// Kind bytes after `F_KIND` (every other value is `Unsupported`; 2 is
/// reserved and never reused, see `docs/FORMAT.md`).
const KIND_SYMLINK: u8 = 1;
// Conflict term flags (see `Conflict::encode_payload`).
const C_PRESENT: u8 = 1 << 0;
const C_EXEC: u8 = 1 << 1;
const C_SIZE: u8 = 1 << 2;
const C_FALLBACK: u8 = 1 << 3;
/// Bits 6–7 of a conflict term's flags: its kind (format 5).
const C_KIND_SHIFT: u8 = 6;
const C_KIND_MASK: u8 = 0b11 << C_KIND_SHIFT;

fn term_kind_bits(k: TermKind) -> u8 {
    match k {
        TermKind::File => 0,
        TermKind::Symlink => 1,
    }
}
const TIER_PUBLIC: u8 = 0;
const TIER_CLOAKED: u8 = 1;
const TIER_EMBARGOED: u8 = 2;
/// Smallest possible encoded entry: 1-byte name length, 1-byte name, flags, id.
const MIN_ENTRY_LEN: usize = 1 + 1 + 1 + 32;

fn tier_of(v: &Visibility) -> (u8, Option<&String>) {
    match v {
        Visibility::Public => (TIER_PUBLIC, None),
        Visibility::Cloaked { scope } => (TIER_CLOAKED, Some(scope)),
        Visibility::Embargoed { embargo } => (TIER_EMBARGOED, Some(embargo)),
    }
}

fn put_uvarint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn tree_corrupt(m: impl Into<String>) -> VeilError {
    VeilError::Corrupt("tree".into(), m.into())
}

struct BinReader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> BinReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| tree_corrupt("truncated"))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Unsigned LEB128, shortest form only.
    fn uvarint(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let b = self.byte()?;
            if i == 9 && b > 1 {
                return Err(tree_corrupt("varint overflows 64 bits"));
            }
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    return Err(tree_corrupt("varint is not in shortest form"));
                }
                return Ok(v);
            }
        }
        Err(tree_corrupt("varint is too long"))
    }

    fn len(&mut self) -> Result<usize> {
        let n = self.uvarint()?;
        usize::try_from(n).ok().filter(|n| *n <= self.b.len() - self.at).ok_or_else(|| tree_corrupt("truncated"))
    }

    fn string(&mut self) -> Result<String> {
        let n = self.len()?;
        let raw = self.take(n)?;
        std::str::from_utf8(raw).map(str::to_string).map_err(|_| tree_corrupt("name or label is not valid UTF-8"))
    }

    fn id(&mut self) -> Result<ObjectId> {
        Ok(ObjectId(self.take(32)?.try_into().unwrap()))
    }
}

impl Tree {
    /// The binary (format-2) payload, without the object tag: version byte
    /// `0x02`, then the entries as stored. Callers encode only valid,
    /// non-empty trees; the empty tree is always JSON (see [`Object::encode_with`]).
    pub fn encode_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.entries.len() * 48);
        out.push(ENCODING_BINARY_TREE);
        put_uvarint(&mut out, self.entries.len() as u64);
        for e in &self.entries {
            put_uvarint(&mut out, e.name.len() as u64);
            out.extend_from_slice(e.name.as_bytes());
            let (tier, label) = tier_of(&e.visibility);
            let mut flags = tier << TIER_SHIFT;
            let kind_byte = match e.kind {
                EntryKind::Dir => {
                    flags |= F_DIR;
                    None
                }
                EntryKind::Conflict => {
                    flags |= F_CONFLICT;
                    None
                }
                EntryKind::File => None,
                EntryKind::Symlink => Some(KIND_SYMLINK),
            };
            if kind_byte.is_some() {
                flags |= F_KIND;
            }
            if e.executable {
                flags |= F_EXEC;
            }
            if e.size != 0 {
                flags |= F_SIZE;
            }
            if e.fallback.is_some() {
                flags |= F_FALLBACK;
            }
            out.push(flags);
            if let Some(k) = kind_byte {
                out.push(k);
            }
            out.extend_from_slice(&e.id.0);
            if e.size != 0 {
                put_uvarint(&mut out, e.size);
            }
            if let Some(l) = label {
                put_uvarint(&mut out, l.len() as u64);
                out.extend_from_slice(l.as_bytes());
            }
            if let Some(fb) = &e.fallback {
                out.extend_from_slice(&fb.0);
            }
        }
        out
    }

    /// Decode a binary (format-2) payload (starting at the version byte).
    /// Accepts exactly the bytes [`Tree::encode_binary`] writes for a valid
    /// tree, so decoding is canonical without re-encoding.
    pub fn decode_binary(payload: &[u8]) -> Result<Tree> {
        let mut r = BinReader { b: payload, at: 0 };
        if r.byte()? != ENCODING_BINARY_TREE {
            return Err(tree_corrupt("not a binary tree"));
        }
        let count = r.uvarint()?;
        if count == 0 {
            return Err(tree_corrupt("the empty tree must use the format-1 encoding"));
        }
        let room = (payload.len() - r.at) / MIN_ENTRY_LEN;
        if count > room as u64 {
            return Err(tree_corrupt("truncated"));
        }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let name = r.string()?;
            let flags = r.byte()?;
            let special = if flags & F_KIND != 0 {
                let k = r.byte()?;
                let kind = match k {
                    KIND_SYMLINK => EntryKind::Symlink,
                    _ => {
                        return Err(VeilError::Unsupported(format!(
                            "tree entry {:?} uses entry kind {k}, which vl {} does not know; this repository needs a newer vl",
                            truncate_for_error(&name),
                            env!("CARGO_PKG_VERSION")
                        )))
                    }
                };
                if flags & (F_DIR | F_EXEC | F_CONFLICT) != 0 {
                    return Err(tree_corrupt(format!(
                        "{} entry {:?} carries the directory, executable or conflict flag",
                        kind.name(),
                        truncate_for_error(&name)
                    )));
                }
                Some(kind)
            } else {
                None
            };
            if flags & F_CONFLICT != 0 && flags != F_CONFLICT {
                return Err(tree_corrupt(format!(
                    "conflict entry {:?} carries other flags",
                    truncate_for_error(&name)
                )));
            }
            let id = r.id()?;
            let size = if flags & F_SIZE != 0 {
                let n = r.uvarint()?;
                if n == 0 {
                    return Err(tree_corrupt("explicit zero size"));
                }
                n
            } else {
                0
            };
            let visibility = match (flags & TIER_MASK) >> TIER_SHIFT {
                TIER_PUBLIC => Visibility::Public,
                TIER_CLOAKED => Visibility::Cloaked { scope: r.string()? },
                TIER_EMBARGOED => Visibility::Embargoed { embargo: r.string()? },
                t => {
                    return Err(VeilError::Unsupported(format!(
                        "tree entry {:?} uses visibility tier {t}, which vl {} does not know; this repository needs a newer vl",
                        truncate_for_error(&name),
                        env!("CARGO_PKG_VERSION")
                    )))
                }
            };
            let fallback = if flags & F_FALLBACK != 0 { Some(r.id()?) } else { None };
            entries.push(TreeEntry {
                name,
                kind: if let Some(k) = special {
                    k
                } else if flags & F_DIR != 0 {
                    EntryKind::Dir
                } else if flags & F_CONFLICT != 0 {
                    EntryKind::Conflict
                } else {
                    EntryKind::File
                },
                id,
                size,
                executable: flags & F_EXEC != 0,
                visibility,
                fallback,
            });
        }
        if r.at != payload.len() {
            return Err(tree_corrupt("trailing bytes after the last entry"));
        }
        let t = Tree { entries };
        t.validate()?;
        Ok(t)
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
    Conflict(Conflict),
    /// An annotated tag (repository format 5).
    Atag(Atag),
    Sealed(Envelope),
}

impl Object {
    /// The format-1 encoding (JSON trees). Kept for compatibility: objects
    /// are *stored* in the repository's format, so use
    /// [`crate::store::ObjectStore::encode`] (or [`Object::encode_with`]) to
    /// compute the id a tree will have in a given repository. Blobs,
    /// snapshots and sealed objects encode the same way in every format.
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with(TreeEncoding::Json)
    }

    /// Encode with trees in `trees` encoding. The empty tree is always
    /// format 1 (it is part of the universal root snapshot, whose id must
    /// never change).
    pub fn encode_with(&self, trees: TreeEncoding) -> Vec<u8> {
        let (tag, body): (&[u8], Vec<u8>) = match self {
            Object::Blob(b) => (BLOB_TAG, b.clone()),
            Object::Tree(t) if trees == TreeEncoding::Binary && !t.is_empty() => (TREE_TAG, t.encode_binary()),
            Object::Tree(t) => (TREE_TAG, serde_json::to_vec(t).unwrap()),
            Object::Snapshot(s) => (SNAP_TAG, serde_json::to_vec(s).unwrap()),
            Object::Conflict(c) => (CONF_TAG, c.encode_payload()),
            Object::Atag(a) => (ATAG_TAG, a.encode_payload()),
            Object::Sealed(e) if e.is_aes_siv() => (SEAL_AES_SIV_TAG, e.to_bytes()),
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
            // one logical tree has exactly one id per encoding.
            match b.first() {
                Some(&ENCODING_JSON) => {
                    let t: Tree = serde_json::from_slice(b)?;
                    t.validate()?;
                    if serde_json::to_vec(&t)? != b {
                        return Err(corrupt("tree is not in canonical encoding"));
                    }
                    Ok(Object::Tree(t))
                }
                Some(&ENCODING_BINARY_TREE) => Ok(Object::Tree(Tree::decode_binary(b)?)),
                Some(v) if ENCODING_RESERVED.contains(v) => Err(unsupported_encoding("tree", *v)),
                _ => Err(corrupt("tree is not in canonical encoding")),
            }
        } else if let Some(b) = raw.strip_prefix(SNAP_TAG) {
            match b.first() {
                Some(&ENCODING_JSON) => {
                    // Canonical too: otherwise one signed snapshot could be
                    // re-encoded under many ids, all with a valid signature.
                    let s: Snapshot = serde_json::from_slice(b)?;
                    if serde_json::to_vec(&s)? != b {
                        return Err(corrupt("snapshot is not in canonical encoding"));
                    }
                    Ok(Object::Snapshot(s))
                }
                Some(v) if *v == ENCODING_BINARY_TREE || ENCODING_RESERVED.contains(v) => {
                    Err(unsupported_encoding("snapshot", *v))
                }
                _ => Err(corrupt("snapshot is not in canonical encoding")),
            }
        } else if let Some(b) = raw.strip_prefix(CONF_TAG) {
            match b.first() {
                Some(&ENCODING_CONFLICT) => Ok(Object::Conflict(Conflict::decode_payload(b)?)),
                Some(v) if ENCODING_RESERVED.contains(v) || *v < ENCODING_CONFLICT => Err(unsupported_encoding("conflict", *v)),
                _ => Err(corrupt("conflict is not in canonical encoding")),
            }
        } else if let Some(b) = raw.strip_prefix(ATAG_TAG) {
            match b.first() {
                Some(&ENCODING_JSON) => Ok(Object::Atag(Atag::decode_payload(b)?)),
                Some(v) if ENCODING_RESERVED.contains(v) || *v == ENCODING_BINARY_TREE => Err(unsupported_encoding("atag", *v)),
                _ => Err(corrupt("atag is not in canonical encoding")),
            }
        } else if let Some(b) = raw.strip_prefix(SEAL_TAG) {
            Ok(Object::Sealed(Envelope::from_bytes(b)?))
        } else if let Some(b) = raw.strip_prefix(SEAL_AES_SIV_TAG) {
            Ok(Object::Sealed(Envelope::from_bytes_aes_siv(b)?))
        } else if let Some(kind) = tag_shaped(raw) {
            Err(VeilError::Unsupported(format!(
                "object kind '{kind}' is unknown to vl {}; this repository needs a newer vl",
                env!("CARGO_PKG_VERSION")
            )))
        } else {
            Err(corrupt("unknown object tag"))
        }
    }

    /// Encoding of a raw tree object, `None` if `raw` is not a tree in an
    /// encoding this build knows.
    pub fn tree_encoding(raw: &[u8]) -> Option<TreeEncoding> {
        match *raw.strip_prefix(TREE_TAG)?.first()? {
            ENCODING_JSON => Some(TreeEncoding::Json),
            ENCODING_BINARY_TREE => Some(TreeEncoding::Binary),
            _ => None,
        }
    }

    /// Lowest repository format whose readers can read the raw object
    /// (binary trees: 2; AES-SIV sealed objects: 3; conflict objects and
    /// trees holding a conflict entry: 4; trees holding a symlink,
    /// conflicts with such a term, and annotated tags: 5;
    /// everything else: 1).
    pub fn min_repo_format(raw: &[u8]) -> u32 {
        if let Some(enc) = Object::tree_encoding(raw) {
            // Only a tree that decodes can hold a conflict or special
            // entry; anything else is refused when it is read.
            match Object::decode(raw) {
                Ok(Object::Tree(t)) if t.has_special_entries() => GIT_PARITY_REPO_FORMAT,
                Ok(Object::Tree(t)) if t.has_conflicts() => CONFLICT_REPO_FORMAT,
                _ => enc.min_repo_format(),
            }
        } else if raw.starts_with(CONF_TAG) {
            match Object::decode(raw) {
                Ok(Object::Conflict(c)) if c.has_special_terms() => GIT_PARITY_REPO_FORMAT,
                _ => CONFLICT_REPO_FORMAT,
            }
        } else if raw.starts_with(ATAG_TAG) {
            GIT_PARITY_REPO_FORMAT
        } else if raw.starts_with(SEAL_AES_SIV_TAG) {
            AES_SIV_REPO_FORMAT
        } else {
            1
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
        raw.strip_prefix(SEAL_TAG)
            .or_else(|| raw.strip_prefix(SEAL_AES_SIV_TAG))
            .and_then(Envelope::peek_scope)
    }

    pub fn is_blob_raw(raw: &[u8]) -> bool {
        raw.starts_with(BLOB_TAG)
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Object::Blob(_) => "blob",
            Object::Tree(_) => "tree",
            Object::Snapshot(_) => "snapshot",
            Object::Conflict(_) => "conflict",
            Object::Atag(_) => "atag",
            Object::Sealed(_) => "sealed",
        }
    }
}
