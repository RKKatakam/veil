//! Snapshotting: turn any `StorageBackend` into a tree, applying policy.
//!
//! This is where the engine enforces visibility:
//!
//! * `ignored` paths are skipped;
//! * `isolated` paths (and every built-in secret like `.env`) are reported
//!   back to the caller and **never** written to the CAS;
//! * secret files under a `cloak` rule (`.env`, keys and similar: only
//!   secret files are ever encrypted) are sealed under their scope key;
//! * public files are secret-scanned and quarantined on a hit. A quarantined
//!   file that was already tracked keeps its previous (safe) entry, so the
//!   local edit is held back instead of being recorded as a deletion;
//! * entries this reader cannot see (a secret it holds no key for, or one
//!   it never received) are carried over untouched instead of being
//!   treated as deletions.
//!
//! With a [`StatCache`] the builder skips reading files whose stat data is
//! unchanged, using content facts recorded on an earlier run. Classification
//! still runs for every path, every time.
//!
//! The working copy is untrusted ground, so nothing in it can fail a build
//! or slip through silently:
//!
//! * crash leftovers of interrupted writes (`.name.vltmpXXXXXXXX`) are
//!   skipped;
//! * an unreadable file or directory keeps its previous entry (or stays out
//!   if it was never tracked) and is reported;
//! * names that are not valid UTF-8 cannot be recorded and are reported;
//! * a tracked path that became a symlink (or socket, device…) is never
//!   followed: its tracked entry is kept and reported.
//!
//! On a backend that folds names ([`StorageBackend::name_folding`], e.g. a
//! macOS volume) a name that is an alias of the parent's entry (another case,
//! or HFS+ handing back NFD for a name checked out in NFC) keeps the parent's
//! spelling, and new names are recorded in NFC. Directories whose entries
//! would collide on such a filesystem are reported on every backend
//! ([`BuildReport::name_collisions`]), so a Linux user learns before a macOS
//! teammate's checkout refuses the snapshot.
//!
//! Line endings follow the working copy's `.veilattributes` (see
//! [`crate::attributes`] and [`LineEndings`]): a file is normalised (CRLF →
//! LF) before it is hashed, scanned and sealed, all on the one buffer, and
//! only when that is lossless; a file that still holds its recorded version
//! (as it is, or as the CRLF rendering checkout wrote for it) keeps it, so
//! a change of attributes never re-records anything by itself (`vl
//! renormalize` does, [`LineEndings::Renormalize`]).
//!
//! With [`InjectedSecrets`] (the isolated files a `ws exec` sandbox was given)
//! any new content that contains one of those values is quarantined, so a
//! command cannot launder an injected secret into history under another name.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    attributes::{lf_to_crlf, to_odb, Attrs, ToOdb},
    checkout::Materialised,
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{tier_keyword, Classification, HeldBack, Policy, PolicyFile, Tier, POLICY_FILE},
    secrets::{self, Finding},
    statcache::{CacheKey, CacheRun, EolFact, StatCache},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::{is_temp_name, DirEntry, DirListing, Metadata, NodeKind, StorageBackend},
    vpath::{NameFolding, VPath},
};

/// One directory of the working copy being built (see `Builder::build_dir`).
struct BuildFrame {
    dir: VPath,
    parent: Option<(Arc<Tree>, ObjectId)>,
    entries: Vec<DirEntry>,
    /// The listing's stats of `entries` ([`DirListing::stats`]).
    stats: Vec<Option<Metadata>>,
    /// Their classifications, when made ahead of the walk (by entry).
    classes: Vec<Option<Classification>>,
    next: usize,
    out: Tree,
    /// Special entries (symlinks where a directory or file was tracked…)
    /// whose tracked entry was kept.
    kept_special: Vec<String>,
    /// Name of the subdirectory being built on top of this frame.
    waiting: Option<String>,
}

enum Opened {
    Frame(BuildFrame),
    Done(Option<ObjectId>),
}

/// Is a listed entry part of the working copy the walk records? Not a
/// reserved name (`.veil`, at any depth), nor a file left by an interrupted
/// atomic write (crash debris, never content).
fn counted(e: &DirEntry) -> bool {
    !crate::object::is_reserved_name(&e.name) && !(e.kind == NodeKind::File && is_temp_name(&e.name))
}

/// What the listing of its directory told of a leaf ([`Builder::listed`]).
struct Listed {
    path: VPath,
    meta: Option<Metadata>,
    /// Its classification as a file or a symlink (the kind it was listed
    /// as): for that kind only.
    class: Option<(EntryKind, Classification)>,
}

pub struct BuildOptions<'a> {
    pub policy: &'a Policy,
    /// Tree of the snapshot being amended (enables reuse and carry-over).
    pub parent_tree: Option<ObjectId>,
    /// Tree of the change's committed parent(s) (`None` means `parent_tree`).
    /// Moved-secret protection and non-secret sealing are judged against this
    /// tree so a secret created and renamed within one change is classified by
    /// its final path (BUG-1833).
    pub base_tree: Option<ObjectId>,
    /// Secret content the engine handed to whoever wrote `fs` (the isolated
    /// files injected into a sandbox). New content containing any of it is
    /// quarantined, whatever its path and tier.
    pub injected: Option<&'a InjectedSecrets>,
    /// Re-scan unchanged public files (normally trusted because they were
    /// scanned when they entered the parent). Set once after the secret
    /// scanner's rules change, so files an older scanner let through are
    /// caught. Also disables reuse hints for that build.
    pub rescan: bool,
    /// What the working copy `fs` was materialised from, relative to
    /// `parent_tree` (see [`Materialised`]): which files were left out
    /// because this reader could not read them. A path that was never materialised is never
    /// recorded as deleted, even once it has become readable. `None` when
    /// `fs` is not a checked-out working copy (overlays, sandboxes) or the
    /// caller keeps no record.
    pub materialised: Option<&'a Materialised>,
    /// How `.veilattributes` decides the line endings recorded.
    pub line_endings: LineEndings<'a>,
}

/// How a build applies the line-ending attributes of `.veilattributes`.
#[derive(Clone, Copy, Default)]
pub enum LineEndings<'a> {
    /// Normalise new content as the working copy's attributes say (when
    /// lossless); a file that still holds its recorded version keeps it.
    #[default]
    Convert,
    /// `vl renormalize`: the paths selected are recorded as the attributes
    /// say now, even unchanged ones; the others as with `Convert`.
    Renormalize(&'a (dyn Fn(&VPath) -> bool + 'a)),
}

/// Rule name of a [`Finding`] for content copied from an injected secret.
pub const INJECTED_RULE: &str = "injected-isolated-secret";

/// The "scope" under which a stat cache record notes that a file is the
/// rendering of a conflict entry (`sealed` = `(CONFLICT_COPY, conflict
/// id)`). No scope can have this name, so the fact is never taken for a
/// sealing.
const CONFLICT_COPY: &str = ":conflict";

/// Values the engine injected from the vault (isolated files such as
/// `.env`, keys, keystores, quarantined files) into a sandbox.
///
/// Built from the files' contents, as text: every `KEY=value` /
/// `key: value` value that looks like a secret (at least 8 characters, and
/// either 20+ characters or a mix of character classes, so `localhost`,
/// `production` or `3000` never match), plus the whole content and every
/// whitespace-free line of 24+ characters (key material, bare tokens).
///
/// And as bytes (BUG-099): a file that is not UTF-8 (a PKCS#12 bundle, a
/// Java keystore, a DER key), and the DER inside every PEM block of a text
/// file, yields its whole content (16+ bytes) plus [`WINDOW`]-byte windows
/// of its key material: of the raw bytes, of its base64 encoding (all three
/// alignments, so any copied segment is covered) and of its hex encoding
/// (lower and upper case). Windows are taken every [`STRIDE`] positions, so
/// any copied run of 47+ bytes, and any base64 or hex copy wrapped at 48+
/// characters per line (`base64`, PEM, `xxd -p`), contains one. Only
/// windows over *distinctive* bytes count (at least 3/4 distinct bytes in
/// the source span): padding and the ASN.1 structure every key of a kind
/// shares (OIDs, length headers) never match unrelated files. Memory and
/// time are bounded: windows are matched with a rolling hash behind a bit
/// filter (one pass over each checked file), each file contributes at most
/// about 74 000 windows (the stride grows for larger files) and all files
/// together at most [`MAX_WINDOWS`].
#[derive(Debug, Default, Clone)]
pub struct InjectedSecrets {
    /// (needle, the injected file it came from)
    needles: Vec<(Vec<u8>, String)>,
    matcher: Option<regex::bytes::Regex>,
    /// Whole contents of binary injected files (and DER decoded from PEM),
    /// matched as raw bytes.
    raw: Vec<(Vec<u8>, String)>,
    windows: WindowIndex,
}

/// Length of a binary window (bytes of raw content, or characters of its
/// base64 / hex encoding).
pub const WINDOW: usize = 32;
/// Distance between consecutive windows of one encoding (for files up to
/// 128 KiB; larger files use a proportionally larger stride).
pub const STRIDE: usize = 16;
/// Upper bound on the windows of all injected files together.
pub const MAX_WINDOWS: usize = 1 << 18;
/// Binary files contribute at most this many bytes of content.
const MAX_BINARY: usize = 16 << 20;
/// Bits of the window filter (2^20 bits = 128 KiB).
const FILTER_BITS: u32 = 20;
const HASH_BASE: u64 = 0x100_0000_01b3;

/// How a window encodes the injected bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Raw,
    Base64,
    Hex,
}

#[derive(Debug, Default, Clone)]
struct WindowIndex {
    windows: Vec<([u8; WINDOW], u32, Encoding)>,
    sources: Vec<String>,
    by_hash: HashMap<u64, Vec<u32>>,
    filter: Vec<u64>,
    /// `HASH_BASE^(WINDOW-1)`, to roll the hash.
    top: u64,
}

fn window_hash(w: &[u8]) -> u64 {
    w.iter().fold(0u64, |h, &b| h.wrapping_mul(HASH_BASE).wrapping_add(u64::from(b) + 1))
}

fn filter_slot(h: u64) -> (usize, u64) {
    let i = (h.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - FILTER_BITS)) as usize;
    (i / 64, 1u64 << (i % 64))
}

/// At least three quarters of the bytes are distinct.
fn distinctive(span: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut n = 0;
    for &b in span {
        if !std::mem::replace(&mut seen[b as usize], true) {
            n += 1;
        }
    }
    n * 4 >= span.len() * 3
}

impl WindowIndex {
    fn len(&self) -> usize {
        self.windows.len()
    }

    fn add(&mut self, w: &[u8], src: u32, enc: Encoding) -> bool {
        if self.windows.len() >= MAX_WINDOWS {
            return false;
        }
        let arr: [u8; WINDOW] = w.try_into().expect("window length");
        let h = window_hash(&arr);
        let bucket = self.by_hash.entry(h).or_default();
        if bucket.iter().any(|&i| self.windows[i as usize].0 == arr) {
            return true;
        }
        bucket.push(self.windows.len() as u32);
        self.windows.push((arr, src, enc));
        if self.filter.is_empty() {
            self.filter = vec![0; (1usize << FILTER_BITS) / 64];
            self.top = (1..WINDOW).fold(1u64, |t, _| t.wrapping_mul(HASH_BASE));
        }
        let (i, bit) = filter_slot(h);
        self.filter[i] |= bit;
        true
    }

    /// Windows of `data` (one binary secret) in every encoding.
    fn add_source(&mut self, data: &[u8], src: u32) {
        let data = &data[..data.len().min(MAX_BINARY)];
        if data.len() < WINDOW / 2 {
            return;
        }
        // ~9 windows per STRIDE bytes over all encodings: keep one file
        // under ~74k windows.
        let stride = STRIDE.max(data.len().div_ceil(8192)).next_multiple_of(2);
        // Raw bytes.
        let mut i = 0;
        while i + WINDOW <= data.len() {
            if distinctive(&data[i..i + WINDOW]) && !self.add(&data[i..i + WINDOW], src, Encoding::Raw) {
                return;
            }
            i += stride;
        }
        // Base64, in each of the three alignments a copied segment can have.
        for align in 0..3.min(data.len()) {
            let text = base64_encode(&data[align..]);
            let mut i = 0;
            while i + WINDOW <= text.len() {
                // 4 characters encode 3 bytes.
                let from = align + i / 4 * 3;
                let to = (align + (i + WINDOW).div_ceil(4) * 3).min(data.len());
                if distinctive(&data[from..to]) && !self.add(&text[i..i + WINDOW], src, Encoding::Base64) {
                    return;
                }
                i += stride;
            }
        }
        // Hex, in both cases.
        for upper in [false, true] {
            let mut text = hex::encode(data).into_bytes();
            if upper {
                text.make_ascii_uppercase();
            }
            let mut i = 0;
            while i + WINDOW <= text.len() {
                if distinctive(&data[i / 2..(i + WINDOW) / 2]) && !self.add(&text[i..i + WINDOW], src, Encoding::Hex) {
                    return;
                }
                i += stride;
            }
        }
    }

    /// Position and window index of the first window found in `data`.
    fn find(&self, data: &[u8]) -> Option<(usize, u32)> {
        if self.windows.is_empty() || data.len() < WINDOW {
            return None;
        }
        let mut h = window_hash(&data[..WINDOW]);
        let mut at = 0;
        loop {
            let (i, bit) = filter_slot(h);
            if self.filter[i] & bit != 0 {
                if let Some(b) = self.by_hash.get(&h) {
                    if let Some(&w) = b.iter().find(|&&w| self.windows[w as usize].0[..] == data[at..at + WINDOW]) {
                        return Some((at, w));
                    }
                }
            }
            if at + WINDOW >= data.len() {
                return None;
            }
            let (out, inp) = (u64::from(data[at]) + 1, u64::from(data[at + WINDOW]) + 1);
            h = h
                .wrapping_sub(out.wrapping_mul(self.top))
                .wrapping_mul(HASH_BASE)
                .wrapping_add(inp);
            at += 1;
        }
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, without padding (a window never needs it).
fn base64_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..=c.len() {
            out.push(BASE64[(n >> (18 - 6 * k) & 63) as usize]);
        }
    }
    out
}

/// The DER inside each PEM block of `text` (`-----BEGIN …-----` to
/// `-----END …-----`; header lines such as `Proc-Type:` are skipped).
fn pem_bodies(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            body = Some(Vec::new());
        } else if line.starts_with("-----END ") {
            if let Some(b) = body.take() {
                if let Some(der) = base64_decode(&b) {
                    out.push(der);
                }
            }
        } else if let Some(b) = body.as_mut() {
            if !line.contains(':') {
                b.extend(line.bytes());
            }
        }
    }
    out
}

fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in text {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

impl InjectedSecrets {
    pub fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> InjectedSecrets {
        let mut needles: Vec<(Vec<u8>, String)> = Vec::new();
        let mut raw: Vec<(Vec<u8>, String)> = Vec::new();
        let mut windows = WindowIndex::default();
        let mut add = |v: &str, src: &str| {
            let v = v.trim();
            if secret_like(v) && !needles.iter().any(|(n, _)| n == v.as_bytes()) {
                needles.push((v.as_bytes().to_vec(), src.to_string()));
            }
        };
        for (src, data) in files {
            let text = String::from_utf8_lossy(data);
            if text.trim().len() >= LONG_NEEDLE {
                add(&text, src);
            }
            for line in text.lines() {
                // Whole lines only when long and unbroken (key material,
                // tokens), not ordinary `MODE=production` or code lines.
                let line_t = line.trim();
                if line_t.len() >= LONG_NEEDLE && !line_t.contains(char::is_whitespace) {
                    add(line_t, src);
                }
                if let Some(v) = assignment_value(line) {
                    add(v, src);
                }
            }
            // Binary content (BUG-099), and the DER of PEM blocks (a key
            // converted to DER by the command).
            let binary: Vec<Vec<u8>> = match std::str::from_utf8(data) {
                Err(_) => vec![data[..data.len().min(MAX_BINARY)].to_vec()],
                Ok(t) => pem_bodies(t),
            };
            for b in binary {
                if b.len() < WINDOW / 2 {
                    continue;
                }
                windows.sources.push(src.to_string());
                let id = (windows.sources.len() - 1) as u32;
                windows.add_source(&b, id);
                if !raw.iter().any(|(n, _)| *n == b) {
                    raw.push((b, src.to_string()));
                }
            }
        }
        // Longest first, so the leftmost match reports the most specific value.
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        let matcher = (!needles.is_empty())
            .then(|| {
                let alts: Vec<String> = needles
                    .iter()
                    .map(|(n, _)| regex::escape(std::str::from_utf8(n).expect("needles are UTF-8")))
                    .collect();
                regex::bytes::RegexBuilder::new(&alts.join("|"))
                    .size_limit(256 << 20)
                    .dfa_size_limit(64 << 20)
                    .build()
                    .ok()
            })
            .flatten();
        InjectedSecrets {
            needles,
            matcher,
            raw,
            windows,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.needles.is_empty() && self.raw.is_empty() && self.windows.len() == 0
    }

    /// The first injected value contained in `data`, as a printable finding.
    pub fn find(&self, data: &[u8]) -> Option<Finding> {
        let found = |start: usize, excerpt: String| Finding {
            rule: INJECTED_RULE,
            line: data[..start].iter().filter(|&&b| b == b'\n').count() + 1,
            excerpt,
        };
        let text = match &self.matcher {
            Some(re) => re
                .find(data)
                .and_then(|m| Some((m.start(), self.needles.iter().find(|(n, _)| n == m.as_bytes())?))),
            // Pattern too large for the regex engine: plain substring search.
            None => self
                .needles
                .iter()
                .find_map(|n| memchr::memmem::find(data, &n.0).map(|i| (i, n))),
        };
        if let Some((start, needle)) = text {
            return Some(found(start, format!("content of {} injected into the sandbox", needle.1)));
        }
        if let Some((start, (_, src))) = self.raw.iter().find_map(|n| memchr::memmem::find(data, &n.0).map(|i| (i, n))) {
            return Some(found(start, format!("content of {src} injected into the sandbox")));
        }
        let (start, w) = self.windows.find(data)?;
        let (_, src, enc) = &self.windows.windows[w as usize];
        let how = match enc {
            Encoding::Raw => "part of the content",
            Encoding::Base64 => "part of the content (base64)",
            Encoding::Hex => "part of the content (hex)",
        };
        Some(found(
            start,
            format!("{how} of {} injected into the sandbox", self.windows.sources[*src as usize]),
        ))
    }
}

/// Minimum length of whole-file and whole-line needles.
const LONG_NEEDLE: usize = 24;

/// Long enough, and not a plain word or number.
fn secret_like(v: &str) -> bool {
    if v.len() < 8 || v.contains('\u{fffd}') {
        return false;
    }
    let classes = [
        v.bytes().any(|b| b.is_ascii_lowercase()),
        v.bytes().any(|b| b.is_ascii_uppercase()),
        v.bytes().any(|b| b.is_ascii_digit()),
        v.bytes().any(|b| !b.is_ascii_alphanumeric()),
    ];
    v.len() >= 20 || classes.iter().filter(|&&c| c).count() >= 2
}

/// `value` of `KEY=value`, `export KEY="value"` or `key: value`.
fn assignment_value(line: &str) -> Option<&str> {
    let line = line.trim();
    let line = line.strip_prefix("export ").unwrap_or(line);
    let at = line.find(['=', ':'])?;
    let key = line[..at].trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
        return None;
    }
    let v = line[at + 1..].trim();
    let v = v
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(v);
    Some(v)
}

// ---- trusted sealing decisions (BUG-103) ---------------------------------------

/// What the object behind a file entry says about the entry's visibility
/// label (see [`verify_sealing`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sealing {
    /// The object is sealed exactly as the label says (plaintext for a
    /// public label, under scope `s` for `cloaked:s`).
    Verified,
    /// The object is sealed for another audience than the label claims: its
    /// real visibility. The label is hostile or corrupt.
    Relabelled(Visibility),
    /// Nothing can be checked: the object is not here (withheld by a public
    /// remote, not fetched), or it is sealed under a label that is no
    /// audience (`local`, not a scope name) or is not file content.
    Unverifiable,
}

/// The visibility a raw stored object really has, from its own envelope
/// label: plaintext blob → public, sealed under `scope` or `scope#<key-id>`
/// → cloaked under `scope`.
/// `None` for anything else.
pub fn object_visibility(raw: &[u8]) -> Option<Visibility> {
    if Object::is_blob_raw(raw) {
        return Some(Visibility::Public);
    }
    let label = Object::sealed_scope(raw)?;
    let scope = crate::keychain::split_label(&label).0;
    crate::keychain::validate_scope_name(scope)
        .is_ok()
        .then(|| Visibility::Cloaked { scope: scope.to_string() })
}

/// Check a file entry's visibility label against the object it points to.
///
/// Visibility labels in trees, like every other field of history, are
/// written by whoever produced the snapshot: a teammate, a remote anyone
/// with write access can push to. They are a *claim*. The
/// envelope label of a sealed object is bound to its ciphertext (it is the
/// AEAD's associated data), so it is what the content really is sealed
/// for. A tree entry whose label disagrees with its object is hostile (or
/// corrupt) and must never decide how new content is sealed.
pub fn verify_sealing(store: &ObjectStore, e: &TreeEntry) -> Result<Sealing> {
    if !e.kind.holds_blob() {
        return Ok(Sealing::Verified);
    }
    let raw = match store.get_raw(&e.id) {
        Ok(r) => r,
        Err(err) if err.is_unreadable() || err.is_not_found() => return Ok(Sealing::Unverifiable),
        Err(err) => return Err(err),
    };
    Ok(match object_visibility(&raw) {
        None => Sealing::Unverifiable,
        Some(actual) if actual == e.visibility => Sealing::Verified,
        Some(actual) => Sealing::Relabelled(actual),
    })
}

/// Human description of a relabelled entry, for reports.
pub fn relabel_note(claimed: &Visibility, actual: &Visibility) -> String {
    format!(
        "recorded as {} but its content is {}; treated as {} (a remote or an import may have forged the label)",
        claimed.label(),
        match actual {
            Visibility::Public => "plaintext".to_string(),
            v => format!("sealed as {}", v.label()),
        },
        actual.label()
    )
}

#[derive(Debug, Default, Clone)]
pub struct BuildReport {
    /// Files kept local-only by policy.
    pub isolated: Vec<VPath>,
    /// Public files that contained secrets and were held back.
    pub quarantined: Vec<(VPath, Vec<Finding>)>,
    /// The subset of `quarantined` that was already tracked: the tree keeps
    /// the previous (safe) version, and the local edit stays unrecorded.
    pub quarantine_kept: Vec<VPath>,
    /// Built-in secrets a policy rule tried (and failed) to make public.
    pub blocked_exposures: Vec<VPath>,
    /// Paths whose protection the working copy's `.veilpolicy` would weaken
    /// and the member has not accepted (see `wc_policy`). They were built
    /// under the accepted classification; a tracked one the accepted policy
    /// keeps local keeps its previous entry (never a deletion). A directory
    /// the accepted policy ignores is reported once, as a whole.
    pub policy_held_back: Vec<HeldBack>,
    /// The member's own edit of `.veilpolicy` waits for `vl policy accept`
    /// (see [`Policy::own_edit_pending`]).
    pub policy_edit_pending: bool,
    /// An edit of `.veilpolicy` made by a command (a `vl ws exec` sandbox,
    /// a mount; see `SnapshotOptions::policy_from_command`) that weakens
    /// the recorded policy, or could, was not recorded: the tree keeps the
    /// recorded `.veilpolicy`, and the paths it would weaken are in
    /// `policy_held_back`. Says why (`could weaken …`, `was deleted`).
    pub policy_edit_held: Option<String>,
    /// Secret files that should have been sealed but no key was available, or
    /// whose recorded sealing could not be verified (the edit stays local).
    pub cloak_failures: Vec<(VPath, String)>,
    /// Tracked files whose recorded visibility label disagrees with the
    /// sealing of the object it points to (a hostile or corrupt label from
    /// a remote or an import), with what was found. Their audience was
    /// decided from the object's real sealing, never from the label (see
    /// [`verify_sealing`]). Also reported in `policy_warnings`.
    pub relabelled: Vec<(VPath, String)>,
    /// Entries carried over because this reader cannot materialise them.
    pub carried: Vec<VPath>,
    /// Files the working copy holds in a folder carried by id because its
    /// person no longer has access to it (BUG-1528): never recorded, never
    /// touched; `vl status` and `vl commit` name them.
    pub not_recorded: Vec<VPath>,
    pub ignored: usize,
    /// The ignored paths (`vl ls --all`), each with whether it is a
    /// directory (ignored as a whole, never descended into).
    pub ignored_paths: Vec<(VPath, bool)>,
    pub files: usize,
    /// Files whose content was read (and hashed) during this build.
    pub hashed: usize,
    /// Files whose entry came from the stat cache without reading them.
    pub cache_hits: usize,
    pub policy_warnings: Vec<String>,
    /// Files or directories that could not be read (e.g. permission
    /// denied), with the reason. A tracked one keeps its previous entry; an
    /// untracked one is left out. Never fatal.
    pub unreadable: Vec<(VPath, String)>,
    /// Entries whose names are not valid UTF-8 (escaped for display, with
    /// their directory). They cannot be recorded.
    pub unrepresentable: Vec<String>,
    /// Tracked paths that are now a symlink (below repository format 5) or
    /// another special file (a socket, FIFO, device). Veil never follows
    /// them; the tracked entry is kept unchanged.
    pub shadowed: Vec<VPath>,
    /// Symlinks recorded (format 5) whose target is new in this snapshot
    /// and deserves a word: it points outside the repository (other tools
    /// follow it, Veil never does), or at a path the policy isolates (its
    /// name becomes visible in history, its content never). With what to
    /// say.
    pub link_warnings: Vec<(VPath, String)>,
    /// Pairs of recorded paths that differ only in case or Unicode
    /// normalisation, at least one of them new in this snapshot. Valid
    /// here, but a checkout on a case-insensitive filesystem (macOS by
    /// default) refuses the snapshot.
    pub name_collisions: Vec<(VPath, VPath)>,
    /// Directories that hold a Veil repository of their own (a `.veil`
    /// directory): nothing in them is recorded, whatever the policy says
    /// (see [`crate::vfs::holds_repository`]). Something tracked there
    /// before is recorded as deleted (the files stay on disk).
    pub nested: Vec<VPath>,
    /// New content `.veilattributes` asks to normalise (CRLF → LF) that was
    /// recorded exactly as it is because the conversion would lose
    /// information (mixed line endings, a lone CR), with why.
    pub line_endings: Vec<(VPath, String)>,
    /// Files that still hold their recorded version but whose line endings
    /// `vl renormalize` would change (the attributes changed since they
    /// were recorded).
    pub renormalizable: Vec<VPath>,
}

/// Directories the Veil daemon's file watcher says may have changed since
/// `parent_tree` was recorded, plus those whose [`BuildReport`] findings
/// must be rechecked.
///
/// A directory in `subtrees` is walked with all its descendants (a
/// subdirectory was created, renamed or removed there). A directory in
/// `dirs` has its own entries inspected, while any tracked subdirectory
/// inside it that is neither in `dirs`/`subtrees` nor an ancestor of one
/// keeps its entry from `parent_tree` without being opened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchPlan {
    dirs: HashSet<VPath>,
    subtrees: Vec<VPath>,
    ancestors: HashSet<VPath>,
}

impl WatchPlan {
    pub fn new(
        dirty_dirs: impl IntoIterator<Item = VPath>,
        dirty_subtrees: impl IntoIterator<Item = VPath>,
        recheck_dirs: impl IntoIterator<Item = VPath>,
    ) -> Self {
        let mut dirs: HashSet<VPath> = dirty_dirs.into_iter().chain(recheck_dirs).collect();
        let mut subtrees: Vec<VPath> = dirty_subtrees.into_iter().collect();
        subtrees.sort();
        subtrees.dedup();
        // Compact `subtrees` so no entry is inside another.
        let mut compact: Vec<VPath> = Vec::with_capacity(subtrees.len());
        for s in subtrees {
            if compact.last().is_none_or(|prev| !s.starts_with(prev)) {
                compact.push(s);
            }
        }
        dirs.retain(|d| !compact.iter().any(|s| d.starts_with(s)));
        let mut ancestors = HashSet::new();
        for p in dirs.iter().chain(compact.iter()) {
            if !p.is_root() {
                ancestors.insert(VPath::root());
                for a in p.ancestors() {
                    ancestors.insert(a);
                }
            }
        }
        WatchPlan {
            dirs,
            subtrees: compact,
            ancestors,
        }
    }

    /// Nothing changed anywhere and nothing needs rechecking.
    pub fn is_clean(&self) -> bool {
        self.dirs.is_empty() && self.subtrees.is_empty()
    }

    /// Must `dir` and all its descendants be walked?
    pub fn in_dirty_subtree(&self, dir: &VPath) -> bool {
        self.subtrees.iter().any(|s| dir.starts_with(s))
    }

    /// Must `dir` itself be opened and listed?
    pub fn must_open(&self, dir: &VPath) -> bool {
        self.dirs.contains(dir) || self.ancestors.contains(dir) || self.in_dirty_subtree(dir)
    }

    /// Must `dir`'s own leaf entries be inspected (rather than carried from
    /// `parent_tree`)?
    pub fn inspect_leaves(&self, dir: &VPath) -> bool {
        self.dirs.contains(dir) || self.in_dirty_subtree(dir)
    }

    /// Direct child directory names of `dir` (when `!self.inspect_leaves(dir)`)
    /// that must be opened.
    pub fn must_open_children(&self, dir: &VPath) -> Vec<String> {
        let mut names: Vec<String> = self
            .dirs
            .iter()
            .chain(self.subtrees.iter())
            .chain(self.ancestors.iter())
            .filter(|p| p.parent().as_ref() == Some(dir))
            .map(|p| p.file_name().to_string())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

impl BuildReport {
    /// Paths that exist locally but are not in the tree.
    pub fn local_only(&self) -> Vec<VPath> {
        let mut v: Vec<VPath> = self.isolated.clone();
        v.extend(self.quarantined.iter().map(|(p, _)| p.clone()));
        v.extend(self.cloak_failures.iter().map(|(p, _)| p.clone()));
        v.sort();
        v.dedup();
        v
    }

    /// Directories that produced any local-only file, held-back edit, or
    /// warning during this build: a later watched build includes them so
    /// that its [`BuildReport`] matches a full scan.
    pub fn recheck_dirs(&self) -> Vec<VPath> {
        let mut dirs: HashSet<VPath> = HashSet::new();
        fn add(dirs: &mut HashSet<VPath>, p: &VPath) {
            dirs.insert(p.parent().unwrap_or_else(VPath::root));
        }
        for p in &self.isolated {
            add(&mut dirs, p);
        }
        for (p, _) in &self.quarantined {
            add(&mut dirs, p);
        }
        for p in &self.quarantine_kept {
            add(&mut dirs, p);
        }
        for p in &self.blocked_exposures {
            add(&mut dirs, p);
        }
        for h in &self.policy_held_back {
            add(&mut dirs, &h.path);
        }
        for (p, _) in &self.cloak_failures {
            add(&mut dirs, p);
        }
        for (p, _) in &self.relabelled {
            add(&mut dirs, p);
        }
        for p in &self.carried {
            add(&mut dirs, p);
        }
        for p in &self.not_recorded {
            add(&mut dirs, p);
            dirs.insert(VPath::root());
            for a in p.ancestors() {
                dirs.insert(a);
            }
        }
        for (p, _) in &self.unreadable {
            add(&mut dirs, p);
            dirs.insert(p.clone());
        }
        for s in &self.unrepresentable {
            let name = s.split(" (").next().unwrap_or(s);
            match name.rfind('/') {
                Some(i) => {
                    if let Ok(d) = VPath::new(&name[..i]) {
                        dirs.insert(d);
                    } else {
                        dirs.insert(VPath::root());
                    }
                }
                None => {
                    dirs.insert(VPath::root());
                }
            }
        }
        for p in &self.shadowed {
            add(&mut dirs, p);
        }
        for (p, _) in &self.link_warnings {
            add(&mut dirs, p);
        }
        for (a, b) in &self.name_collisions {
            add(&mut dirs, a);
            add(&mut dirs, b);
        }
        for p in &self.nested {
            add(&mut dirs, p);
            dirs.insert(p.clone());
        }
        for (p, _) in &self.line_endings {
            add(&mut dirs, p);
        }
        for p in &self.renormalizable {
            add(&mut dirs, p);
        }
        if !self.policy_warnings.is_empty() {
            for w in &self.policy_warnings {
                if let Some((path, _)) = w.split_once(": ") {
                    if let Ok(vp) = VPath::new(path) {
                        add(&mut dirs, &vp);
                    }
                }
            }
        }
        if self.policy_edit_pending || self.policy_edit_held.is_some() {
            dirs.insert(VPath::root());
        }
        let mut out: Vec<VPath> = dirs.into_iter().collect();
        out.sort();
        out
    }
}

struct Builder<'a> {
    store: &'a ObjectStore,
    fs: &'a dyn StorageBackend,
    opts: &'a BuildOptions<'a>,
    use_hints: bool,
    /// `.veilpolicy` differs from the parent's: content that is unchanged
    /// since the parent must still be re-scanned, because the parent may
    /// have been built under rules (e.g. `public!`) that no longer apply.
    policy_changed: bool,
    /// The parent's policy, when `policy_changed`: only a path whose
    /// classification *this* snapshot's policy edit changed may leave the
    /// audience it is sealed for (see `file_entry`).
    parent_policy: Option<Policy>,
    /// Re-scan unchanged public content (scanner rules changed since this
    /// device last scanned). Affects secret scanning only, never visibility.
    rescan: bool,
    cache: Option<CacheRun>,
    report: BuildReport,
    /// How `fs` compares names (read once per build).
    folding: NameFolding,
    /// Symlinks are recorded as entries (repository format 5); below that
    /// they are special files, never recorded.
    links: bool,
    /// The working copy's attributes, read on first need.
    attrs: Option<Attrs<'a>>,
    /// For the file just read: its bytes on disk and its line-ending facts
    /// (see [`Builder::line_endings`]), for the stat cache.
    eol_now: Option<(ObjectId, EolFact)>,
    /// What was learnt of the leaf about to be built as its directory was
    /// listed (used instead of asking again, for that path only).
    listed: Option<Listed>,
    /// When set, the daemon's file watcher vouches that only these
    /// directories changed since `parent_tree`.
    watch: Option<&'a WatchPlan>,
    /// Listings made ahead of the walk, on other threads.
    #[cfg(feature = "os")]
    prefetch: Option<&'a crate::prefetch::Prefetch<'a>>,
}

/// Build a tree from `fs`, returning its id and a report.
pub fn build_tree(store: &ObjectStore, fs: &dyn StorageBackend, opts: &BuildOptions) -> Result<(ObjectId, BuildReport)> {
    build_tree_cached(store, fs, opts, None)
}

/// [`build_tree`] with a stat cache for `fs`. The cache is consulted and
/// updated in place (it is only used if `fs` has a [`StatClock`]).
///
/// [`StatClock`]: crate::vfs::StatClock
pub fn build_tree_cached(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    opts: &BuildOptions,
    cache: Option<&mut StatCache>,
) -> Result<(ObjectId, BuildReport)> {
    build_tree_watched(store, fs, opts, cache, None)
}

/// [`build_tree_cached`] guided by `watch` when the daemon's file watcher
/// vouches for which directories changed since `opts.parent_tree`.
pub fn build_tree_watched(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    opts: &BuildOptions,
    cache: Option<&mut StatCache>,
    watch: Option<&WatchPlan>,
) -> Result<(ObjectId, BuildReport)> {
    #[cfg(feature = "os")]
    secrets::prepare();
    let parent = opts.parent_tree.map(|t| store.tree(&t)).transpose()?;
    // Hints (reuse of unchanged subtrees by id) are only valid if the policy
    // is unchanged, otherwise reclassification could be skipped.
    let policy_path = VPath::new(POLICY_FILE)?;
    let parent_policy = parent.as_ref().and_then(|t| t.get(POLICY_FILE)).map(|e| e.id);
    let use_hints = match (fs.known_id(&policy_path), parent_policy) {
        (Some(h), Some(p)) => h == p,
        (None, None) => !fs.exists(&policy_path)?,
        _ => false,
    };
    let use_hints = use_hints && !opts.rescan;
    // Read as the policy is (a symlink followed, see `read_policy_file`).
    let policy_changed = match (crate::policy::read_policy_file(fs)?, parent_policy) {
        (PolicyFile::File(now) | PolicyFile::Linked(now), Some(p)) => !store.matches_encoding(&p, &now)?,
        (PolicyFile::File(_) | PolicyFile::Linked(_), None) => true,
        // A policy file this working copy never showed (a `vl clone
        // --only`) is not deleted: nothing is reclassified (BUG-832).
        (PolicyFile::Absent, p) => p.is_some() && !opts.materialised.is_some_and(|m| m.hidden(&policy_path)),
        // Unreadable: the accepted policy applies, nothing to reclassify.
        (PolicyFile::Unavailable(_), _) => false,
    };
    // The cache only works on backends whose stamps can be trusted. The
    // clock is read before any file is stat'ed (see `statcache`).
    let mut cache = cache;
    let mut run = match (cache.as_deref_mut(), fs.stat_clock()) {
        (Some(c), Some(clock)) => Some(c.begin_run(CacheKey::compute(fs, &store.keys, clock)?, clock)),
        _ => None,
    };
    // The watcher's plan applies only when we have a parent tree, policy and
    // keys have not changed, no unaccepted policy guards the working copy,
    // no scanner rescan or renormalization is requested, and no sandbox
    // secrets are injected.
    let watch = watch.filter(|_| {
        parent.is_some()
            && !policy_changed
            && opts.policy.accepted().is_none()
            && !opts.policy.own_edit_pending
            && !opts.rescan
            && opts.injected.is_none()
            && matches!(opts.line_endings, LineEndings::Convert)
            && !run.as_ref().is_some_and(|r| r.key_changed)
    });
    if watch.is_some() {
        if let Some(r) = run.as_mut() {
            r.enable_partial();
        }
    }
    // Large working copies on a disk are listed ahead of the walk (see
    // `prefetch`), from now on: after the clock reading the cache run
    // took. With a watcher plan we only list the dirty directories, so
    // background full-tree prefetching stays off.
    #[cfg(feature = "os")]
    let prefetch = match (watch.is_none(), fs.kind(), run.as_ref().map(CacheRun::len)) {
        (true, "disk", Some(files)) if crate::prefetch::workers_for(files) > 0 => {
            Some((crate::prefetch::Prefetch::new(fs, store, opts.policy, opts.parent_tree), crate::prefetch::workers_for(files)))
        }
        _ => None,
    };
    let parent_policy = match parent.as_ref().and_then(|t| t.get(POLICY_FILE)) {
        // A directory (a hostile tree, BUG-121) holds no rules.
        Some(e) if policy_changed && e.kind != EntryKind::File => None,
        Some(e) if policy_changed => match store.read_entry(e) {
            Ok(b) => Some(Policy::parse(&String::from_utf8_lossy(&b))),
            Err(err) if err.is_unreadable() => None,
            Err(err) => return Err(err),
        },
        None if policy_changed => Some(Policy::builtin()),
        _ => None,
    };
    let mut b = Builder {
        store,
        fs,
        opts,
        use_hints,
        policy_changed,
        parent_policy,
        rescan: opts.rescan,
        cache: run,
        report: BuildReport {
            policy_warnings: opts.policy.warnings.clone(),
            policy_edit_pending: opts.policy.own_edit_pending,
            ..Default::default()
        },
        folding: fs.name_folding(),
        links: store.format() >= crate::object::GIT_PARITY_REPO_FORMAT,
        attrs: None,
        eol_now: None,
        listed: None,
        watch,
        #[cfg(feature = "os")]
        prefetch: prefetch.as_ref().map(|(p, _)| p),
    };
    let root_parent = parent.clone().zip(opts.parent_tree);
    #[cfg(feature = "os")]
    let built = match &prefetch {
        Some((p, workers)) => std::thread::scope(|s| {
            for _ in 0..*workers {
                // A worker that cannot start leaves its share to the others
                // (and the walk).
                let _ = std::thread::Builder::new().stack_size(256 << 10).spawn_scoped(s, || p.work());
            }
            // The workers stop when the walk ends, however it ends (a panic
            // too: the scope waits for them before passing it on).
            let _stop = p.stopper();
            b.build_dir(&VPath::root(), root_parent)
        }),
        None => b.build_dir(&VPath::root(), root_parent),
    };
    #[cfg(not(feature = "os"))]
    let built = b.build_dir(&VPath::root(), root_parent);
    let id = match built? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    let id = b.protect_moves(id)?;
    if let (Some(c), Some(run)) = (cache, b.cache.take()) {
        c.end_run(run);
    }
    Ok((id, b.report))
}

impl<'a> Builder<'a> {
    /// Protection follows content across a rename (renames design, builder
    /// hardening): a new public file (or symlink) whose plaintext is
    /// exactly that of a cloaked entry this snapshot deletes is the same
    /// content moved (`mv secrets/db.yml docs/db.yml` where the policy
    /// cloaks only `secrets/`), and is sealed as that entry was, never
    /// recorded public. Only a sealing verified against its object counts
    /// (BUG-103), and only for a path no rule of the policy explicitly
    /// classifies (an explicit `public` rule is the member's decision).
    /// Exact content only; nothing is read unless the snapshot both
    /// deletes a sealed entry and adds a public one.
    fn protect_moves(&mut self, id: ObjectId) -> Result<ObjectId> {
        let Some(parent) = self.opts.base_tree.or(self.opts.parent_tree).filter(|p| *p != id) else { return Ok(id) };
        let changes = crate::tree::diff_trees(self.store, Some(&parent), Some(&id))?;
        let blob_kind = |e: &TreeEntry| matches!(e.kind, EntryKind::File | EntryKind::Symlink);
        let deleted: Vec<&TreeEntry> = changes
            .iter()
            .filter(|c| c.new.is_none())
            .filter_map(|c| c.old.as_ref())
            .filter(|e| blob_kind(e) && matches!(e.visibility, Visibility::Cloaked { .. }))
            .collect();
        let added: Vec<(&VPath, &TreeEntry)> = changes
            .iter()
            .filter(|c| c.old.is_none())
            .filter_map(|c| c.new.as_ref().map(|e| (&c.path, e)))
            .filter(|(_, e)| blob_kind(e) && e.visibility.is_public())
            .collect();
        let mut tree = id;
        if !deleted.is_empty() && !added.is_empty() {
            let mut sealed_as: HashMap<(EntryKind, ObjectId), Visibility> = HashMap::new();
            for d in &deleted {
                if verify_sealing(self.store, d)? != Sealing::Verified {
                    continue;
                }
                match self.store.read_blob(&d.id) {
                    Ok(plain) => {
                        sealed_as.entry((d.kind, Object::blob_id(&plain))).or_insert_with(|| d.visibility.clone());
                    }
                    Err(e) if e.is_unreadable() || e.is_not_found() => {}
                    Err(e) => return Err(e),
                }
            }
            for (path, e) in added {
                let Some(vis) = sealed_as.get(&(e.kind, e.id)) else { continue };
                let class = match e.kind {
                    EntryKind::Symlink => self.opts.policy.classify_link(path),
                    _ => self.opts.policy.classify(path, false),
                };
                if class.tier != Tier::Public || class.rule.is_some() {
                    continue;
                }
                let data = self.store.read_blob(&e.id)?;
                let sealed = match self.store.store_file(&data, vis) {
                    Ok(s) => s,
                    Err(VeilError::Redacted { .. }) => continue,
                    Err(err) => return Err(err),
                };
                let entry = TreeEntry {
                    id: sealed,
                    visibility: vis.clone(),
                    ..e.clone()
                };
                tree = crate::conflict::set_entry(self.store, &tree, path, Some(entry))?;
                if let Some(run) = self.cache.as_mut() {
                    run.forget(path);
                }
                self.report.policy_warnings.push(format!(
                    "{path}: its content was moved from a path sealed as {}; it stays sealed there (protection follows a secret across a rename)",
                    vis.label()
                ));
            }
        }
        if self.opts.base_tree.is_some() && self.opts.base_tree != self.opts.parent_tree {
            for c in &changes {
                let Some(e) = c.new.as_ref().filter(|e| blob_kind(e)) else { continue };
                let Visibility::Cloaked { scope } = &e.visibility else { continue };
                if crate::policy::seals_secret(c.path.as_str()) {
                    continue;
                }
                let in_base = c.old.as_ref().is_some_and(|o| match o.kind {
                    EntryKind::Conflict => self
                        .store
                        .conflict(&o.id)
                        .ok()
                        .is_some_and(|cf| cf.adds.iter().chain(&cf.removes).flatten().any(|t| !t.visibility.is_public())),
                    _ => !o.visibility.is_public(),
                });
                let moved = deleted.iter().any(|d| matches!(&d.visibility, Visibility::Cloaked { scope: s } if s == scope));
                if in_base || moved {
                    continue;
                }
                let data = match self.store.read_blob(&e.id) {
                    Ok(d) => d,
                    Err(err) if err.is_unreadable() || err.is_not_found() => continue,
                    Err(err) => return Err(err),
                };
                let class = match e.kind {
                    EntryKind::Symlink => self.opts.policy.classify_link(&c.path),
                    _ => self.opts.policy.classify(&c.path, false),
                };
                let replacement = match class.tier {
                    Tier::Public => {
                        if !class.allow_secrets {
                            let findings = secrets::scan(&data);
                            if !findings.is_empty() {
                                let kept = self.quarantine(&c.path, findings, c.old.as_ref())?;
                                tree = crate::conflict::set_entry(self.store, &tree, &c.path, kept)?;
                                if let Some(run) = self.cache.as_mut() {
                                    run.forget(&c.path);
                                }
                                continue;
                            }
                        }
                        let pub_id = self.store.store_file(&data, &Visibility::Public)?;
                        Some(TreeEntry {
                            id: pub_id,
                            visibility: Visibility::Public,
                            size: data.len() as u64,
                            ..e.clone()
                        })
                    }
                    Tier::Isolated => {
                        self.report.isolated.push(c.path.clone());
                        None
                    }
                    Tier::Ignored => {
                        self.report.ignored += 1;
                        self.report.ignored_paths.push((c.path.clone(), false));
                        None
                    }
                    Tier::Cloaked(_) => continue,
                };
                tree = crate::conflict::set_entry(self.store, &tree, &c.path, replacement)?;
                if let Some(run) = self.cache.as_mut() {
                    run.forget(&c.path);
                }
            }
        }
        Ok(tree)
    }

    /// Build the tree of directory `dir`. `parent` is the parent snapshot's
    /// tree for `dir` and its id. Iterative: one frame per directory being
    /// built (working copies on memory or overlay backends can nest without
    /// bound); nesting beyond [`MAX_TREE_DEPTH`] is reported as unreadable
    /// and keeps what was tracked.
    fn build_dir(&mut self, dir: &VPath, parent: Option<(Arc<Tree>, ObjectId)>) -> Result<Option<ObjectId>> {
        let mut stack = match self.open_dir(dir.clone(), parent)? {
            Opened::Done(r) => return Ok(r),
            Opened::Frame(f) => vec![f],
        };
        let mut done: Option<Option<ObjectId>> = None;
        loop {
            let depth = stack.len();
            let f = stack.last_mut().expect("never empty here");
            if let Some(name) = f.waiting.take() {
                if let Some(id) = done.take().expect("a finished subdirectory") {
                    f.out.insert(TreeEntry::dir(&name, id));
                }
            }
            let Some(child) = f.entries.get(f.next) else {
                let fin = stack.pop().expect("checked");
                let id = self.finish_dir(fin)?;
                if stack.is_empty() {
                    return Ok(id);
                }
                done = Some(id);
                continue;
            };
            let kind = child.kind;
            // `.veil` is reserved at every depth (trees containing it are
            // refused on decode). A directory holding one is a nested
            // repository, left out as a whole by `open_dir`.
            if !counted(child) {
                if !crate::object::is_reserved_name(&child.name) {
                    // Crash debris of an interrupted atomic write, never content.
                    self.report.ignored += 1;
                }
                f.next += 1;
                continue;
            }
            let path = f.dir.join(&child.name);
            let meta = f.stats.get_mut(f.next).and_then(Option::take);
            let class = f.classes.get_mut(f.next).and_then(Option::take);
            f.next += 1;
            let name = path.file_name();
            self.listed = (meta.is_some() || class.is_some()).then(|| Listed {
                path: path.clone(),
                meta,
                class: class.and_then(|c| match kind {
                    NodeKind::File => Some((EntryKind::File, c)),
                    NodeKind::Symlink => Some((EntryKind::Symlink, c)),
                    NodeKind::Dir => None,
                }),
            });
            let parent_tree = f.parent.as_ref().map(|(t, _)| t.clone());
            let parent_entry = parent_tree.as_deref().and_then(|t| t.get(name));
            // A folder its person lost access to (BUG-1509): the current
            // view does not name it, and what the working copy holds there
            // is theirs: listed, never recorded, never touched.
            if parent_entry.is_none() && self.opts.materialised.is_some_and(|m| m.lost(&path)) {
                let files = match kind {
                    // Links too, never followed (BUG-1559).
                    NodeKind::Dir => crate::vfs::walk_leaves(self.fs, &path, &|_| false)?.into_iter().map(|(p, _)| p).collect(),
                    _ => vec![path.clone()],
                };
                self.report.not_recorded.extend(files);
                continue;
            }
            match kind {
                NodeKind::Dir => {
                    let class = self.opts.policy.classify(&path, true);
                    let pdir = parent_entry.filter(|e| e.kind == EntryKind::Dir);
                    if class.tier == Tier::Ignored {
                        self.report.ignored += 1;
                        self.report.ignored_paths.push((path.clone(), true));
                        // Ignored only by the accepted policy: reported, and
                        // not a deletion.
                        if let Some((t, force)) = &class.held_back {
                            self.report.policy_held_back.push(HeldBack {
                                path: path.clone(),
                                accepted: class.keyword(),
                                wanted: tier_keyword(t, *force),
                                dir: true,
                            });
                            if let Some(pe) = pdir {
                                f.out.insert(pe.clone());
                            }
                        }
                        continue;
                    }
                    if let Some(pe) = pdir {
                        if self.use_hints && self.fs.known_id(&path) == Some(pe.id) {
                            f.out.insert(pe.clone());
                            continue;
                        }
                        if self.watch.is_some_and(|w| !w.must_open(&path)) {
                            f.out.insert(pe.clone());
                            continue;
                        }
                    } else if self.watch.is_some_and(|w| !w.must_open(&path)) {
                        continue;
                    }
                    if depth >= MAX_TREE_DEPTH {
                        self.report
                            .unreadable
                            .push((path, format!("directory nesting exceeds {MAX_TREE_DEPTH} levels")));
                        if let Some(pe) = pdir {
                            f.out.insert(pe.clone());
                        }
                        continue;
                    }
                    let sub = match pdir {
                        Some(e) => match self.store.tree(&e.id) {
                            Ok(t) => Some((t, e.id)),
                            // A folder the server refuses (BUG-1508), with
                            // something in the working copy. Left out by
                            // checkout, what is there is not an edit of a
                            // version this reader never saw: the folder is
                            // carried by id and what is there not recorded.
                            // Otherwise it cannot be recorded against a
                            // version this reader cannot read; the folder is
                            // never left out or emptied either.
                            Err(err) if crate::tree::refused_tree(self.store, &err) => {
                                if self.opts.materialised.is_some_and(|m| m.hidden(&path)) {
                                    // What is there is listed, never silently
                                    // left (BUG-1528), and never touched.
                                    // Links too, never followed (BUG-1559).
                                    let files: Vec<VPath> = crate::vfs::walk_leaves(self.fs, &path, &|_| false)?.into_iter().map(|(p, _)| p).collect();
                                    self.report.not_recorded.extend(files);
                                    self.report.carried.push(path.clone());
                                    f.out.insert(e.clone());
                                    continue;
                                }
                                return Err(crate::tree::no_access(&path, "the working copy holds files in it (move them out of it to record the rest)"));
                            }
                            Err(err) => return Err(err),
                        },
                        None => None,
                    };
                    let name = name.to_string();
                    match self.open_dir(path, sub)? {
                        Opened::Done(Some(id)) => f.out.insert(TreeEntry::dir(&name, id)),
                        Opened::Done(None) => {}
                        Opened::Frame(c) => {
                            f.waiting = Some(name);
                            stack.push(c);
                        }
                    }
                }
                NodeKind::File => {
                    if self.watch.is_some_and(|w| !w.inspect_leaves(&f.dir)) {
                        if let Some(pe) = parent_entry.filter(|e| e.kind != EntryKind::Dir) {
                            self.report.files += 1;
                            f.out.insert(pe.clone());
                        }
                        continue;
                    }
                    if let Some(e) = self.file_entry(&path, name, parent_entry, EntryKind::File)? {
                        self.report.files += 1;
                        f.out.insert(e);
                    }
                }
                // Below format 5, and for `.veilpolicy` always (the policy
                // is read through the link, BUG-058): a special file, never
                // recorded or followed. A tracked entry there is kept.
                NodeKind::Symlink if !self.links || path.as_str() == POLICY_FILE => {
                    if let Some(pe) = parent_entry {
                        let tier = self.opts.policy.classify(&path, pe.kind == EntryKind::Dir).tier;
                        if !matches!(tier, Tier::Ignored | Tier::Isolated) {
                            f.out.insert(pe.clone());
                            self.report.shadowed.push(path);
                        }
                    }
                }
                NodeKind::Symlink => {
                    if self.watch.is_some_and(|w| !w.inspect_leaves(&f.dir)) {
                        if let Some(pe) = parent_entry.filter(|e| e.kind != EntryKind::Dir) {
                            self.report.files += 1;
                            f.out.insert(pe.clone());
                        }
                        continue;
                    }
                    if let Some(e) = self.file_entry(&path, name, parent_entry, EntryKind::Symlink)? {
                        self.report.files += 1;
                        f.out.insert(e);
                    }
                }
            }
        }
    }

    /// List `dir` and start its frame, or finish at once (vanished or
    /// unreadable directory).
    fn open_dir(&mut self, dir: VPath, parent: Option<(Arc<Tree>, ObjectId)>) -> Result<Opened> {
        if self.watch.is_some_and(|w| !w.must_open(&dir)) {
            return Ok(Opened::Done(parent.map(|(_, id)| id)));
        }
        if let Some(w) = self.watch.filter(|w| !w.inspect_leaves(&dir)) {
            let children = w.must_open_children(&dir);
            let mut out = Tree::default();
            let mut kept_special = Vec::new();
            if let Some((p, _)) = &parent {
                for e in &p.entries {
                    if children.binary_search(&e.name).is_err() {
                        if e.kind != EntryKind::Dir {
                            self.report.files += 1;
                        }
                        kept_special.push(e.name.clone());
                        out.insert(e.clone());
                    }
                }
            }
            let entries = children
                .into_iter()
                .map(|name| crate::vfs::DirEntry { name, kind: NodeKind::Dir })
                .collect();
            return Ok(Opened::Frame(BuildFrame {
                dir,
                parent,
                entries,
                stats: Vec::new(),
                classes: Vec::new(),
                next: 0,
                out,
                kept_special,
                waiting: None,
            }));
        }
        let (listing, classes) = match self.list_dir(&dir, parent.as_ref().map(|(t, _)| &**t)) {
            // Names may change: classified again, under the names recorded.
            Ok((l, _)) if self.folding.folds() => (self.canonical_names(&dir, l, parent.as_ref().map(|(t, _)| &**t)), Vec::new()),
            Ok(l) => l,
            // Vanished while we were building (or never materialised): carry
            // any unreadable entries from `parent`, as `finish_dir` does.
            Err(e) if e.is_not_found() && !dir.is_root() => {
                if let Some(run) = self.cache.as_mut() {
                    run.note_deleted_dir(dir.clone());
                }
                let carried = match parent {
                    Some((_, id)) => self
                        .carry_unreadable(&TreeEntry::dir(dir.file_name(), id), &dir)?
                        .map(|e| e.id),
                    None => None,
                };
                return Ok(Opened::Done(carried));
            }
            // Unreadable (e.g. permission denied): keep what was tracked.
            Err(VeilError::Io { source, .. }) if !dir.is_root() => {
                self.report.unreadable.push((dir.clone(), source.to_string()));
                return Ok(Opened::Done(parent.map(|(_, id)| id)));
            }
            Err(e) => return Err(e),
        };
        if let Some(run) = self.cache.as_mut() {
            run.note_visited_dir(&dir);
        }
        // A repository of its own: none of it is ours to record (BUG-200).
        if !dir.is_root() && crate::vfs::holds_repository(&listing) {
            if let Some(run) = self.cache.as_mut() {
                run.note_deleted_dir(dir.clone());
            }
            self.report.nested.push(dir);
            return Ok(Opened::Done(None));
        }
        for name in &listing.unrepresentable {
            self.report.unrepresentable.push(match dir.is_root() {
                true => name.clone(),
                false => format!("{dir}/{name}"),
            });
        }
        let mut out = Tree::default();
        let mut kept_special = Vec::new();
        // A tracked path that is now a symlink (or socket, device…) is never
        // followed, and is not a deletion either: keep the tracked entry.
        for name in &listing.special {
            if let Some(pe) = parent.as_ref().and_then(|(t, _)| t.get(name)) {
                let path = dir.join(name);
                let tier = self.opts.policy.classify(&path, pe.kind == EntryKind::Dir).tier;
                if matches!(tier, Tier::Ignored | Tier::Isolated) {
                    continue; // no longer tracked by policy anyway
                }
                kept_special.push(name.clone());
                self.report.shadowed.push(path);
                out.insert(pe.clone());
            }
        }
        // Stats and classes only stand for the names they were listed under.
        let stats = match listing.stats.len() == listing.entries.len() {
            true => listing.stats,
            false => Vec::new(),
        };
        let classes = match classes.len() == listing.entries.len() {
            true => classes,
            false => Vec::new(),
        };
        Ok(Opened::Frame(BuildFrame {
            dir,
            parent,
            entries: listing.entries,
            stats,
            classes,
            next: 0,
            out,
            kept_special,
            waiting: None,
        }))
    }

    /// `dir`'s listing (`tree`: its tree in the parent snapshot).
    #[allow(unused_variables)]
    fn list_dir(&self, dir: &VPath, tree: Option<&Tree>) -> Result<(DirListing, Vec<Option<Classification>>)> {
        #[cfg(feature = "os")]
        if let Some(p) = self.prefetch {
            return p.list(dir, tree);
        }
        Ok((self.fs.list_dir_full(dir)?, Vec::new()))
    }

    fn finish_dir(&mut self, f: BuildFrame) -> Result<Option<ObjectId>> {
        let BuildFrame { dir, parent, mut out, entries, kept_special, .. } = f;
        // What the walk looked at: every listed entry (sorted by name) but
        // reserved names and crash debris, and the special entries kept.
        let seen = |name: &str| {
            entries.binary_search_by(|e| e.name.as_str().cmp(name)).is_ok_and(|i| counted(&entries[i])) || kept_special.iter().any(|n| n == name)
        };
        // Entries we could never have materialised are not deletions.
        if let Some((p, _)) = &parent {
            for e in &p.entries {
                if !seen(&e.name) {
                    let cpath = dir.join(&e.name);
                    if e.kind == EntryKind::Dir {
                        if let Some(run) = self.cache.as_mut() {
                            run.note_deleted_dir(cpath.clone());
                        }
                    }
                    if let Some(c) = self.carry_unreadable(e, &cpath)? {
                        out.insert(c);
                    }
                }
            }
        }
        if out.is_empty() {
            return Ok(None);
        }
        // Unchanged directory: same entries, same id, already stored. Skips
        // encoding, hashing and the existence check for most directories,
        // and keeps the id of a tree written in an older format.
        if let Some((p, id)) = &parent {
            if **p == out {
                return Ok(Some(*id));
            }
        }
        self.report_collisions(&dir, &out, parent.as_ref().map(|(t, _)| &**t));
        Ok(Some(self.store.put_tree(&out)?))
    }

    /// Rewrite the names of a listing from a name-folding backend to the
    /// spelling to record: the parent's entry when the name is an alias of
    /// it (unless an entry with that exact name is listed too), otherwise
    /// [`NameFolding::record`] (NFC on macOS). A substituted name is only
    /// used if the backend really resolves it, so a wrongly reported
    /// folding can never make a file look deleted.
    fn canonical_names(&self, dir: &VPath, mut listing: DirListing, parent: Option<&Tree>) -> DirListing {
        // Names may change and entries move: stats are taken again.
        listing.stats.clear();
        let folding = self.folding;
        let tracked: HashMap<std::borrow::Cow<'_, str>, &str> = parent
            .map(|t| t.entries.iter().map(|e| (folding.key(&e.name), e.name.as_str())).collect())
            .unwrap_or_default();
        let listed: HashSet<String> = listing
            .entries
            .iter()
            .map(|e| e.name.clone())
            .chain(listing.special.iter().cloned())
            .collect();
        let mut used = HashSet::new();
        // `verify`: special entries (symlinks…) report no metadata, so they
        // are only matched to a tracked alias, never checked.
        let mut canonical = |name: &str, verify: bool| -> String {
            if parent.is_some_and(|t| t.get(name).is_some()) {
                used.insert(name.to_string());
                return name.to_string();
            }
            let want = match tracked.get(&folding.key(name)) {
                Some(&p) if !listed.contains(p) => p.to_string(),
                _ => folding.record(name).into_owned(),
            };
            if want == name
                || listed.contains(&want)
                || used.contains(&want)
                || (verify && !matches!(self.fs.metadata(&dir.join(&want)), Ok(Some(_))))
            {
                used.insert(name.to_string());
                return name.to_string();
            }
            used.insert(want.clone());
            want
        };
        for e in &mut listing.entries {
            e.name = canonical(&e.name, true);
        }
        for n in &mut listing.special {
            *n = canonical(n, false);
        }
        listing.entries.sort_by(|a, b| a.name.cmp(&b.name));
        listing.special.sort();
        listing
    }

    /// Record pairs of entries of `out` that a macOS volume would store as
    /// one, when at least one of them is new relative to `parent`.
    fn report_collisions(&mut self, dir: &VPath, out: &Tree, parent: Option<&Tree>) {
        if out.entries.len() < 2 || out.entries.iter().all(|e| e.name.is_ascii() && !e.name.bytes().any(|b| b.is_ascii_uppercase())) {
            return;
        }
        let mut first: HashMap<std::borrow::Cow<'_, str>, &str> = HashMap::new();
        for e in &out.entries {
            if let Some(other) = first.insert(NameFolding::MACOS.key(&e.name), &e.name) {
                let old = |n: &str| parent.is_some_and(|t| t.get(n).is_some());
                if !(old(other) && old(&e.name)) {
                    self.report.name_collisions.push((dir.join(other), dir.join(&e.name)));
                }
            }
        }
    }

    /// What to keep of a tracked entry that is not in the working copy:
    /// everything this reader could not have materialised. Iterative over
    /// stored trees (a tampered `.veil/` may nest without bound; beyond
    /// [`MAX_TREE_DEPTH`] the subtree is carried whole).
    fn carry_unreadable(&mut self, e: &TreeEntry, path: &VPath) -> Result<Option<TreeEntry>> {
        struct Frame {
            entry: TreeEntry,
            path: VPath,
            tree: Arc<Tree>,
            next: usize,
            kept: Tree,
        }
        let open = |b: &mut Self, e: &TreeEntry, path: &VPath, depth: usize| -> Result<std::result::Result<Frame, Option<TreeEntry>>> {
            match e.kind {
                EntryKind::File => {
                    // Readable and absent is a deletion, unless it was never
                    // materialised (it became readable since checkout).
                    let never_materialised = b.opts.materialised.is_some_and(|m| m.hidden(path));
                    // In a thin clone, not fetched is shown (S8): absent is a deletion.
                    let readable = b.store.entry_shown(e);
                    if readable && !never_materialised {
                        Ok(Err(None))
                    } else {
                        b.report.carried.push(path.clone());
                        Ok(Err(Some(e.clone())))
                    }
                }
                EntryKind::Conflict => {
                    // Deleting a conflicted file resolves it as a deletion,
                    // but only for a reader who sees every side of it (and
                    // was shown it): a version it cannot read is carried.
                    let never_materialised = b.opts.materialised.is_some_and(|m| m.hidden(path));
                    let all_seen = match crate::conflict::inspect_entry(b.store, e, crate::conflict::Audience::Reader) {
                        Ok(m) => !m.unreadable_side,
                        Err(err) if err.is_unreadable() || err.is_not_found() || matches!(err, VeilError::Corrupt(..) | VeilError::Unsupported(_)) => false,
                        Err(err) => return Err(err),
                    };
                    if all_seen && !never_materialised {
                        Ok(Err(None))
                    } else {
                        b.report.carried.push(path.clone());
                        Ok(Err(Some(e.clone())))
                    }
                }
                // Format 5. Below it, symlinks are special files the builder
                // never records, so their absence is never a deletion.
                // Otherwise as a file: readable, materialised and absent is
                // a deletion (a removed link).
                EntryKind::Symlink => {
                    let never_materialised = b.opts.materialised.is_some_and(|m| m.hidden(path));
                    // In a thin clone, not fetched is shown (S8): absent is a deletion.
                    let readable = b.store.entry_shown(e);
                    if b.links && readable && !never_materialised {
                        Ok(Err(None))
                    } else {
                        b.report.carried.push(path.clone());
                        Ok(Err(Some(e.clone())))
                    }
                }
                EntryKind::Dir => match b.store.tree(&e.id) {
                    Ok(tree) if depth < MAX_TREE_DEPTH => Ok(Ok(Frame {
                        entry: e.clone(),
                        path: path.clone(),
                        tree,
                        next: 0,
                        kept: Tree::default(),
                    })),
                    _ => {
                        b.report.carried.push(path.clone());
                        Ok(Err(Some(e.clone())))
                    }
                },
            }
        };
        let mut stack = match open(self, e, path, 0)? {
            Err(r) => return Ok(r),
            Ok(f) => vec![f],
        };
        loop {
            let depth = stack.len();
            let f = stack.last_mut().expect("never empty here");
            let Some(c) = f.tree.entries.get(f.next).cloned() else {
                let fin = stack.pop().expect("checked");
                let r = if fin.kept.is_empty() {
                    None
                } else {
                    Some(TreeEntry::dir(&fin.entry.name, self.store.put_tree(&fin.kept)?))
                };
                match stack.last_mut() {
                    None => return Ok(r),
                    Some(p) => {
                        if let Some(k) = r {
                            p.kept.insert(k);
                        }
                    }
                }
                continue;
            };
            f.next += 1;
            let cpath = f.path.join(&c.name);
            match open(self, &c, &cpath, depth)? {
                Err(Some(k)) => stack.last_mut().expect("checked").kept.insert(k),
                Err(None) => {}
                Ok(child) => stack.push(child),
            }
        }
    }

    /// A working-copy file could not be stat'ed or read. Vanished meanwhile:
    /// a deletion. Unreadable (e.g. permission denied): a tracked file keeps
    /// its previous entry, an untracked one stays out; both are reported.
    /// Errors of the store are never swallowed here.
    fn unreadable(&mut self, path: &VPath, e: VeilError, parent_file: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        match e {
            e if e.is_not_found() => Ok(None),
            VeilError::Io { source, .. } => {
                self.report.unreadable.push((path.clone(), source.to_string()));
                Ok(parent_file.cloned())
            }
            e => Err(e),
        }
    }

    /// The entry for the leaf at `path` of the working copy, a file or (in
    /// format 5) a symlink (`kind`).
    fn file_entry(&mut self, path: &VPath, name: &str, parent_entry: Option<&TreeEntry>, kind: EntryKind) -> Result<Option<TreeEntry>> {
        match parent_entry {
            Some(ce) if ce.kind == EntryKind::Conflict => self.conflict_entry(path, name, ce, kind),
            _ => self.plain_file_entry(path, name, parent_entry, kind),
        }
    }

    /// The working-copy leaf at `path` (a file or a symlink, `kind`) whose
    /// parent entry is conflict `ce` with a symlink side
    /// (format 5). Checkout wrote its shown side as it is, never a file of
    /// markers (a link target must never become file content, symlinks
    /// design, threat 12). That side, unchanged, keeps the conflict;
    /// anything else resolves it, built as an edit of that side (its
    /// sealing kept) when of the same kind. A reader who cannot read every
    /// side cannot resolve it: the edit stays local.
    fn special_conflict_entry(&mut self, path: &VPath, name: &str, ce: &TreeEntry, conflict: &crate::object::Conflict, kind: EntryKind) -> Result<Option<TreeEntry>> {
        let shown = crate::conflict::shown_side(conflict).map(|(_, t)| t.entry(name));
        let class = match kind {
            EntryKind::Symlink => self.opts.policy.classify_link(path),
            _ => self.opts.policy.classify(path, false),
        };
        let local_only = matches!(class.tier, Tier::Ignored | Tier::Isolated);
        if let Some(se) = shown.as_ref().filter(|se| se.kind == kind && !local_only) {
            if self.holds_leaf(path, se)? {
                return Ok(Some(ce.clone()));
            }
        }
        let unreadable_side = match crate::conflict::inspect(self.store, conflict, crate::conflict::Audience::Reader) {
            Ok(v) => v.unreadable_side,
            Err(e) if e.is_unreadable() || e.is_not_found() || matches!(e, VeilError::Corrupt(..) | VeilError::Unsupported(_)) => true,
            Err(e) => return Err(e),
        };
        let never_materialised = self.opts.materialised.is_some_and(|m| m.hidden(path));
        if (unreadable_side || never_materialised) && !local_only {
            return self.cannot_seal(
                path,
                name,
                Some(ce),
                "it is a conflict with a version you cannot read, so you cannot resolve it; the edit stays local, history keeps the conflict".into(),
            );
        }
        let pseudo = shown.filter(|se| se.kind == kind);
        let held = |r: &BuildReport| (r.cloak_failures.len(), r.quarantined.len(), r.unreadable.len());
        let before = held(&self.report);
        let resolved = self.plain_file_entry(path, name, pseudo.as_ref(), kind)?;
        if held(&self.report) != before && !local_only {
            return Ok(Some(ce.clone()));
        }
        Ok(resolved)
    }

    /// Does the leaf at `path` hold exactly `e` (a file's content and
    /// mode, a symlink's target)? Unreadable either way is `false`.
    fn holds_leaf(&mut self, path: &VPath, e: &TreeEntry) -> Result<bool> {
        let data = match e.kind {
            EntryKind::Symlink => self.fs.read_link(path),
            _ => self.fs.read(path),
        };
        let Ok(data) = data else { return Ok(false) };
        if e.kind == EntryKind::File && !self.fs.metadata(path)?.is_some_and(|m| m.executable == e.executable) {
            return Ok(false);
        }
        match self.store.matches_encoding(&e.id, &data) {
            Ok(true) => Ok(true),
            // A file written with converted line endings (`eol=crlf`).
            Ok(false) if e.kind == EntryKind::File && memchr::memchr(b'\r', &data).is_some() => match self.store.read_entry(e) {
                Ok(want) => Ok(self.disk_stands_for(path, &data, &want)),
                Err(err) if err.is_unreadable() || err.is_not_found() => Ok(false),
                Err(err) => Err(err),
            },
            Ok(false) => Ok(false),
            Err(err) if err.is_unreadable() || err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// The working-copy file at `path`, whose parent entry is the conflict
    /// `ce` (repository format 4):
    ///
    /// * exactly what checkout writes for this reader (or a copy it wrote
    ///   with fewer keys, per the materialisation record): the conflict
    ///   stays, as it is;
    /// * markers partly edited but still parseable: still a conflict, its
    ///   sides taken from the copy (text outside the markers belongs to
    ///   every side, as in jj), each sealed as a resolution would be;
    /// * anything else (markers gone or no longer parseable): a resolution,
    ///   built as an edit of a file whose parent is the side that decided
    ///   the materialised file's audience, so every rule for edits applies
    ///   (scanning, sealed content keeping its audience, held-back edits).
    ///
    /// A reader who cannot read every side cannot resolve the conflict:
    /// its edits are held back, as an edit of a file it cannot seal.
    fn conflict_entry(&mut self, path: &VPath, name: &str, ce: &TreeEntry, kind: EntryKind) -> Result<Option<TreeEntry>> {
        if self.use_hints && self.fs.known_id(path) == Some(ce.id) {
            return Ok(Some(ce.clone()));
        }
        let conflict = match self.store.conflict(&ce.id) {
            Ok(c) => c,
            Err(e) if e.is_unreadable() || e.is_not_found() || matches!(e, VeilError::Corrupt(..) | VeilError::Unsupported(_)) => {
                self.report.carried.push(path.clone());
                self.report.policy_warnings.push(format!("{path}: its conflict cannot be read ({e}); kept as recorded"));
                return Ok(Some(ce.clone()));
            }
            Err(e) => return Err(e),
        };
        if conflict.has_special_terms() {
            return self.special_conflict_entry(path, name, ce, &conflict, kind);
        }
        if kind != EntryKind::File {
            // A symlink where a file conflict was materialised: a
            // resolution by a link, which only a reader of every side may
            // make.
            return self.special_conflict_entry(path, name, ce, &conflict, kind);
        }
        let meta = match self.fs.metadata(path) {
            Ok(m) => m,
            Err(e) => return self.unreadable(path, e, Some(ce)),
        };
        let class = self.opts.policy.classify(path, false);
        let local_only = matches!(class.tier, Tier::Ignored | Tier::Isolated);
        // A copy whose stat has not moved since it was found to be exactly
        // this conflict's rendering is still that: no need to render the
        // conflict again to compare (BUG-484). The stat cache is dropped
        // whenever keys change, which could change the rendering.
        let rendered_as = |id: &ObjectId| Some((CONFLICT_COPY.to_string(), *id));
        if let (false, Some(meta)) = (local_only, meta.as_ref()) {
            if let Some(rec) = self.cache.as_ref().and_then(|c| c.trusted(path, meta)).cloned() {
                if rec.sealed == rendered_as(&ce.id) {
                    if let Some(run) = self.cache.as_mut() {
                        run.keep(path, rec);
                    }
                    return Ok(Some(ce.clone()));
                }
            }
        }
        let m = crate::conflict::materialize(self.store, &conflict, crate::conflict::Audience::Reader)?;
        let executable = meta.as_ref().is_some_and(|m| m.executable);
        let raw = match self.fs.read(path) {
            Ok(d) => d,
            Err(e) => return self.unreadable(path, e, Some(ce)),
        };
        self.report.hashed += 1;
        // Line endings (`.veilattributes`): the copy as recorded, markers
        // and all (checkout wrote it converted for `eol=crlf`, and an
        // editor that keeps CRLF keeps it so).
        let data = if raw != m.content && self.disk_stands_for(path, &raw, &m.content) {
            m.content.clone()
        } else {
            match memchr::memchr(b'\r', &raw) {
                None => raw.clone(),
                Some(_) => {
                    let conv = self.attrs().for_path(path).conversion;
                    match to_odb(&raw, conv, || true) {
                        ToOdb::Converted(v) => v,
                        _ => raw.clone(),
                    }
                }
            }
        };
        if !local_only && data == m.content && executable == m.executable {
            if let (Some(run), Some(meta), true) = (self.cache.as_mut(), meta.as_ref(), raw == data) {
                run.learn(path, meta, Object::blob_id(&data), false, rendered_as(&ce.id), None);
            }
            return Ok(Some(ce.clone()));
        }
        // The rendering checkout wrote while a side was unreadable here, not
        // refreshed since (a grant arrived): the conflict as recorded, never
        // an edit of it.
        if let Some(rec) = self.opts.materialised {
            if !local_only && rec.from_fallback(self.store, path)? == Some(Object::blob_id(&data)) {
                return Ok(Some(ce.clone()));
            }
        }
        if m.unreadable_side && !local_only {
            return self.cannot_seal(
                path,
                name,
                Some(ce),
                "it is a conflict with a version you cannot read, so you cannot resolve it; the edit stays local, history keeps the conflict".into(),
            );
        }
        // The side that stands in for the parent of a resolution.
        let pick = m
            .winner
            .or_else(|| conflict.adds.iter().position(|t| t.as_ref().is_some_and(|t| t.visibility.is_public())))
            .or_else(|| conflict.adds.iter().position(Option::is_some));
        let pseudo = pick.and_then(|i| conflict.adds[i].as_ref()).map(|t| TreeEntry {
            visibility: if m.winner.is_some() { m.visibility.clone() } else { t.visibility.clone() },
            executable: m.executable,
            ..t.entry(name)
        });
        let held = |r: &BuildReport| (r.cloak_failures.len(), r.quarantined.len(), r.unreadable.len());
        let before = held(&self.report);
        let resolved = self.plain_file_entry(path, name, pseudo.as_ref(), EntryKind::File)?;
        if held(&self.report) != before {
            // The edit was held back: the conflict stays recorded.
            return Ok(match resolved {
                Some(_) => Some(ce.clone()),
                None if local_only => None,
                None => Some(ce.clone()),
            });
        }
        let Some(r) = resolved else { return Ok(None) };
        if let Some(p) = &pseudo {
            // Kept the stand-in without the copy being its content: never
            // a resolution (the stand-in is not what the user has).
            if r.id == p.id && !self.store.matches_encoding(&p.id, &data)? {
                return Ok(Some(ce.clone()));
            }
        }
        if r.kind == EntryKind::File && crate::conflict::has_markers(&data, &m.style) {
            if let Some((o, b, t)) = crate::conflict::parse_markers(&data, &m.style) {
                // Each side keeps its own executable bit unless the copy's
                // bit was changed.
                let exec_of = |t: &Option<crate::object::ConflictTerm>| match executable == m.executable {
                    true => t.as_ref().map_or(executable, |t| t.executable),
                    false => executable,
                };
                let term = |bytes: &[u8], exec: bool| -> Result<Option<crate::object::ConflictTerm>> {
                    let id = self.store.store_file(bytes, &r.visibility)?;
                    Ok(Some(crate::object::ConflictTerm {
                        kind: crate::object::TermKind::File,
                        id,
                        size: bytes.len() as u64,
                        executable: exec,
                        visibility: r.visibility.clone(),
                    }))
                };
                let merge = crate::conflict::Merge {
                    adds: vec![term(&o, exec_of(&conflict.adds[0]))?, term(&t, exec_of(&conflict.adds[1]))?],
                    removes: vec![term(&b, exec_of(&conflict.removes[0]))?],
                }
                .simplify();
                if merge.trivial().is_none() {
                    if let Some(c) = merge.into_conflict()? {
                        return Ok(Some(TreeEntry::conflict(name, self.store.put_conflict(&c)?)));
                    }
                }
            }
        }
        Ok(Some(r))
    }

    /// The entry for the working-copy leaf at `path`: a file, or (format 5)
    /// a symlink, whose content is its target string (read with
    /// `readlinkat`, never followed). A link is classified by its own path,
    /// scanned and sealed exactly as a file's content would be: its target
    /// can name private paths or carry a token. Only a parent entry of the
    /// same kind is its previous version: a file replaced by a link (or
    /// the reverse) is a new leaf, its old version kept in history.
    fn plain_file_entry(&mut self, path: &VPath, name: &str, parent_entry: Option<&TreeEntry>, kind: EntryKind) -> Result<Option<TreeEntry>> {
        self.eol_now = None;
        let parent_file = parent_entry.filter(|e| e.kind == kind);
        let (listed, listed_class) = match self.listed.take().filter(|l| l.path == *path) {
            Some(l) => (l.meta, l.class),
            None => (None, None),
        };
        let class = match listed_class.filter(|(k, _)| *k == kind) {
            Some((_, c)) => c,
            None => match kind {
                EntryKind::Symlink => self.opts.policy.classify_link(path),
                _ => self.opts.policy.classify(path, false),
            },
        };
        if class.blocked_exposure {
            self.report.blocked_exposures.push(path.clone());
        }
        // Held back by the accepted policy: a tracked file it keeps local
        // keeps its entry (the edit is not recorded, nor is a deletion).
        if let Some((t, force)) = &class.held_back {
            self.report.policy_held_back.push(HeldBack {
                path: path.clone(),
                accepted: class.keyword(),
                wanted: tier_keyword(t, *force),
                dir: false,
            });
            if let (Tier::Isolated | Tier::Ignored, Some(pe)) = (&class.tier, parent_file) {
                return Ok(Some(pe.clone()));
            }
        }
        match &class.tier {
            // A secret this working copy holds sealed keeps its recorded
            // entry, unless this snapshot's own edit of `.veilpolicy`
            // isolates it: a view without the project's policy (one that
            // cannot read it, a `vl clone --only`) applies the built-in
            // rules, which keep `.env` local, and would otherwise record
            // the shared secret as deleted for everyone (BUG-832). Nothing
            // of the local file is recorded: under a rule that keeps it
            // local, it may be the member's own (a `.netrc` where a
            // teammate committed a sealed one), so its edit stays local.
            Tier::Ignored | Tier::Isolated if self.keeps_sealing(path, &class, parent_file) => {
                let pe = parent_file.expect("keeps_sealing checks it");
                if !self.holds_leaf(path, pe)? {
                    self.report.policy_warnings.push(format!(
                        "{path}: kept as recorded ({}): the policy this working copy applies keeps the file local, so \
                         its edit is not recorded",
                        pe.visibility.label()
                    ));
                }
                return Ok(Some(pe.clone()));
            }
            Tier::Ignored => {
                self.report.ignored += 1;
                self.report.ignored_paths.push((path.clone(), false));
                return Ok(None);
            }
            Tier::Isolated => {
                self.report.isolated.push(path.clone());
                return Ok(None);
            }
            Tier::Public | Tier::Cloaked(_) => {}
        }
        // Decided on the parent entry's label as recorded. Before any new
        // content is sealed (below, once the file is read), the label is
        // checked against its object and the decision taken again on what
        // the object really is (BUG-103). The fast paths in between only
        // ever reuse existing objects.
        let mut desired = self.audience(path, &class, parent_file);

        // Fast path: overlay/tree-view says the file is byte-identical.
        if let Some(pe) = parent_file {
            if self.use_hints && !self.renormalizing(path) && self.fs.known_id(path) == Some(pe.id) {
                return Ok(Some(pe.clone()));
            }
        }

        let meta = match listed {
            Some(m) => Some(m),
            None => match self.fs.metadata(path) {
                Ok(m) => m,
                Err(e) => return self.unreadable(path, e, parent_file),
            },
        };
        // Vanished, or replaced by something else since it was listed.
        let want = match kind {
            EntryKind::Symlink => NodeKind::Symlink,
            _ => NodeKind::File,
        };
        if meta.as_ref().is_some_and(|m| m.kind != want) {
            return Ok(parent_file.cloned());
        }
        let executable = kind == EntryKind::File && meta.as_ref().is_some_and(|m| m.executable);
        // With injected secrets every changed file must be read and checked.
        // A link's target is read in one call, cheaper than a cache lookup
        // is worth: never cached.
        let cacheable = self.opts.injected.is_none() && kind == EntryKind::File;
        let meta = meta.filter(|_| kind == EntryKind::File);
        if let (Some(m), true) = (&meta, cacheable) {
            if let Some(e) = self.cached_entry(path, name, m, &desired, class.allow_secrets, parent_file)? {
                return Ok(Some(e));
            }
        }

        let data = match kind {
            EntryKind::Symlink => match self.fs.read_link(path) {
                Ok(d) => d,
                // Replaced by something else since it was listed (or a
                // backend that holds no links): never a failed snapshot.
                Err(VeilError::InvalidPath(why) | VeilError::Unsupported(why)) => {
                    self.report.unreadable.push((path.clone(), why));
                    return Ok(parent_file.cloned());
                }
                Err(e) => return self.unreadable(path, e, parent_file),
            },
            _ => match self.fs.read(path) {
                Ok(d) => d,
                Err(e) => return self.unreadable(path, e, parent_file),
            },
        };
        if kind == EntryKind::Symlink {
            match crate::vfs::check_link_target(&data) {
                // Not representable (not UTF-8, a NUL, too long): reported
                // like a name that is not UTF-8, never recorded; a tracked
                // link keeps its entry.
                Err(e) => {
                    self.report.unrepresentable.push(format!("{path} ({e})"));
                    return Ok(parent_file.cloned());
                }
                Ok(target) => {
                    if parent_file.is_none_or(|pe| !self.store.matches_encoding(&pe.id, &data).unwrap_or(false)) {
                        self.note_link(path, target);
                    }
                }
            }
        }
        self.report.hashed += 1;
        // Line endings (`.veilattributes`): from here on `data` is what is
        // recorded, and exactly what is scanned, hashed and sealed.
        let data = match kind {
            EntryKind::File => self.line_endings(path, parent_file, data)?,
            _ => data,
        };
        let content = Object::blob_id(&data);

        // The parent's visibility label is a claim (it comes from whoever
        // wrote the snapshot: a remote, an import). Only the sealing of its
        // object may decide the audience of new content. A public entry
        // whose id is the blob id of this very content is plaintext by
        // construction, so the common unchanged case costs nothing.
        let corrected;
        let mut parent_file = parent_file;
        if let Some(pe) = parent_file.filter(|pe| !(pe.visibility.is_public() && pe.id == content)) {
            match verify_sealing(self.store, pe)? {
                Sealing::Verified => {}
                Sealing::Relabelled(actual) => {
                    let note = relabel_note(&pe.visibility, &actual);
                    self.report.policy_warnings.push(format!("{path}: {note}"));
                    self.report.relabelled.push((path.clone(), note));
                    corrected = TreeEntry {
                        visibility: actual,
                        ..pe.clone()
                    };
                    parent_file = Some(&corrected);
                    desired = self.audience(path, &class, parent_file);
                }
                Sealing::Unverifiable if !pe.visibility.is_public() => {
                    // The claim would decide the sealing of this edit:
                    // without its object, it cannot be trusted.
                    let trusted = self.audience(path, &class, None);
                    if desired != trusted {
                        let why = format!(
                            "its recorded version is labelled {} and its content is not in this repository to verify that; the edit stays local, history keeps the recorded version",
                            pe.visibility.label()
                        );
                        return self.cannot_seal(path, name, Some(pe), why);
                    }
                }
                Sealing::Unverifiable => {}
            }
        }

        // Content the engine injected (e.g. `.env` in a sandbox) never
        // enters history under another name, whatever the tier. Unchanged
        // tracked content predates the injection and is left alone.
        if let Some(inj) = self.opts.injected {
            let unchanged = match parent_file {
                Some(pe) => pe.executable == executable && self.store.matches_encoding(&pe.id, &data)?,
                None => false,
            };
            if !unchanged {
                if let Some(f) = inj.find(&data) {
                    return self.quarantine(path, vec![f], parent_file);
                }
            }
        }

        let mut scanned_clean = false;
        if desired.is_public() {
            if let Some(pe) = parent_file {
                if !self.policy_changed && !self.rescan && pe.id == content && pe.visibility.is_public() && pe.executable == executable {
                    self.learn(path, meta.as_ref(), content, scanned_clean, None);
                    return Ok(Some(pe.clone())); // unchanged; scanned before
                }
            }
            if !class.allow_secrets {
                let findings = secrets::scan(&data);
                if !findings.is_empty() {
                    return self.quarantine(path, findings, parent_file);
                }
                scanned_clean = true;
            }
        }

        // An unchanged secret keeps its sealing (and key generation), so a
        // key rotation does not show every secret as modified.
        if let Some(pe) = parent_file {
            if !desired.is_public()
                && pe.visibility == desired
                && pe.executable == executable
                && self.store.matches_encoding(&pe.id, &data)?
            {
                // Verified: the next snapshot may take it from the stat
                // cache (BUG-300).
                if let Visibility::Cloaked { scope } = &desired {
                    self.learn(path, meta.as_ref(), content, false, Some((scope.clone(), pe.id)));
                }
                return Ok(Some(TreeEntry {
                    name: name.to_string(),
                    ..pe.clone()
                }));
            }
        }

        // The policy names one scope, the parent's (verified) sealing another,
        // and no edit of `.veilpolicy` in this snapshot re-keyed the path
        // (BUG-125). No honest route leaves that state behind (a re-key edits
        // the policy in the same snapshot); Mallory, who can push, can, with
        // a genuine object of a scope Alice is also in. Neither audience is
        // taken: sealing for the parent's would hand the edit to whoever put
        // that object there, sealing for the policy's would hand the old
        // content to the policy's scope. Unchanged content was kept above.
        if let (Tier::Cloaked(named), Visibility::Cloaked { scope }) = (&class.tier, &desired) {
            if named != scope {
                let why = match &class.held_back {
                    Some(_) => format!(
                        "its recorded version is sealed for '{scope}', and so would be the edit, but your accepted policy seals it for '{named}'; the edit stays local, history keeps the recorded version (if '{scope}' is meant, `vl policy accept`)"
                    ),
                    None => format!(
                        "the policy seals it for '{named}' but its recorded version is sealed for '{scope}' (a remote may have replaced it); the edit stays local, history keeps the recorded version (`vl cloak --scope {named} {path}` seals it for '{named}')"
                    ),
                };
                return self.cannot_seal(path, name, parent_file, why);
            }
        }

        // Backstop: new content is never sealed under a key that is not an
        // audience: a cloak label must name a scope (never `local` or a
        // generation).
        let unsealable = match &desired {
            Visibility::Public => None,
            Visibility::Cloaked { scope } => crate::keychain::validate_scope_name(scope)
                .is_err()
                .then(|| format!("'{scope}' is not a scope")),
        };
        if let Some(why) = unsealable {
            return self.cannot_seal(path, name, parent_file, format!("{why}; the edit stays local"));
        }
        // Unchanged plain content, rescanned (a policy change, a directory
        // with no stat cache, as one a `ws switch` leaves): the parent's
        // object at this path, wherever it is held. A thin clone's fetched
        // file is not local work, and is not copied into the main store
        // (BUG-1293); new content always is.
        if let Some(pe) = parent_file {
            if desired.is_public() && pe.visibility.is_public() && pe.executable == executable && pe.id == content && self.store.has(&content) {
                self.learn(path, meta.as_ref(), content, scanned_clean, None);
                return Ok(Some(TreeEntry { name: name.to_string(), ..pe.clone() }));
            }
        }
        let id = match self.store.store_file(&data, &desired) {
            Ok(id) => id,
            Err(VeilError::Redacted { scope }) => {
                // A tracked file keeps its recorded entry: this reader cannot
                // seal the edit, and recording a deletion instead would drop
                // content it may not even be able to read.
                let why = match parent_file {
                    Some(_) => format!("no key for scope '{scope}'; the edit stays local, history keeps the recorded version"),
                    None => format!("no key for scope '{scope}'"),
                };
                return self.cannot_seal(path, name, parent_file, why);
            }
            Err(e) => return Err(e),
        };
        let sealed = match &desired {
            Visibility::Cloaked { scope } => Some((scope.clone(), id)),
            _ => None,
        };
        self.learn(path, meta.as_ref(), content, scanned_clean, sealed);
        Ok(Some(TreeEntry {
            name: name.to_string(),
            kind,
            id,
            size: data.len() as u64,
            executable,
            visibility: desired,
        }))
    }

    /// Warn about a symlink target recorded for the first time (see
    /// [`BuildReport::link_warnings`]).
    fn note_link(&mut self, path: &VPath, target: &str) {
        if crate::vfs::link_escapes(path, target) {
            self.report.link_warnings.push((
                path.clone(),
                format!("points outside the repository ({target}); Veil never follows it, but other tools will"),
            ));
            return;
        }
        let Some(parts) = crate::vfs::link_resolves_to(path, target) else { return };
        let Ok(to) = VPath::new(&parts.join("/")) else { return };
        if to.is_root() {
            return;
        }
        if self.opts.policy.classify(&to, false).tier == Tier::Isolated {
            self.report.link_warnings.push((
                path.clone(),
                format!("points to {to}, which the policy isolates: its name is recorded in history, its content never is"),
            ));
        }
    }

    /// The edit of `path` cannot be sealed (no key, or no trustworthy
    /// audience): it stays local, reported in `cloak_failures`. A tracked
    /// file keeps its recorded entry, never a deletion.
    fn cannot_seal(&mut self, path: &VPath, name: &str, parent_file: Option<&TreeEntry>, why: String) -> Result<Option<TreeEntry>> {
        self.report.cloak_failures.push((path.clone(), why));
        Ok(parent_file.map(|pe| TreeEntry {
            name: name.to_string(),
            ..pe.clone()
        }))
    }

    /// Does sealed content at `path` (its parent entry `parent_file`) keep
    /// its entry against `class`? Yes unless an edit of `.veilpolicy` in
    /// this very snapshot reclassifies the path (as in
    /// [`Builder::audience`]).
    fn keeps_sealing(&self, path: &VPath, class: &Classification, parent_file: Option<&TreeEntry>) -> bool {
        !crate::secret_share::personal_key(path.as_str())
            && parent_file.is_some_and(|pe| matches!(pe.visibility, Visibility::Cloaked { .. }))
            && !self.parent_policy.as_ref().is_some_and(|old| old.classify(path, false) != *class)
    }

    /// The audience of new content at `path` (classified `class`, not
    /// ignored or isolated), given its parent entry: the visibility to seal
    /// it under. Inputs: the policy (with the accepted pin) and the parent
    /// entry, whose label the caller must have verified before content is
    /// sealed under the result.
    fn audience(&self, path: &VPath, class: &Classification, parent_file: Option<&TreeEntry>) -> Visibility {
        let mut desired = match &class.tier {
            Tier::Cloaked(s) => Visibility::Cloaked { scope: s.clone() },
            _ => Visibility::Public,
        };
        // A sealed secret keeps its audience. Neither a change of workspace,
        // nor a rebase, nor a policy that arrived by merge may re-key it or
        // make it public: only an edit of `.veilpolicy` in this very
        // snapshot that reclassifies the path is a deliberate decision to.
        if let Some(pe) = parent_file.filter(|pe| matches!(pe.visibility, Visibility::Cloaked { .. })) {
            if desired != pe.visibility {
                let reclassified = self
                    .parent_policy
                    .as_ref()
                    .is_some_and(|old| old.classify(path, false) != *class);
                if !reclassified || class.held_back.is_some() {
                    desired = pe.visibility.clone();
                }
            }
        }
        desired
    }

    /// Hold the edit back, but do not record a deletion: keep the previously
    /// tracked version if it is itself safe.
    fn quarantine(&mut self, path: &VPath, findings: Vec<Finding>, parent_file: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        self.report.quarantined.push((path.clone(), findings));
        if let Some(pe) = parent_file {
            if self.previous_is_safe(pe)? {
                self.report.quarantine_kept.push(path.clone());
                return Ok(Some(pe.clone()));
            }
        }
        Ok(None)
    }

    /// Record content facts for a file that was just read.
    fn learn(
        &mut self,
        path: &VPath,
        meta: Option<&Metadata>,
        content: ObjectId,
        scanned_clean: bool,
        sealed: Option<(String, ObjectId)>,
    ) {
        // The record describes the bytes on disk: with a line-ending fact
        // when they hold a CR (and the blob recorded for them, when it is
        // another).
        let (content, eol) = match self.eol_now.take() {
            Some((disk, fact)) => (disk, Some(fact)),
            None => (content, None),
        };
        if let (Some(run), Some(m)) = (self.cache.as_mut(), meta) {
            run.learn(path, m, content, scanned_clean, sealed, eol);
        }
    }

    /// The working copy's attributes (read on first use).
    fn attrs(&mut self) -> &Attrs<'a> {
        let (store, fs) = (self.store, self.fs);
        self.attrs.get_or_insert_with(|| Attrs::for_backend(store, fs))
    }

    /// Is `path` re-recorded by `vl renormalize` in this build?
    fn renormalizing(&self, path: &VPath) -> bool {
        matches!(self.opts.line_endings, LineEndings::Renormalize(f) if f(path))
    }

    /// The bytes recorded for working-copy file `path` whose content on
    /// disk is `raw`, given its parent entry (see the module
    /// documentation): `raw` itself unless it holds a CR; the parent's
    /// version when `raw` still stands for it (unchanged, or the CRLF
    /// rendering checkout wrote for it), so no attribute change re-records
    /// a file; else `raw` normalised (CRLF → LF) when the attributes ask
    /// for it and that is lossless. Sets `eol_now` for the stat cache.
    fn line_endings(&mut self, path: &VPath, parent_file: Option<&TreeEntry>, raw: Vec<u8>) -> Result<Vec<u8>> {
        self.eol_now = None;
        if memchr::memchr(b'\r', &raw).is_none() {
            return Ok(raw);
        }
        let renorm = self.renormalizing(path);
        let conv = self.attrs().for_path(path).conversion;
        let code = self.attrs().fingerprint(path);
        let disk = Object::blob_id(&raw);
        // What `vl renormalize` would record for `raw`.
        let renormalised = |raw: &[u8]| match to_odb(raw, conv, || false) {
            ToOdb::Converted(v) => v,
            _ => raw.to_vec(),
        };
        if !renorm {
            if let Some(pe) = parent_file {
                let unchanged = matches_quietly(self.store, &pe.id, &raw);
                if unchanged {
                    let renormalize = renormalised(&raw) != raw;
                    if renormalize {
                        self.report.renormalizable.push(path.clone());
                    }
                    self.eol_now = Some((
                        disk,
                        EolFact {
                            attributes: code,
                            renormalize,
                            recorded: None,
                        },
                    ));
                    return Ok(raw);
                }
                if self.opts.materialised.is_some_and(|m| m.wrote_crlf(path)) {
                    for v in self.shown_versions(pe) {
                        if lf_to_crlf(&v) == raw {
                            let renormalize = renormalised(&raw) != v;
                            if renormalize {
                                self.report.renormalizable.push(path.clone());
                            }
                            self.eol_now = Some((
                                disk,
                                EolFact {
                                    attributes: code,
                                    renormalize,
                                    recorded: Some(Object::blob_id(&v)),
                                },
                            ));
                            return Ok(v);
                        }
                    }
                }
            }
        }
        // Git's "safer autocrlf": under `text=auto` a file recorded with a
        // CR is never normalised by an edit (only by `vl renormalize`).
        let store = self.store;
        let recorded_has_cr = || {
            !renorm
                && parent_file
                    .and_then(|pe| store.read_entry(pe).ok())
                    .is_some_and(|b| memchr::memchr(b'\r', &b).is_some())
        };
        let (data, recorded) = match to_odb(&raw, conv, recorded_has_cr) {
            ToOdb::Unchanged => (raw, None),
            ToOdb::Converted(v) => {
                let id = Object::blob_id(&v);
                (v, Some(id))
            }
            ToOdb::Lossy(why) => {
                self.report.line_endings.push((
                    path.clone(),
                    format!("{why}; recorded unchanged (`.veilattributes` asks for LF line endings, and converting would change more than the line endings)"),
                ));
                (raw, None)
            }
        };
        self.eol_now = Some((
            disk,
            EolFact {
                attributes: code,
                renormalize: false,
                recorded,
            },
        ));
        Ok(data)
    }

    /// The versions of `e` a reader may have been shown in the working
    /// copy: its content if readable.
    fn shown_versions(&self, e: &TreeEntry) -> Vec<Vec<u8>> {
        self.store.read_blob(&e.id).into_iter().collect()
    }

    /// Does working-copy content `raw` at `path` stand for recorded content
    /// `want`: the same bytes, the CRLF rendering checkout wrote for it, or
    /// bytes the attributes normalise to it?
    fn disk_stands_for(&mut self, path: &VPath, raw: &[u8], want: &[u8]) -> bool {
        if raw == want {
            return true;
        }
        if memchr::memchr(b'\r', raw).is_none() {
            return false;
        }
        if self.opts.materialised.is_some_and(|m| m.wrote_crlf(path)) && lf_to_crlf(want) == raw {
            return true;
        }
        let conv = self.attrs().for_path(path).conversion;
        matches!(to_odb(raw, conv, || memchr::memchr(b'\r', want).is_some()), ToOdb::Converted(v) if v == want)
    }

    /// The entry for an unchanged file, built from cached content facts
    /// instead of reading it. `None` means "read the file".
    #[allow(clippy::too_many_arguments)]
    fn cached_entry(
        &mut self,
        path: &VPath,
        name: &str,
        meta: &Metadata,
        desired: &Visibility,
        allow_secrets: bool,
        parent_file: Option<&TreeEntry>,
    ) -> Result<Option<TreeEntry>> {
        let Some((key, rec)) = self.cache.as_mut().and_then(|c| c.take_trusted(path, meta)) else {
            return Ok(None);
        };
        let entry = self.entry_from_record(path, name, meta, desired, allow_secrets, parent_file, &rec);
        // A record that made the entry is carried into the next run.
        if let Some(run) = self.cache.as_mut() {
            match entry {
                Ok(Some(_)) => run.keep_taken(key, rec),
                _ => run.give_back(key, rec),
            }
        }
        entry
    }

    /// [`Builder::cached_entry`] from `rec`, the trusted record of `path`.
    #[allow(clippy::too_many_arguments)]
    fn entry_from_record(
        &mut self,
        path: &VPath,
        name: &str,
        meta: &Metadata,
        desired: &Visibility,
        allow_secrets: bool,
        parent_file: Option<&TreeEntry>,
        rec: &crate::statcache::Record,
    ) -> Result<Option<TreeEntry>> {
        // Content holding a CR: its facts only hold for the parent entry
        // they were learned against and the attributes then in force (the
        // file is read again otherwise, once).
        if let Some(f) = &rec.eol {
            if self.renormalizing(path) || f.attributes != self.attrs().fingerprint(path) {
                return Ok(None);
            }
        }
        let same_as_parent =
            |id: &ObjectId| parent_file.filter(|pe| pe.id == *id && pe.visibility == *desired && pe.executable == meta.executable);
        let entry = match desired {
            Visibility::Public => {
                let id = rec.eol.as_ref().and_then(|f| f.recorded).unwrap_or(rec.content);
                match same_as_parent(&id) {
                    // Same rule as the uncached path: unchanged public content
                    // was scanned when it entered the parent.
                    Some(pe) if !self.policy_changed && !self.rescan => Some(pe.clone()),
                    _ if (allow_secrets || rec.scanned_clean) && self.store.has(&id) => Some(self.fresh_entry(name, id, meta, desired)),
                    _ => None,
                }
            }
            Visibility::Cloaked { scope } => match &rec.sealed {
                Some((s, id)) if s == scope && self.store.keys.has(scope) => match same_as_parent(id) {
                    Some(pe) => Some(pe.clone()),
                    None if self.store.has(id) => Some(self.fresh_entry(name, *id, meta, desired)),
                    None => None,
                },
                _ => None,
            },
        };
        let entry = match (&rec.eol, entry) {
            (Some(_), Some(e)) if !parent_file.is_some_and(|pe| *pe == e) => None,
            (_, e) => e,
        };
        if entry.is_some() {
            if rec.eol.as_ref().is_some_and(|f| f.renormalize) {
                self.report.renormalizable.push(path.clone());
            }
            self.report.cache_hits += 1;
        }
        Ok(entry)
    }

    fn fresh_entry(&self, name: &str, id: ObjectId, meta: &Metadata, visibility: &Visibility) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            id,
            size: meta.len,
            executable: meta.executable,
            visibility: visibility.clone(),
        }
    }

    /// May a quarantined file keep its previous entry? Encrypted entries
    /// are safe by construction. A public one is re-scanned: it may have
    /// been recorded under a rule (e.g. `public!`) that no longer applies,
    /// and must not be carried into a new snapshot if it holds a secret.
    fn previous_is_safe(&self, pe: &TreeEntry) -> Result<bool> {
        if !pe.visibility.is_public() {
            return Ok(true);
        }
        match self.store.read_entry(pe) {
            Ok(old) => Ok(secrets::scan(&old).is_empty()),
            Err(e) if e.is_unreadable() => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Is `raw` the content of object `id` (an unreadable or missing object is
/// not)?
fn matches_quietly(store: &ObjectStore, id: &ObjectId, raw: &[u8]) -> bool {
    store.matches_encoding(id, raw).unwrap_or(false)
}
