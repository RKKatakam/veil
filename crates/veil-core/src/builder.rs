//! Snapshotting: turn any `StorageBackend` into a tree, applying policy.
//!
//! This is where the engine enforces visibility:
//!
//! * `ignored` paths are skipped;
//! * `isolated` paths (and every built-in secret like `.env`) are reported
//!   back to the caller and **never** written to the CAS;
//! * `cloaked` paths, and every file of a cloaked line of work, are sealed
//!   under their scope key;
//! * public files are secret-scanned and quarantined on a hit. A quarantined
//!   file that was already tracked keeps its previous (safe) entry, so the
//!   local edit is held back instead of being recorded as a deletion;
//! * embargoed entries stay embargoed until released, and a key holder's edit
//!   of one is secret-scanned (the release will publish it);
//! * entries this reader cannot see (no key, or stripped by a public remote)
//!   are carried over untouched instead of being treated as deletions.
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
//! With [`InjectedSecrets`] (the isolated files a `ws exec` sandbox was given)
//! any new content that contains one of those values is quarantined, so a
//! command cannot launder an injected secret into history under another name.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    checkout::Materialised,
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{tier_keyword, Classification, HeldBack, Policy, PolicyFile, Tier, POLICY_FILE},
    secrets::{self, Finding},
    statcache::{CacheKey, CacheRun, StatCache},
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
    next: usize,
    out: Tree,
    seen: HashSet<String>,
    /// Name of the subdirectory being built on top of this frame.
    waiting: Option<String>,
}

enum Opened {
    Frame(BuildFrame),
    Done(Option<ObjectId>),
}

pub struct BuildOptions<'a> {
    pub policy: &'a Policy,
    /// Tree of the snapshot being amended (enables reuse and carry-over).
    pub parent_tree: Option<ObjectId>,
    /// Cloak every public file under this scope (cloaked line of work).
    pub cloak: Option<&'a str>,
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
    /// because this reader could not read them, and which were written from
    /// an embargo fallback. A path that was never materialised is never
    /// recorded as deleted, even once it has become readable. `None` when
    /// `fs` is not a checked-out working copy (overlays, sandboxes) or the
    /// caller keeps no record.
    pub materialised: Option<&'a Materialised>,
}

/// Rule name of a [`Finding`] for content copied from an injected secret.
pub const INJECTED_RULE: &str = "injected-isolated-secret";

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
    /// public label, under scope `s` for `cloaked:s`, under `embargo/<id>`
    /// for `embargo:<id>`).
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
/// label: plaintext blob → public, sealed under `embargo/<id>` → embargoed,
/// sealed under `scope` or `scope#<key-id>` → cloaked under `scope`.
/// `None` for anything else.
pub fn object_visibility(raw: &[u8]) -> Option<Visibility> {
    if Object::is_blob_raw(raw) {
        return Some(Visibility::Public);
    }
    let label = Object::sealed_scope(raw)?;
    if let Some(id) = label.strip_prefix("embargo/") {
        return (!id.is_empty()).then(|| Visibility::Embargoed { embargo: id.to_string() });
    }
    let scope = crate::keychain::split_label(&label).0;
    crate::keychain::validate_scope_name(scope)
        .is_ok()
        .then(|| Visibility::Cloaked { scope: scope.to_string() })
}

/// Check a file entry's visibility label against the object it points to.
///
/// Visibility labels in trees, like every other field of history, are
/// written by whoever produced the snapshot: a teammate, a remote anyone
/// with write access can push to, a Git import. They are a *claim*. The
/// envelope label of a sealed object is bound to its ciphertext (it is the
/// AEAD's associated data), so it is what the content really is sealed
/// for. A tree entry whose label disagrees with its object is hostile (or
/// corrupt) and must never decide how new content is sealed.
pub fn verify_sealing(store: &ObjectStore, e: &TreeEntry) -> Result<Sealing> {
    if e.kind != EntryKind::File {
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

/// The cloak of a line of work, as recorded in a snapshot's `cloak` field,
/// if it may decide how new content is sealed: a valid scope name. Never
/// `local`, an embargo label (a released embargo's key is public) or a key
/// generation (`team#<old key>`, which a revoked member still holds). The
/// field comes from whoever wrote the snapshot, so anything else is a
/// forged claim and is ignored. Sealing under a valid scope still needs
/// the key: for a scope the member is not in, edits are held back.
pub fn trusted_cloak(cloak: Option<&str>) -> Option<&str> {
    cloak.filter(|c| crate::keychain::validate_scope_name(c).is_ok())
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
    /// Files that should have been cloaked but no key was available, or
    /// whose recorded sealing could not be verified (the edit stays local).
    pub cloak_failures: Vec<(VPath, String)>,
    /// Tracked files whose recorded visibility label disagrees with the
    /// sealing of the object it points to (a hostile or corrupt label from
    /// a remote or an import), with what was found. Their audience was
    /// decided from the object's real sealing, never from the label (see
    /// [`verify_sealing`]). Also reported in `policy_warnings`.
    pub relabelled: Vec<(VPath, String)>,
    /// Edits held back on a line under an unreleased embargo this reader
    /// holds no key for (recording them would revert the hidden fix), with
    /// the embargo's id. They are recorded once the embargo is released.
    pub held_back: Vec<(VPath, String)>,
    /// Entries carried over because this reader cannot materialise them.
    pub carried: Vec<VPath>,
    pub ignored: usize,
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
    /// Tracked paths that are now a symlink or another special file. Veil
    /// never follows them; the tracked entry is kept unchanged.
    pub shadowed: Vec<VPath>,
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
}

impl BuildReport {
    /// Paths that exist locally but are not in the tree.
    pub fn local_only(&self) -> Vec<VPath> {
        let mut v: Vec<VPath> = self.isolated.clone();
        v.extend(self.quarantined.iter().map(|(p, _)| p.clone()));
        v.extend(self.cloak_failures.iter().map(|(p, _)| p.clone()));
        v.extend(self.held_back.iter().map(|(p, _)| p.clone()));
        v.sort();
        v.dedup();
        v
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
    /// The line's cloak, if it may decide sealing ([`trusted_cloak`]).
    cloak: Option<&'a str>,
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
        (PolicyFile::Absent, p) => p.is_some(),
        // Unreadable: the accepted policy applies, nothing to reclassify.
        (PolicyFile::Unavailable(_), _) => false,
    };
    // The cache only works on backends whose stamps can be trusted. The
    // clock is read before any file is stat'ed (see `statcache`).
    let mut cache = cache;
    let run = match (cache.as_deref_mut(), fs.stat_clock()) {
        (Some(c), Some(clock)) => Some(c.begin_run(CacheKey::compute(fs, &store.keys, clock)?, clock)),
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
        cloak: trusted_cloak(opts.cloak),
    };
    if let (Some(c), None) = (opts.cloak, b.cloak) {
        b.report.policy_warnings.push(format!(
            "this change claims to be on a line cloaked under '{c}', which is not a scope; the claim is ignored (a remote or an import may have forged it)"
        ));
    }
    let root_parent = parent.clone().zip(opts.parent_tree);
    let id = match b.build_dir(&VPath::root(), root_parent)? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    let id = b.keep_embargo(id)?;
    if let (Some(c), Some(run)) = (cache, b.cache.take()) {
        c.end_run(run);
    }
    Ok((id, b.report))
}

impl Builder<'_> {
    /// A line under an unreleased embargo stays under it. A key holder's new
    /// tree is re-wrapped under the same embargo (readers without the key
    /// keep seeing the pre-merge tree). A reader without the key only sees
    /// that pre-merge tree, so recording edits on top of it would silently
    /// revert the hidden change for everyone else: such edits are held back
    /// (reported in [`BuildReport::held_back`]) until the embargo is released.
    fn keep_embargo(&mut self, id: ObjectId) -> Result<ObjectId> {
        let Some(parent) = self.opts.parent_tree.filter(|p| *p != id) else {
            return Ok(id);
        };
        let Some(w) = crate::embargo::unreleased_wrapper(self.store, &parent)? else {
            return Ok(id);
        };
        if self.store.keys.has(&w.key_label()) {
            return crate::embargo::wrap(self.store, &w.embargo, &id, &w.fallback);
        }
        for c in crate::tree::diff_trees(self.store, Some(&parent), Some(&id))? {
            self.report.held_back.push((c.path, w.embargo.clone()));
        }
        Ok(parent)
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
            let Some(child) = f.entries.get(f.next).cloned() else {
                let fin = stack.pop().expect("checked");
                let id = self.finish_dir(fin)?;
                if stack.is_empty() {
                    return Ok(id);
                }
                done = Some(id);
                continue;
            };
            f.next += 1;
            // `.veil` is reserved at every depth (trees containing it are
            // refused on decode). A directory holding one is a nested
            // repository, left out as a whole by `open_dir`.
            if crate::object::is_reserved_name(&child.name) {
                continue;
            }
            // Crash debris of an interrupted atomic write, never content.
            if child.kind == NodeKind::File && is_temp_name(&child.name) {
                self.report.ignored += 1;
                continue;
            }
            f.seen.insert(child.name.clone());
            let path = f.dir.join(&child.name);
            let parent_entry = f.parent.as_ref().and_then(|(t, _)| t.get(&child.name)).cloned();
            match child.kind {
                NodeKind::Dir => {
                    let class = self.opts.policy.classify(&path, true);
                    let pdir = parent_entry.filter(|e| e.kind == EntryKind::Dir);
                    if class.tier == Tier::Ignored {
                        self.report.ignored += 1;
                        // Ignored only by the accepted policy: reported, and
                        // not a deletion.
                        if let Some((t, force)) = &class.held_back {
                            self.report.policy_held_back.push(HeldBack {
                                path: path.clone(),
                                accepted: class.keyword(),
                                wanted: tier_keyword(t, *force),
                                dir: true,
                            });
                            if let Some(pe) = &pdir {
                                f.out.insert(pe.clone());
                            }
                        }
                        continue;
                    }
                    if let Some(pe) = &pdir {
                        if self.use_hints && self.fs.known_id(&path) == Some(pe.id) {
                            f.out.insert(pe.clone());
                            continue;
                        }
                    }
                    if depth >= MAX_TREE_DEPTH {
                        self.report
                            .unreadable
                            .push((path, format!("directory nesting exceeds {MAX_TREE_DEPTH} levels")));
                        if let Some(pe) = pdir {
                            f.out.insert(pe);
                        }
                        continue;
                    }
                    let sub = match pdir {
                        Some(e) => Some((self.store.tree(&e.id)?, e.id)),
                        None => None,
                    };
                    match self.open_dir(path, sub)? {
                        Opened::Done(Some(id)) => f.out.insert(TreeEntry::dir(&child.name, id)),
                        Opened::Done(None) => {}
                        Opened::Frame(c) => {
                            f.waiting = Some(child.name.clone());
                            stack.push(c);
                        }
                    }
                }
                NodeKind::File => {
                    if let Some(e) = self.file_entry(&path, &child.name, parent_entry.as_ref())? {
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
        let listing = match self.fs.list_dir_full(&dir) {
            Ok(l) if self.folding.folds() => self.canonical_names(&dir, l, parent.as_ref().map(|(t, _)| &**t)),
            Ok(l) => l,
            // Vanished while we were building: a deletion like any other.
            Err(e) if e.is_not_found() && !dir.is_root() => return Ok(Opened::Done(None)),
            // Unreadable (e.g. permission denied): keep what was tracked.
            Err(VeilError::Io { source, .. }) if !dir.is_root() => {
                self.report.unreadable.push((dir.clone(), source.to_string()));
                return Ok(Opened::Done(parent.map(|(_, id)| id)));
            }
            Err(e) => return Err(e),
        };
        // A repository of its own: none of it is ours to record (BUG-200).
        if !dir.is_root() && crate::vfs::holds_repository(&listing) {
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
        let mut seen = HashSet::new();
        // A tracked path that is now a symlink (or socket, device…) is never
        // followed, and is not a deletion either: keep the tracked entry.
        for name in &listing.special {
            if let Some(pe) = parent.as_ref().and_then(|(t, _)| t.get(name)) {
                let path = dir.join(name);
                let tier = self.opts.policy.classify(&path, pe.kind == EntryKind::Dir).tier;
                if matches!(tier, Tier::Ignored | Tier::Isolated) {
                    continue; // no longer tracked by policy anyway
                }
                seen.insert(name.clone());
                self.report.shadowed.push(path);
                out.insert(pe.clone());
            }
        }
        Ok(Opened::Frame(BuildFrame {
            dir,
            parent,
            entries: listing.entries,
            next: 0,
            out,
            seen,
            waiting: None,
        }))
    }

    fn finish_dir(&mut self, f: BuildFrame) -> Result<Option<ObjectId>> {
        let BuildFrame { dir, parent, mut out, seen, .. } = f;
        // Entries we could never have materialised are not deletions.
        if let Some((p, _)) = &parent {
            for e in &p.entries {
                if !seen.contains(&e.name) {
                    if let Some(c) = self.carry_unreadable(e, &dir.join(&e.name))? {
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
                    // A cloaked file this reader only sees as its last public
                    // version (fallback): deleting that copy must not delete
                    // the sealed content it cannot read.
                    let readable = match &e.visibility {
                        Visibility::Cloaked { .. } => b.store.entry_readable(&TreeEntry {
                            fallback: None,
                            ..e.clone()
                        }),
                        _ => b.store.entry_readable(e),
                    };
                    if readable && !never_materialised {
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

    fn file_entry(&mut self, path: &VPath, name: &str, parent_entry: Option<&TreeEntry>) -> Result<Option<TreeEntry>> {
        let parent_file = parent_entry.filter(|e| e.kind == EntryKind::File);
        let class = self.opts.policy.classify(path, false);
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
            Tier::Ignored => {
                self.report.ignored += 1;
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
        let (mut desired, mut cloak_fallback) = self.audience(path, &class, parent_file);

        // Fast path: overlay/tree-view says the file is byte-identical.
        if let Some(pe) = parent_file {
            if self.use_hints && self.fs.known_id(path) == Some(pe.id) {
                return Ok(Some(pe.clone()));
            }
        }

        let meta = match self.fs.metadata(path) {
            Ok(m) => m,
            Err(e) => return self.unreadable(path, e, parent_file),
        };
        let executable = meta.as_ref().is_some_and(|m| m.executable);
        // Embargoed entries depend on the parent entry and on embargo state,
        // not only on content: always take the slow path for them.
        let parent_embargoed = parent_file.is_some_and(|pe| matches!(pe.visibility, Visibility::Embargoed { .. }));
        // With injected secrets every changed file must be read and checked.
        let cacheable = !parent_embargoed && self.opts.injected.is_none();
        if let (Some(m), true) = (&meta, cacheable) {
            if let Some(e) = self.cached_entry(path, name, m, &desired, cloak_fallback, class.allow_secrets, parent_file)? {
                return Ok(Some(e));
            }
        }

        let data = match self.fs.read(path) {
            Ok(d) => d,
            Err(e) => return self.unreadable(path, e, parent_file),
        };
        self.report.hashed += 1;
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
                    (desired, cloak_fallback) = self.audience(path, &class, parent_file);
                }
                Sealing::Unverifiable if !pe.visibility.is_public() => {
                    // Shown the recorded fallback and left untouched.
                    if pe.fallback == Some(content) && pe.executable == executable {
                        return Ok(Some(TreeEntry {
                            name: name.to_string(),
                            ..pe.clone()
                        }));
                    }
                    // The claim would decide the sealing of this edit:
                    // without its object, it cannot be trusted.
                    let (trusted, _) = self.audience(path, &class, None);
                    let keeps_embargo = matches!(pe.visibility, Visibility::Embargoed { .. })
                        && trusted.is_public()
                        && pe.visibility.key_scope().is_some_and(|l| self.store.keys.has(&l));
                    if desired != trusted || keeps_embargo {
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

        // Embargoes are sticky until released.
        let mut fallback = None;
        if let Some(pe) = parent_file {
            if let Visibility::Embargoed { embargo } = &pe.visibility {
                if self.store.keys.embargo_released(embargo) {
                    // Released: unchanged content keeps its (now readable)
                    // entry instead of showing up as a spurious edit.
                    if pe.executable == executable && self.store.matches_encoding(&pe.id, &data)? {
                        return Ok(Some(pe.clone()));
                    }
                    // Content equal to the pre-embargo version is a
                    // deliberate revert (BUG-050), unless the working copy's
                    // materialisation record says checkout wrote exactly that
                    // fallback here and nothing has refreshed it since: then
                    // it is a stale copy, and recording it would silently
                    // revert the released fix. (The CLI normally fills such
                    // files in before snapshotting; this is the backstop.)
                    if let (Some(fb), Some(rec)) = (pe.fallback, self.opts.materialised) {
                        if pe.executable == executable
                            && rec.from_fallback(self.store, path)? == Some(fb)
                            && self.store.matches_encoding(&fb, &data)?
                        {
                            return Ok(Some(pe.clone()));
                        }
                    }
                    // Anything else is an edit.
                } else {
                    if self.store.keys.has(&format!("embargo/{embargo}")) {
                        // Stays under the embargo only if the path is public
                        // anyway (the release publishes it). A path the
                        // policy now cloaks is sealed under its scope: the
                        // release must never publish it.
                        if desired.is_public() {
                            desired = pe.visibility.clone();
                            fallback = pe.fallback;
                        }
                    } else if let Some(fb) = pe.fallback {
                        if self.store.matches_encoding(&fb, &data)? {
                            // We were shown the fallback and did not touch it.
                            return Ok(Some(TreeEntry {
                                name: name.to_string(),
                                ..pe.clone()
                            }));
                        }
                    }
                }
            }
        }

        if fallback.is_none() {
            fallback = cloak_fallback;
        }
        if let (Some(fb), Some(pe), Visibility::Cloaked { scope }) = (cloak_fallback, parent_file, &desired) {
            if pe.executable == executable && content == fb && pe.visibility == desired && !self.store.keys.has(scope) {
                // A reader without the key was shown the last public version
                // and did not touch it.
                return Ok(Some(TreeEntry {
                    name: name.to_string(),
                    ..pe.clone()
                }));
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

        // A cloaked line of work seals what it *introduces*. A file left
        // exactly as its public parent had it is already public; keep the
        // entry (as the overlay fast path above does) rather than sealing a
        // copy of public bytes.
        if let Some(pe) = parent_file {
            if self.cloak.is_some()
                && class.tier == Tier::Public
                && pe.visibility.is_public()
                && pe.id == content
                && pe.executable == executable
                && !self.policy_changed
            {
                return Ok(Some(pe.clone()));
            }
        }

        // Content sealed under an embargo key is published by the release:
        // it goes through the scanner like public content (BUG-042). A hit
        // holds the edit back; the previous (sealed) entry stays.
        if matches!(desired, Visibility::Embargoed { .. }) && !class.allow_secrets {
            let unchanged = match parent_file {
                Some(pe) => pe.executable == executable && self.store.matches_encoding(&pe.id, &data)?,
                None => false,
            };
            if !unchanged {
                let findings = secrets::scan(&data);
                if !findings.is_empty() {
                    return self.quarantine(path, findings, parent_file);
                }
            }
        }

        let mut scanned_clean = false;
        if desired.is_public() {
            if let Some(pe) = parent_file {
                if !self.policy_changed && !self.rescan && pe.id == content && pe.visibility.is_public() && pe.executable == executable {
                    self.learn(path, meta.as_ref(), content, false, None, parent_embargoed);
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

        // Unchanged cloaked content keeps its sealing (and key generation),
        // so a key rotation does not show every cloaked file as modified.
        if let Some(pe) = parent_file {
            if !desired.is_public()
                && pe.visibility == desired
                && pe.fallback == fallback
                && pe.executable == executable
                && self.store.matches_encoding(&pe.id, &data)?
            {
                return Ok(Some(TreeEntry {
                    name: name.to_string(),
                    ..pe.clone()
                }));
            }
        }

        // A sealed edit of a public file, edited back to its last public
        // version: nothing to seal, that content is public already.
        if let (Some(fb), Visibility::Cloaked { .. }) = (cloak_fallback, &desired) {
            if content == fb && !self.policy_changed && !self.rescan {
                return Ok(Some(TreeEntry {
                    name: name.to_string(),
                    kind: EntryKind::File,
                    id: fb,
                    size: data.len() as u64,
                    executable,
                    visibility: Visibility::Public,
                    fallback: None,
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
        // audience: a released embargo's key is public, and a cloak label
        // must name a scope (never `embargo/…`, `local` or a generation).
        let unsealable = match &desired {
            Visibility::Public => None,
            Visibility::Cloaked { scope } => crate::keychain::validate_scope_name(scope)
                .is_err()
                .then(|| format!("'{scope}' is not a scope")),
            Visibility::Embargoed { embargo } => self
                .store
                .keys
                .embargo_released(embargo)
                .then(|| format!("embargo {embargo} is released and its key is public")),
        };
        if let Some(why) = unsealable {
            return self.cannot_seal(path, name, parent_file, format!("{why}; the edit stays local"));
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
        if fallback.is_none() || matches!(desired, Visibility::Cloaked { .. }) {
            let sealed = match &desired {
                Visibility::Cloaked { scope } => Some((scope.clone(), id)),
                _ => None,
            };
            self.learn(path, meta.as_ref(), content, scanned_clean, sealed, parent_embargoed);
        }
        Ok(Some(TreeEntry {
            name: name.to_string(),
            kind: EntryKind::File,
            id,
            size: data.len() as u64,
            executable,
            visibility: desired,
            fallback,
        }))
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

    /// The audience of new content at `path` (classified `class`, not
    /// ignored or isolated), given its parent entry: the visibility to seal
    /// it under, and the last public version to show readers without the
    /// key. Inputs: the policy (with the accepted pin), the line's trusted
    /// cloak, and the parent entry, whose label the caller must have
    /// verified before content is sealed under the result.
    fn audience(&self, path: &VPath, class: &Classification, parent_file: Option<&TreeEntry>) -> (Visibility, Option<ObjectId>) {
        let mut desired = match &class.tier {
            Tier::Cloaked(s) => Visibility::Cloaked { scope: s.clone() },
            _ => Visibility::Public,
        };
        if let (Some(scope), Visibility::Public) = (self.cloak, &desired) {
            if path.as_str() != POLICY_FILE {
                desired = Visibility::Cloaked {
                    scope: scope.to_string(),
                };
            }
        }
        // Sealed content keeps its audience. Neither a change of workspace
        // (`vl new <cloaked change>`), nor a rebase, nor a policy that arrived
        // by merge may re-key it or make it public: only an edit of
        // `.veilpolicy` in this very snapshot that reclassifies the path
        // (`vl expose`, `vl cloak --scope`) is a deliberate decision to.
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
        // A public file sealed only because of the line it is edited on (a
        // cloaked workspace, or sealed content keeping its audience; the
        // policy itself says public) keeps its last public version as
        // `fallback`: readers without the key (public remotes, Git, members
        // of other scopes) go on seeing that version instead of losing the
        // file. A file the policy cloaks has none: hiding it is the point.
        let cloak_fallback = match (&desired, parent_file) {
            (Visibility::Cloaked { .. }, Some(pe)) if class.tier == Tier::Public => {
                if pe.visibility.is_public() && pe.fallback.is_none() {
                    Some(pe.id)
                } else if pe.visibility == desired {
                    pe.fallback
                } else {
                    None
                }
            }
            _ => None,
        };
        (desired, cloak_fallback)
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
        parent_embargoed: bool,
    ) {
        if let (Some(run), Some(m), false) = (self.cache.as_mut(), meta, parent_embargoed) {
            run.learn(path, m, content, scanned_clean, sealed);
        }
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
        cloak_fallback: Option<ObjectId>,
        allow_secrets: bool,
        parent_file: Option<&TreeEntry>,
    ) -> Result<Option<TreeEntry>> {
        let Some(rec) = self.cache.as_ref().and_then(|c| c.trusted(path, meta)).cloned() else {
            return Ok(None);
        };
        // Only cloaked entries carry a fallback here (a sealed edit of a
        // public file); embargoed ones never come from the cache.
        let fallback = match desired {
            Visibility::Cloaked { .. } => cloak_fallback,
            _ => None,
        };
        let same_as_parent = |id: &ObjectId| {
            parent_file.filter(|pe| pe.id == *id && pe.visibility == *desired && pe.executable == meta.executable && pe.fallback == fallback)
        };
        let entry = match desired {
            Visibility::Public => {
                let id = rec.content;
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
                    None if self.store.has(id) => Some(TreeEntry {
                        fallback,
                        ..self.fresh_entry(name, *id, meta, desired)
                    }),
                    None => None,
                },
                _ => None,
            },
            Visibility::Embargoed { .. } => None,
        };
        if entry.is_some() {
            self.report.cache_hits += 1;
            if let Some(run) = self.cache.as_mut() {
                run.keep(path, rec);
            }
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
            fallback: None,
        }
    }

    /// May a quarantined file keep its previous entry? Encrypted entries
    /// are safe by construction. A public one is re-scanned: it may have
    /// been recorded under a rule (e.g. `public!`) that no longer applies,
    /// and must not be carried into a new snapshot if it holds a secret.
    fn previous_is_safe(&self, pe: &TreeEntry) -> Result<bool> {
        if !pe.visibility.is_public() || pe.fallback.is_some() {
            return Ok(true);
        }
        match self.store.read_entry(pe) {
            Ok(old) => Ok(secrets::scan(&old).is_empty()),
            Err(e) if e.is_unreadable() => Ok(false),
            Err(e) => Err(e),
        }
    }
}
