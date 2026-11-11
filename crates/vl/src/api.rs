//! Structured results of the read commands, shared by their text output,
//! their `--json` output and `vl serve --local` (`crate::serve`).
//!
//! Every read command is split in two: a function here computes a typed
//! result from the repository context and prints nothing, and a renderer
//! turns it into text ([`text`], today's output, byte for byte) or into one
//! JSON document ([`emit_json`]). The schemas are documented, field by
//! field, in `docs/reference/json.md`; `crates/vl/tests/cli_basic/json_cli.rs` pins
//! their shape.
//!
//! **Confidentiality.** The results hold exactly what the text output
//! shows, so JSON can never reveal more: content the reader cannot decrypt
//! is a [`Redaction`] (a reason, never the plaintext), and secret values
//! never enter a result at all (`secret list` reads names only).
//!
//! **Versioning.** Each document starts with `"schema": "veil.<command>/<n>"`.
//! Adding a field keeps the version; renaming, removing or retyping one, or
//! changing what a value means, bumps it.

pub mod shape;
pub mod text;

use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use serde::Serialize;
use veil_core::{
    blame::Reader,
    keychain::{ReleaseState, SignatureStatus},
    rename::{Item, Pair, RenameOptions},
    search::{LogFilter, Match, Searcher},
    object::{EntryKind, Snapshot, Visibility},
    policy::{Policy, Tier},
    attributes::Attrs,
    secrets::{self, looks_binary},
    tree::{lookup, TreeChange},
    vfs::walk_files,
    ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

use crate::ctx::Ctx;

// ---- schema names ------------------------------------------------------------

pub const STATUS_SCHEMA: &str = "veil.status/2";
pub const LOG_SCHEMA: &str = "veil.log/2";
pub const DIFF_SCHEMA: &str = "veil.diff/2";
pub const SHOW_SCHEMA: &str = "veil.show/2";
pub const WORKSPACE_LIST_SCHEMA: &str = "veil.workspace.list/2";
pub const TAG_LIST_SCHEMA: &str = "veil.tag.list/2";
pub const OP_LOG_SCHEMA: &str = "veil.op.log/1";
pub const SCAN_SCHEMA: &str = "veil.scan/1";
pub const SECRET_LIST_SCHEMA: &str = "veil.secret.list/1";
pub const ERROR_SCHEMA: &str = "veil.error/1";
pub const LS_SCHEMA: &str = "veil.ls/2";
pub const RESOLVE_LIST_SCHEMA: &str = "veil.resolve.list/2";
pub const SNAPSHOT_SCHEMA: &str = "veil.snapshot/2";
pub const DESCRIBE_SCHEMA: &str = "veil.describe/2";
pub const NEW_SCHEMA: &str = "veil.new/2";
pub const COMMIT_SCHEMA: &str = "veil.commit/2";
pub const BLAME_SCHEMA: &str = "veil.blame/2";
pub const GREP_SCHEMA: &str = "veil.grep/2";

// ---- JSON output -------------------------------------------------------------

static JSON_EMITTED: AtomicBool = AtomicBool::new(false);

/// Has this process already printed its JSON document? `main` prints a
/// `veil.error/1` document for a failure only if not, so stdout never
/// carries two.
pub fn json_emitted() -> bool {
    JSON_EMITTED.load(Ordering::Relaxed)
}

/// Serialise `doc` as one compact line of JSON. Besides what JSON itself
/// escapes (the C0 controls, `"` and `\`), DEL, the C1 controls and the
/// Unicode bidirectional overrides are written as `\uXXXX` escapes, so
/// `vl … --json` printed straight to a terminal cannot drive it; the
/// decoded strings are unchanged.
pub fn to_json<T: Serialize>(doc: &T) -> Result<String> {
    let raw = serde_json::to_string(doc)?;
    if !raw.chars().any(needs_json_escape) {
        return Ok(raw);
    }
    // Outside strings a JSON document is ASCII, so every such character is
    // inside a string, where an escape means the same character.
    let mut out = String::with_capacity(raw.len() + 16);
    for c in raw.chars() {
        if needs_json_escape(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// All of these are in the Basic Multilingual Plane: one `\uXXXX` each.
fn needs_json_escape(c: char) -> bool {
    matches!(c, '\u{7f}'..='\u{9f}' | '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Print `doc` as this invocation's JSON document.
pub fn emit_json<T: Serialize>(doc: &T) -> Result<()> {
    let line = to_json(doc)?;
    JSON_EMITTED.store(true, Ordering::Relaxed);
    println!("{line}");
    Ok(())
}

/// `{"schema":"veil.error/1","error":{"message":…,"hint":…}}`.
#[derive(Serialize, Debug)]
pub struct ErrorDoc {
    pub schema: &'static str,
    pub error: ErrorBody,
}

#[derive(Serialize, Debug)]
pub struct ErrorBody {
    /// The message printed after `error:` on stderr, unescaped.
    pub message: String,
    /// The `hint:` printed after it, if any.
    pub hint: Option<String>,
}

impl ErrorDoc {
    pub fn new(message: String, hint: Option<String>) -> ErrorDoc {
        ErrorDoc { schema: ERROR_SCHEMA, error: ErrorBody { message, hint } }
    }
}

// ---- shared pieces -------------------------------------------------------------

/// Milliseconds since the epoch as RFC 3339 in UTC, to the millisecond.
pub fn rfc3339(ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// A path as JSON shows it: repository-relative, `/`-separated.
fn path(p: &VPath) -> String {
    p.as_str().to_string()
}

/// Who can read an entry: `{"kind":"cloaked","scope":"team"}` (a sealed
/// secret file).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Vis {
    /// `public` or `cloaked`.
    pub kind: &'static str,
    /// The scope of a cloaked entry.
    pub scope: Option<String>,
}

impl From<&Visibility> for Vis {
    fn from(v: &Visibility) -> Vis {
        match v {
            Visibility::Public => Vis { kind: "public", scope: None },
            Visibility::Cloaked { scope } => Vis { kind: "cloaked", scope: Some(scope.clone()) },
        }
    }
}

impl Vis {
    pub fn visibility(&self) -> Visibility {
        match (self.kind, &self.scope) {
            ("cloaked", Some(s)) => Visibility::Cloaked { scope: s.clone() },
            _ => Visibility::Public,
        }
    }
}

/// Content this reader cannot see, and why. Never carries the content.
#[derive(Serialize, Debug, Clone)]
pub struct Redaction {
    /// `no_key` (cloaked for a scope you hold no key for, or unreadable),
    /// `no_access` (a folder the server refuses: you no longer have access
    /// to it, BUG-1508),
    /// `withheld` (never received: a public mirror never delivers it),
    /// `unwritable` (readable, but this
    /// filesystem could not hold the file), `missing` (a public object
    /// absent from the store: damage, not a redaction) or `error` (the
    /// store could not read it).
    pub reason: &'static str,
    /// The explanation the text output prints, unescaped.
    pub message: String,
}

/// A snapshot's description (plain text).
fn description(_repo: &Repo, s: &Snapshot) -> Option<String> {
    Some(s.description.as_str().to_string())
}

/// A snapshot in one line, as `vl status`, `tag list` and `workspace list`
/// show it (`render::one_line`).
#[derive(Serialize, Debug, Clone)]
pub struct SnapshotRef {
    pub snapshot_id: String,
    pub snapshot_short: String,
    /// In the reverse-hex alphabet (`k`–`z`) the command line uses; null
    /// if the snapshot is not available here.
    pub change_id: Option<String>,
    pub change_short: Option<String>,
    /// False when this repository cannot read the snapshot (withheld by an
    /// unreleased embargo on a public clone, or removed by `vl gc`): only
    /// its id is known.
    pub available: bool,
    /// The change has no changes of its own.
    pub empty: bool,
    pub description: Option<String>,
}

pub fn snapshot_ref(repo: &Repo, id: &ObjectId) -> SnapshotRef {
    match repo.snapshot(id) {
        Ok(s) => {
            let description = description(repo, &s);
            SnapshotRef {
                snapshot_id: id.hex(),
                snapshot_short: id.short(),
                change_id: Some(s.change_id.display()),
                change_short: Some(s.change_id.short()),
                available: true,
                empty: repo.is_empty_change(id).unwrap_or(false) && !s.parents.is_empty(),
                description,
            }
        }
        Err(_) => SnapshotRef {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: None,
            change_short: None,
            available: false,
            empty: false,
            description: None,
        },
    }
}

/// [`snapshot_ref`] in a thin clone when `empty` is known from the server
/// (or by comparing held trees), so `repo.is_empty_change` never pages in
/// unheld parent snapshots.
fn snapshot_ref_thin(
    repo: &Repo,
    promisor: &dyn veil_core::promisor::Promisor,
    id: &ObjectId,
) -> SnapshotRef {
    if let Ok(Some(s)) = repo.held().snapshot(id) {
        let description = description(repo, &s);
        let empty = if s.parents.is_empty() {
            false
        } else if let Some(Some(ps)) = s.parents.first().map(|p| repo.held().snapshot(p).ok().flatten()) {
            s.tree == ps.tree
        } else if let Ok(Ok(v)) = promisor.query("show", &[("rev", id.hex()), ("stat", "true".into())]) {
            v["empty"].as_bool().unwrap_or(false)
        } else {
            false
        };
        return SnapshotRef {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: Some(s.change_id.display()),
            change_short: Some(s.change_id.short()),
            available: true,
            empty,
            description,
        };
    }
    if let Ok(Ok(v)) = promisor.query("show", &[("rev", id.hex()), ("stat", "true".into())]) {
        return SnapshotRef {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: v["change_id"].as_str().map(str::to_string),
            change_short: v["change_short"].as_str().map(str::to_string),
            available: true,
            empty: !v["root"].as_bool().unwrap_or(false) && v["empty"].as_bool().unwrap_or(false),
            description: v["description"].as_str().map(str::to_string),
        };
    }
    SnapshotRef {
        snapshot_id: id.hex(),
        snapshot_short: id.short(),
        change_id: None,
        change_short: None,
        available: false,
        empty: false,
        description: None,
    }
}

/// A snapshot signature.
#[derive(Serialize, Debug, Clone)]
pub struct Sig {
    /// `good`, `server` (valid, by the signing key of this clone's server,
    /// pinned when this device signed in: a snapshot the server made, such
    /// as a landed change), `unknown` (valid, by a key no key ring
    /// knows), `bad` or `unsigned`.
    pub status: &'static str,
    /// The member who signed (`good` only).
    pub signer: Option<String>,
    /// The signing public key, in hex, and its first 16 digits.
    pub key: Option<String>,
    pub key_short: Option<String>,
}

fn sig(repo: &Repo, status: &SignatureStatus, s: &Snapshot) -> Sig {
    let key = s.signature.as_ref().map(|g| g.key.clone());
    let key_short = s.signature.as_ref().map(|g| g.key.get(..16).unwrap_or(&g.key).to_string());
    let (status, signer) = match status {
        SignatureStatus::Good { name, .. } => ("good", Some(name.clone())),
        // A signature that verifies, by the key this device pinned for the
        // clone's server (BUG-1910). Any other key no ring knows stays
        // unknown.
        SignatureStatus::Unknown { key } if crate::hub::server_keys(repo).contains(key) => ("server", None),
        SignatureStatus::Unknown { .. } => ("unknown", None),
        SignatureStatus::Bad => ("bad", None),
        SignatureStatus::Unsigned => ("unsigned", None),
    };
    Sig { status, signer, key, key_short }
}

/// Rename and copy detection for `vl diff`, `vl show` and `vl status`
/// (`veil_core::rename`): on by default, as in Git; computed for this
/// reader, never stored.
#[derive(Clone, Debug)]
pub struct Renames {
    pub detect: bool,
    pub opts: RenameOptions,
}

impl Default for Renames {
    fn default() -> Self {
        Renames { detect: true, opts: RenameOptions::default() }
    }
}

impl Renames {
    pub fn off() -> Renames {
        Renames { detect: false, opts: RenameOptions::default() }
    }
}

/// `changes` with renames (and copies) detected as `r` says, in their
/// order; and whether a limit stopped the inexact pass.
pub fn detect_renames(repo: &Repo, (from, to): (&ObjectId, &ObjectId), changes: Vec<TreeChange>, r: &Renames) -> Result<(Vec<Item>, bool)> {
    if !r.detect {
        return Ok((changes.into_iter().map(Item::Change).collect(), false));
    }
    let d = veil_core::rename::detect(repo.store(), Some(from), Some(to), &changes, Reader::Me, &r.opts)?;
    Ok((d.items(), d.truncated))
}

/// A detected pair as the change it stands for (the destination's path,
/// the source as the old side).
fn pair_change(p: &Pair) -> TreeChange {
    TreeChange { path: p.to.clone(), old: Some(p.old.clone()), new: Some(p.new.clone()) }
}

fn status_word(c: &TreeChange) -> &'static str {
    match c.status() {
        'A' => "added",
        'D' => "deleted",
        _ => "modified",
    }
}

/// A conflict entry (repository format 4) as this reader sees it: the
/// versions a merge could not combine. Labels are public metadata; no
/// content is ever included.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ConflictInfo {
    /// Versions being combined (2 for a three-way conflict).
    pub sides: usize,
    /// Base versions (1 for a three-way conflict).
    pub bases: usize,
    /// Every version, sides and bases interleaved as stored.
    pub versions: Vec<ConflictVersion>,
    /// Some version is not shown in the file materialised here (sealed for
    /// another audience than the file's, or unreadable here).
    pub redacted: bool,
    /// A side cannot be read here: this reader cannot resolve it.
    pub unreadable_side: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ConflictVersion {
    /// `side` or `base`.
    pub role: &'static str,
    /// 1-based, per role.
    pub number: usize,
    /// Null when this version has no file (added on one side only, or
    /// deleted).
    pub visibility: Option<Vis>,
    /// This reader can read the version.
    pub readable: bool,
}

/// [`ConflictInfo`] of `e`, `None` unless it is a conflict entry.
pub fn conflict_info(repo: &Repo, e: &TreeEntry) -> Option<ConflictInfo> {
    look(repo, e).map(|l| l.info)
}

/// A conflict entry as this reader is told about it: what its
/// materialised file would be ([`veil_core::conflict::inspect`]: the
/// sides' text is never merged, BUG-484) and its [`ConflictInfo`]. Each
/// listing computes it once per entry.
struct Looked {
    view: veil_core::conflict::View,
    info: ConflictInfo,
}

fn look(repo: &Repo, e: &TreeEntry) -> Option<Looked> {
    if e.kind != EntryKind::Conflict {
        return None;
    }
    let c = repo.store().conflict(&e.id).ok()?;
    let m = veil_core::conflict::inspect(repo.store(), &c, veil_core::conflict::Audience::Reader).ok()?;
    let versions = c
        .interleaved()
        .enumerate()
        .map(|(i, t)| ConflictVersion {
            role: if i % 2 == 0 { "side" } else { "base" },
            number: i / 2 + 1,
            visibility: t.as_ref().map(|t| Vis::from(&t.visibility)),
            readable: t.as_ref().is_none_or(|t| id_readable(repo, &t.id)),
        })
        .collect();
    let info = ConflictInfo { sides: c.adds.len(), bases: c.removes.len(), versions, redacted: m.redacted, unreadable_side: m.unreadable_side };
    Some(Looked { view: m, info })
}

/// The visibility of file entry `e` as its object proves it: labels are
/// claims (BUG-103), and a push sends an object by what it is, so a sealed
/// label whose object is plaintext is public (BUG-482), as the builder and
/// `vl push` take it (`builder::verify_sealing`). A public label is taken
/// as it is (a push withholds a sealed object whatever it is called, so
/// believing it can only overstate what is public).
pub fn verified_visibility(repo: &Repo, e: &TreeEntry) -> Visibility {
    match &e.visibility {
        Visibility::Public => Visibility::Public,
        claimed => match veil_core::builder::verify_sealing(repo.store(), e) {
            Ok(veil_core::builder::Sealing::Relabelled(actual)) => actual,
            _ => claimed.clone(),
        },
    }
}

/// One changed path, as `vl status` and `vl diff --stat` list it.
#[derive(Serialize, Debug, Clone)]
pub struct Change {
    pub path: String,
    /// `added`, `deleted`, `modified`, `renamed` or `copied`.
    pub status: &'static str,
    /// Renamed or copied: the source path (absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Renamed or copied: the similarity in percent (absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    /// Of the new version (of the old one for a deletion).
    pub visibility: Vis,
    /// The new version is unreadable here (`(redacted)` in the text).
    pub redacted: bool,
    /// The tier of the new version (of the old one for a deletion), as
    /// `vl ls` shows it: `public`, `embargoed` (an unreleased embargo
    /// withholds it), `cloaked` or `redacted`
    /// (this reader cannot read it; `visibility` says for whom it is).
    pub tier: &'static str,
    /// The new version is an unresolved conflict (null otherwise).
    pub conflict: Option<ConflictInfo>,
    /// What the new version is (the old one for a deletion): `file`,
    /// `symlink` (format 5) or `conflict`.
    pub kind: &'static str,
    /// The old version's kind when a modification changed it (a file
    /// replaced by a symlink: `T` in the text); null otherwise.
    pub old_kind: Option<&'static str>,
}

/// What entry `e` is, as JSON spells it: `file`, `symlink`, `conflict`
/// (or `dir`).
pub fn entry_kind(e: &TreeEntry) -> &'static str {
    e.kind.name()
}

/// The target of symlink entry `e` as this reader reads it; `None` for
/// anything else, and for a link this reader cannot read (its target is
/// content, sealed as a file's would be: never shown to a non-member).
pub fn link_target(repo: &Repo, e: &TreeEntry) -> Option<String> {
    if e.kind != EntryKind::Symlink {
        return None;
    }
    if !repo.store().entry_readable(e) {
        return None;
    }
    repo.store().read_entry(e).ok().map(|t| String::from_utf8_lossy(&t).into_owned())
}

/// The mode of entry `e`: `100644`, `100755` or `120000` (symlink).
fn git_mode(e: &TreeEntry, executable: bool) -> &'static str {
    match e.kind {
        EntryKind::Symlink => "120000",
        _ if executable => "100755",
        _ => "100644",
    }
}

pub fn change(repo: &Repo, c: &TreeChange) -> Change {
    let e = c.new.as_ref().or(c.old.as_ref()).expect("a change has a side");
    let looked = look(repo, e);
    // A conflict's visibility is that of its materialised file.
    let visibility = looked.as_ref().map_or_else(|| verified_visibility(repo, e), |l| l.view.visibility.clone());
    let tier = entry_tier_with(repo, e, looked.as_ref());
    Change {
        path: path(&c.path),
        status: status_word(c),
        from: None,
        score: None,
        visibility: Vis::from(&visibility),
        redacted: c.new.as_ref().is_some_and(|e| !repo.store().entry_readable(e)),
        tier,
        // The conflict of the new version only (`e` is the old one for a
        // deletion).
        conflict: if c.new.is_some() { looked.map(|l| l.info) } else { None },
        kind: entry_kind(e),
        // A conflict edited into a file is a resolution, not a new kind.
        old_kind: match (&c.old, &c.new) {
            (Some(o), Some(n)) if o.kind != n.kind && o.kind.holds_blob() && n.kind.holds_blob() => Some(entry_kind(o)),
            _ => None,
        },
    }
}

/// A [`Change`] for each item: a pair is listed at its destination, with
/// its source in `from`.
/// Which files of a snapshot an unreleased embargo still withholds
/// (BUG-944): those that differ from the tree a push already published
/// (`remote::embargo_base`). Their tier is `embargoed`, never `public`:
/// no push sends them before the release.
pub struct EmbargoTiers {
    base: Option<ObjectId>,
}

impl EmbargoTiers {
    pub fn of(repo: &Repo, snapshot: &ObjectId) -> Result<EmbargoTiers> {
        let base = match veil_core::remote::embargo_base(repo, snapshot)? {
            Some(b) => Some(repo.snapshot(&b)?.tree),
            None => None,
        };
        Ok(EmbargoTiers { base })
    }

    /// `tier` of the version `e` at `p`, or `embargoed` if it is a public
    /// version the embargo withholds.
    pub fn tier(&self, repo: &Repo, p: &VPath, e: Option<&TreeEntry>, tier: &'static str) -> &'static str {
        match (&self.base, e) {
            (Some(base), Some(e)) if tier == "public" => {
                match lookup(repo.store(), base, p).ok().flatten() {
                    Some(b) if b.id == e.id && b.kind == e.kind => tier,
                    _ => "embargoed",
                }
            }
            _ => tier,
        }
    }
}

pub fn item_change(repo: &Repo, item: &Item) -> Change {
    match item {
        Item::Change(c) => change(repo, c),
        Item::Pair(p) => {
            let mut c = change(repo, &pair_change(p));
            c.status = if p.copy { "copied" } else { "renamed" };
            c.from = Some(path(&p.from));
            c.score = Some(p.score);
            c
        }
    }
}

// ---- tiers -----------------------------------------------------------------------

/// The tier of a recorded file for this reader, as `vl ls` and `vl status`
/// show it: `public` (plaintext), `cloaked` (a sealed secret file this
/// reader holds the key of), or `redacted`
/// (sealed for someone else, or withheld here). The local-only tiers
/// (`isolated`, `ignored`, `quarantined`) come from the working copy.
pub fn entry_tier(repo: &Repo, e: &TreeEntry) -> &'static str {
    entry_tier_with(repo, e, look(repo, e).as_ref())
}

/// [`entry_tier`] with `e`'s [`look`] already computed.
fn entry_tier_with(repo: &Repo, e: &TreeEntry, looked: Option<&Looked>) -> &'static str {
    // A conflict: the tier of its materialised file, `redacted` when a
    // side cannot be read here.
    if let Some(l) = looked {
        return match &l.view.visibility {
            _ if l.view.unreadable_side => "redacted",
            Visibility::Public => "public",
            Visibility::Cloaked { .. } => "cloaked",
        };
    }
    match &verified_visibility(repo, e) {
        Visibility::Public => "public",
        _ if !id_readable(repo, &e.id) => "redacted",
        Visibility::Cloaked { .. } => "cloaked",
    }
}

/// Can this reader open object `id` (present, and sealed, if at all, for a
/// key it holds)?
fn id_readable(repo: &Repo, id: &ObjectId) -> bool {
    match repo.store().get_raw(id) {
        Ok(raw) => match veil_core::object::Object::sealed_scope(&raw) {
            Some(scope) => repo.keys().has(&scope),
            None => true,
        },
        Err(_) => false,
    }
}

/// The tier of a path the accepted policy decides (a policy keyword such
/// as `isolate` or `cloak ops`), with its scope.
fn keyword_tier(keyword: &str) -> (&'static str, Option<String>) {
    match keyword.split_once(' ') {
        Some(("cloak", scope)) => ("cloaked", Some(scope.to_string())),
        _ => match keyword {
            "isolate" => ("isolated", None),
            "ignore" => ("ignored", None),
            _ => ("public", None),
        },
    }
}

/// Why `e` cannot be materialised here, in the words of `vl status`
/// (`render::hidden_reason`).
fn redaction_for_listing(repo: &Repo, e: &TreeEntry) -> Option<Redaction> {
    // A folder carried as recorded: `no_access` only where the server
    // refuses it (BUG-1508); one carried for another reason says so.
    if e.kind == EntryKind::Dir {
        let store = repo.store();
        let refused = !store.has(&e.id) && matches!(store.tree(&e.id), Err(err) if veil_core::tree::refused_tree(store, &err));
        return Some(match refused {
            true => Redaction { reason: "no_access", message: "you no longer have access to this folder".into() },
            false => Redaction { reason: "error", message: "its content could not be read here; kept as recorded".into() },
        });
    }
    if e.kind == EntryKind::Conflict {
        return Some(Redaction {
            reason: "conflict_side",
            message: "a conflict with a version you cannot read (shown redacted)".into(),
        });
    }
    let present = repo.store().has(&e.id);
    Some(match &e.visibility {
        Visibility::Public => return None,
        Visibility::Cloaked { scope } if present => Redaction { reason: "no_key", message: format!("cloaked:{scope}; no key") },
        Visibility::Cloaked { scope } => {
            Redaction { reason: "withheld", message: format!("cloaked:{scope}; not received") }
        }
    })
}

/// Why the content of `e` cannot be shown in a diff
/// (`render::hidden_note`).
fn redaction_for_diff(repo: &Repo, e: &TreeEntry, err: &veil_core::VeilError) -> Redaction {
    let present = repo.store().has(&e.id);
    match &e.visibility {
        Visibility::Public => Redaction { reason: "missing", message: err.to_string() },
        Visibility::Cloaked { .. } if present => {
            Redaction { reason: "no_key", message: format!("{}; you hold no key", e.visibility.label()) }
        }
        Visibility::Cloaked { .. } => {
            Redaction { reason: "withheld", message: format!("{}; not received", e.visibility.label()) }
        }
    }
}

// ---- status ----------------------------------------------------------------------

/// `vl status --json` (`veil.status/2`).
#[derive(Serialize, Debug)]
pub struct Status {
    pub schema: &'static str,
    pub workspace: WorkspaceInfo,
    pub working_copy: SnapshotRef,
    pub parents: Vec<SnapshotRef>,
    /// The working-copy change's own changes, against its parents.
    pub changes: Vec<Change>,
    /// Local-only files: never snapshotted or pushed.
    pub isolated: Vec<String>,
    pub quarantined: Vec<Quarantined>,
    pub policy_held_back: Vec<PolicyHeldBack>,
    /// Repositories of their own inside this one (directories).
    pub nested: Vec<String>,
    /// Files in the working-copy snapshot that are absent on disk.
    pub redacted: Vec<RedactedPath>,
    pub conflicts: Vec<Conflict>,
    /// Files still recorded with line endings `.veilattributes` would now
    /// convert (`vl renormalize` re-records them). Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub renormalizable: Vec<String>,
    /// Files in a folder you no longer have access to (a thin clone; the
    /// folder is kept as recorded): never recorded, never touched
    /// (BUG-1528). Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_recorded: Vec<String>,
    /// Folders the working-copy change's diff did not compare: the server
    /// refuses them (as in `veil.diff/2`). Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct WorkspaceInfo {
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct Quarantined {
    pub path: String,
    /// The first secret rule that matched, and its line.
    pub rule: &'static str,
    pub line: usize,
    /// `held_back` (history keeps the previous version) or
    /// `never_recorded`.
    pub state: &'static str,
    /// Always `quarantined`.
    pub tier: &'static str,
}

#[derive(Serialize, Debug)]
pub struct PolicyHeldBack {
    /// With a trailing `/` when `dir`.
    pub path: String,
    /// A directory held back as a whole.
    pub dir: bool,
    /// The accepted classification and what `.veilpolicy` wants, as policy
    /// keywords (`isolate`, `cloak ops`, `public!`).
    pub accepted: String,
    pub wanted: String,
    /// The tier the accepted classification gives it (`isolated`,
    /// `ignored`, `cloaked` or `public`), and the scope of a cloak.
    pub tier: &'static str,
    pub scope: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct RedactedPath {
    pub path: String,
    pub redaction: Redaction,
    /// The entry's tier (`redacted` unless the reason is `unwritable`).
    pub tier: &'static str,
}

#[derive(Serialize, Debug)]
pub struct Conflict {
    pub path: String,
    /// Short change id of the parent the conflict was recorded on (a
    /// merge), or null if recorded on the working-copy change itself.
    pub recorded_on: Option<String>,
    /// The conflict as data (repository format 4); null for a conflict
    /// recorded as markers in the file (older formats, embargoes) or a
    /// file moved aside by a file/directory conflict.
    pub conflict: Option<ConflictInfo>,
    /// Your own edit of a version you held before you lost access to its
    /// folder, kept when the folder was written back (the recorded version
    /// is newer, BUG-1531). Absent otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub kept_edit: bool,
}

pub fn status(ctx: &Ctx) -> Result<Status> {
    let repo = &ctx.repo;
    let wc = ctx.wc()?;
    let s = repo.snapshot(&wc)?;
    let base = ctx.parents_tree(&s.parents)?;
    let wc_tree = ctx.restrict_tree(s.tree)?;
    let (changes, hidden) = veil_core::tree::diff_trees_hiding(repo.store(), Some(&base), Some(&wc_tree))?;
    let (changes, _) = detect_renames(repo, (&base, &wc_tree), changes, &Renames::default())?;
    let report = &ctx.report;
    let embargo = EmbargoTiers::of(repo, &wc)?;
    let mut redacted = Vec::new();
    for p in &report.carried {
        if !ctx.in_only(p) {
            continue;
        }
        let entry = lookup(repo.store(), &wc_tree, p)?;
        let why = entry.as_ref().and_then(|e| redaction_for_listing(repo, e));
        // Readable, yet never materialised: the filesystem refused it.
        let tier = entry.as_ref().map_or("redacted", |e| embargo.tier(repo, p, Some(e), entry_tier(repo, e)));
        let fallback = match entry {
            Some(e) if repo.store().entry_readable(&e) => {
                Redaction { reason: "unwritable", message: "this filesystem could not hold it".into() }
            }
            _ => Redaction { reason: "no_key", message: "no key".into() },
        };
        let redaction = why.unwrap_or(fallback);
        let tier = if redaction.reason == "unwritable" { tier } else { "redacted" };
        redacted.push(RedactedPath { path: path(p), redaction, tier });
    }
    // Conflicts recorded on `@`, and those of its parents (a merge records
    // them on the merge, `@-`) whose file `@` has not touched since.
    // A conflict entry `@` has unchanged from a parent that records it was
    // recorded there.
    let parents: Vec<_> = s.parents.iter().map(|p| repo.snapshot(p)).collect::<std::result::Result<_, _>>()?;
    let mut conflicts: Vec<Conflict> = Vec::new();
    for c in &s.conflicts {
        if !ctx.in_only_str(c) {
            continue;
        }
        let entry = VPath::new(c).ok().and_then(|cp| lookup(repo.store(), &wc_tree, &cp).ok().flatten());
        let recorded_on = parents.iter().find_map(|ps| {
            let cp = VPath::new(c).ok()?;
            let ps_tree = ctx.restrict_tree(ps.tree).ok()?;
            let before = lookup(repo.store(), &ps_tree, &cp).ok().flatten();
            (ps.conflicts.contains(c) && before.is_some() && before == entry).then(|| ps.change_id.short())
        });
        let conflict = entry.as_ref().and_then(|e| conflict_info(repo, e));
        conflicts.push(Conflict { path: c.clone(), recorded_on, conflict, kept_edit: false });
    }
    for ps in &parents {
        for c in &ps.conflicts {
            let Ok(cp) = VPath::new(c) else { continue };
            if !ctx.in_only(&cp) {
                continue;
            }
            let ps_tree = ctx.restrict_tree(ps.tree)?;
            let before = lookup(repo.store(), &ps_tree, &cp)?;
            if before.is_some() && before == lookup(repo.store(), &wc_tree, &cp)? && !conflicts.iter().any(|x| x.path == *c) {
                let conflict = before.as_ref().and_then(|e| conflict_info(repo, e));
                conflicts.push(Conflict { path: c.clone(), recorded_on: Some(ps.change_id.short()), conflict, kept_edit: false });
            }
        }
    }
    Ok(Status {
        schema: STATUS_SCHEMA,
        workspace: WorkspaceInfo { name: ctx.ws.clone() },
        working_copy: snapshot_ref(repo, &wc),
        parents: s.parents.iter().map(|p| snapshot_ref(repo, p)).collect(),
        changes: {
            changes
                .iter()
                .map(|c| {
                    let mut ch = item_change(repo, c);
                    let (p, e) = match c {
                        Item::Change(c) => (&c.path, c.new.as_ref()),
                        Item::Pair(pr) => (&pr.to, Some(&pr.new)),
                    };
                    ch.tier = embargo.tier(repo, p, e, ch.tier);
                    ch
                })
                .collect()
        },
        isolated: report.isolated.iter().map(path).collect(),
        quarantined: report
            .quarantined
            .iter()
            .map(|(p, f)| Quarantined {
                path: path(p),
                rule: f[0].rule,
                line: f[0].line,
                state: if report.quarantine_kept.contains(p) { "held_back" } else { "never_recorded" },
                tier: "quarantined",
            })
            .collect(),
        policy_held_back: report
            .policy_held_back
            .iter()
            .map(|h| {
                let (tier, scope) = keyword_tier(&h.accepted);
                PolicyHeldBack { path: h.shown_path(), dir: h.dir, accepted: h.accepted.clone(), wanted: h.wanted.clone(), tier, scope }
            })
            .collect(),
        nested: report.nested.iter().map(path).collect(),
        redacted,
        conflicts: {
            // Kept edits of a version left with a folder (BUG-1531).
            for k in ctx.materialised().kept_edits() {
                if !ctx.in_only(k) {
                    continue;
                }
                // Only while `@`'s parents record exactly the version
                // written back: once they record anything else (the
                // person's own version, committed), it is resolved
                // (BUG-1558). `@` itself is what the working copy holds
                // (every command snapshots it), so not the person's choice.
                if let Some(v) = ctx.materialised().kept_version(k) {
                    let at = |t: &ObjectId| veil_core::tree::lookup(repo.store(), t, k).map(|e| e.map(|e| e.id));
                    let mut trees = Vec::new();
                    for p in &s.parents {
                        trees.push(ctx.restrict_tree(repo.snapshot(p)?.tree)?);
                    }
                    if trees.iter().any(|t| at(t).is_ok_and(|e| e != v)) {
                        continue;
                    }
                }
                if !conflicts.iter().any(|c| c.path == k.as_str()) {
                    conflicts.push(Conflict { path: path(k), recorded_on: None, conflict: None, kept_edit: true });
                }
            }
            conflicts
        },
        renormalizable: report.renormalizable.iter().map(path).collect(),
        not_recorded: report.not_recorded.iter().map(path).collect(),
        hidden: hidden.iter().map(|h| hidden_dir(&h.path)).collect(),
    })
}

// ---- log -------------------------------------------------------------------------

/// `vl log --json` (`veil.log/2`).
#[derive(Serialize, Debug)]
pub struct Log {
    pub schema: &'static str,
    /// Children before parents, newest first among unrelated snapshots.
    pub entries: Vec<LogEntry>,
    /// `-n` cut the log short (with a filter: snapshots were left
    /// unsearched).
    pub truncated: bool,
    /// With a filter (paths, `--author`, `--signed-by`, `-S`, `-G`): how
    /// the search went. Absent without one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<LogSearch>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LogSearch {
    /// Snapshots looked at.
    pub searched: usize,
    /// Snapshots not searched because the versions to read are sealed for
    /// this reader (listed in `entries` only with `--show-skipped`).
    pub skipped: usize,
    /// `--max-changes` stopped the search.
    pub stopped: bool,
}

#[derive(Serialize, Debug)]
pub struct LogEntry {
    pub snapshot_id: String,
    pub snapshot_short: String,
    pub change_id: String,
    pub change_short: String,
    /// The universal root (`root()`): no author, time, signature.
    pub root: bool,
    /// The working-copy snapshot of the current workspace (`@`).
    pub current: bool,
    pub author: Option<String>,
    /// Who produced the content: an agent, its task, prompt reference and
    /// run (*optional*: absent when no agent is recorded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<veil_core::object::Attribution>,
    pub timestamp: Option<String>,
    pub signature: Option<Sig>,
    /// Workspaces whose working copy this is.
    pub workspaces: Vec<String>,
    pub tags: Vec<TagLabel>,
    /// `remote/tag` names last seen on a remote.
    pub remote_tags: Vec<String>,
    pub empty: bool,
    pub conflicts: Vec<String>,
    pub embargo: Option<LogEmbargo>,
    pub description: Option<String>,
    pub parents: Vec<ParentRef>,
    /// With `-S` / `-G`: the files that matched (every changed file with
    /// `--pickaxe-all`). Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<String>>,
    /// With `--show-skipped`: this snapshot was not searched, because the
    /// versions to read are sealed for these audiences. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_searched: Option<Vec<Vis>>,
    #[serde(skip)]
    pub(crate) id: ObjectId,
    #[serde(skip)]
    pub(crate) timestamp_ms: i64,
}

#[derive(Serialize, Debug, Clone)]
pub struct TagLabel {
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct LogEmbargo {
    pub id: String,
    pub released: bool,
}

#[derive(Serialize, Debug)]
pub struct ParentRef {
    pub snapshot_id: String,
    pub snapshot_short: String,
    /// Null when the parent is withheld here.
    pub change_short: Option<String>,
    /// Not in this repository (an unreleased embargo on a public clone).
    pub withheld: bool,
    #[serde(skip)]
    pub(crate) id: ObjectId,
}

/// The log, lazily: the text output stops early when its reader goes away
/// (`vl log | head`).
pub struct LogEntries<'a> {
    repo: &'a Repo,
    precomputed: Option<std::vec::IntoIter<LogEntry>>,
    ids: std::iter::Peekable<Box<dyn Iterator<Item = veil_core::error::Result<ObjectId>> + 'a>>,
    signers: std::collections::BTreeMap<String, (String, String)>,
    tags: HashMap<ObjectId, Vec<TagLabel>>,
    remote_tags: HashMap<ObjectId, Vec<String>>,
    workspaces: HashMap<ObjectId, Vec<String>>,
    current: Option<ObjectId>,
    root: ObjectId,
    /// More snapshots exist than `limit` lets through.
    pub truncated: bool,
    limit: Option<usize>,
    yielded: usize,
    searcher: Option<Searcher<'a>>,
    precomputed_search: Option<LogSearch>,
    show_skipped: bool,
    max_changes: Option<usize>,
    skipped: usize,
    stopped: bool,
    within: Option<veil_core::vfs::SparseSet>,
}

/// What `vl log` shows: which snapshots (`-r`), how many (`-n`), and the
/// filters.
#[derive(Default)]
pub struct LogQuery {
    pub limit: Option<usize>,
    /// Snapshot ids in log order (`revset::resolve_set`); all visible
    /// snapshots when `None`.
    pub ids: Option<Vec<ObjectId>>,
    /// Starting roots for `::REV` in a thin clone (when `ids` is `None`).
    pub roots: Option<Vec<ObjectId>>,
    pub filter: Option<LogFilter>,
    pub show_skipped: bool,
    /// Stop searching after this many snapshots.
    pub max_changes: Option<usize>,
}

/// Can `q` be answered in a thin clone by S13's `q/log` or S14's
/// `q/history` without paging history into `.veil/objects/` (S16,
/// `docs/HUB.md` §13.34)?
fn thin_log_route(q: &LogQuery) -> Option<Option<(VPath, bool)>> {
    if q.ids.is_some() || q.max_changes.is_some() {
        return None;
    }
    let Some(f) = &q.filter else { return Some(None) };
    if f.author.is_some() || f.agent.is_some() || f.signed_by.is_some() || f.pickaxe.is_some() {
        return None;
    }
    match f.paths.as_slice() {
        [] => Some(None),
        [p] => Some(Some((p.clone(), f.follow))),
        _ => None,
    }
}

/// A snapshot entry from the server's `q/log` or `q/history` turned into a
/// [`LogEntry`] with this clone's tags, workspaces and signers.
#[allow(clippy::too_many_arguments)]
fn remote_log_entry(
    v: &serde_json::Value,
    signers: &std::collections::BTreeMap<String, (String, String)>,
    server_keys: &[String],
    tags: &mut HashMap<ObjectId, Vec<TagLabel>>,
    remote_tags: &mut HashMap<ObjectId, Vec<String>>,
    workspaces: &mut HashMap<ObjectId, Vec<String>>,
    current: Option<ObjectId>,
    root: ObjectId,
) -> Result<LogEntry> {
    let snap_hex = v["snapshot_id"].as_str().unwrap_or_default();
    let id = ObjectId::from_hex(snap_hex)?;
    let is_root = id == root || v["root"].as_bool().unwrap_or(false);
    let ts = v["timestamp"].as_i64().unwrap_or(0);
    let sig_val = if is_root {
        None
    } else {
        Some(match v.get("signature").filter(|s| !s.is_null()) {
            Some(s) => {
                let signer_hex = s["signer"].as_str().unwrap_or_default();
                let key_hex = s["key"].as_str().unwrap_or_default().to_string();
                let key_short = key_hex.get(..16).unwrap_or(&key_hex).to_string();
                let (status, signer) = match signers.get(&key_hex) {
                    Some((member, name)) if member == signer_hex => ("good", Some(name.clone())),
                    // The key this device pinned for the clone's server, as
                    // a clone that holds the snapshot shows it (BUG-1910).
                    _ if server_keys.contains(&key_hex) => ("server", None),
                    _ => ("unknown", None),
                };
                Sig { status, signer, key: Some(key_hex), key_short: Some(key_short) }
            }
            None => Sig { status: "unsigned", signer: None, key: None, key_short: None },
        })
    };
    let parents = v["parents"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let ph = p["snapshot_id"].as_str()?;
                    let pid = ObjectId::from_hex(ph).ok()?;
                    let change_short = p["change_short"].as_str().map(str::to_string);
                    Some(ParentRef {
                        snapshot_id: pid.hex(),
                        snapshot_short: pid.short(),
                        withheld: change_short.is_none(),
                        change_short,
                        id: pid,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let agent = v.get("agent").filter(|a| !a.is_null()).and_then(|a| serde_json::from_value(a.clone()).ok());
    let conflicts = v["conflicts"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Ok(LogEntry {
        snapshot_id: id.hex(),
        snapshot_short: id.short(),
        change_id: v["change_id"].as_str().unwrap_or_default().to_string(),
        change_short: v["change_short"].as_str().unwrap_or_default().to_string(),
        root: is_root,
        current: Some(id) == current,
        author: (!is_root).then(|| v["author"].as_str().unwrap_or_default().to_string()),
        agent,
        timestamp: if is_root { None } else { rfc3339(ts) },
        signature: sig_val,
        workspaces: workspaces.remove(&id).unwrap_or_default(),
        tags: tags.remove(&id).unwrap_or_default(),
        remote_tags: remote_tags.remove(&id).unwrap_or_default(),
        empty: !is_root && v["empty"].as_bool().unwrap_or(false),
        conflicts,
        embargo: None,
        description: Some(v["description"].as_str().unwrap_or_default().to_string()),
        parents,
        files: None,
        not_searched: None,
        id,
        timestamp_ms: ts,
    })
}

/// Run a thin clone's `vl log`, `vl log -- PATH` or `vl log --follow --
/// PATH` over the server's query routes (`q/log`, `q/history`), merging the
/// clone's own local commits on top without paging history into
/// `.veil/objects/` (S16, `docs/HUB.md` §13.34).
#[allow(clippy::too_many_arguments)]
fn thin_query_log<'a>(
    repo: &'a Repo,
    promisor: &dyn veil_core::promisor::Promisor,
    explicit_roots: Option<Vec<ObjectId>>,
    path_filter: Option<(VPath, bool)>,
    limit: Option<usize>,
    show_skipped: bool,
    signers: std::collections::BTreeMap<String, (String, String)>,
    mut tags: HashMap<ObjectId, Vec<TagLabel>>,
    mut remote_tags: HashMap<ObjectId, Vec<String>>,
    mut workspaces: HashMap<ObjectId, Vec<String>>,
    current: Option<ObjectId>,
    root: ObjectId,
) -> Result<Option<LogEntries<'a>>> {
    // Partition the view's visible heads (or `explicit_roots`) into commits
    // only this clone holds and snapshots on the server (including server
    // bases below local commits).
    let mut local_ids: Vec<ObjectId> = Vec::new();
    let mut server_roots: Vec<ObjectId> = Vec::new();
    let mut seen_local: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
    let mut stack: Vec<ObjectId> = explicit_roots.unwrap_or_else(|| repo.view().refs());
    while let Some(x) = stack.pop() {
        if !seen_local.insert(x) {
            continue;
        }
        if repo.store().is_servers(&x)? {
            if !server_roots.contains(&x) {
                server_roots.push(x);
            }
        } else if let Some(s) = repo.held().snapshot(&x)? {
            local_ids.push(x);
            stack.extend(s.parents.iter().copied());
        }
    }
    server_roots.sort();
    server_roots.dedup();
    if server_roots.len() > 1 {
        server_roots.retain(|id| *id != root);
    }

    let empty_ids: Box<dyn Iterator<Item = veil_core::error::Result<ObjectId>> + 'a> = Box::new(std::iter::empty());
    let mut helper = LogEntries {
        repo,
        precomputed: None,
        ids: empty_ids.peekable(),
        signers,
        tags: HashMap::new(),
        remote_tags: HashMap::new(),
        workspaces: HashMap::new(),
        current,
        root,
        truncated: false,
        limit,
        yielded: 0,
        searcher: None,
        precomputed_search: None,
        show_skipped,
        max_changes: None,
        skipped: 0,
        stopped: false,
        // Never reached from a sparse sandbox (`log_entries_with`).
        within: None,
    };
    let mut local_searcher = path_filter.as_ref().map(|(p, follow)| {
        Searcher::new(
            repo,
            LogFilter {
                paths: vec![p.clone()],
                follow: *follow,
                ..LogFilter::default()
            },
        )
    });

    // Build `LogEntry` and `(generation, parents)` for every local commit.
    let mut local_entries: HashMap<ObjectId, (veil_core::graph_index::Gen, Vec<ObjectId>, Option<LogEntry>)> = HashMap::new();
    let mut searched = 0usize;
    for id in &local_ids {
        let g = repo.held().generation(id)?.unwrap_or(0);
        let Some(s) = repo.held().snapshot(id)? else { continue };
        let matches_filter = match &mut local_searcher {
            Some(sr) => matches!(sr.check(id)?, Match::Yes { .. }),
            None => true,
        };
        if !matches_filter {
            local_entries.insert(*id, (g, s.parents.clone(), None));
            continue;
        }
        let is_root = *id == root;
        let description = description(repo, &s);
        let empty = if is_root || s.parents.is_empty() {
            false
        } else if s.parents.len() == 1 {
            let p = &s.parents[0];
            let parent_tree = match repo.held().snapshot(p)? {
                Some(ps) => Some(ps.tree),
                None => {
                    let w = veil_core::promisor::Located { snapshot: *p, path: String::new(), id: *p, chain: None };
                    promisor
                        .fetch_objects(&[w])?
                        .into_iter()
                        .next()
                        .flatten()
                        .and_then(|raw| match veil_core::object::Object::decode(&raw).ok()? {
                            veil_core::object::Object::Snapshot(ps) => Some(ps.tree),
                            _ => None,
                        })
                }
            };
            parent_tree == Some(s.tree)
        } else {
            repo.is_empty_change(id).unwrap_or(false)
        };
        let parents = s
            .parents
            .iter()
            .map(|p| {
                let change_short = repo.held().snapshot(p).ok().flatten().map(|ps| ps.change_id.short());
                ParentRef { snapshot_id: p.hex(), snapshot_short: p.short(), withheld: change_short.is_none(), change_short, id: *p }
            })
            .collect();
        let e = LogEntry {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: s.change_id.display(),
            change_short: s.change_id.short(),
            root: is_root,
            current: Some(*id) == current,
            author: (!is_root).then(|| s.author.clone()),
            agent: s.agent.clone(),
            timestamp: if is_root { None } else { rfc3339(s.timestamp) },
            signature: (!is_root).then(|| sig(repo, &repo.keys().snapshot_status_with(&s, &helper.signers), &s)),
            workspaces: workspaces.remove(id).unwrap_or_default(),
            tags: tags.remove(id).unwrap_or_default(),
            remote_tags: remote_tags.remove(id).unwrap_or_default(),
            empty,
            conflicts: s.conflicts.clone(),
            embargo: s.embargo.as_ref().map(|e| LogEmbargo { id: e.clone(), released: repo.keys().embargo_released(e) }),
            description,
            parents,
            files: None,
            not_searched: None,
            id: *id,
            timestamp_ms: s.timestamp,
        };
        if path_filter.is_some() {
            searched += 1;
        }
        local_entries.insert(*id, (g, s.parents.clone(), Some(e)));
    }

    let mut server_entries: Vec<LogEntry> = Vec::new();
    let mut server_has_more = false;
    if !server_roots.is_empty() {
        let want = limit.map(|l| l.saturating_add(1));
        match &path_filter {
            Some((p, true)) => {
                // `vl log --follow -- PATH`: `q/history?follow=true` takes
                // one starting revision; ask from the newest server root
                // (or `main` when on it).
                let rev = server_roots[0].hex();
                let mut after: Option<String> = None;
                let mut seen_srv: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
                while want.is_none_or(|w| server_entries.len() < w) {
                    let page_n = want.map(|w| (w - server_entries.len()).clamp(1, 500)).unwrap_or(500);
                    let mut params = vec![("path", p.as_str().to_string()), ("follow", "true".into()), ("n", page_n.to_string())];
                    match &after {
                        Some(a) => params.push(("after", a.clone())),
                        None => params.push(("rev", rev.clone())),
                    }
                    let v = match promisor.query("history", &params)? {
                        Ok(v) => v,
                        Err((code, msg)) if code == "not_found" && msg.contains("revision") => return Ok(None),
                        Err((code, _)) if code == "no_path" || code == "not_found" => break,
                        Err((code, msg)) => anyhow::bail!("{msg} (server: {code})"),
                    };
                    if let Some(arr) = v["entries"].as_array() {
                        for item in arr {
                            let e = remote_log_entry(
                                item,
                                &helper.signers,
                                &crate::hub::server_keys(repo),
                                &mut tags,
                                &mut remote_tags,
                                &mut workspaces,
                                current,
                                root,
                            )?;
                            if !local_entries.contains_key(&e.id) && seen_srv.insert(e.id) {
                                server_entries.push(e);
                                searched += 1;
                                if want.is_some_and(|w| server_entries.len() >= w) {
                                    break;
                                }
                            }
                        }
                    }
                    after = v["next"].as_str().map(str::to_string);
                    if after.is_none() {
                        break;
                    }
                }
                server_has_more = after.is_some();
            }
            path_opt => {
                let rev = server_roots.iter().map(ObjectId::hex).collect::<Vec<_>>().join(",");
                let mut after: Option<String> = None;
                let mut seen_srv: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();
                while want.is_none_or(|w| server_entries.len() < w) {
                    let page_n = want.map(|w| (w - server_entries.len()).clamp(1, 500)).unwrap_or(500);
                    let mut params = vec![("n", page_n.to_string())];
                    if let Some((p, _)) = path_opt {
                        params.push(("path", p.as_str().to_string()));
                    }
                    match &after {
                        Some(a) => params.push(("after", a.clone())),
                        None => params.push(("rev", rev.clone())),
                    }
                    let v = match promisor.query("log", &params)? {
                        Ok(v) => v,
                        Err((code, msg)) if code == "not_found" && msg.contains("revision") => return Ok(None),
                        Err((code, _)) if code == "no_path" || code == "not_found" => break,
                        Err((code, msg)) => anyhow::bail!("{msg} (server: {code})"),
                    };
                    if let Some(arr) = v["entries"].as_array() {
                        for item in arr {
                            let e = remote_log_entry(
                                item,
                                &helper.signers,
                                &crate::hub::server_keys(repo),
                                &mut tags,
                                &mut remote_tags,
                                &mut workspaces,
                                current,
                                root,
                            )?;
                            if !local_entries.contains_key(&e.id) && seen_srv.insert(e.id) {
                                server_entries.push(e);
                                if path_opt.is_some() {
                                    searched += 1;
                                }
                                if want.is_some_and(|w| server_entries.len() >= w) {
                                    break;
                                }
                            }
                        }
                    }
                    after = v["next"].as_str().map(str::to_string);
                    if after.is_none() {
                        break;
                    }
                }
                server_has_more = after.is_some();
            }
        }
    }

    // Merge `local_entries` and `server_entries` in topological children-first
    // order (using exact generations from the server for `server_entries` when
    // local commits exist alongside them, as `GraphIndex::topo_iter` does).
    let mut entries: Vec<LogEntry> = if local_entries.is_empty() {
        server_entries
    } else if server_entries.is_empty() {
        let mut in_deg: HashMap<ObjectId, usize> = local_entries.keys().map(|id| (*id, 0)).collect();
        for (_, parents, _) in local_entries.values() {
            for p in parents {
                if let Some(d) = in_deg.get_mut(p) {
                    *d += 1;
                }
            }
        }
        let mut heap: std::collections::BinaryHeap<(veil_core::graph_index::Gen, ObjectId)> = in_deg
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| (local_entries[&id].0, id))
            .collect();
        let mut out = Vec::new();
        while let Some((_, id)) = heap.pop() {
            let (_, parents, entry) = local_entries.remove(&id).unwrap();
            if let Some(e) = entry {
                out.push(e);
            }
            for p in parents {
                if let Some(d) = in_deg.get_mut(&p) {
                    *d -= 1;
                    if *d == 0 {
                        heap.push((local_entries[&p].0, p));
                    }
                }
            }
        }
        out
    } else {
        let srv_ids: Vec<ObjectId> = server_entries.iter().map(|e| e.id).collect();
        let srv_gens = promisor.generations(&srv_ids)?.unwrap_or_default();
        let mut nodes: HashMap<ObjectId, (veil_core::graph_index::Gen, Vec<ObjectId>, Option<LogEntry>)> = local_entries;
        for (idx, e) in server_entries.into_iter().enumerate() {
            let g = srv_gens
                .get(idx)
                .copied()
                .flatten()
                .or_else(|| repo.held().generation(&e.id).ok().flatten())
                .unwrap_or(e.timestamp_ms.max(0) as u64);
            let parents: Vec<ObjectId> = e.parents.iter().map(|p| p.id).collect();
            nodes.insert(e.id, (g, parents, Some(e)));
        }
        let mut in_deg: HashMap<ObjectId, usize> = nodes.keys().map(|id| (*id, 0)).collect();
        for (_, parents, _) in nodes.values() {
            for p in parents {
                if let Some(d) = in_deg.get_mut(p) {
                    *d += 1;
                }
            }
        }
        let mut heap: std::collections::BinaryHeap<(veil_core::graph_index::Gen, ObjectId)> = in_deg
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| (nodes[&id].0, id))
            .collect();
        let mut out = Vec::new();
        while let Some((_, id)) = heap.pop() {
            let (_, parents, entry) = nodes.remove(&id).unwrap();
            if let Some(e) = entry {
                out.push(e);
            }
            for p in parents {
                if let Some(d) = in_deg.get_mut(&p) {
                    *d -= 1;
                    if *d == 0 {
                        heap.push((nodes[&p].0, p));
                    }
                }
            }
        }
        out
    };

    let mut truncated = server_has_more;
    if let Some(l) = limit {
        if entries.len() > l {
            truncated = true;
            if path_filter.is_some() {
                searched = searched.saturating_sub(entries.len() - l);
            }
            entries.truncate(l);
        }
    }
    if path_filter.is_some() && !truncated && !server_roots.is_empty() {
        // When a path-filtered log walks to the root without stopping at
        // `-n`, a full clone's `Searcher` visits every visible snapshot;
        // ask `q/log` for the total visible snapshots from `server_roots`
        // so `search.searched` matches.
        let rev = server_roots.iter().map(ObjectId::hex).collect::<Vec<_>>().join(",");
        let mut server_total = 0usize;
        let mut after: Option<String> = None;
        loop {
            let mut params = vec![("n", "500".into())];
            match &after {
                Some(a) => params.push(("after", a.clone())),
                None => params.push(("rev", rev.clone())),
            }
            let Ok(Ok(v)) = promisor.query("log", &params) else { break };
            server_total += v["entries"].as_array().map_or(0, Vec::len);
            after = v["next"].as_str().map(str::to_string);
            if after.is_none() {
                break;
            }
        }
        if server_total > 0 {
            searched = local_searcher.as_ref().map_or(0, |s| s.searched) + server_total;
        }
    }
    // Fill in `change_short` on every parent from the entries we already
    // have (or held snapshots), asking `q/show?stat=true` only for any
    // parent beyond the page.
    let mut known_changes: HashMap<ObjectId, String> = entries.iter().map(|e| (e.id, e.change_short.clone())).collect();
    for e in &mut entries {
        for p in &mut e.parents {
            if p.change_short.is_some() {
                continue;
            }
            if let Some(c) = known_changes.get(&p.id) {
                p.change_short = Some(c.clone());
                p.withheld = false;
                continue;
            }
            if let Ok(Some(s)) = repo.held().snapshot(&p.id) {
                let c = s.change_id.short();
                known_changes.insert(p.id, c.clone());
                p.change_short = Some(c);
                p.withheld = false;
                continue;
            }
            if let Ok(Ok(v)) = promisor.query("show", &[("rev", p.id.hex()), ("stat", "true".into())]) {
                if let Some(c) = v["change_short"].as_str() {
                    let c = c.to_string();
                    known_changes.insert(p.id, c.clone());
                    p.change_short = Some(c);
                    p.withheld = false;
                }
            }
        }
    }
    helper.truncated = truncated;
    helper.precomputed_search = path_filter.map(|_| LogSearch { searched, skipped: 0, stopped: false });
    helper.precomputed = Some(entries.into_iter());
    Ok(Some(helper))
}

pub fn log_entries_with<'a>(repo: &'a Repo, ws: &str, mut q: LogQuery) -> Result<LogEntries<'a>> {
    let mut tags: HashMap<ObjectId, Vec<TagLabel>> = HashMap::new();
    for (name, t) in &repo.view().tags {
        tags.entry(t.target).or_default().push(TagLabel { name: name.clone() });
    }
    let mut remote_tags: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, t) in &repo.view().remote_tags {
        remote_tags.entry(*t).or_default().push(name.clone());
    }
    let mut workspaces: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, w) in &repo.view().workspaces {
        workspaces.entry(w.wc).or_default().push(name.clone());
    }
    let current = repo.view().workspaces.get(ws).map(|w| w.wc);
    let root = repo.root_id();
    let signers = repo.keys().known_signers();

    // A sparse sandbox (`--only`, BUG-1844) is shown its own paths only: its
    // log comes from what this clone holds, restricted below, never from the
    // server's answer for the whole project.
    let sparse = q.filter.as_ref().is_some_and(|f| f.within.is_some());
    if repo.is_partial() && !sparse {
        if let Some(path_filter) = thin_log_route(&q) {
            let promisor = repo
                .store()
                .promisor()
                .ok_or_else(|| veil_core::VeilError::Unavailable("this thin clone has no connection to its server".into()))?;
            if let Some(entries) = thin_query_log(
                repo,
                &*promisor,
                q.roots.clone(),
                path_filter,
                q.limit,
                q.show_skipped,
                signers.clone(),
                tags.clone(),
                remote_tags.clone(),
                workspaces.clone(),
                current,
                root,
            )? {
                return Ok(entries);
            }
        }
    }

    // A thin clone with a local-only filter (`-r`, `-S`, `-G`, `--author`,
    // `--signed-by`, `--agent`, multiple paths): the history it shows is a
    // full clone's, paged in from the server where the walk reaches what it
    // does not hold (`Exact`; BUG-1290).
    if repo.is_partial() && q.ids.is_none() {
        let most = if q.filter.as_ref().is_some_and(|f| !f.is_empty()) { None } else { q.limit.map(|l| l + 1) };
        q.ids = Some(repo.exact().run(|r| {
            let mut ids = Vec::new();
            for id in r.held().visible_iter() {
                ids.push(id?);
                if most.is_some_and(|m| ids.len() >= m) {
                    break;
                }
            }
            Ok(ids)
        })?);
    }
    // All visible snapshots are produced lazily (the history index), so
    // `-n` reads only the history it shows.
    let mut ids: Box<dyn Iterator<Item = veil_core::error::Result<ObjectId>> + 'a> = match q.ids {
        Some(ids) => Box::new(ids.into_iter().map(Ok)),
        None => Box::new(repo.held().visible_iter()),
    };
    let within = q.filter.as_ref().and_then(|f| f.within.clone());
    let searcher = q.filter.filter(|f| !f.is_empty()).map(|f| Searcher::new(repo, f));
    // Without a filter `-n` is known at once; with one, only once enough
    // snapshots matched.
    let mut truncated = false;
    if let (None, Some(l)) = (&searcher, q.limit) {
        let mut first = Vec::new();
        for id in ids.by_ref() {
            first.push(id?);
            if first.len() > l {
                break;
            }
        }
        truncated = first.len() > l;
        first.truncate(l);
        ids = Box::new(first.into_iter().map(Ok));
    }
    Ok(LogEntries {
        repo,
        precomputed: None,
        ids: ids.peekable(),
        signers,
        tags,
        remote_tags,
        workspaces,
        // None in a bare repository (no workspace).
        current,
        root,
        truncated,
        limit: q.limit,
        yielded: 0,
        searcher,
        precomputed_search: None,
        show_skipped: q.show_skipped,
        max_changes: q.max_changes,
        skipped: 0,
        stopped: false,
        within,
    })
}

impl Iterator for LogEntries<'_> {
    type Item = Result<LogEntry>;

    fn next(&mut self) -> Option<Result<LogEntry>> {
        if let Some(pre) = &mut self.precomputed {
            return pre.next().map(Ok);
        }
        if self.searcher.is_none() {
            return Some(self.ids.next()?.map_err(Into::into).and_then(|id| self.entry(id)));
        }
        loop {
            if self.limit.is_some_and(|l| self.yielded >= l) {
                self.truncated = self.ids.peek().is_some();
                return None;
            }
            let searcher = self.searcher.as_mut().expect("a filter");
            if self.max_changes.is_some_and(|m| searcher.searched >= m) {
                self.stopped = self.ids.peek().is_some();
                return None;
            }
            let id = match self.ids.next()? {
                Ok(id) => id,
                Err(e) => return Some(Err(e.into())),
            };
            let pickaxe = searcher.filter().pickaxe.is_some();
            match searcher.check(&id) {
                Err(e) => return Some(Err(e.into())),
                Ok(Match::No) => continue,
                Ok(Match::Yes { files }) => {
                    self.yielded += 1;
                    return Some(self.entry(id).map(|mut e| {
                        if pickaxe {
                            e.files = Some(files.iter().map(path).collect());
                        }
                        e
                    }));
                }
                Ok(Match::Skipped { sealed_for }) => {
                    self.skipped += 1;
                    if !self.show_skipped {
                        continue;
                    }
                    self.yielded += 1;
                    return Some(self.entry(id).map(|mut e| {
                        e.not_searched = Some(sealed_for.iter().map(Vis::from).collect());
                        e
                    }));
                }
            }
        }
    }
}

impl LogEntries<'_> {
    /// `--show-skipped`: skipped snapshots are entries.
    pub fn lists_skipped(&self) -> bool {
        self.show_skipped
    }

    /// How the search went (`None` without a filter). Complete once the
    /// iterator is done.
    pub fn search(&self) -> Option<LogSearch> {
        if let Some(s) = &self.precomputed_search {
            return Some(s.clone());
        }
        self.searcher.as_ref().map(|s| LogSearch { searched: s.searched, skipped: self.skipped, stopped: self.stopped })
    }

    fn entry(&mut self, id: ObjectId) -> Result<LogEntry> {
        let repo = self.repo;
        let s = repo.snapshot(&id)?;
        let root = id == self.root;
        let description = description(repo, &s);
        let parents = s
            .parents
            .iter()
            .map(|p| {
                // A parent may be withheld (unreleased embargo on a public
                // clone): it is known by snapshot id only.
                let change_short = match repo.exact().snapshot(p) {
                    Ok(Some(ps)) => Some(ps.change_id.short()),
                    _ => None,
                };
                ParentRef { snapshot_id: p.hex(), snapshot_short: p.short(), withheld: change_short.is_none(), change_short, id: *p }
            })
            .collect();
        let empty = !root
            && match &self.within {
                Some(set) if s.parents.len() > 1 => repo
                    .parents_tree_within(&s.parents, Some(set))
                    .and_then(|m| veil_core::vfs::restrict(repo.store(), &s.tree, set).map(|t| m.tree == t))
                    .unwrap_or(false),
                _ => repo.is_empty_change(&id).unwrap_or(false),
            };
        let conflicts = match &self.within {
            Some(set) => s.conflicts.iter().filter(|c| VPath::new(c).is_ok_and(|p| set.contains(&p))).cloned().collect(),
            None => s.conflicts.clone(),
        };
        Ok(LogEntry {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: s.change_id.display(),
            change_short: s.change_id.short(),
            root,
            current: Some(id) == self.current,
            author: (!root).then(|| s.author.clone()),
            agent: s.agent.clone(),
            timestamp: if root { None } else { rfc3339(s.timestamp) },
            signature: (!root).then(|| sig(repo, &repo.keys().snapshot_status_with(&s, &self.signers), &s)),
            workspaces: self.workspaces.remove(&id).unwrap_or_default(),
            tags: self.tags.remove(&id).unwrap_or_default(),
            remote_tags: self.remote_tags.remove(&id).unwrap_or_default(),
            empty,
            conflicts,
            embargo: s.embargo.as_ref().map(|e| LogEmbargo { id: e.clone(), released: repo.keys().embargo_released(e) }),
            description,
            parents,
            files: None,
            not_searched: None,
            id,
            timestamp_ms: s.timestamp,
        })
    }
}

pub fn log(repo: &Repo, ws: &str, limit: Option<usize>) -> Result<Log> {
    log_with(repo, ws, LogQuery { limit, ..LogQuery::default() })
}

pub fn log_with(repo: &Repo, ws: &str, q: LogQuery) -> Result<Log> {
    let mut it = log_entries_with(repo, ws, q)?;
    let entries = it.by_ref().collect::<Result<Vec<_>>>()?;
    Ok(Log { schema: LOG_SCHEMA, entries, truncated: it.truncated, search: it.search() })
}

// ---- diff ------------------------------------------------------------------------

/// `vl diff --json` (`veil.diff/2`).
#[derive(Serialize, Debug)]
pub struct Diff {
    pub schema: &'static str,
    #[serde(flatten)]
    pub body: DiffBody,
}

#[derive(Serialize, Debug)]
pub struct DiffBody {
    /// `--stat`: paths only, every `content` is null.
    pub stat: bool,
    pub files: Vec<FileDiff>,
    /// Inexact rename detection was skipped: too many files (only exact
    /// renames are shown). Absent otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub renames_skipped: bool,
    /// Folders not compared: in a thin clone, the server refuses their
    /// content (you no longer have access to them, BUG-1508). Only their
    /// paths, which their parents already named. Absent when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hidden: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct FileDiff {
    pub path: String,
    /// `added`, `deleted`, `modified`, `renamed` or `copied`.
    pub status: &'static str,
    /// Renamed or copied: the source path; `old` is the source's version
    /// (absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Renamed or copied: the similarity in percent (absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    /// The tier of the new version (of the old one for a deletion), as
    /// `vl ls` shows it, or `embargoed` when an unreleased embargo
    /// withholds either version (the hunks show both; BUG-992).
    pub tier: &'static str,
    /// Null for an added (old) or deleted (new) file.
    pub old: Option<EntryInfo>,
    pub new: Option<EntryInfo>,
    /// Null with `--stat`.
    pub content: Option<Content>,
}

#[derive(Serialize, Debug)]
pub struct EntryInfo {
    pub visibility: Vis,
    pub executable: bool,
    /// `100644` or `100755`, as Git writes it.
    pub mode: &'static str,
    /// This reader can materialise the file.
    pub readable: bool,
    /// An unresolved conflict (null otherwise); its content is the file
    /// with markers this reader is shown.
    pub conflict: Option<ConflictInfo>,
    /// `file`, `symlink` (format 5) or `conflict`.
    pub kind: &'static str,
    /// A symlink's target, when this reader can read it (null otherwise,
    /// and for anything but a symlink).
    pub target: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Content {
    /// Either side is binary: no hunks.
    pub binary: bool,
    /// Either side is unreadable here: no hunks, and why.
    pub hidden: Option<Redaction>,
    pub hunks: Vec<Hunk>,
}

#[derive(Serialize, Debug)]
pub struct Hunk {
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<HunkLine>,
}

#[derive(Serialize, Debug)]
pub struct HunkLine {
    /// `context`, `added` or `removed`.
    pub kind: &'static str,
    /// The line, without its line break.
    pub text: String,
    /// False only for a last line without a line break.
    pub newline: bool,
}

/// `readable` costs a read of the object: the text output, which never
/// shows it, skips it (`check_readable: false` leaves it true).
fn entry_info(repo: &Repo, e: &TreeEntry, check_readable: bool) -> EntryInfo {
    if let Some(Looked { view, info }) = look(repo, e) {
        return EntryInfo {
            visibility: Vis::from(&view.visibility),
            executable: view.executable,
            mode: if view.executable { "100755" } else { "100644" },
            readable: !view.unreadable_side,
            conflict: Some(info),
            kind: entry_kind(e),
            target: None,
        };
    }
    EntryInfo {
        visibility: Vis::from(&verified_visibility(repo, e)),
        executable: e.executable,
        mode: git_mode(e, e.executable),
        readable: !check_readable || repo.store().entry_readable(e),
        conflict: None,
        kind: entry_kind(e),
        target: link_target(repo, e),
    }
}

/// The changes between two trees, each turned into a [`FileDiff`] by
/// [`item_diff`] (lazily, for the text output). In a thin clone both sides
/// are fetched first, each at its own path (BUG-1506): their content and
/// readability are read by id.
pub fn diff_changes(repo: &Repo, from: &ObjectId, to: &ObjectId) -> Result<(Vec<TreeChange>, Vec<VPath>)> {
    // A folder the server refuses is listed, never compared (BUG-1508).
    let (changes, hidden) = veil_core::tree::diff_trees_hiding(repo.store(), Some(from), Some(to))?;
    veil_core::tree::prefetch_changes(repo.store(), Some(from), Some(to), &changes)?;
    Ok((changes, hidden.into_iter().map(|h| h.path).collect()))
}

/// A folder a diff did not compare, as shown: its path and a slash (`/`
/// for the root).
pub fn hidden_dir(p: &VPath) -> String {
    if p.is_root() {
        "/".to_string()
    } else {
        format!("{p}/")
    }
}

fn file_diff_with(repo: &Repo, c: &TreeChange, stat: bool, check_readable: bool, attrs: &Attrs<'_>) -> FileDiff {
    FileDiff {
        path: path(&c.path),
        status: status_word(c),
        from: None,
        score: None,
        tier: c.new.as_ref().or(c.old.as_ref()).map_or("public", |e| entry_tier(repo, e)),
        old: c.old.as_ref().map(|e| entry_info(repo, e, check_readable)),
        new: c.new.as_ref().map(|e| entry_info(repo, e, check_readable)),
        content: (!stat).then(|| content(repo, c, attrs)),
    }
}

/// The [`FileDiff`] of a detected item (a pair: the source's version against
/// the destination's).
pub fn item_diff(repo: &Repo, item: &Item, stat: bool, attrs: &Attrs<'_>) -> FileDiff {
    item_diff_with(repo, item, stat, true, attrs)
}

/// [`item_diff`] for the text output of a full diff, which does not show
/// `readable`: each entry's `readable` is left true instead of costing a
/// second read of every object.
pub(crate) fn item_diff_for_text(repo: &Repo, item: &Item, attrs: &Attrs<'_>) -> FileDiff {
    item_diff_with(repo, item, false, false, attrs)
}

/// The attributes diffs are shown under: the working copy's
/// `.veilattributes` (as Git does), with the device-local file.
pub fn diff_attrs(repo: &Repo) -> Attrs<'_> {
    Attrs::for_backend(repo.store(), &**repo.backend())
}

fn item_diff_with(repo: &Repo, item: &Item, stat: bool, check_readable: bool, attrs: &Attrs<'_>) -> FileDiff {
    match item {
        Item::Change(c) => file_diff_with(repo, c, stat, check_readable, attrs),
        Item::Pair(p) => {
            let mut f = file_diff_with(repo, &pair_change(p), stat, check_readable, attrs);
            f.status = if p.copy { "copied" } else { "renamed" };
            f.from = Some(path(&p.from));
            f.score = Some(p.score);
            f
        }
    }
}

fn content(repo: &Repo, c: &TreeChange, attrs: &Attrs<'_>) -> Content {
    let read = |e: &Option<TreeEntry>| -> Result<Vec<u8>, Redaction> {
        match e {
            None => Ok(Vec::new()),
            Some(e) => match veil_core::conflict::read_file_like(repo.store(), e) {
                Ok(d) => Ok(d),
                Err(err) if err.is_unreadable() => Err(redaction_for_diff(repo, e, &err)),
                Err(err) => Err(Redaction { reason: "error", message: err.to_string() }),
            },
        }
    };
    let none = |binary, hidden| Content { binary, hidden, hunks: Vec::new() };
    let (old, new) = match (read(&c.old), read(&c.new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(v), _) | (_, Err(v)) => return none(false, Some(v)),
    };
    // `.veilattributes`: `-diff` / `binary` show "binary"; `diff=<name>`
    // diffs the output of this device's textconv of that name, if it
    // defines one (never anything a tree defines; nothing is cached).
    let (old, new) = match veil_core::attributes::diff_strategy(repo.store(), attrs, &c.path) {
        veil_core::attributes::DiffAttr::Binary => return none(true, None),
        veil_core::attributes::DiffAttr::Driver(name) => match repo.store().device_drivers() {
            Some(d) => {
                let conv = |data: &[u8]| if data.is_empty() { Some(Vec::new()) } else { d.textconv(&name, &c.path, data) };
                match (conv(&old), conv(&new)) {
                    (Some(a), Some(b)) => (a, b),
                    _ => (old, new),
                }
            }
            None => (old, new),
        },
        veil_core::attributes::DiffAttr::Auto => (old, new),
    };
    if looks_binary(&old) || looks_binary(&new) {
        return none(true, None);
    }
    let old_s = String::from_utf8_lossy(&old);
    let new_s = String::from_utf8_lossy(&new);
    // Bounded (BUG-484), as `vl diff`'s text output is.
    let mut scratch = String::new();
    Content { binary: false, hidden: None, hunks: hunks(&veil_core::textmerge::create_patch(&old_s, &new_s, &mut scratch)) }
}

fn hunks(patch: &diffy::Patch<'_, str>) -> Vec<Hunk> {
    patch
        .hunks()
        .iter()
        .map(|h| Hunk {
            old_start: h.old_range().start(),
            old_lines: h.old_range().len(),
            new_start: h.new_range().start(),
            new_lines: h.new_range().len(),
            lines: h
                .lines()
                .iter()
                .map(|l| {
                    let (kind, s) = match l {
                        diffy::Line::Context(s) => ("context", *s),
                        diffy::Line::Delete(s) => ("removed", *s),
                        diffy::Line::Insert(s) => ("added", *s),
                    };
                    match s.strip_suffix('\n') {
                        Some(t) => HunkLine { kind, text: t.to_string(), newline: true },
                        None => HunkLine { kind, text: s.to_string(), newline: false },
                    }
                })
                .collect(),
        })
        .collect()
}

/// The two trees a diff compares, and the snapshots whose embargo each
/// side's versions answer to: for a snapshot against its parents, the
/// snapshot for both (its parents are withheld only if it is).
pub struct DiffTrees {
    pub from: ObjectId,
    pub to: ObjectId,
    pub from_rev: ObjectId,
    pub to_rev: ObjectId,
}

pub fn diff_body_with(repo: &Repo, t: &DiffTrees, stat: bool, r: &Renames) -> Result<DiffBody> {
    let (changes, hidden) = diff_changes(repo, &t.from, &t.to)?;
    let (items, renames_skipped) = detect_renames(repo, (&t.from, &t.to), changes, r)?;
    let attrs = diff_attrs(repo);
    let old = EmbargoTiers::of(repo, &t.from_rev)?;
    let new = if t.to_rev == t.from_rev { None } else { Some(EmbargoTiers::of(repo, &t.to_rev)?) };
    let new = new.as_ref().unwrap_or(&old);
    let mut files = Vec::with_capacity(items.len());
    for c in &items {
        let mut f = item_diff(repo, c, stat, &attrs);
        let (from, to) = match c {
            Item::Change(c) => ((&c.path, c.old.as_ref()), (&c.path, c.new.as_ref())),
            Item::Pair(p) => ((&p.from, Some(&p.old)), (&p.to, Some(&p.new))),
        };
        // A version an embargo withholds is "embargoed" whatever its label.
        let withheld = |tiers: &EmbargoTiers, (p, e): (&VPath, Option<&TreeEntry>)| e.is_some() && tiers.tier(repo, p, e, "public") == "embargoed";
        let public = |e: Option<&TreeEntry>| e.is_some_and(|e| entry_tier(repo, e) == "public");
        if (public(to.1) && withheld(new, to)) || (public(from.1) && withheld(&old, from)) {
            f.tier = "embargoed";
        }
        files.push(f);
    }
    Ok(DiffBody { stat, files, renames_skipped, hidden: hidden.iter().map(hidden_dir).collect() })
}

/// `vl diff --json` with rename detection on (the default).
pub fn diff(repo: &Repo, t: &DiffTrees, stat: bool) -> Result<Diff> {
    diff_with(repo, t, stat, &Renames::default())
}

pub fn diff_with(repo: &Repo, t: &DiffTrees, stat: bool, r: &Renames) -> Result<Diff> {
    Ok(Diff { schema: DIFF_SCHEMA, body: diff_body_with(repo, t, stat, r)? })
}

/// The two trees `vl diff` compares: a snapshot's parents and the snapshot
/// (`-r`, default `@`), or `--from` and `--to` (each default `@`).
pub fn diff_trees_for(ctx: &Ctx, rev: Option<&str>, from: Option<&str>, to: Option<&str>) -> Result<DiffTrees> {
    Ok(match (from, to) {
        (None, None) => {
            let id = ctx.rev(rev.unwrap_or("@"))?;
            let s = ctx.repo.snapshot(&id)?;
            DiffTrees {
                from: ctx.parents_tree(&s.parents)?,
                to: ctx.restrict_tree(s.tree)?,
                from_rev: id,
                to_rev: id,
            }
        }
        _ => {
            let a = ctx.rev(from.unwrap_or("@"))?;
            let b = ctx.rev(to.unwrap_or("@"))?;
            DiffTrees {
                from: ctx.restrict_tree(ctx.repo.snapshot(&a)?.tree)?,
                to: ctx.restrict_tree(ctx.repo.snapshot(&b)?.tree)?,
                from_rev: a,
                to_rev: b,
            }
        }
    })
}

// ---- show ------------------------------------------------------------------------

/// `vl show --json` (`veil.show/2`).
#[derive(Serialize, Debug)]
pub struct Show {
    pub schema: &'static str,
    pub snapshot_id: String,
    pub snapshot_short: String,
    pub change_id: String,
    pub change_short: String,
    pub root: bool,
    pub author: String,
    pub timestamp: Option<String>,
    /// Null for the root.
    pub signature: Option<Sig>,
    pub parents: Vec<SnapshotRef>,
    /// Local tags pointing here.
    pub tags: Vec<String>,
    pub embargo: Option<EmbargoInfo>,
    pub conflicts: Vec<String>,
    pub description: Option<String>,
    /// Who produced the content (*optional*: absent when no agent is
    /// recorded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<veil_core::object::Attribution>,
    /// This version is an abandoned attempt, for this reason (*optional*).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<String>,
    /// The change's recorded dead ends, oldest first (*optional*: absent
    /// when there are none).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<AttemptInfo>,
    /// The snapshot's changes against its parents.
    pub diff: DiffBody,
    /// The merged parents' tree and the snapshot's tree.
    #[serde(skip)]
    pub(crate) base_tree: ObjectId,
    #[serde(skip)]
    pub(crate) tree: ObjectId,
    #[serde(skip)]
    pub(crate) timestamp_ms: i64,
    #[serde(skip)]
    pub(crate) signature_status: Option<SignatureStatus>,
    #[serde(skip)]
    pub(crate) snapshot: Option<std::sync::Arc<Snapshot>>,
}

/// One recorded dead end of a change (`vl attempt drop`).
#[derive(Serialize, Debug)]
pub struct AttemptInfo {
    pub snapshot_id: String,
    pub snapshot_short: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<veil_core::object::Attribution>,
    pub timestamp: Option<String>,
    /// The paths the attempt changed, against its own parents.
    pub files: Vec<String>,
    /// Removed by `vl gc` or never fetched: only its id is known.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub missing: bool,
}

/// The attempts snapshot `s` lists, with what each changed.
pub fn attempts_of(repo: &Repo, s: &Snapshot, within: Option<&veil_core::vfs::SparseSet>) -> Result<Vec<AttemptInfo>> {
    let mut out = Vec::new();
    for a in &s.attempts {
        // As a full clone answers: a thin clone fetches an attempt it lacks.
        let Some(at) = repo.exact().snapshot(a)? else {
            out.push(AttemptInfo {
                snapshot_id: a.hex(),
                snapshot_short: a.short(),
                reason: String::new(),
                agent: None,
                timestamp: None,
                files: vec![],
                missing: true,
            });
            continue;
        };
        let base = repo.parents_tree_within(&at.parents, within)?.tree;
        let to = match within {
            Some(set) => veil_core::vfs::restrict(repo.store(), &at.tree, set)?,
            None => at.tree,
        };
        let diff = diff_body_with(repo, &DiffTrees { from: base, to, from_rev: *a, to_rev: *a }, true, &Renames::default())?;
        out.push(AttemptInfo {
            snapshot_id: a.hex(),
            snapshot_short: a.short(),
            reason: at.abandoned.clone().unwrap_or_default(),
            agent: at.agent.clone(),
            timestamp: rfc3339(at.timestamp),
            files: diff.files.into_iter().map(|f| f.path).collect(),
            missing: false,
        });
    }
    Ok(out)
}

#[derive(Serialize, Debug)]
pub struct EmbargoInfo {
    pub id: String,
    /// `pending`, `staged` (released here, not pushed yet), `released` or
    /// `unknown` (no record of it here).
    pub state: &'static str,
    /// Automatic release time of a pending embargo (null: manual release).
    pub until: Option<String>,
    #[serde(skip)]
    pub(crate) until_ms: Option<i64>,
}

/// `vl show --json` with rename detection on (the default).
pub fn show(ctx: &Ctx, rev: &str, stat: bool) -> Result<Show> {
    show_with(ctx, rev, stat, &Renames::default())
}

pub fn show_with(ctx: &Ctx, rev: &str, stat: bool, r: &Renames) -> Result<Show> {
    let mut s = show_header(ctx, rev, stat)?;
    let id = ctx.rev(rev)?;
    s.diff = diff_body_with(&ctx.repo, &DiffTrees { from: s.base_tree, to: s.tree, from_rev: id, to_rev: id }, stat, r)?;
    Ok(s)
}

/// [`show`] without the diff (`diff.files` is empty): the text output
/// renders the diff itself, one file at a time, from `base_tree` to `tree`.
pub fn show_header(ctx: &Ctx, rev: &str, stat: bool) -> Result<Show> {
    let repo = &ctx.repo;
    let id = ctx.rev(rev)?;
    let s = repo.snapshot(&id)?;
    let root = id == repo.root_id();
    let embargo = match &s.embargo {
        Some(e) => {
            let rec = repo.keys().load_embargo(e)?;
            let (state, until_ms) = match rec {
                Some(_) if repo.keys().release_state(e) == ReleaseState::Released => ("released", None),
                // Staged and in force by the op log (BUG-1487); otherwise
                // the next push does not publish it: pending.
                Some(_) if repo.keys().release_state(e) == ReleaseState::Staged && repo.staged_release_standing()?.0.get(e) == Some(&veil_core::commands::Standing::InForce) => ("staged", None),
                Some(r) => ("pending", r.until),
                None => ("unknown", None),
            };
            Some(EmbargoInfo { id: e.clone(), state, until: until_ms.and_then(rfc3339), until_ms })
        }
        None => None,
    };
    let status = (!root).then(|| repo.keys().snapshot_status(&s));
    let description = description(repo, &s);
    let base = ctx.parents_tree(&s.parents)?;
    let tree = ctx.restrict_tree(s.tree)?;
    let conflicts = s.conflicts.iter().filter(|c| ctx.in_only_str(c)).cloned().collect();
    Ok(Show {
        schema: SHOW_SCHEMA,
        snapshot_id: id.hex(),
        snapshot_short: id.short(),
        change_id: s.change_id.display(),
        change_short: s.change_id.short(),
        root,
        author: s.author.clone(),
        timestamp: rfc3339(s.timestamp),
        signature: status.as_ref().map(|st| sig(repo, st, &s)),
        parents: s.parents.iter().map(|p| snapshot_ref(repo, p)).collect(),
        tags: repo.view().tags.iter().filter(|(_, t)| t.target == id).map(|(n, _)| n.clone()).collect(),
        embargo,
        conflicts,
        description,
        agent: s.agent.clone(),
        abandoned: s.abandoned.clone(),
        attempts: attempts_of(repo, &s, ctx.only.as_ref())?,
        diff: DiffBody { stat, files: Vec::new(), renames_skipped: false, hidden: Vec::new() },
        base_tree: base,
        tree,
        timestamp_ms: s.timestamp,
        signature_status: status,
        snapshot: Some(s),
    })
}

// ---- workspace list, tag list, op log, secret list ----------------------------------------

/// `vl workspace list --json` (`veil.workspace.list/2`).
#[derive(Serialize, Debug)]
pub struct WorkspaceList {
    pub schema: &'static str,
    pub workspaces: Vec<WorkspaceItem>,
}

#[derive(Serialize, Debug)]
pub struct WorkspaceItem {
    pub name: String,
    /// The workspace the project directory is attached to.
    pub current: bool,
    pub working_copy: SnapshotRef,
}

pub fn workspace_list(repo: &Repo, current: &str) -> WorkspaceList {
    WorkspaceList {
        schema: WORKSPACE_LIST_SCHEMA,
        workspaces: repo
            .view()
            .workspaces
            .iter()
            .map(|(name, w)| WorkspaceItem {
                name: name.clone(),
                current: name == current,
                working_copy: snapshot_ref(repo, &w.wc),
            })
            .collect(),
    }
}

/// `vl tag list --json` (`veil.tag.list/2`).
#[derive(Serialize, Debug)]
pub struct TagList {
    pub schema: &'static str,
    pub tags: Vec<TagItem>,
    pub remote_tags: Vec<RemoteTagItem>,
}

#[derive(Serialize, Debug)]
pub struct TagItem {
    pub name: String,
    pub target: SnapshotRef,
    /// `release` (annotated: immutable) or `branch`.
    pub kind: &'static str,
    /// The annotation of a release tag (`null` for a plain tag).
    pub annotation: Option<AnnotationItem>,
}

/// An annotated tag object as `vl tag list --json` shows it.
#[derive(Serialize, Debug)]
pub struct AnnotationItem {
    pub id: String,
    /// `annotated`.
    pub kind: &'static str,
    pub tagger: String,
    pub timestamp: Option<String>,
    /// The message; `null` when sealed for a scope you are not in.
    pub message: Option<String>,
    /// The signer's name, when signed by a key a ring knows.
    pub signer: Option<String>,
    /// A valid Veil signature by a known key.
    pub verified: bool,
    /// What the check found (`signed by …`, `unsigned`, `unverified (…)`).
    pub status: String,
}


/// The annotation `id` shown as `name → target`.
pub fn annotation_item(repo: &Repo, name: &str, target: &ObjectId, id: &ObjectId) -> Option<AnnotationItem> {
    let c = repo.check_atag(name, target, id).ok()?;
    Some(AnnotationItem {
        id: id.hex(),
        kind: match c.atag.kind {
            veil_core::tag_object::AtagKind::Annotated => "annotated",
        },
        tagger: c.atag.tagger.clone(),
        timestamp: rfc3339(c.atag.timestamp),
        message: c.message.clone(),
        signer: c.signer.clone(),
        verified: c.verified,
        status: match (&c.signer, c.verification.is_signed()) {
            (Some(who), true) => format!("good signature by {who}"),
            (None, true) => "signed by a key no ring knows".into(),
            _ => c.verification.describe(),
        },
    })
}

#[derive(Serialize, Debug)]
pub struct RemoteTagItem {
    /// `remote/tag`.
    pub name: String,
    pub target: SnapshotRef,
}

pub fn tag_list(repo: &Repo) -> TagList {
    TagList {
        schema: TAG_LIST_SCHEMA,
        tags: repo
            .view()
            .tags
            .iter()
            .map(|(name, t)| TagItem {
                name: name.clone(),
                target: snapshot_ref(repo, &t.target),
                kind: if t.annotation.is_some() { "release" } else { "branch" },
                annotation: t.annotation.and_then(|a| annotation_item(repo, name, &t.target, &a)),
            })
            .collect(),
        remote_tags: repo
            .view()
            .remote_tags
            .iter()
            .map(|(name, t)| RemoteTagItem { name: name.clone(), target: snapshot_ref(repo, t) })
            .collect(),
    }
}

/// `vl op log --json` (`veil.op.log/1`).
#[derive(Serialize, Debug)]
pub struct OpLog {
    pub schema: &'static str,
    /// Newest first.
    pub operations: Vec<OpEntry>,
}

#[derive(Serialize, Debug)]
pub struct OpEntry {
    pub op_id: String,
    pub op_short: String,
    pub timestamp: Option<String>,
    pub user: String,
    pub description: String,
    /// The workspace the command was run for (format 6; absent for
    /// repository-wide commands and older operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// A merge of concurrent operations: the operations it merges.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub merges: Vec<String>,
    #[serde(skip)]
    pub(crate) timestamp_ms: i64,
}

pub(crate) fn op_entry(id: veil_core::ObjectId, op: veil_core::oplog::Operation) -> OpEntry {
    OpEntry {
        op_id: id.hex(),
        op_short: id.short(),
        timestamp: rfc3339(op.timestamp),
        user: op.user,
        description: op.description,
        workspace: op.workspace,
        merges: match op.parents.len() {
            0 | 1 => Vec::new(),
            _ => op.parents.iter().map(|p| p.short()).collect(),
        },
        timestamp_ms: op.timestamp,
    }
}

pub fn op_log(repo: &Repo, limit: usize) -> Result<OpLog> {
    Ok(OpLog {
        schema: OP_LOG_SCHEMA,
        operations: repo.op_log(limit)?.into_iter().map(|(id, op)| op_entry(id, op)).collect(),
    })
}

/// `vl op heads --json` (`veil.op.log/1`, one entry per head): the heads
/// of the operation log as stored, ancestors dropped.
pub fn op_heads(repo: &Repo) -> Result<OpLog> {
    let mut operations = Vec::new();
    for h in repo.ops().heads()? {
        operations.push(op_entry(h, repo.ops().get(&h)?));
    }
    Ok(OpLog {
        schema: OP_LOG_SCHEMA,
        operations,
    })
}

/// `vl secret list --json` (`veil.secret.list/1`): names only. A secret's
/// value never enters this structure. With `--scope` (a team vault) the
/// document gains `scope`, and each item who last set it, when, and under
/// which key generation (BUG-494); with `--exposed-to`, `exposed_to` too.
#[derive(Serialize, Debug)]
pub struct SecretList {
    pub schema: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed_to: Option<ExposedTo>,
    pub secrets: Vec<SecretItem>,
    /// Records of the team vault that do not count, and why (printed as
    /// warnings by the text output; not part of the JSON document).
    #[serde(skip)]
    pub(crate) warnings: Vec<String>,
}

/// The member `--exposed-to` asked about.
#[derive(Serialize, Debug)]
pub struct ExposedTo {
    pub member_id: String,
    pub name: String,
    /// Still a member of the scope (then every entry is readable to them).
    pub current: bool,
}

#[derive(Serialize, Debug)]
pub struct SecretItem {
    pub name: String,
    #[serde(flatten)]
    pub team: Option<TeamSecretItem>,
}

/// What a team-vault item adds.
#[derive(Serialize, Debug)]
pub struct TeamSecretItem {
    /// Name, in the scope's ring, of the member who last set it.
    pub set_by: String,
    pub set_by_id: String,
    pub timestamp: Option<String>,
    pub timestamp_ms: i64,
    /// Key generation the value is sealed under.
    pub generation: u32,
    /// Sealed under an old generation by a writer whose key ring was out of
    /// date, after a revocation: set it again (BUG-524).
    pub stale_generation: bool,
}

pub fn secret_list(repo: &Repo) -> Result<SecretList> {
    let vault = repo.vault_load()?;
    Ok(SecretList {
        schema: SECRET_LIST_SCHEMA,
        scope: None,
        exposed_to: None,
        secrets: vault.secrets.keys().map(|k| SecretItem { name: k.clone(), team: None }).collect(),
        warnings: vec![],
    })
}

/// `vl secret list --scope S [--exposed-to M] --json`: the live names of a
/// team vault (never values).
pub fn team_secret_list(repo: &Repo, scope: &str, exposed_to: Option<&str>) -> Result<SecretList> {
    let keys = repo.keys();
    crate::team_secret::check_scope(keys, scope)?;
    let vault = keys.team_vault(scope)?;
    let warnings = crate::team_secret::ignored_warnings(scope, &vault);
    let (entries, exposed_to) = match exposed_to {
        Some(who) => {
            let (id, name, exposed) = keys.team_vault_exposed_to(scope, who)?;
            let current = keys
                .ring_state(scope)?
                .and_then(|r| r.ok())
                .is_some_and(|st| st.members.contains_key(&id));
            (exposed, Some(ExposedTo { member_id: id, name, current }))
        }
        None => (vault.live().cloned().collect(), None),
    };
    Ok(SecretList {
        schema: SECRET_LIST_SCHEMA,
        scope: Some(scope.to_string()),
        exposed_to,
        secrets: entries
            .into_iter()
            .map(|e| SecretItem {
                name: e.name,
                team: Some(TeamSecretItem {
                    set_by: e.signer_name,
                    set_by_id: e.signer,
                    timestamp: rfc3339(e.timestamp),
                    timestamp_ms: e.timestamp,
                    generation: e.generation,
                    stale_generation: e.stale_generation,
                }),
            })
            .collect(),
        warnings,
    })
}

// ---- scan ------------------------------------------------------------------------

/// `vl scan --json` (`veil.scan/1`).
#[derive(Serialize, Debug)]
pub struct Scan {
    pub schema: &'static str,
    /// `working_copy` (the repository's own policy) or `gate`
    /// (`--policy-from`).
    pub mode: &'static str,
    /// The trusted policy file of a gate scan, as given.
    pub policy_from: Option<String>,
    /// Nested repositories, not scanned (`working_copy` only).
    pub nested: Vec<String>,
    /// Files with findings, or that could not be read (`gate` only), in
    /// path order.
    pub files: Vec<ScanFile>,
    /// Files that would publish a secret (in a gate: also unreadable ones).
    pub exposed: usize,
    /// Cloaked or isolated files that contain secrets (`working_copy` only).
    pub protected: usize,
    /// No exposed file: the command exits 0, otherwise 1.
    pub clean: bool,
}

#[derive(Serialize, Debug)]
pub struct ScanFile {
    pub path: String,
    /// The policy tier: `public`, `cloaked` or `isolated`.
    pub tier: &'static str,
    pub scope: Option<String>,
    /// Its tier keeps the secret out of public history (always false in a
    /// gate: a CI checkout publishes every file).
    pub protected: bool,
    pub findings: Vec<ScanFinding>,
    /// Why the file could not be read (`gate` only); it then has no
    /// findings and counts as exposed.
    pub error: Option<String>,
    #[serde(skip)]
    pub(crate) tier_label: String,
}

#[derive(Serialize, Debug)]
pub struct ScanFinding {
    pub line: usize,
    pub rule: &'static str,
    /// The scanner's redacted excerpt (the first characters and a length),
    /// never the secret.
    pub excerpt: String,
}

fn tier_word(t: &Tier) -> (&'static str, Option<String>) {
    match t {
        Tier::Public => ("public", None),
        Tier::Cloaked(s) => ("cloaked", Some(s.clone())),
        Tier::Isolated => ("isolated", None),
        Tier::Ignored => ("ignored", None),
    }
}

fn scan_findings(f: &[secrets::Finding]) -> Vec<ScanFinding> {
    f.iter().map(|f| ScanFinding { line: f.line, rule: f.rule, excerpt: f.excerpt.clone() }).collect()
}

/// `vl scan`: the working copy, under the repository's effective policy.
pub fn scan(ctx: &Ctx) -> Result<Scan> {
    let policy = ctx.repo.effective_policy(&*ctx.fs)?;
    // A nested repository is never recorded here (BUG-200): its files are
    // that repository's to scan.
    let nested = std::cell::RefCell::new(Vec::new());
    let skip = |p: &VPath| {
        if p.as_str() == ".veil" || policy.classify(p, true).tier == Tier::Ignored {
            return true;
        }
        let n = veil_core::vfs::is_nested_repository(&*ctx.fs, p).unwrap_or(false);
        if n {
            nested.borrow_mut().push(p.clone());
        }
        n
    };
    let walked = walk_files(&*ctx.fs, &VPath::root(), &skip)?;
    let nested: Vec<String> = nested.into_inner().iter().map(path).collect();
    let (mut exposed, mut protected) = (0, 0);
    let mut files = Vec::new();
    for p in walked {
        let class = policy.classify(&p, false);
        if class.tier == Tier::Ignored || class.allow_secrets {
            continue;
        }
        let findings = secrets::scan(&ctx.fs.read(&p)?);
        if findings.is_empty() {
            continue;
        }
        let is_protected = class.tier != Tier::Public;
        if is_protected {
            protected += 1;
        } else {
            exposed += 1;
        }
        let (tier, scope) = tier_word(&class.tier);
        files.push(ScanFile {
            path: path(&p),
            tier,
            scope,
            protected: is_protected,
            findings: scan_findings(&findings),
            error: None,
            tier_label: class.tier.label(),
        });
    }
    Ok(Scan { schema: SCAN_SCHEMA, mode: "working_copy", policy_from: None, nested, files, exposed, protected, clean: exposed == 0 })
}

/// `vl scan --policy-from FILE`: the CI gate over the files of `fs`, under
/// `policy` (see `cmd_scan_gate` in `main.rs`).
pub fn scan_gate(fs: &dyn StorageBackend, policy: &Policy, policy_from: &str) -> Result<Scan> {
    let skip = |p: &VPath| p.as_str() == ".veil" || veil_core::policy::vcs_metadata_name(p.file_name()).is_some();
    let mut exposed = 0;
    let mut files = Vec::new();
    for p in walk_files(fs, &VPath::root(), &skip)? {
        let class = policy.classify(&p, false);
        if class.tier == Tier::Public && class.allow_secrets {
            continue;
        }
        let (tier, scope) = tier_word(&class.tier);
        let mut file = ScanFile {
            path: path(&p),
            tier,
            scope,
            protected: false,
            findings: Vec::new(),
            error: None,
            tier_label: class.tier.label(),
        };
        match fs.read(&p) {
            Ok(d) => {
                let findings = secrets::scan(&d);
                if findings.is_empty() {
                    continue;
                }
                file.findings = scan_findings(&findings);
            }
            Err(e) => file.error = Some(e.to_string()),
        }
        exposed += 1;
        files.push(file);
    }
    Ok(Scan {
        schema: SCAN_SCHEMA,
        mode: "gate",
        policy_from: Some(policy_from.to_string()),
        nested: Vec::new(),
        files,
        exposed,
        protected: 0,
        clean: exposed == 0,
    })
}

// ---- ls --------------------------------------------------------------------------

/// `vl ls --json` (`veil.ls/2`).
#[derive(Serialize, Debug)]
pub struct Ls {
    pub schema: &'static str,
    pub snapshot: SnapshotRef,
    /// The snapshot is the working copy, so its local-only files are listed
    /// too: isolated and quarantined ones, and with `--all` ignored ones.
    pub working_copy: bool,
    /// `--all`: ignored paths are listed.
    pub all: bool,
    /// In tree order (depth first, by name within a directory).
    pub entries: Vec<LsEntry>,
}

#[derive(Serialize, Debug)]
pub struct LsEntry {
    pub path: String,
    /// A directory listed as a whole (never descended into): an ignored
    /// one, or a recorded one you no longer have access to (`kind` `dir`,
    /// BUG-1508).
    pub dir: bool,
    /// `public`, `cloaked`, `embargoed` (withheld by an unreleased embargo), `redacted` (recorded, but sealed for someone
    /// else or withheld here), `isolated`, `ignored` or
    /// `quarantined` (see [`entry_tier`]).
    pub tier: &'static str,
    /// The scope of a cloaked (or redacted cloaked) file.
    pub scope: Option<String>,
    /// In the snapshot. False for local-only files of the working copy.
    pub recorded: bool,
    /// The recorded entry's visibility label (null when not recorded).
    pub visibility: Option<Vis>,
    /// In bytes: the recorded size, or the file's on disk for a local-only
    /// file. Null for an ignored directory, and for an unresolved conflict
    /// (its file is only rendered when checked out, BUG-484).
    pub size: Option<u64>,
    pub executable: bool,
    /// This reader can read the content (a local-only file: it is on disk).
    pub readable: bool,
    /// Why the content cannot be read (`redacted` only). Never content.
    pub redaction: Option<Redaction>,
    /// A quarantined file: the secret rule that matched, and whether
    /// history keeps an earlier version (`held_back`) or none
    /// (`never_recorded`).
    pub quarantine: Option<LsQuarantine>,
    /// An unresolved conflict (null otherwise): `tier`, `visibility`,
    /// `size` and `executable` are those of the file with markers this
    /// reader is shown.
    pub conflict: Option<ConflictInfo>,
    /// `file`, `symlink` (format 5) or `conflict`.
    pub kind: &'static str,
    /// A symlink's target, when this reader can read it (null for a
    /// redacted link, whose target is sealed content, and for anything but
    /// a symlink).
    pub target: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct LsQuarantine {
    pub rule: &'static str,
    pub line: usize,
    pub state: &'static str,
}

fn vis_scope(v: &Visibility) -> Option<String> {
    match v {
        Visibility::Public => None,
        Visibility::Cloaked { scope } => Some(scope.clone()),
    }
}

/// Does `p` (an ignored directory when `dir`) fall under one of `filters`?
fn under(filters: &[VPath], p: &VPath, dir: bool) -> bool {
    let inside = |a: &VPath, b: &VPath| b.is_root() || a == b || a.as_str().starts_with(&b.child_prefix());
    filters.is_empty() || filters.iter().any(|f| inside(p, f) || (dir && inside(f, p)))
}

/// `vl ls [-r REV] [PATHS…]`: the files of a snapshot with their tiers. For
/// the working copy (and `local_files`, i.e. it was just snapshotted), the
/// local-only files the snapshot reported are listed too.
pub fn ls(ctx: &Ctx, rev: &str, paths: &[String], all: bool, local_files: bool) -> Result<Ls> {
    let repo = &ctx.repo;
    let id = ctx.rev(rev)?;
    let snap = repo.snapshot(&id)?;
    let working_copy = local_files && !ctx.bare && ctx.wc().ok() == Some(id);
    let filters: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let report = &ctx.report;
    let embargo = EmbargoTiers::of(repo, &id)?;
    let quarantined: HashMap<&VPath, &veil_core::secrets::Finding> =
        report.quarantined.iter().filter_map(|(p, f)| f.first().map(|f| (p, f))).collect();
    let quarantine = |p: &VPath| {
        quarantined.get(p).map(|f| LsQuarantine {
            rule: f.rule,
            line: f.line,
            state: if report.quarantine_kept.contains(p) { "held_back" } else { "never_recorded" },
        })
    };
    let mut entries: Vec<(VPath, LsEntry)> = Vec::new();
    let (files, hidden) = veil_core::tree::walk_files_hiding(repo.store(), &snap.tree)?;
    let files: Vec<(VPath, TreeEntry)> = files.into_iter().filter(|(p, _)| under(&filters, p, false)).collect();
    // A folder the server refuses (BUG-1508): listed whole, by its path only.
    for h in hidden.into_iter().filter(|h| under(&filters, h, true)) {
        entries.push((
            h.clone(),
            LsEntry {
                path: path(&h),
                dir: true,
                tier: "redacted",
                scope: None,
                recorded: true,
                visibility: None,
                size: None,
                executable: false,
                readable: false,
                redaction: Some(Redaction { reason: "no_access", message: "you no longer have access to this folder".into() }),
                quarantine: None,
                conflict: None,
                kind: EntryKind::Dir.name(),
                target: None,
            },
        ));
    }
    // Readability is read by id: in a thin clone, each asked for at its
    // own path first (BUG-1506).
    veil_core::tree::prefetch_files(repo.store(), &snap.tree, files.iter().map(|(p, e)| (p, e)))?;
    for (p, e) in files {
        let looked = look(repo, &e);
        let mut tier = entry_tier_with(repo, &e, looked.as_ref());
        let readable = match &looked {
            Some(l) => !l.view.unreadable_side,
            None => id_readable(repo, &e.id),
        };
        let redaction = match tier {
            "redacted" => redaction_for_listing(repo, &e),
            _ => None,
        };
        tier = embargo.tier(repo, &p, Some(&e), tier);
        let q = working_copy.then(|| quarantine(&p)).flatten();
        if q.is_some() {
            tier = "quarantined";
        }
        // A conflict's size is its materialised file's, which only a
        // checkout renders (BUG-484): unknown here.
        let (vis, size, executable) = match &looked {
            Some(l) => (l.view.visibility.clone(), None, l.view.executable),
            None => (verified_visibility(repo, &e), Some(e.size), e.executable),
        };
        let scope = vis_scope(&vis);
        entries.push((
            p.clone(),
            LsEntry {
                path: path(&p),
                dir: false,
                tier,
                scope,
                recorded: true,
                visibility: Some(Vis::from(&vis)),
                size,
                executable,
                readable,
                redaction,
                quarantine: q,
                conflict: looked.map(|l| l.info),
                kind: entry_kind(&e),
                target: link_target(repo, &e),
            },
        ));
    }
    if working_copy {
        let on_disk = |p: &VPath| ctx.fs.metadata(p).ok().flatten();
        let mut local: Vec<(VPath, &'static str, bool)> = Vec::new();
        local.extend(report.isolated.iter().map(|p| (p.clone(), "isolated", false)));
        local.extend(
            report
                .quarantined
                .iter()
                .filter(|(p, _)| !report.quarantine_kept.contains(p))
                .map(|(p, _)| (p.clone(), "quarantined", false)),
        );
        if all {
            local.extend(report.ignored_paths.iter().map(|(p, dir)| (p.clone(), "ignored", *dir)));
        }
        let recorded: std::collections::HashSet<VPath> = entries.iter().map(|(p, _)| p.clone()).collect();
        for (p, tier, dir) in local {
            if !under(&filters, &p, dir) || recorded.contains(&p) {
                continue;
            }
            let meta = on_disk(&p);
            entries.push((
                p.clone(),
                LsEntry {
                    path: path(&p),
                    dir,
                    tier,
                    scope: None,
                    recorded: false,
                    visibility: None,
                    size: if dir { None } else { meta.as_ref().map(|m| m.len) },
                    executable: meta.as_ref().is_some_and(|m| m.executable),
                    readable: meta.is_some(),
                    redaction: None,
                    quarantine: if tier == "quarantined" { quarantine(&p) } else { None },
                    conflict: None,
                    kind: match meta.as_ref().map(|m| m.kind) {
                        Some(veil_core::vfs::NodeKind::Symlink) => "symlink",
                        _ => "file",
                    },
                    // A local-only link's target stays local: never shown.
                    target: None,
                },
            ));
        }
    }
    for f in &filters {
        if !entries.iter().any(|(p, e)| under(std::slice::from_ref(f), p, e.dir)) {
            anyhow::bail!(
                "'{}' matches no file in {}{}",
                crate::render::safe(f.as_str()),
                id.short(),
                if working_copy && !all { " (`--all` also lists ignored files)" } else { "" }
            );
        }
    }
    // Tree order: by path components.
    entries.sort_by(|(a, _), (b, _)| a.as_str().split('/').cmp(b.as_str().split('/')));
    Ok(Ls { schema: LS_SCHEMA, snapshot: snapshot_ref(repo, &id), working_copy, all, entries: entries.into_iter().map(|(_, e)| e).collect() })
}

// ---- resolve --list -----------------------------------------------------------------

/// `vl resolve --list --json` (`veil.resolve.list/2`).
#[derive(Serialize, Debug)]
pub struct ResolveList {
    pub schema: &'static str,
    pub snapshot: SnapshotRef,
    /// In path order.
    pub conflicts: Vec<ResolveItem>,
}

#[derive(Serialize, Debug)]
pub struct ResolveItem {
    pub path: String,
    /// The conflict as data; null for a conflict recorded as markers in the
    /// file (older repository formats, embargoes) or a file moved aside by
    /// a file/directory conflict: those are resolved by editing the file.
    pub conflict: Option<ConflictInfo>,
}

/// `vl resolve [--list] [-r REV] [PATHS…]`.
pub fn resolve_list(ctx: &Ctx, rev: &str, paths: &[String]) -> Result<ResolveList> {
    let repo = &ctx.repo;
    let id = ctx.rev(rev)?;
    let snap = repo.snapshot(&id)?;
    let filters: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let mut conflicts: Vec<ResolveItem> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in veil_core::conflict::conflict_paths(repo.store(), &snap.tree)? {
        if !under(&filters, &p, false) {
            continue;
        }
        let e = lookup(repo.store(), &snap.tree, &p)?.expect("listed");
        seen.insert(p.to_string());
        conflicts.push(ResolveItem { path: path(&p), conflict: conflict_info(repo, &e) });
    }
    for c in &snap.conflicts {
        let Ok(p) = VPath::new(c) else { continue };
        if seen.contains(c) || !under(&filters, &p, false) {
            continue;
        }
        conflicts.push(ResolveItem { path: c.clone(), conflict: None });
    }
    conflicts.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')));
    Ok(ResolveList { schema: RESOLVE_LIST_SCHEMA, snapshot: snapshot_ref(repo, &id), conflicts })
}

// ---- the write methods of `vl serve --local` ----------------------------------------
//
// `vl describe`, `vl new` and `vl commit` call these too, so the CLI and the
// server make the same calls under the same repository lock (each `Repo`
// method is one transaction) and record the same operations. Their results
// are documented in `docs/reference/json-rpc.md`; the CLI prints text.

/// The operation a write ended at (the head of the operation log).
#[derive(Serialize, Debug, Clone)]
pub struct OpRef {
    pub op_id: String,
    pub op_short: String,
}

pub fn op_ref(repo: &Repo) -> OpRef {
    let id = repo.op_id();
    OpRef { op_id: id.hex(), op_short: id.short() }
}

/// `snapshot` (`veil.snapshot/2`): the working copy was recorded.
#[derive(Serialize, Debug)]
pub struct Recorded {
    pub schema: &'static str,
    pub working_copy: SnapshotRef,
    pub operation: OpRef,
}

/// The result of the automatic snapshot every command starts with.
pub fn recorded(ctx: &Ctx) -> Result<Recorded> {
    Ok(Recorded { schema: SNAPSHOT_SCHEMA, working_copy: snapshot_ref(&ctx.repo, &ctx.wc()?), operation: op_ref(&ctx.repo) })
}

/// `vl describe` (`veil.describe/2`).
#[derive(Serialize, Debug)]
pub struct Described {
    pub schema: &'static str,
    /// The change with its new description (a new snapshot of it).
    pub described: SnapshotRef,
    pub operation: OpRef,
    #[serde(skip)]
    pub(crate) id: ObjectId,
}

/// A description must be one the command line could give (BUG-486): no
/// NUL, which no argument can carry.
pub fn check_message(message: &str) -> Result<()> {
    if message.contains('\0') {
        anyhow::bail!("a description cannot contain a NUL character");
    }
    Ok(())
}

pub fn describe(ctx: &mut Ctx, rev: &str, message: &str) -> Result<Described> {
    check_message(message)?;
    let id = ctx.rev(rev)?;
    let new = ctx.repo.describe(id, message)?;
    Ok(Described { schema: DESCRIBE_SCHEMA, described: snapshot_ref(&ctx.repo, &new), operation: op_ref(&ctx.repo), id: new })
}

/// `vl new` (`veil.new/2`).
#[derive(Serialize, Debug)]
pub struct NewChange {
    pub schema: &'static str,
    /// The new change, now the working copy.
    pub working_copy: SnapshotRef,
    pub operation: OpRef,
}

pub fn new_change(ctx: &mut Ctx, revs: &[String], message: &str) -> Result<NewChange> {
    check_message(message)?;
    let parents = if revs.is_empty() { vec![ctx.wc()?] } else { revs.iter().map(|r| ctx.rev(r)).collect::<Result<_>>()? };
    let ws = ctx.ws.clone();
    let id = ctx.repo.new_change(&ws, parents, message)?;
    Ok(NewChange { schema: NEW_SCHEMA, working_copy: snapshot_ref(&ctx.repo, &id), operation: op_ref(&ctx.repo) })
}

/// `vl commit` (`veil.commit/2`).
#[derive(Serialize)]
pub struct Committed {
    pub schema: &'static str,
    pub committed: SnapshotRef,
    /// The new, empty working-copy change on top of it.
    pub working_copy: SnapshotRef,
    /// Tags that moved from the parent to the committed change.
    pub advanced: Vec<String>,
    /// Tags at the parent that stayed.
    pub kept: Vec<KeptTag>,
    pub operation: OpRef,
    #[serde(skip)]
    pub(crate) result: veil_core::commands::CommitResult,
}

#[derive(Serialize, Debug)]
pub struct KeptTag {
    pub name: String,
    /// `no_advance` or `release_tag`.
    pub reason: &'static str,
}

/// `vl commit`: with `record`, the project directory is recorded and
/// committed as one operation ([`Ctx::commit`]).
pub fn commit(ctx: &mut Ctx, message: &str, advance: bool, record: bool) -> Result<Committed> {
    use veil_core::commands::TagKept;
    check_message(message)?;
    let r = match record {
        true => ctx.commit(message, advance)?,
        false => {
            let ws = ctx.ws.clone();
            ctx.repo.commit(&ws, message, advance)?
        }
    };
    let repo = &ctx.repo;
    Ok(Committed {
        schema: COMMIT_SCHEMA,
        committed: snapshot_ref(repo, &r.committed),
        working_copy: snapshot_ref(repo, &r.wc),
        advanced: r.advanced.clone(),
        kept: r
            .kept
            .iter()
            .map(|(name, why)| match why {
                TagKept::NoAdvance => KeptTag { name: name.clone(), reason: "no_advance" },
                TagKept::Release => KeptTag { name: name.clone(), reason: "release_tag" },
            })
            .collect(),
        operation: op_ref(repo),
        result: r,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_what_could_drive_a_terminal() {
        #[derive(Serialize)]
        struct D {
            s: String,
        }
        let s = to_json(&D { s: "a\x1b[2J\u{9b}\u{7f}\u{202e}b\nc✓".into() }).unwrap();
        assert_eq!(s, r#"{"s":"a\u001b[2J\u009b\u007f\u202eb\nc✓"}"#);
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["s"], "a\x1b[2J\u{9b}\u{7f}\u{202e}b\nc✓");
    }

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_762_257_600_123).unwrap(), "2025-11-04T12:00:00.123Z");
    }
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use crate::cli::Cli;

    /// Every read command takes `--json`; nothing else claims to.
    #[test]
    fn every_read_command_takes_json() {
        let read: &[&[&str]] = &[
            &["status"],
            &["st"],
            &["log"],
            &["diff"],
            &["show"],
            &["workspace", "list"],
            &["ws", "list"],
            &["tag", "list"],
            &["op", "log"],
            &["scan"],
            &["scan", "--policy-from", "f"],
            &["secret", "list"],
            &["ls"],
            &["ls", "-r", "@-", "src"],
        ];
        for args in read {
            let with = |json: bool| {
                let mut a = vec!["vl"];
                a.extend_from_slice(args);
                if json {
                    a.push("--json");
                }
                Cli::try_parse_from(&a).unwrap_or_else(|e| panic!("{a:?}: {e}")).cmd.wants_json()
            };
            assert!(with(true), "{args:?} --json");
            assert!(!with(false), "{args:?}");
        }
        for args in [&["vl", "commit", "-m", "x"][..], &["vl", "files"], &["vl", "scope", "list"]] {
            assert!(!Cli::try_parse_from(args).unwrap().cmd.wants_json());
        }
        assert!(Cli::try_parse_from(["vl", "commit", "-m", "x", "--json"]).is_err(), "write commands do not take --json");
        assert!(Cli::try_parse_from(["vl", "push", "--json"]).is_err(), "a push takes no --json");
    }
}

// ---- blame -----------------------------------------------------------------------

/// `vl blame --json` (`veil.blame/2`).
#[derive(Serialize, Debug)]
pub struct BlameDoc {
    pub schema: &'static str,
    pub path: String,
    pub rev: SnapshotRef,
    /// Annotated as a public mirror sees the history (`--public`).
    pub public: bool,
    /// A diff was past its work limit somewhere: a differing middle was
    /// attributed whole to one change.
    pub coarse: bool,
    /// Why the walk stopped early: `max_changes` or `budget` (null: it
    /// did not).
    pub stopped: Option<&'static str>,
    /// Snapshot visits of the walk.
    pub visited: usize,
    /// How many lines have no change.
    pub unattributed: usize,
    pub lines: Vec<BlameLineDoc>,
    /// Every change a line is attributed to, once, newest first.
    pub changes: Vec<SnapshotRef>,
}

#[derive(Serialize, Debug)]
pub struct BlameLineDoc {
    /// 1-based.
    pub line: usize,
    /// The line, without its line break.
    pub text: String,
    /// The change that introduced the line (null when unattributed).
    pub change: Option<String>,
    pub change_short: Option<String>,
    pub snapshot: Option<String>,
    /// The file's path in that change (another name with `--follow`).
    pub path: Option<String>,
    /// The author claim of that change (anyone who can push writes it).
    pub author: Option<String>,
    pub timestamp: Option<String>,
    /// Why there is no change (null when attributed).
    pub unattributed: Option<UnattributedDoc>,
    #[serde(skip)]
    pub(crate) timestamp_ms: i64,
}

#[derive(Serialize, Debug)]
pub struct UnattributedDoc {
    /// `sealed` (the history it would move into is sealed for this
    /// reader), `max_changes` or `budget`.
    pub reason: &'static str,
    /// With `sealed`: for whom.
    pub sealed_for: Option<Vis>,
}

/// What `vl blame` annotates.
pub struct BlameRequest<'a> {
    pub path: &'a str,
    pub rev: &'a str,
    pub lines: Option<(usize, usize)>,
    pub follow: bool,
    pub max_changes: usize,
    pub public: bool,
}

/// `vl blame` in a thin clone when `id` is on the server (S16,
/// `docs/HUB.md` §13.34): answered from `q/blame` (paged if needed)
/// without paging history into `.veil/objects/`. Returns `Ok(None)` if the
/// file is a secret or a conflict on the server (so the local blame runs).
fn thin_query_blame(
    repo: &Repo,
    promisor: &dyn veil_core::promisor::Promisor,
    id: &ObjectId,
    p: &VPath,
    req: &BlameRequest<'_>,
) -> Result<Option<BlameDoc>> {
    let mut after = req.lines.map(|(a, _)| a.saturating_sub(1)).unwrap_or(0);
    let to_line = req.lines.map(|(_, b)| b);
    let mut lines: Vec<BlameLineDoc> = Vec::new();
    let mut changes_by_id: HashMap<String, (i64, ObjectId, SnapshotRef)> = HashMap::new();
    let mut coarse = false;
    let mut visited = 0usize;
    loop {
        if let Some(to) = to_line {
            if after >= to {
                break;
            }
        }
        let mut params = vec![
            ("path", path(p)),
            ("rev", id.hex()),
            ("follow", req.follow.to_string()),
            ("after", after.to_string()),
        ];
        if let Some(to) = to_line {
            params.push(("n", (to - after).to_string()));
        }
        let v = match promisor.query("blame", &params)? {
            Ok(v) => v,
            Err((code, _)) if code == "bad_request" => return Ok(None),
            Err((code, msg)) if code == "not_found" && msg.contains("revision") => return Ok(None),
            Err((code, _)) if code == "no_path" || code == "not_found" => {
                anyhow::bail!("{} does not exist in {}", crate::render::safe(p.as_str()), id.short());
            }
            Err((code, msg)) => anyhow::bail!("{msg} (server: {code})"),
        };
        coarse |= v["coarse"].as_bool().unwrap_or(false);
        visited = visited.max(v["visited"].as_u64().unwrap_or(0) as usize);
        let line_count = v["line_count"].as_u64().unwrap_or(0) as usize;
        if let Some((a, _)) = req.lines {
            if line_count < a && a > 1 {
                anyhow::bail!("-L {a},…: {} has fewer than {a} lines", crate::render::safe(p.as_str()));
            }
        }
        let mut authors_by_id: HashMap<String, String> = HashMap::new();
        if let Some(ch_arr) = v["changes"].as_array() {
            for c in ch_arr {
                let Some(sid) = c["snapshot_id"].as_str() else { continue };
                let Ok(oid) = ObjectId::from_hex(sid) else { continue };
                if let Some(a) = c["author"].as_str() {
                    authors_by_id.insert(sid.to_string(), a.to_string());
                }
                let sshort = c["snapshot_short"].as_str().unwrap_or_default().to_string();
                let cid = c["change_id"].as_str().map(str::to_string);
                let cshort = c["change_short"].as_str().map(str::to_string);
                let ts = c["timestamp"].as_i64().unwrap_or(0);
                let desc = c["description"]
                    .as_str()
                    .or_else(|| c["summary"].as_str())
                    .map(str::to_string);
                changes_by_id.entry(sid.to_string()).or_insert_with(|| {
                    (
                        ts,
                        oid,
                        SnapshotRef {
                            snapshot_id: sid.to_string(),
                            snapshot_short: sshort,
                            change_id: cid,
                            change_short: cshort,
                            available: true,
                            empty: false,
                            description: desc,
                        },
                    )
                });
            }
        }
        if let Some(l_arr) = v["lines"].as_array() {
            for r in l_arr {
                let line_no = r["line"].as_u64().unwrap_or(1) as usize;
                let text = r["text"].as_str().unwrap_or_default().to_string();
                let snap = r["snapshot"]
                    .as_str()
                    .or_else(|| r["snapshot_id"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let cshort = r["change_short"].as_str().map(str::to_string);
                let orig_path = r["path"].as_str().unwrap_or(p.as_str()).to_string();
                let ch_entry = changes_by_id.get(&snap);
                let cid = r["change"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| ch_entry.and_then(|(_, _, sr)| sr.change_id.clone()));
                let ts_ms = ch_entry.map(|(ts, _, _)| *ts).unwrap_or(0);
                let author = authors_by_id.get(&snap).cloned();
                lines.push(BlameLineDoc {
                    line: line_no,
                    text,
                    change: cid,
                    change_short: cshort,
                    snapshot: Some(snap),
                    path: Some(orig_path),
                    author,
                    timestamp: rfc3339(ts_ms),
                    unattributed: None,
                    timestamp_ms: ts_ms,
                });
            }
        }
        match v["next"].as_u64() {
            Some(next) => after = next as usize,
            None => break,
        }
    }
    let rev_ref = snapshot_ref_thin(repo, promisor, id);
    if !changes_by_id.is_empty() {
        // A full clone's `blame` walks every snapshot along the history
        // down to the snapshot where the last line was attributed,
        // including commits that did not touch this file; ask `q/log` from
        // `id` down to the oldest change in `changes_by_id` so `visited`
        // matches.
        let mut remaining: std::collections::HashSet<&str> = changes_by_id.keys().map(String::as_str).collect();
        let mut walk_count = 0usize;
        let mut log_after: Option<String> = None;
        let mut found_all = false;
        'log_walk: loop {
            let mut params = vec![("n", "500".into())];
            match &log_after {
                Some(a) => params.push(("after", a.clone())),
                None => params.push(("rev", id.hex())),
            }
            let Ok(Ok(v)) = promisor.query("log", &params) else { break };
            if let Some(arr) = v["entries"].as_array() {
                for item in arr {
                    walk_count += 1;
                    if let Some(sid) = item["snapshot_id"].as_str() {
                        remaining.remove(sid);
                        if remaining.is_empty() {
                            found_all = true;
                            break 'log_walk;
                        }
                    }
                }
            }
            log_after = v["next"].as_str().map(str::to_string);
            if log_after.is_none() {
                break;
            }
        }
        if found_all {
            visited = walk_count;
        }
    }
    let mut stamped: Vec<(i64, ObjectId, SnapshotRef)> = changes_by_id.into_values().collect();
    stamped.sort_by_key(|a| std::cmp::Reverse((a.0, a.1)));
    Ok(Some(BlameDoc {
        schema: BLAME_SCHEMA,
        path: path(p),
        rev: rev_ref,
        public: req.public,
        coarse,
        stopped: None,
        visited,
        unattributed: 0,
        lines,
        changes: stamped.into_iter().map(|(_, _, sr)| sr).collect(),
    }))
}

pub fn blame(ctx: &Ctx, req: &BlameRequest<'_>) -> Result<BlameDoc> {
    use veil_core::blame::{BlameOptions, Origin, Stop, Unattributed};
    let repo = &ctx.repo;
    let id = ctx.rev(req.rev)?;
    let p = ctx.repo_path(req.path)?;
    if let Some((a, b)) = req.lines {
        if a == 0 || b < a {
            anyhow::bail!("-L {a},{b}: give START,END with 1 <= START <= END");
        }
    }
    // In a sparse sandbox (`--only`), a path outside it is never asked of the
    // server: it falls through to the restricted tree below (BUG-1844).
    if repo.is_partial() && ctx.in_only(&p) && !req.public && req.max_changes >= 100_000 && repo.store().is_servers(&id)? {
        let promisor = repo
            .store()
            .promisor()
            .ok_or_else(|| veil_core::VeilError::Unavailable("this thin clone has no connection to its server".into()))?;
        if let Some(doc) = thin_query_blame(repo, &*promisor, &id, &p, req)? {
            return Ok(doc);
        }
    }
    let tree = ctx.restrict_tree(repo.snapshot(&id)?.tree)?;
    let reader = if req.public { Reader::Public } else { Reader::Me };
    let e = match crate::render::lookup_shown(repo, &tree, &p)? {
        Some(e) if e.kind.is_file_like() => e,
        Some(_) => anyhow::bail!("{} is a directory in {}, not a file", crate::render::safe(p.as_str()), id.short()),
        None => anyhow::bail!("{} does not exist in {}", crate::render::safe(p.as_str()), id.short()),
    };
    if let veil_core::blame::Readable::Redacted(_) = veil_core::blame::readable_version(repo.store(), &e, reader)? {
        let why = match req.public {
            true => None,
            false => crate::render::hidden_explanation(repo, &p, &e),
        };
        anyhow::bail!(
            "{}",
            why.unwrap_or_else(|| format!("{} cannot be read as the public sees it (it is not public)", crate::render::safe(p.as_str())))
        );
    }
    let o = BlameOptions {
        reader,
        follow: req.follow,
        max_changes: req.max_changes,
        lines: req.lines,
        within: ctx.only.clone(),
        ..BlameOptions::default()
    };
    let b = veil_core::blame::blame(repo, &id, &p, &o)?;
    if let Some((a, _)) = req.lines {
        if b.lines.is_empty() && a > 1 {
            anyhow::bail!("-L {a},…: {} has fewer than {a} lines", crate::render::safe(p.as_str()));
        }
    }
    let mut changes: Vec<ObjectId> = Vec::new();
    let mut lines = Vec::with_capacity(b.lines.len());
    for l in &b.lines {
        let text = String::from_utf8_lossy(l.text.strip_suffix(b"\n").unwrap_or(&l.text)).into_owned();
        let mut doc = BlameLineDoc {
            line: l.number,
            text,
            change: None,
            change_short: None,
            snapshot: None,
            path: None,
            author: None,
            timestamp: None,
            unattributed: None,
            timestamp_ms: 0,
        };
        match &l.origin {
            Origin::Snapshot { id, path: at } => {
                let s = repo.snapshot(id)?;
                if !changes.contains(id) {
                    changes.push(*id);
                }
                doc.change = Some(s.change_id.display());
                doc.change_short = Some(s.change_id.short());
                doc.snapshot = Some(id.hex());
                doc.path = Some(path(at));
                doc.author = Some(s.author.clone());
                doc.timestamp = rfc3339(s.timestamp);
                doc.timestamp_ms = s.timestamp;
            }
            Origin::Unattributed(u) => {
                doc.unattributed = Some(UnattributedDoc {
                    reason: u.as_str(),
                    sealed_for: match u {
                        Unattributed::Sealed(v) => Some(Vis::from(v)),
                        _ => None,
                    },
                })
            }
        }
        lines.push(doc);
    }
    // Newest first.
    let mut stamped: Vec<(i64, ObjectId)> = changes.iter().map(|c| (repo.snapshot(c).map_or(0, |s| s.timestamp), *c)).collect();
    stamped.sort_by(|a, b| b.cmp(a));
    Ok(BlameDoc {
        schema: BLAME_SCHEMA,
        path: path(&p),
        rev: snapshot_ref(repo, &id),
        public: req.public,
        coarse: b.coarse,
        stopped: b.stopped.map(|s| match s {
            Stop::MaxChanges => "max_changes",
            Stop::Budget => "budget",
        }),
        visited: b.visited,
        unattributed: b.unattributed(),
        lines,
        changes: stamped.iter().map(|(_, c)| snapshot_ref(repo, c)).collect(),
    })
}

// ---- grep ------------------------------------------------------------------------

/// `vl grep --json` (`veil.grep/2`).
#[derive(Serialize, Debug)]
pub struct GrepDoc {
    pub schema: &'static str,
    /// The snapshot searched (never the working copy's local-only files).
    pub rev: SnapshotRef,
    /// Every matching line, by path then line.
    pub matches: Vec<GrepMatchDoc>,
    /// Every file with a match.
    pub files: Vec<GrepFileDoc>,
    pub skipped: GrepSkipped,
    /// Files of the snapshot searched or skipped.
    pub searched: usize,
}

#[derive(Serialize, Debug)]
pub struct GrepMatchDoc {
    pub path: String,
    /// 1-based.
    pub line: usize,
    /// The line without its line break (cut at 1 MiB).
    pub text: String,
    /// `public` or `cloaked` (a sealed secret file, and this reader holds
    /// the key).
    pub tier: &'static str,
    /// The line was longer than 1 MiB and is cut.
    pub truncated: bool,
}

#[derive(Serialize, Debug)]
pub struct GrepFileDoc {
    pub path: String,
    pub tier: &'static str,
    /// The scope of a cloaked file.
    pub scope: Option<String>,
    /// Matching lines (up to `--max-count`).
    pub count: usize,
    /// Binary content: its lines are not listed (unless `-a`).
    pub binary: bool,
    /// An unresolved conflict, searched in its rendering for this reader.
    pub conflict: bool,
}

#[derive(Serialize, Debug)]
pub struct GrepSkipped {
    /// Files this reader cannot read (and has no public version of).
    pub sealed: usize,
    /// Binary files that matched, whose lines are not listed.
    pub binary: usize,
    /// Files over 256 MiB.
    pub too_large: usize,
    /// Folders not searched: you no longer have access to them (a thin
    /// clone; the server refuses their content). Absent when none.
    #[serde(skip_serializing_if = "is_zero")]
    pub hidden_folders: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// What `vl grep` searches.
pub struct GrepRequest<'a> {
    pub pattern: &'a str,
    pub rev: &'a str,
    pub paths: &'a [String],
    pub opts: veil_core::grep::GrepOptions,
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '#' | '&' | '-' | '~') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `vl grep` in a thin clone when `id` is on the server (S16,
/// `docs/HUB.md` §13.34): answered from `q/grep` (paged through every page)
/// without fetching every file into `.veil/cache/`.
fn thin_query_grep(
    repo: &Repo,
    promisor: &dyn veil_core::promisor::Promisor,
    id: &ObjectId,
    pattern: &str,
    opts: &veil_core::grep::GrepOptions,
) -> Result<Option<GrepDoc>> {
    if opts.text || opts.paths.len() > 1 {
        return Ok(None);
    }
    let body = if opts.fixed { regex_escape(pattern) } else { pattern.to_string() };
    let body = if opts.word { format!("(?-u:(?:^|[^A-Za-z0-9_]))(?:{body})(?-u:(?:[^A-Za-z0-9_]|$))") } else { body };
    if body.len() > 4_096 {
        return Ok(None);
    }
    let rev_arg = id.hex();
    let path_arg = opts.paths.first().filter(|p| !p.is_root()).map(|p| p.as_str().to_string());

    let mut matches: Vec<GrepMatchDoc> = Vec::new();
    let mut files: Vec<GrepFileDoc> = Vec::new();
    let mut searched = 0usize;
    let mut server_sealed = 0usize;
    let mut after: Option<String> = None;
    loop {
        let mut params = vec![("pattern", body.clone()), ("rev", rev_arg.clone()), ("n", "1000".into())];
        if opts.ignore_case {
            params.push(("i", "true".into()));
        }
        if let Some(p) = &path_arg {
            params.push(("path", p.clone()));
        }
        if let Some(a) = &after {
            params.push(("after", a.clone()));
        }
        let v = match promisor.query("grep", &params)? {
            Ok(v) => v,
            Err((code, msg)) if code == "not_found" && msg.contains("revision") => return Ok(None),
            Err((code, _)) if code == "no_path" || code == "not_found" => break,
            Err((code, msg)) => anyhow::bail!("{msg} (server: {code})"),
        };
        searched += v["searched"].as_u64().unwrap_or(0) as usize;
        server_sealed += v["sealed"].as_u64().unwrap_or(0) as usize;
        if let Some(f_arr) = v["files"].as_array() {
            for f in f_arr {
                let Some(fp) = f["path"].as_str() else { continue };
                let file_matches = f["matches"].as_u64().unwrap_or(0) as usize;
                if file_matches == 0 {
                    continue;
                }
                let max = opts.max_count.unwrap_or(usize::MAX);
                if max == 0 {
                    continue;
                }
                let count = file_matches.min(max);
                files.push(GrepFileDoc {
                    path: fp.to_string(),
                    tier: "public",
                    scope: None,
                    count,
                    binary: false,
                    conflict: false,
                });
                if let Some(l_arr) = f["lines"].as_array() {
                    for l in l_arr.iter().take(count) {
                        let line_no = l["line"].as_u64().unwrap_or(1) as usize;
                        let text = l["text"].as_str().unwrap_or_default().to_string();
                        matches.push(GrepMatchDoc {
                            path: fp.to_string(),
                            line: line_no,
                            text,
                            tier: "public",
                            truncated: false,
                        });
                    }
                }
            }
        }
        after = v["next"].as_str().map(str::to_string);
        if after.is_none() {
            break;
        }
    }
    let mut skipped_sealed = 0usize;
    let mut skipped_binary = 0usize;
    let mut skipped_too_large = 0usize;
    if server_sealed > 0 {
        let re = veil_core::grep::compile(pattern, opts)?;
        // The server never decrypts secret files; walk the snapshot's tree
        // (held or fetched via `fetch`, never paging history via `history`)
        // to grep only the sealed entries locally with our keys.
        let tree_id = match repo.held().snapshot(id)? {
            Some(s) => Some(s.tree),
            None => {
                let w = veil_core::promisor::Located { snapshot: *id, path: String::new(), id: *id, chain: None };
                promisor
                    .fetch_objects(&[w])?
                    .into_iter()
                    .next()
                    .flatten()
                    .and_then(|raw| match veil_core::object::Object::decode(&raw).ok()? {
                        veil_core::object::Object::Snapshot(s) => Some(s.tree),
                        _ => None,
                    })
            }
        };
        if let Some(tree_id) = tree_id {
            let (all_files, _) = veil_core::tree::walk_files_hiding(repo.store(), &tree_id)?;
            let sealed_entries: Vec<(VPath, TreeEntry)> = all_files
                .into_iter()
                .filter(|(p, e)| !e.visibility.is_public() && under(&opts.paths, p, false))
                .collect();
            for (fp, _e) in sealed_entries {
                let mut single_opts = opts.clone();
                single_opts.paths = vec![fp.clone()];
                let g = veil_core::grep::grep(repo.store(), &tree_id, &re, &single_opts)?;
                skipped_sealed += g.skipped.sealed;
                skipped_binary += g.skipped.binary;
                skipped_too_large += g.skipped.too_large;
                for f in &g.files {
                    let scope = match &f.tier {
                        veil_core::grep::Tier::Cloaked(s) => Some(s.clone()),
                        _ => None,
                    };
                    let tier = f.tier.as_str();
                    files.push(GrepFileDoc {
                        path: path(&f.path),
                        tier,
                        scope,
                        count: f.count,
                        binary: f.binary,
                        conflict: f.conflict,
                    });
                    for l in &f.lines {
                        matches.push(GrepMatchDoc {
                            path: path(&f.path),
                            line: l.number,
                            text: String::from_utf8_lossy(&l.text).into_owned(),
                            tier,
                            truncated: l.truncated,
                        });
                    }
                }
            }
            files.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')));
            matches.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')).then_with(|| a.line.cmp(&b.line)));
        }
    }
    Ok(Some(GrepDoc {
        schema: GREP_SCHEMA,
        rev: snapshot_ref_thin(repo, promisor, id),
        matches,
        files,
        skipped: GrepSkipped { sealed: skipped_sealed, binary: skipped_binary, too_large: skipped_too_large, hidden_folders: 0 },
        searched,
    }))
}

pub fn grep(ctx: &Ctx, req: GrepRequest<'_>) -> Result<GrepDoc> {
    use veil_core::grep::Tier;
    let repo = &ctx.repo;
    let id = ctx.rev(req.rev)?;
    let mut o = req.opts;
    o.paths = req.paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let re = veil_core::grep::compile(req.pattern, &o)?;
    if repo.is_partial() && o.reader == Reader::Me && repo.store().is_servers(&id)? {
        let promisor = repo
            .store()
            .promisor()
            .ok_or_else(|| veil_core::VeilError::Unavailable("this thin clone has no connection to its server".into()))?;
        if let Some(doc) = thin_query_grep(repo, &*promisor, &id, req.pattern, &o)? {
            return Ok(doc);
        }
    }
    let tree = repo.snapshot(&id)?.tree;
    let g = veil_core::grep::grep(repo.store(), &tree, &re, &o)?;
    let embargo = EmbargoTiers::of(repo, &id)?;
    let mut matches = Vec::new();
    let mut files = Vec::new();
    for f in &g.files {
        let scope = match &f.tier {
            Tier::Cloaked(s) => Some(s.clone()),
            _ => None,
        };
        let entry = lookup(repo.store(), &tree, &f.path)?;
        let tier = embargo.tier(repo, &f.path, entry.as_ref(), f.tier.as_str());
        files.push(GrepFileDoc { path: path(&f.path), tier, scope, count: f.count, binary: f.binary, conflict: f.conflict });
        for l in &f.lines {
            matches.push(GrepMatchDoc {
                path: path(&f.path),
                line: l.number,
                text: String::from_utf8_lossy(&l.text).into_owned(),
                tier,
                truncated: l.truncated,
            });
        }
    }
    Ok(GrepDoc {
        schema: GREP_SCHEMA,
        rev: snapshot_ref(repo, &id),
        matches,
        files,
        skipped: GrepSkipped { sealed: g.skipped.sealed, binary: g.skipped.binary, too_large: g.skipped.too_large, hidden_folders: g.skipped.hidden_folders },
        searched: g.searched,
    })
}
