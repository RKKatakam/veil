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
//! is a [`Redaction`] (a reason, never the plaintext), descriptions sealed
//! for a scope the reader is not in are a [`HiddenText`], and secret
//! values never enter a result at all (`secret list` reads names only).
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
    keychain::{split_label, ReleaseState, SignatureStatus},
    rename::{Item, Pair, RenameOptions},
    search::{LogFilter, Match, Searcher},
    object::{EntryKind, Snapshot, Text, Visibility},
    policy::{Policy, Tier},
    attributes::Attrs,
    secrets::{self, looks_binary},
    tree::{diff_trees, lookup, TreeChange},
    vfs::walk_files,
    ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

use crate::ctx::Ctx;

// ---- schema names ------------------------------------------------------------

pub const STATUS_SCHEMA: &str = "veil.status/1";
pub const LOG_SCHEMA: &str = "veil.log/1";
pub const DIFF_SCHEMA: &str = "veil.diff/1";
pub const SHOW_SCHEMA: &str = "veil.show/1";
pub const WORKSPACE_LIST_SCHEMA: &str = "veil.workspace.list/1";
pub const TAG_LIST_SCHEMA: &str = "veil.tag.list/1";
pub const OP_LOG_SCHEMA: &str = "veil.op.log/1";
pub const SCAN_SCHEMA: &str = "veil.scan/1";
pub const SECRET_LIST_SCHEMA: &str = "veil.secret.list/1";
pub const ERROR_SCHEMA: &str = "veil.error/1";
pub const LS_SCHEMA: &str = "veil.ls/1";
pub const PUSH_PLAN_SCHEMA: &str = "veil.push.plan/1";
pub const RESOLVE_LIST_SCHEMA: &str = "veil.resolve.list/1";
pub const SNAPSHOT_SCHEMA: &str = "veil.snapshot/1";
pub const DESCRIBE_SCHEMA: &str = "veil.describe/1";
pub const NEW_SCHEMA: &str = "veil.new/1";
pub const COMMIT_SCHEMA: &str = "veil.commit/1";
pub const BLAME_SCHEMA: &str = "veil.blame/1";
pub const GREP_SCHEMA: &str = "veil.grep/1";

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

/// Who can read an entry: `{"kind":"cloaked","scope":"team","embargo":null}`.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Vis {
    /// `public`, `cloaked` or `embargoed`.
    pub kind: &'static str,
    /// The scope of a cloaked entry.
    pub scope: Option<String>,
    /// The embargo id of an embargoed entry.
    pub embargo: Option<String>,
}

impl From<&Visibility> for Vis {
    fn from(v: &Visibility) -> Vis {
        match v {
            Visibility::Public => Vis { kind: "public", scope: None, embargo: None },
            Visibility::Cloaked { scope } => Vis { kind: "cloaked", scope: Some(scope.clone()), embargo: None },
            Visibility::Embargoed { embargo } => Vis { kind: "embargoed", scope: None, embargo: Some(embargo.clone()) },
        }
    }
}

impl Vis {
    pub fn visibility(&self) -> Visibility {
        match (self.kind, &self.scope, &self.embargo) {
            ("cloaked", Some(s), _) => Visibility::Cloaked { scope: s.clone() },
            ("embargoed", _, Some(e)) => Visibility::Embargoed { embargo: e.clone() },
            _ => Visibility::Public,
        }
    }
}

/// Content this reader cannot see, and why. Never carries the content.
#[derive(Serialize, Debug, Clone)]
pub struct Redaction {
    /// `no_key` (cloaked for a scope you hold no key for, or unreadable),
    /// `withheld` (a public remote never delivered it), `not_released`
    /// (an unreleased embargo), `unwritable` (readable, but this
    /// filesystem could not hold the file), `missing` (a public object
    /// absent from the store: damage, not a redaction) or `error` (the
    /// store could not read it).
    pub reason: &'static str,
    /// The explanation the text output prints, unescaped.
    pub message: String,
}

/// A description sealed for a scope this reader is not in.
#[derive(Serialize, Debug, Clone)]
pub struct HiddenText {
    /// The scope the description is sealed for.
    pub scope: String,
    /// `no_key`, or `not_public` (a `--public` view: a public mirror
    /// cannot read it, whatever keys this reader holds).
    pub reason: &'static str,
}

/// A snapshot's description: the text, or why it is hidden.
fn description(repo: &Repo, s: &Snapshot) -> (Option<String>, Option<HiddenText>) {
    match repo.store().read_text(&s.description) {
        Some(t) => (Some(t), None),
        None => match &s.description {
            Text::Sealed(e) => (None, Some(HiddenText { scope: split_label(&e.scope).0.to_string(), reason: "no_key" })),
            Text::Plain(t) => (Some(t.clone()), None),
        },
    }
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
    pub description_hidden: Option<HiddenText>,
}

pub fn snapshot_ref(repo: &Repo, id: &ObjectId) -> SnapshotRef {
    snapshot_ref_as(repo, id, false)
}

/// [`snapshot_ref`], with `public`: the description as a public mirror
/// reads it (`--public` views). A description sealed for a cloak scope or
/// an unreleased embargo is hidden (`not_public`), keys held or not.
pub fn snapshot_ref_as(repo: &Repo, id: &ObjectId, public: bool) -> SnapshotRef {
    match repo.snapshot(id) {
        Ok(s) => {
            let (description, description_hidden) = match (&s.description, public) {
                (Text::Sealed(e), true) => match veil_core::git::public_description(repo.store(), &s.description) {
                    Some(t) => (Some(t), None),
                    None => (None, Some(HiddenText { scope: split_label(&e.scope).0.to_string(), reason: "not_public" })),
                },
                _ => description(repo, &s),
            };
            SnapshotRef {
                snapshot_id: id.hex(),
                snapshot_short: id.short(),
                change_id: Some(s.change_id.display()),
                change_short: Some(s.change_id.short()),
                available: true,
                empty: repo.is_empty_change(id).unwrap_or(false) && !s.parents.is_empty(),
                description,
                description_hidden,
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
            description_hidden: None,
        },
    }
}

/// A snapshot signature.
#[derive(Serialize, Debug, Clone)]
pub struct Sig {
    /// `good`, `unknown` (valid, by a key no key ring knows), `bad` or
    /// `unsigned`.
    pub status: &'static str,
    /// The member who signed (`good` only).
    pub signer: Option<String>,
    /// The signing public key, in hex, and its first 16 digits.
    pub key: Option<String>,
    pub key_short: Option<String>,
}

fn sig(status: &SignatureStatus, s: &Snapshot) -> Sig {
    let key = s.signature.as_ref().map(|g| g.key.clone());
    let key_short = s.signature.as_ref().map(|g| g.key.get(..16).unwrap_or(&g.key).to_string());
    let (status, signer) = match status {
        SignatureStatus::Good { name, .. } => ("good", Some(name.clone())),
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
pub fn detect_renames(repo: &Repo, changes: Vec<TreeChange>, r: &Renames) -> Result<(Vec<Item>, bool)> {
    if !r.detect {
        return Ok((changes.into_iter().map(Item::Change).collect(), false));
    }
    let d = veil_core::rename::detect(repo.store(), &changes, Reader::Me, &r.opts)?;
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
    /// `vl ls` shows it: `public`, `cloaked`, `embargoed` or `redacted`
    /// (this reader cannot read it; `visibility` says for whom it is).
    pub tier: &'static str,
    /// The new version is an unresolved conflict (null otherwise).
    pub conflict: Option<ConflictInfo>,
    /// What the new version is (the old one for a deletion): `file`,
    /// `symlink`, `gitlink` (format 5) or `conflict`.
    pub kind: &'static str,
    /// The old version's kind when a modification changed it (a file
    /// replaced by a symlink: `T` in the text); null otherwise.
    pub old_kind: Option<&'static str>,
}

/// What entry `e` is, as JSON spells it: `file`, `symlink`, `gitlink`,
/// `conflict` (or `dir`).
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
    // Never its embargo fallback: that is another version.
    let own = TreeEntry { fallback: None, ..e.clone() };
    if !repo.store().entry_readable(&own) {
        return None;
    }
    repo.store().read_entry(&own).ok().map(|t| String::from_utf8_lossy(&t).into_owned())
}

/// The Git mode of entry `e`: `100644`, `100755`, `120000` (symlink) or
/// `160000` (gitlink).
fn git_mode(e: &TreeEntry, executable: bool) -> &'static str {
    match e.kind {
        EntryKind::Symlink => "120000",
        EntryKind::Gitlink => "160000",
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
/// show it: `public` (plaintext, or a released embargo), `cloaked` or
/// `embargoed` (sealed, and this reader holds the key), or `redacted`
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
            Visibility::Embargoed { embargo } if repo.keys().embargo_released(embargo) => "public",
            Visibility::Cloaked { .. } => "cloaked",
            Visibility::Embargoed { .. } => "embargoed",
        };
    }
    match &verified_visibility(repo, e) {
        Visibility::Public => "public",
        Visibility::Embargoed { embargo } if repo.keys().embargo_released(embargo) => "public",
        _ if !id_readable(repo, &e.id) => "redacted",
        Visibility::Cloaked { .. } => "cloaked",
        Visibility::Embargoed { .. } => "embargoed",
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
            Redaction { reason: "withheld", message: format!("cloaked:{scope}; withheld by a public remote") }
        }
        Visibility::Embargoed { embargo } => {
            Redaction { reason: "not_released", message: format!("embargo {embargo}; not released") }
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
            Redaction { reason: "withheld", message: format!("{}; withheld by a public remote", e.visibility.label()) }
        }
        Visibility::Embargoed { .. } => {
            Redaction { reason: "not_released", message: format!("{}; not released yet", e.visibility.label()) }
        }
    }
}

// ---- status ----------------------------------------------------------------------

/// `vl status --json` (`veil.status/1`).
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
    /// Files still recorded with line endings `.gitattributes` would now
    /// convert (`vl renormalize` re-records them). Omitted when none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub renormalizable: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct WorkspaceInfo {
    pub name: String,
    /// Scope everything recorded in this workspace is cloaked under.
    pub cloak: Option<String>,
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
}

pub fn status(ctx: &Ctx) -> Result<Status> {
    let repo = &ctx.repo;
    let wc = ctx.wc()?;
    let s = repo.snapshot(&wc)?;
    let base = repo.parents_tree(&s.parents)?.tree;
    let changes = diff_trees(repo.store(), Some(&base), Some(&s.tree))?;
    let (changes, _) = detect_renames(repo, changes, &Renames::default())?;
    let report = &ctx.report;
    let mut redacted = Vec::new();
    for p in &report.carried {
        let entry = lookup(repo.store(), &s.tree, p)?;
        let why = entry.as_ref().and_then(|e| redaction_for_listing(repo, e));
        // Readable, yet never materialised: the filesystem refused it.
        let tier = entry.as_ref().map_or("redacted", |e| entry_tier(repo, e));
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
        let entry = VPath::new(c).ok().and_then(|cp| lookup(repo.store(), &s.tree, &cp).ok().flatten());
        let recorded_on = parents.iter().find_map(|ps| {
            let cp = VPath::new(c).ok()?;
            let before = lookup(repo.store(), &ps.tree, &cp).ok().flatten();
            (ps.conflicts.contains(c) && before.is_some() && before == entry).then(|| ps.change_id.short())
        });
        let conflict = entry.as_ref().and_then(|e| conflict_info(repo, e));
        conflicts.push(Conflict { path: c.clone(), recorded_on, conflict });
    }
    for ps in &parents {
        for c in &ps.conflicts {
            let Ok(cp) = VPath::new(c) else { continue };
            let before = lookup(repo.store(), &ps.tree, &cp)?;
            if before.is_some() && before == lookup(repo.store(), &s.tree, &cp)? && !conflicts.iter().any(|x| x.path == *c) {
                let conflict = before.as_ref().and_then(|e| conflict_info(repo, e));
                conflicts.push(Conflict { path: c.clone(), recorded_on: Some(ps.change_id.short()), conflict });
            }
        }
    }
    Ok(Status {
        schema: STATUS_SCHEMA,
        workspace: WorkspaceInfo { name: ctx.ws.clone(), cloak: repo.view().workspace(&ctx.ws)?.cloak.clone() },
        working_copy: snapshot_ref(repo, &wc),
        parents: s.parents.iter().map(|p| snapshot_ref(repo, p)).collect(),
        changes: changes.iter().map(|c| item_change(repo, c)).collect(),
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
        conflicts,
        renormalizable: report.renormalizable.iter().map(path).collect(),
    })
}

// ---- log -------------------------------------------------------------------------

/// `vl log --json` (`veil.log/1`).
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
    pub timestamp: Option<String>,
    pub signature: Option<Sig>,
    /// Workspaces whose working copy this is.
    pub workspaces: Vec<String>,
    pub tags: Vec<TagLabel>,
    /// `remote/tag` names last seen on a remote.
    pub remote_tags: Vec<String>,
    pub empty: bool,
    pub conflicts: Vec<String>,
    pub cloak: Option<String>,
    pub embargo: Option<LogEmbargo>,
    pub description: Option<String>,
    pub description_hidden: Option<HiddenText>,
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

#[derive(Serialize, Debug)]
pub struct TagLabel {
    pub name: String,
    pub cloak: Option<String>,
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
    ids: std::vec::IntoIter<ObjectId>,
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
    show_skipped: bool,
    max_changes: Option<usize>,
    skipped: usize,
    stopped: bool,
}

/// What `vl log` shows: which snapshots (`-r`), how many (`-n`), and the
/// filters.
#[derive(Default)]
pub struct LogQuery {
    pub limit: Option<usize>,
    /// Snapshot ids in log order (`revset::resolve_set`); all visible
    /// snapshots when `None`.
    pub ids: Option<Vec<ObjectId>>,
    pub filter: Option<LogFilter>,
    pub show_skipped: bool,
    /// Stop searching after this many snapshots.
    pub max_changes: Option<usize>,
}

pub fn log_entries_with<'a>(repo: &'a Repo, ws: &str, q: LogQuery) -> Result<LogEntries<'a>> {
    let mut ids = match q.ids {
        Some(ids) => ids,
        None => repo.visible_snapshots()?,
    };
    let searcher = q.filter.filter(|f| !f.is_empty()).map(|f| Searcher::new(repo, f));
    // Without a filter `-n` is known at once; with one, only once enough
    // snapshots matched.
    let truncated = searcher.is_none() && q.limit.is_some_and(|l| ids.len() > l);
    if let (None, Some(l)) = (&searcher, q.limit) {
        ids.truncate(l);
    }
    let mut tags: HashMap<ObjectId, Vec<TagLabel>> = HashMap::new();
    for (name, t) in &repo.view().tags {
        tags.entry(t.target).or_default().push(TagLabel { name: name.clone(), cloak: t.cloak.clone() });
    }
    let mut remote_tags: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, t) in &repo.view().remote_tags {
        remote_tags.entry(*t).or_default().push(name.clone());
    }
    let mut workspaces: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, w) in &repo.view().workspaces {
        workspaces.entry(w.wc).or_default().push(name.clone());
    }
    Ok(LogEntries {
        repo,
        ids: ids.into_iter(),
        signers: repo.keys().known_signers(),
        tags,
        remote_tags,
        workspaces,
        // None in a bare repository (no workspace).
        current: repo.view().workspaces.get(ws).map(|w| w.wc),
        root: repo.root_id(),
        truncated,
        limit: q.limit,
        yielded: 0,
        searcher,
        show_skipped: q.show_skipped,
        max_changes: q.max_changes,
        skipped: 0,
        stopped: false,
    })
}

impl Iterator for LogEntries<'_> {
    type Item = Result<LogEntry>;

    fn next(&mut self) -> Option<Result<LogEntry>> {
        if self.searcher.is_none() {
            let id = self.ids.next()?;
            return Some(self.entry(id));
        }
        loop {
            if self.limit.is_some_and(|l| self.yielded >= l) {
                self.truncated = self.ids.len() > 0;
                return None;
            }
            let searcher = self.searcher.as_mut().expect("a filter");
            if self.max_changes.is_some_and(|m| searcher.searched >= m) {
                self.stopped = self.ids.len() > 0;
                return None;
            }
            let id = self.ids.next()?;
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
        self.searcher.as_ref().map(|s| LogSearch { searched: s.searched, skipped: self.skipped, stopped: self.stopped })
    }

    fn entry(&mut self, id: ObjectId) -> Result<LogEntry> {
        let repo = self.repo;
        let s = repo.snapshot(&id)?;
        let root = id == self.root;
        let (description, description_hidden) = description(repo, &s);
        let parents = s
            .parents
            .iter()
            .map(|p| {
                // A parent may be withheld (unreleased embargo on a public
                // clone): it is known by snapshot id only.
                let change_short = match repo.snapshot_opt(p) {
                    Ok(Some(ps)) => Some(ps.change_id.short()),
                    _ => None,
                };
                ParentRef { snapshot_id: p.hex(), snapshot_short: p.short(), withheld: change_short.is_none(), change_short, id: *p }
            })
            .collect();
        Ok(LogEntry {
            snapshot_id: id.hex(),
            snapshot_short: id.short(),
            change_id: s.change_id.display(),
            change_short: s.change_id.short(),
            root,
            current: Some(id) == self.current,
            author: (!root).then(|| s.author.clone()),
            timestamp: if root { None } else { rfc3339(s.timestamp) },
            signature: (!root).then(|| sig(&repo.keys().snapshot_status_with(&s, &self.signers), &s)),
            workspaces: self.workspaces.remove(&id).unwrap_or_default(),
            tags: self.tags.remove(&id).unwrap_or_default(),
            remote_tags: self.remote_tags.remove(&id).unwrap_or_default(),
            empty: !root && repo.is_empty_change(&id).unwrap_or(false),
            conflicts: s.conflicts.clone(),
            cloak: s.cloak.clone(),
            embargo: s.embargo.as_ref().map(|e| LogEmbargo { id: e.clone(), released: repo.keys().embargo_released(e) }),
            description,
            description_hidden,
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

/// `vl diff --json` (`veil.diff/1`).
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
    /// `file`, `symlink`, `gitlink` (format 5) or `conflict`.
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
/// [`item_diff`] (lazily, for the text output).
pub fn diff_changes(repo: &Repo, from: &ObjectId, to: &ObjectId) -> Result<Vec<TreeChange>> {
    Ok(diff_trees(repo.store(), Some(from), Some(to))?)
}

fn file_diff_with(repo: &Repo, c: &TreeChange, stat: bool, check_readable: bool, attrs: &Attrs<'_>) -> FileDiff {
    FileDiff {
        path: path(&c.path),
        status: status_word(c),
        from: None,
        score: None,
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
/// `.gitattributes` (as Git does), with the device-local file.
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
    // `.gitattributes`: `-diff` / `binary` show "binary"; `diff=<name>`
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

pub fn diff_body_with(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool, r: &Renames) -> Result<DiffBody> {
    let (items, renames_skipped) = detect_renames(repo, diff_changes(repo, from, to)?, r)?;
    let attrs = diff_attrs(repo);
    Ok(DiffBody { stat, files: items.iter().map(|c| item_diff(repo, c, stat, &attrs)).collect(), renames_skipped })
}

/// `vl diff --json` with rename detection on (the default).
pub fn diff(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool) -> Result<Diff> {
    diff_with(repo, from, to, stat, &Renames::default())
}

pub fn diff_with(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool, r: &Renames) -> Result<Diff> {
    Ok(Diff { schema: DIFF_SCHEMA, body: diff_body_with(repo, from, to, stat, r)? })
}

/// The two trees `vl diff` compares: a snapshot's parents and the snapshot
/// (`-r`, default `@`), or `--from` and `--to` (each default `@`).
pub fn diff_trees_for(ctx: &Ctx, rev: Option<&str>, from: Option<&str>, to: Option<&str>) -> Result<(ObjectId, ObjectId)> {
    Ok(match (from, to) {
        (None, None) => {
            let id = ctx.rev(rev.unwrap_or("@"))?;
            let s = ctx.repo.snapshot(&id)?;
            (ctx.repo.parents_tree(&s.parents)?.tree, s.tree)
        }
        _ => {
            let a = ctx.rev(from.unwrap_or("@"))?;
            let b = ctx.rev(to.unwrap_or("@"))?;
            (ctx.repo.snapshot(&a)?.tree, ctx.repo.snapshot(&b)?.tree)
        }
    })
}

// ---- show ------------------------------------------------------------------------

/// `vl show --json` (`veil.show/1`).
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
    pub cloak: Option<String>,
    pub embargo: Option<EmbargoInfo>,
    pub conflicts: Vec<String>,
    pub description: Option<String>,
    pub description_hidden: Option<HiddenText>,
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
    s.diff = diff_body_with(&ctx.repo, &s.base_tree, &s.tree, stat, r)?;
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
                Some(_) if repo.keys().release_state(e) == ReleaseState::Staged => ("staged", None),
                Some(r) => ("pending", r.until),
                None => ("unknown", None),
            };
            Some(EmbargoInfo { id: e.clone(), state, until: until_ms.and_then(rfc3339), until_ms })
        }
        None => None,
    };
    let status = (!root).then(|| repo.keys().snapshot_status(&s));
    let (description, description_hidden) = description(repo, &s);
    let base = repo.parents_tree(&s.parents)?.tree;
    Ok(Show {
        schema: SHOW_SCHEMA,
        snapshot_id: id.hex(),
        snapshot_short: id.short(),
        change_id: s.change_id.display(),
        change_short: s.change_id.short(),
        root,
        author: s.author.clone(),
        timestamp: rfc3339(s.timestamp),
        signature: status.as_ref().map(|st| sig(st, &s)),
        parents: s.parents.iter().map(|p| snapshot_ref(repo, p)).collect(),
        tags: repo.view().tags.iter().filter(|(_, t)| t.target == id).map(|(n, _)| n.clone()).collect(),
        cloak: s.cloak.clone(),
        embargo,
        conflicts: s.conflicts.clone(),
        description,
        description_hidden,
        diff: DiffBody { stat, files: Vec::new(), renames_skipped: false },
        base_tree: base,
        tree: s.tree,
        timestamp_ms: s.timestamp,
        signature_status: status,
        snapshot: Some(s),
    })
}

// ---- workspace list, tag list, op log, secret list ----------------------------------------

/// `vl workspace list --json` (`veil.workspace.list/1`).
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
    pub cloak: Option<String>,
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
                cloak: w.cloak.clone(),
                working_copy: snapshot_ref(repo, &w.wc),
            })
            .collect(),
    }
}

/// `vl tag list --json` (`veil.tag.list/1`).
#[derive(Serialize, Debug)]
pub struct TagList {
    pub schema: &'static str,
    pub tags: Vec<TagItem>,
    pub remote_tags: Vec<RemoteTagItem>,
    /// Git tags fetched from Git remotes (`<remote>/<name>`), format 5.
    pub remote_release_tags: Vec<RemoteReleaseTagItem>,
}

#[derive(Serialize, Debug)]
pub struct TagItem {
    pub name: String,
    /// Cloaked tags are never pushed to public remotes.
    pub cloak: Option<String>,
    pub target: SnapshotRef,
    /// `release` (annotated: immutable, a Git tag) or `branch`.
    pub kind: &'static str,
    /// What the Git bridge exports it as: `refs/tags/<name>` or
    /// `refs/heads/<name>`.
    pub git_ref: String,
    /// The annotation of a release tag (`null` for a plain tag).
    pub annotation: Option<AnnotationItem>,
}

/// An annotated tag object as `vl tag list --json` shows it.
#[derive(Serialize, Debug)]
pub struct AnnotationItem {
    pub id: String,
    /// `annotated` or `lightweight-git`.
    pub kind: &'static str,
    pub tagger: String,
    pub timestamp: Option<String>,
    /// The message; `null` when sealed for a scope you are not in.
    pub message: Option<String>,
    /// The signer's name, when signed by a key a ring knows.
    pub signer: Option<String>,
    /// A valid Veil signature by a known key (a Git signature never is).
    pub verified: bool,
    /// What the check found (`signed by …`, `unsigned`, `Git signature,
    /// not verified by Veil`, `unverified (…)`).
    pub status: String,
}

#[derive(Serialize, Debug)]
pub struct RemoteReleaseTagItem {
    /// `remote/tag`.
    pub name: String,
    pub target: Option<SnapshotRef>,
    pub annotation: Option<AnnotationItem>,
}

/// The annotation `id` shown as `name → target`.
pub fn annotation_item(repo: &Repo, name: &str, target: &ObjectId, id: &ObjectId) -> Option<AnnotationItem> {
    let c = repo.check_atag(name, target, id).ok()?;
    Some(AnnotationItem {
        id: id.hex(),
        kind: match c.atag.kind {
            veil_core::tag_object::AtagKind::Annotated => "annotated",
            veil_core::tag_object::AtagKind::LightweightGit => "lightweight-git",
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
                cloak: t.cloak.clone(),
                target: snapshot_ref(repo, &t.target),
                kind: if t.annotation.is_some() { "release" } else { "branch" },
                git_ref: format!("refs/{}/{name}", if t.annotation.is_some() { "tags" } else { "heads" }),
                annotation: t.annotation.and_then(|a| annotation_item(repo, name, &t.target, &a)),
            })
            .collect(),
        remote_tags: repo
            .view()
            .remote_tags
            .iter()
            .map(|(name, t)| RemoteTagItem { name: name.clone(), target: snapshot_ref(repo, t) })
            .collect(),
        remote_release_tags: repo
            .view()
            .remote_release_tags
            .iter()
            .map(|(key, a)| {
                let atag = repo.store().atag(a).ok();
                let short = key.split_once('/').map_or(key.as_str(), |(_, n)| n);
                RemoteReleaseTagItem {
                    name: key.clone(),
                    target: atag.as_ref().map(|t| snapshot_ref(repo, &t.target)),
                    annotation: atag.as_ref().and_then(|t| annotation_item(repo, short, &t.target, a)),
                }
            })
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
    #[serde(skip)]
    pub(crate) timestamp_ms: i64,
}

pub fn op_log(repo: &Repo, limit: usize) -> Result<OpLog> {
    Ok(OpLog {
        schema: OP_LOG_SCHEMA,
        operations: repo
            .op_log(limit)?
            .into_iter()
            .map(|(id, op)| OpEntry {
                op_id: id.hex(),
                op_short: id.short(),
                timestamp: rfc3339(op.timestamp),
                user: op.user,
                description: op.description,
                timestamp_ms: op.timestamp,
            })
            .collect(),
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
    /// gate: a Git checkout publishes every file).
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

/// `vl ls --json` (`veil.ls/1`).
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
    /// An ignored directory, listed as a whole (never descended into).
    pub dir: bool,
    /// `public`, `cloaked`, `embargoed`, `redacted` (recorded, but sealed
    /// for someone else or withheld here), `isolated`, `ignored` or
    /// `quarantined` (see [`entry_tier`]).
    pub tier: &'static str,
    /// The scope of a cloaked (or redacted cloaked) file.
    pub scope: Option<String>,
    /// The embargo of an embargoed (or redacted embargoed) file.
    pub embargo: Option<String>,
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
    /// What this reader reads is the file's last public version (it was
    /// edited on a cloaked line whose scope this reader is not in).
    pub fallback: bool,
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
    /// `file`, `symlink`, `gitlink` (format 5) or `conflict`.
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

fn vis_parts(v: &Visibility) -> (Option<String>, Option<String>) {
    match v {
        Visibility::Public => (None, None),
        Visibility::Cloaked { scope } => (Some(scope.clone()), None),
        Visibility::Embargoed { embargo } => (None, Some(embargo.clone())),
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
    for (p, e) in veil_core::tree::walk_files(repo.store(), &snap.tree)? {
        if !under(&filters, &p, false) {
            continue;
        }
        let looked = look(repo, &e);
        let mut tier = entry_tier_with(repo, &e, looked.as_ref());
        let readable = match &looked {
            Some(l) => !l.view.unreadable_side,
            None => id_readable(repo, &e.id),
        };
        let fallback = !readable && e.fallback.is_some_and(|f| id_readable(repo, &f));
        let redaction = match tier {
            "redacted" => redaction_for_listing(repo, &e).map(|mut r| {
                if fallback {
                    r.message.push_str("; you read its last public version");
                }
                r
            }),
            _ => None,
        };
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
        let (scope, embargo) = vis_parts(&vis);
        entries.push((
            p.clone(),
            LsEntry {
                path: path(&p),
                dir: false,
                tier,
                scope,
                embargo,
                recorded: true,
                visibility: Some(Vis::from(&vis)),
                size,
                executable,
                readable: readable || fallback,
                fallback,
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
                    embargo: None,
                    recorded: false,
                    visibility: None,
                    size: if dir { None } else { meta.as_ref().map(|m| m.len) },
                    executable: meta.as_ref().is_some_and(|m| m.executable),
                    readable: meta.is_some(),
                    fallback: false,
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

/// `vl resolve --list --json` (`veil.resolve.list/1`).
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

// ---- push --dry-run ----------------------------------------------------------------

/// `vl push --dry-run --json` (`veil.push.plan/1`): one plan per remote.
#[derive(Serialize, Debug)]
pub struct PushPlanDoc {
    pub schema: &'static str,
    pub remotes: Vec<RemotePlan>,
}

#[derive(Serialize, Debug, Default)]
pub struct RemotePlan {
    pub name: String,
    pub url: String,
    pub public: bool,
    /// Planning failed for this remote (unreachable, not a repository, a
    /// tag that would publish withheld history…): the push would fail the
    /// same way. The other fields are then empty.
    pub error: Option<String>,
    /// No repository there yet: the push would create one.
    pub creates_remote: bool,
    pub tags: Vec<PlanTag>,
    /// How many objects would be sent, by kind, and their bytes.
    pub snapshots: usize,
    pub objects: usize,
    pub trees: usize,
    /// Plaintext file contents.
    pub blobs: usize,
    /// Ciphertext: cloaked or embargoed content, sealed trees.
    pub sealed: usize,
    /// Sum of the objects' encodings, before packing.
    pub object_bytes: u64,
    /// Size of the pack(s) the push would write (compressed, with deltas).
    pub pack_bytes: u64,
    /// Every snapshot and every object that would be sent, in hex.
    pub snapshot_ids: Vec<String>,
    pub object_ids: Vec<String>,
    /// Objects the visibility filter holds back (cloaked or embargoed
    /// content, on a public remote).
    pub withheld_objects: usize,
    /// History reachable from the pushed tags only through an unreleased
    /// embargo: it stays here until the release.
    pub withheld_snapshots: Vec<PlanSnapshot>,
    /// Embargo releases staged here that the push would publish.
    pub releases: Vec<String>,
    /// Public remotes only.
    pub files: Option<PlanFiles>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct PlanTag {
    pub name: String,
    /// `create`, `update`, `unchanged`, `rejected` (non-fast-forward) or
    /// `skipped` (held back by design; see `reason`).
    pub action: &'static str,
    pub target: String,
    pub target_short: String,
    /// The remote's tag now, if it has one.
    pub remote_target: Option<String>,
    /// Why it is rejected or skipped.
    pub message: Option<String>,
    /// The scope of a cloaked tag.
    pub cloak: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct PlanSnapshot {
    pub snapshot_id: String,
    pub snapshot_short: String,
    pub embargo: String,
}

#[derive(Serialize, Debug)]
pub struct PlanFiles {
    /// Content that becomes public on this remote with this push.
    pub published: Vec<PlanPublished>,
    /// Files of the pushed history whose content stays withheld.
    pub withheld: Vec<PlanWithheld>,
    /// Snapshots under an unreleased embargo this reader holds no key for:
    /// the remote sees their pre-merge tree (which files the embargo
    /// changes cannot be listed here).
    pub embargoed_trees: Vec<PlanSnapshot>,
}

#[derive(Serialize, Debug)]
pub struct PlanPublished {
    pub path: String,
    /// `new` (never public there), `exposed` (there, but withheld until
    /// now) or `modified` (public there; new content).
    pub exposure: &'static str,
    pub size: Option<u64>,
    /// Published because this embargo was released.
    pub released_embargo: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct PlanWithheld {
    pub path: String,
    /// `cloaked`, `cloaked_edit` (the remote keeps the last public version)
    /// or `embargoed` (the remote shows the pre-merge version).
    pub reason: &'static str,
    pub scope: Option<String>,
    pub embargo: Option<String>,
    /// The explanation the text output prints.
    pub message: String,
}

fn plan_snapshot((id, embargo): &(ObjectId, String)) -> PlanSnapshot {
    PlanSnapshot { snapshot_id: id.hex(), snapshot_short: id.short(), embargo: embargo.clone() }
}

fn remote_plan(name: &str, url: &str, plan: veil_core::push_plan::PushPlan) -> RemotePlan {
    use veil_core::push_plan::WithheldReason;
    let sent: std::collections::HashSet<ObjectId> = plan.snapshots.iter().copied().collect();
    let count = |f: &dyn Fn(&veil_core::remote::PlannedObject) -> bool| plan.objects.iter().filter(|o| f(o)).count();
    let files = plan.files.as_ref().map(|f| PlanFiles {
        published: f
            .published
            .iter()
            .map(|p| PlanPublished {
                path: path(&p.path),
                exposure: p.exposure.word(),
                size: p.size,
                released_embargo: p.released_embargo.clone(),
            })
            .collect(),
        withheld: f
            .withheld
            .iter()
            .map(|w| {
                let (reason, scope, embargo) = match &w.reason {
                    WithheldReason::Cloaked { scope } => ("cloaked", Some(scope.clone()), None),
                    WithheldReason::CloakedEdit { scope } => ("cloaked_edit", Some(scope.clone()), None),
                    WithheldReason::Embargoed { embargo } => ("embargoed", None, Some(embargo.clone())),
                };
                PlanWithheld { path: path(&w.path), reason, scope, embargo, message: w.reason.text() }
            })
            .collect(),
        embargoed_trees: f.embargoed_trees.iter().map(plan_snapshot).collect(),
    });
    RemotePlan {
        name: name.to_string(),
        url: url.to_string(),
        public: plan.public,
        error: None,
        creates_remote: plan.creates_remote,
        tags: plan
            .tags
            .iter()
            .map(|t| PlanTag {
                name: t.name.clone(),
                action: t.action.word(),
                target: t.target.hex(),
                target_short: t.target.short(),
                remote_target: t.remote.map(|r| r.hex()),
                message: t.reason.clone(),
                cloak: t.cloak.clone(),
            })
            .collect(),
        snapshots: plan.snapshots.len(),
        objects: plan.objects.len(),
        trees: count(&|o| !o.blob && !o.sealed && !sent.contains(&o.id)),
        blobs: count(&|o| o.blob),
        sealed: count(&|o| o.sealed),
        object_bytes: plan.object_bytes(),
        pack_bytes: plan.pack_bytes,
        snapshot_ids: plan.snapshots.iter().map(|i| i.hex()).collect(),
        object_ids: plan.objects.iter().map(|o| o.id.hex()).collect(),
        withheld_objects: plan.redacted,
        withheld_snapshots: plan.withheld_snapshots.iter().map(plan_snapshot).collect(),
        releases: plan.releases.clone(),
        files,
        warnings: plan.warnings.clone(),
    }
}

/// `vl push --dry-run [REMOTE] [-t TAG…]`: what a push would send to
/// `remote`, or to every configured remote. Nothing is written to any
/// remote. With one remote named, a failure is the command's; for all
/// remotes, each failure is recorded in its plan and the others go on.
pub fn push_plan(ctx: &Ctx, remote: Option<&str>, tags: &[String], force: bool, force_tags: bool) -> Result<PushPlanDoc> {
    let names: Vec<String> = match remote {
        Some(n) => vec![n.to_string()],
        None => ctx.repo.config().remotes.keys().cloned().collect(),
    };
    if names.is_empty() {
        anyhow::bail!("no remotes are configured (add one with `vl remote add <name> <path>`)");
    }
    let mut remotes = Vec::new();
    for name in &names {
        let planned = crate::remote_backend(ctx, name).and_then(|(backend, cfg)| {
            let plan = veil_core::push_plan::plan_push_with(&ctx.repo, backend, cfg.public, tags, force, force_tags)?;
            Ok(remote_plan(name, &cfg.url, plan))
        });
        match planned {
            Ok(p) => remotes.push(p),
            Err(e) if remote.is_some() => return Err(e),
            Err(e) => {
                let cfg = ctx.repo.config().remotes.get(name).cloned();
                remotes.push(RemotePlan {
                    name: name.clone(),
                    url: cfg.as_ref().map(|c| c.url.clone()).unwrap_or_default(),
                    public: cfg.is_some_and(|c| c.public),
                    error: Some(format!("{e:#}")),
                    ..Default::default()
                });
            }
        }
    }
    Ok(PushPlanDoc { schema: PUSH_PLAN_SCHEMA, remotes })
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

/// `snapshot` (`veil.snapshot/1`): the working copy was recorded.
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

/// `vl describe` (`veil.describe/1`).
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
/// NUL, which no argument can carry and no Git commit may hold
/// (`nulInCommit`).
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

/// `vl new` (`veil.new/1`).
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

/// `vl commit` (`veil.commit/1`).
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
    /// `cloaked_line` (a commit on a line cloaked for `scope` never moves
    /// an uncloaked tag) or `no_advance`.
    pub reason: &'static str,
    pub scope: Option<String>,
}

pub fn commit(ctx: &mut Ctx, message: &str, advance: bool) -> Result<Committed> {
    use veil_core::commands::TagKept;
    check_message(message)?;
    let ws = ctx.ws.clone();
    let r = ctx.repo.commit(&ws, message, advance)?;
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
                TagKept::CloakedLine(s) => KeptTag { name: name.clone(), reason: "cloaked_line", scope: Some(s.clone()) },
                TagKept::NoAdvance => KeptTag { name: name.clone(), reason: "no_advance", scope: None },
                TagKept::Release => KeptTag { name: name.clone(), reason: "release_tag", scope: None },
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
            &["push", "--dry-run"],
            &["push", "origin", "--dry-run"],
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
        assert!(Cli::try_parse_from(["vl", "push", "--json"]).is_err(), "a push takes --json only with --dry-run");
        assert!(Cli::try_parse_from(["vl", "push", "--dry-run", "--full"]).is_err());
        assert!(Cli::try_parse_from(["vl", "push", "--dry-run", "--delete", "x"]).is_err());
    }
}

// ---- blame -----------------------------------------------------------------------

/// `vl blame --json` (`veil.blame/1`).
#[derive(Serialize, Debug)]
pub struct BlameDoc {
    pub schema: &'static str,
    pub path: String,
    pub rev: SnapshotRef,
    /// `plain`, or `fallback`: this reader cannot read the file at `rev`,
    /// and its last public version is annotated instead.
    pub version: &'static str,
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

pub fn blame(ctx: &Ctx, req: &BlameRequest<'_>) -> Result<BlameDoc> {
    use veil_core::blame::{BlameOptions, Origin, Stop, Unattributed};
    let repo = &ctx.repo;
    let id = ctx.rev(req.rev)?;
    let p = ctx.repo_path(req.path)?;
    let tree = repo.snapshot(&id)?.tree;
    let reader = if req.public { Reader::Public } else { Reader::Me };
    let e = match lookup(repo.store(), &tree, &p)? {
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
    if let Some((a, b)) = req.lines {
        if a == 0 || b < a {
            anyhow::bail!("-L {a},{b}: give START,END with 1 <= START <= END");
        }
    }
    let o = BlameOptions {
        reader,
        follow: req.follow,
        max_changes: req.max_changes,
        lines: req.lines,
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
        rev: snapshot_ref_as(repo, &id, req.public),
        version: if b.fallback { "fallback" } else { "plain" },
        public: req.public,
        coarse: b.coarse,
        stopped: b.stopped.map(|s| match s {
            Stop::MaxChanges => "max_changes",
            Stop::Budget => "budget",
        }),
        visited: b.visited,
        unattributed: b.unattributed(),
        lines,
        changes: stamped.iter().map(|(_, c)| snapshot_ref_as(repo, c, req.public)).collect(),
    })
}

// ---- grep ------------------------------------------------------------------------

/// `vl grep --json` (`veil.grep/1`).
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
    /// `public`, `cloaked`, `embargoed` (sealed, and this reader holds the
    /// key) or `fallback` (the last public version of a file this reader
    /// cannot read; members see newer content).
    pub tier: &'static str,
    /// The line was longer than 1 MiB and is cut.
    pub truncated: bool,
}

#[derive(Serialize, Debug)]
pub struct GrepFileDoc {
    pub path: String,
    pub tier: &'static str,
    /// The scope of a cloaked file, the embargo of an embargoed one.
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
}

/// What `vl grep` searches.
pub struct GrepRequest<'a> {
    pub pattern: &'a str,
    pub rev: &'a str,
    pub paths: &'a [String],
    pub opts: veil_core::grep::GrepOptions,
}

pub fn grep(ctx: &Ctx, req: GrepRequest<'_>) -> Result<GrepDoc> {
    use veil_core::grep::Tier;
    let repo = &ctx.repo;
    let id = ctx.rev(req.rev)?;
    let tree = repo.snapshot(&id)?.tree;
    let mut o = req.opts;
    o.paths = req.paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let re = veil_core::grep::compile(req.pattern, &o)?;
    let g = veil_core::grep::grep(repo.store(), &tree, &re, &o)?;
    let mut matches = Vec::new();
    let mut files = Vec::new();
    for f in &g.files {
        let scope = match &f.tier {
            Tier::Cloaked(s) | Tier::Embargoed(s) => Some(s.clone()),
            _ => None,
        };
        files.push(GrepFileDoc { path: path(&f.path), tier: f.tier.as_str(), scope, count: f.count, binary: f.binary, conflict: f.conflict });
        for l in &f.lines {
            matches.push(GrepMatchDoc {
                path: path(&f.path),
                line: l.number,
                text: String::from_utf8_lossy(&l.text).into_owned(),
                tier: f.tier.as_str(),
                truncated: l.truncated,
            });
        }
    }
    Ok(GrepDoc {
        schema: GREP_SCHEMA,
        rev: snapshot_ref(repo, &id),
        matches,
        files,
        skipped: GrepSkipped { sealed: g.skipped.sealed, binary: g.skipped.binary, too_large: g.skipped.too_large },
        searched: g.searched,
    })
}
