//! Structured results of the read commands, shared by their text output,
//! their `--json` output and (later) `vl serve --local`.
//!
//! Every read command is split in two: a function here computes a typed
//! result from the repository context and prints nothing, and a renderer
//! turns it into text ([`text`], today's output, byte for byte) or into one
//! JSON document ([`emit_json`]). The schemas are documented, field by
//! field, in `docs/reference/json.md`; `crates/vl/tests/json_cli.rs` pins
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

pub mod text;

use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use serde::Serialize;
use veil_core::{
    keychain::{split_label, ReleaseState, SignatureStatus},
    object::{Snapshot, Text, Visibility},
    policy::{Policy, Tier},
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
    /// Always `no_key`.
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
    match repo.snapshot(id) {
        Ok(s) => {
            let (description, description_hidden) = description(repo, &s);
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

fn status_word(c: &TreeChange) -> &'static str {
    match c.status() {
        'A' => "added",
        'D' => "deleted",
        _ => "modified",
    }
}

/// One changed path, as `vl status` and `vl diff --stat` list it.
#[derive(Serialize, Debug, Clone)]
pub struct Change {
    pub path: String,
    /// `added`, `deleted` or `modified`.
    pub status: &'static str,
    /// Of the new version (of the old one for a deletion).
    pub visibility: Vis,
    /// The new version is unreadable here (`(redacted)` in the text).
    pub redacted: bool,
}

pub fn change(repo: &Repo, c: &TreeChange) -> Change {
    let e = c.new.as_ref().or(c.old.as_ref()).expect("a change has a side");
    Change {
        path: path(&c.path),
        status: status_word(c),
        visibility: Vis::from(&e.visibility),
        redacted: c.new.as_ref().is_some_and(|e| !repo.store().entry_readable(e)),
    }
}

/// Why `e` cannot be materialised here, in the words of `vl status`
/// (`render::hidden_reason`).
fn redaction_for_listing(repo: &Repo, e: &TreeEntry) -> Option<Redaction> {
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
}

#[derive(Serialize, Debug)]
pub struct RedactedPath {
    pub path: String,
    pub redaction: Redaction,
}

#[derive(Serialize, Debug)]
pub struct Conflict {
    pub path: String,
    /// Short change id of the parent the conflict was recorded on (a
    /// merge), or null if recorded on the working-copy change itself.
    pub recorded_on: Option<String>,
}

pub fn status(ctx: &Ctx) -> Result<Status> {
    let repo = &ctx.repo;
    let wc = ctx.wc()?;
    let s = repo.snapshot(&wc)?;
    let base = repo.parents_tree(&s.parents)?.tree;
    let changes = diff_trees(repo.store(), Some(&base), Some(&s.tree))?;
    let report = &ctx.report;
    let mut redacted = Vec::new();
    for p in &report.carried {
        let entry = lookup(repo.store(), &s.tree, p)?;
        let why = entry.as_ref().and_then(|e| redaction_for_listing(repo, e));
        // Readable, yet never materialised: the filesystem refused it.
        let fallback = match entry {
            Some(e) if repo.store().entry_readable(&e) => {
                Redaction { reason: "unwritable", message: "this filesystem could not hold it".into() }
            }
            _ => Redaction { reason: "no_key", message: "no key".into() },
        };
        redacted.push(RedactedPath { path: path(p), redaction: why.unwrap_or(fallback) });
    }
    // Conflicts recorded on `@`, and those of its parents (a merge records
    // them on the merge, `@-`) whose file `@` has not touched since.
    let mut conflicts: Vec<Conflict> = s.conflicts.iter().map(|c| Conflict { path: c.clone(), recorded_on: None }).collect();
    for p in &s.parents {
        let ps = repo.snapshot(p)?;
        for c in &ps.conflicts {
            let Ok(cp) = VPath::new(c) else { continue };
            let before = lookup(repo.store(), &ps.tree, &cp)?;
            if before.is_some() && before == lookup(repo.store(), &s.tree, &cp)? && !conflicts.iter().any(|x| x.path == *c) {
                conflicts.push(Conflict { path: c.clone(), recorded_on: Some(ps.change_id.short()) });
            }
        }
    }
    Ok(Status {
        schema: STATUS_SCHEMA,
        workspace: WorkspaceInfo { name: ctx.ws.clone(), cloak: repo.view().workspace(&ctx.ws)?.cloak.clone() },
        working_copy: snapshot_ref(repo, &wc),
        parents: s.parents.iter().map(|p| snapshot_ref(repo, p)).collect(),
        changes: changes.iter().map(|c| change(repo, c)).collect(),
        isolated: report.isolated.iter().map(path).collect(),
        quarantined: report
            .quarantined
            .iter()
            .map(|(p, f)| Quarantined {
                path: path(p),
                rule: f[0].rule,
                line: f[0].line,
                state: if report.quarantine_kept.contains(p) { "held_back" } else { "never_recorded" },
            })
            .collect(),
        policy_held_back: report
            .policy_held_back
            .iter()
            .map(|h| PolicyHeldBack { path: h.shown_path(), dir: h.dir, accepted: h.accepted.clone(), wanted: h.wanted.clone() })
            .collect(),
        nested: report.nested.iter().map(path).collect(),
        redacted,
        conflicts,
    })
}

// ---- log -------------------------------------------------------------------------

/// `vl log --json` (`veil.log/1`).
#[derive(Serialize, Debug)]
pub struct Log {
    pub schema: &'static str,
    /// Children before parents, newest first among unrelated snapshots.
    pub entries: Vec<LogEntry>,
    /// `-n` cut the log short.
    pub truncated: bool,
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
}

pub fn log_entries<'a>(repo: &'a Repo, ws: &str, limit: Option<usize>) -> Result<LogEntries<'a>> {
    let mut ids = repo.visible_snapshots()?;
    let truncated = limit.is_some_and(|l| ids.len() > l);
    if let Some(l) = limit {
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
    })
}

impl Iterator for LogEntries<'_> {
    type Item = Result<LogEntry>;

    fn next(&mut self) -> Option<Result<LogEntry>> {
        let id = self.ids.next()?;
        Some(self.entry(id))
    }
}

impl LogEntries<'_> {
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
            id,
            timestamp_ms: s.timestamp,
        })
    }
}

pub fn log(repo: &Repo, ws: &str, limit: Option<usize>) -> Result<Log> {
    let mut it = log_entries(repo, ws, limit)?;
    let entries = it.by_ref().collect::<Result<Vec<_>>>()?;
    Ok(Log { schema: LOG_SCHEMA, entries, truncated: it.truncated })
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
}

#[derive(Serialize, Debug)]
pub struct FileDiff {
    pub path: String,
    /// `added`, `deleted` or `modified`.
    pub status: &'static str,
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
    EntryInfo {
        visibility: Vis::from(&e.visibility),
        executable: e.executable,
        mode: if e.executable { "100755" } else { "100644" },
        readable: !check_readable || repo.store().entry_readable(e),
    }
}

/// The changes between two trees, each turned into a [`FileDiff`] by
/// [`file_diff`] (lazily, for the text output).
pub fn diff_changes(repo: &Repo, from: &ObjectId, to: &ObjectId) -> Result<Vec<TreeChange>> {
    Ok(diff_trees(repo.store(), Some(from), Some(to))?)
}

pub fn file_diff(repo: &Repo, c: &TreeChange, stat: bool) -> FileDiff {
    file_diff_with(repo, c, stat, true)
}

/// [`file_diff`] for the text output of a full diff, which does not show
/// `readable`: each entry's `readable` is left true instead of costing a
/// second read of every object.
pub(crate) fn file_diff_for_text(repo: &Repo, c: &TreeChange) -> FileDiff {
    file_diff_with(repo, c, false, false)
}

fn file_diff_with(repo: &Repo, c: &TreeChange, stat: bool, check_readable: bool) -> FileDiff {
    FileDiff {
        path: path(&c.path),
        status: status_word(c),
        old: c.old.as_ref().map(|e| entry_info(repo, e, check_readable)),
        new: c.new.as_ref().map(|e| entry_info(repo, e, check_readable)),
        content: (!stat).then(|| content(repo, c)),
    }
}

fn content(repo: &Repo, c: &TreeChange) -> Content {
    let read = |e: &Option<TreeEntry>| -> Result<Vec<u8>, Redaction> {
        match e {
            None => Ok(Vec::new()),
            Some(e) => match repo.store().read_entry(e) {
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
    if looks_binary(&old) || looks_binary(&new) {
        return none(true, None);
    }
    let old_s = String::from_utf8_lossy(&old);
    let new_s = String::from_utf8_lossy(&new);
    Content { binary: false, hidden: None, hunks: hunks(&diffy::create_patch(&old_s, &new_s)) }
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

pub fn diff_body(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool) -> Result<DiffBody> {
    let changes = diff_changes(repo, from, to)?;
    Ok(DiffBody { stat, files: changes.iter().map(|c| file_diff(repo, c, stat)).collect() })
}

pub fn diff(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool) -> Result<Diff> {
    Ok(Diff { schema: DIFF_SCHEMA, body: diff_body(repo, from, to, stat)? })
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

pub fn show(ctx: &Ctx, rev: &str, stat: bool) -> Result<Show> {
    let mut s = show_header(ctx, rev, stat)?;
    s.diff = diff_body(&ctx.repo, &s.base_tree, &s.tree, stat)?;
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
        diff: DiffBody { stat, files: Vec::new() },
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
}

#[derive(Serialize, Debug)]
pub struct TagItem {
    pub name: String,
    /// Cloaked tags are never pushed to public remotes.
    pub cloak: Option<String>,
    pub target: SnapshotRef,
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
            .map(|(name, t)| TagItem { name: name.clone(), cloak: t.cloak.clone(), target: snapshot_ref(repo, &t.target) })
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
/// value never enters this structure.
#[derive(Serialize, Debug)]
pub struct SecretList {
    pub schema: &'static str,
    pub secrets: Vec<SecretItem>,
}

#[derive(Serialize, Debug)]
pub struct SecretItem {
    pub name: String,
}

pub fn secret_list(repo: &Repo) -> Result<SecretList> {
    let vault = repo.vault_load()?;
    Ok(SecretList {
        schema: SECRET_LIST_SCHEMA,
        secrets: vault.secrets.keys().map(|k| SecretItem { name: k.clone() }).collect(),
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
    }
}
