//! The text output of the read commands, rendered from their structured
//! results ([`super`]). Every untrusted string (names, paths, descriptions,
//! file content) is escaped with [`safe`] here, at the last moment; the
//! results themselves hold the raw data.

use anyhow::Result;
use veil_core::{keychain::SignatureStatus, ObjectId};

use super::*;
use crate::render::{
    blue, bold, cyan, dim, fmt_deadline, fmt_time, first_line, green, magenta, red, safe, safe_content_line, safe_lines,
    signature_detail, signature_marker, stdout_closed, vis_label, yellow,
};

/// What `render::one_line` prints: `change id  snapshot id  description`.
pub fn one_line(r: &SnapshotRef) -> String {
    let (Some(change), true) = (&r.change_short, r.available) else {
        return r.snapshot_short.clone();
    };
    let desc = description_shown(&r.description, &r.description_hidden);
    let desc = if desc.trim().is_empty() {
        dim("(no description set)")
    } else {
        first_line(&desc).into_owned()
    };
    let empty = if r.empty { format!("{} ", green("(empty)")) } else { String::new() };
    format!("{} {} {empty}{desc}", bold(&magenta(change)), blue(&r.snapshot_short))
}

/// A description as the text output shows it: sealed ones as
/// `[cloaked:scope]` (what `Repo::description` returns).
fn description_shown(d: &Option<String>, hidden: &Option<HiddenText>) -> String {
    match (d, hidden) {
        (Some(d), _) => d.clone(),
        (None, Some(h)) => format!("[cloaked:{}]", h.scope),
        (None, None) => String::new(),
    }
}

// ---- status ----------------------------------------------------------------------

/// One line per change: `A path`, and for a rename `R old -> new`
/// (`R087 old -> new` with `scores`, as `vl diff --stat` shows it; copies
/// are `C`).
pub fn changes_summary(changes: &[Change]) {
    changes_summary_with(changes, false)
}

pub fn changes_summary_with(changes: &[Change], scores: bool) {
    for c in changes {
        let status = match c.status {
            "added" => green("A"),
            "deleted" => red("D"),
            "renamed" | "copied" => {
                let letter = if c.status == "copied" { "C" } else { "R" };
                let code = match (scores, c.score) {
                    (true, Some(n)) => format!("{letter}{n:03}"),
                    _ => letter.to_string(),
                };
                println!("{} {} -> {}{}", cyan(&code), safe(c.from.as_deref().unwrap_or_default()), safe(&c.path), change_mark(c));
                continue;
            }
            _ if c.old_kind.is_some() => yellow("T"),
            _ => cyan("M"),
        };
        let typechange = match c.old_kind {
            Some(o) => dim(&format!(" ({o} → {})", c.kind)),
            None => String::new(),
        };
        println!("{status} {}{typechange}{}", safe(&c.path), change_mark(c));
    }
}

/// A tier as `vl ls` prints it: `public`, `cloaked:<scope>`,
/// `embargoed:<id>`, `redacted`, `isolated`, `ignored`, `quarantined`.
pub fn tier_label(tier: &str, scope: Option<&str>, embargo: Option<&str>) -> String {
    match (tier, scope, embargo) {
        ("cloaked", Some(s), _) => format!("cloaked:{}", safe(s)),
        ("embargoed", _, Some(e)) => format!("embargoed:{}", safe(e)),
        (t, _, _) => t.to_string(),
    }
}

/// `tier_label`, coloured.
fn tier_coloured(label: &str, tier: &str) -> String {
    match tier {
        "cloaked" => magenta(label),
        "embargoed" | "quarantined" => yellow(label),
        "redacted" => red(label),
        _ => dim(label),
    }
}

/// ` [tier]` after a path in `vl status` (nothing for public files), with
/// what a redacted file is sealed for.
fn tier_mark(tier: &str, scope: Option<&str>, embargo: Option<&str>) -> String {
    if tier == "public" {
        return String::new();
    }
    format!(" {}", tier_coloured(&format!("[{}]", tier_label(tier, scope, embargo)), tier))
}

fn change_mark(c: &Change) -> String {
    let (scope, embargo) = (c.visibility.scope.as_deref(), c.visibility.embargo.as_deref());
    let mut mark = tier_mark(c.tier, scope, embargo);
    if c.conflict.is_some() {
        mark.push_str(&format!(" {}", red("[conflict]")));
    }
    if c.tier != "redacted" {
        return mark;
    }
    // Sealed for someone else: say for whom (labels are public metadata).
    format!("{mark} {}", dim(&format!("({})", safe(&c.visibility.visibility().label()))))
}

pub fn status(s: &Status) {
    if s.changes.is_empty() {
        println!("The working copy has no changes.");
    } else {
        println!("Working copy changes:");
        changes_summary(&s.changes);
    }
    println!("Workspace    : {}{}", green(&safe(&s.workspace.name)), match &s.workspace.cloak {
        Some(c) => magenta(&format!(" [cloaked:{}]", safe(c))),
        None => String::new(),
    });
    println!("Working copy : {} {}", bold(&green("@")), one_line(&s.working_copy));
    for p in &s.parents {
        println!("Parent       : {}", one_line(p));
    }
    if !s.isolated.is_empty() {
        println!("{}", dim("Local-only (isolated; never snapshotted or pushed):"));
        for p in &s.isolated {
            println!("  {} {}{}", dim("L"), safe(p), tier_mark("isolated", None, None));
        }
    }
    if !s.quarantined.is_empty() {
        println!("{}", yellow("Quarantined (secrets detected; kept local):"));
        for q in &s.quarantined {
            let state = match q.state {
                "held_back" => "edit held back; history keeps the previous version",
                _ => "never recorded",
            };
            println!("  {} {}{}  ({}; {state})", yellow("Q"), safe(&q.path), tier_mark(q.tier, None, None), q.rule);
        }
    }
    if !s.policy_held_back.is_empty() {
        println!("{}", yellow("Policy change not accepted (protection kept; `vl policy accept` applies it):"));
        for h in &s.policy_held_back {
            println!(
                "  {} {}{}  ({}; .veilpolicy says {})",
                yellow("P"),
                safe(&h.path),
                tier_mark(h.tier, h.scope.as_deref(), None),
                safe(&h.accepted),
                safe(&h.wanted)
            );
        }
    }
    if !s.nested.is_empty() {
        println!("{}", dim("Nested repositories (repositories of their own; nothing in them is recorded here):"));
        for p in &s.nested {
            println!("  {} {}/", dim("N"), safe(p));
        }
    }
    if !s.redacted.is_empty() {
        println!("{}", dim("Redacted (unreadable here; kept in history, absent on disk):"));
        for r in &s.redacted {
            println!("  {} {}{}  ({})", dim("R"), safe(&r.path), tier_mark(r.tier, None, None), safe(&r.redaction.message));
        }
    }
    if !s.conflicts.is_empty() {
        println!("{}", red("Unresolved conflicts:"));
        for c in &s.conflicts {
            match &c.recorded_on {
                Some(change) => println!("  {} {}  (recorded on {change})", red("C"), safe(&c.path)),
                None => println!("  {} {}", red("C"), safe(&c.path)),
            }
        }
        println!(
            "  {} edit the files to resolve the conflict markers (a conflict is resolved once they are gone), or keep one version with `vl resolve PATH --ours|--theirs`. Fold the resolution into the merge with `vl squash`, or `vl commit` it",
            dim("hint:")
        );
    }
}

// ---- log -------------------------------------------------------------------------

fn status_of(sig: &Sig) -> SignatureStatus {
    match sig.status {
        "good" => SignatureStatus::Good { member: String::new(), name: sig.signer.clone().unwrap_or_default() },
        "unknown" => SignatureStatus::Unknown { key: sig.key.clone().unwrap_or_default() },
        "bad" => SignatureStatus::Bad,
        _ => SignatureStatus::Unsigned,
    }
}

/// The snapshot graph, one entry at a time; stops when stdout goes away.
pub fn log(entries: LogEntries<'_>) -> Result<()> {
    let mut entries = entries;
    let mut lanes: Vec<Option<ObjectId>> = Vec::new();
    // A filtered log leaves snapshots out, so the graph's lines would not
    // join: it is drawn as a flat list.
    let flat = entries.search().is_some();
    for e in entries.by_ref() {
        if stdout_closed() {
            return Ok(());
        }
        let e = e?;
        if flat {
            lanes = vec![Some(e.id)];
        }
        log_entry(&e, &mut lanes);
    }
    if entries.truncated && !stdout_closed() {
        println!("{}", dim("~  (more snapshots elided)"));
    }
    if let Some(s) = entries.search() {
        if s.stopped {
            crate::render::warn(&format!("the search stopped after {} snapshots (--max-changes)", s.searched));
        }
        if s.skipped > 0 && !entries.lists_skipped() {
            crate::render::warn(&format!(
                "{} snapshot(s) not searched: the versions to read are sealed for you (--show-skipped lists them)",
                s.skipped
            ));
        }
    }
    Ok(())
}

fn log_entry(e: &LogEntry, lanes: &mut Vec<Option<ObjectId>>) {
    let id = e.id;
    let col = match lanes.iter().position(|l| *l == Some(id)) {
        Some(c) => c,
        None => match lanes.iter().position(|l| l.is_none()) {
            Some(c) => {
                lanes[c] = Some(id);
                c
            }
            None => {
                lanes.push(Some(id));
                lanes.len() - 1
            }
        },
    };
    for (j, l) in lanes.iter_mut().enumerate() {
        if j != col && *l == Some(id) {
            *l = None;
        }
    }
    let marker = if e.current {
        bold(&green("@"))
    } else if e.root {
        "◆".to_string()
    } else if !e.conflicts.is_empty() {
        red("×")
    } else {
        "○".to_string()
    };
    let row = |lanes: &[Option<ObjectId>], node: Option<(usize, &str)>| -> String {
        let mut out = String::new();
        for (j, l) in lanes.iter().enumerate() {
            match node {
                Some((c, m)) if c == j => out.push_str(m),
                _ => out.push_str(if l.is_some() { "│" } else { " " }),
            }
            out.push(' ');
        }
        out
    };
    let line1_prefix = row(lanes, Some((col, &marker)));

    let author = e.author.clone().unwrap_or_default();
    let mut header = vec![bold(&magenta(&e.change_short))];
    if !e.root {
        header.push(yellow(&safe(&author)));
        if let Some(s) = &e.signature {
            header.push(signature_marker(&status_of(s), &author));
        }
        header.push(dim(&fmt_time(e.timestamp_ms)));
    }
    if !e.workspaces.is_empty() {
        header.push(green(&e.workspaces.iter().map(|w| format!("{}@", safe(w))).collect::<Vec<_>>().join(" ")));
    }
    let tags: Vec<String> = e
        .tags
        .iter()
        .map(|t| match &t.cloak {
            Some(s) => format!("{}[cloaked:{}]", safe(&t.name), safe(s)),
            None => safe(&t.name).into_owned(),
        })
        .chain(e.remote_tags.iter().map(|t| safe(t).into_owned()))
        .collect();
    if !tags.is_empty() {
        header.push(cyan(&tags.join(" ")));
    }
    header.push(blue(&e.snapshot_short));
    if e.empty {
        header.push(green("(empty)"));
    }
    if !e.conflicts.is_empty() {
        header.push(red("(conflict)"));
    }
    if let Some(c) = &e.cloak {
        header.push(magenta(&format!("[cloaked:{}]", safe(c))));
    }
    if let Some(em) = &e.embargo {
        header.push(yellow(&format!("[embargo:{}{}]", safe(&em.id), if em.released { " released" } else { "" })));
    }
    if let Some(v) = &e.not_searched {
        let who: Vec<String> = v.iter().map(|v| safe(&v.visibility().label()).into_owned()).collect();
        header.push(dim(&format!("(not searched: sealed for {})", who.join(", "))));
    }

    lanes[col] = e.parents.first().map(|p| p.id);
    for p in e.parents.iter().skip(1) {
        if !lanes.contains(&Some(p.id)) {
            match lanes.iter().position(|l| l.is_none()) {
                Some(c) => lanes[c] = Some(p.id),
                None => lanes.push(Some(p.id)),
            }
        }
    }
    while lanes.last() == Some(&None) {
        lanes.pop();
    }
    let mut line2_prefix = row(lanes, None);
    if line2_prefix.is_empty() {
        line2_prefix = "  ".into();
    }
    println!("{line1_prefix} {}", header.join(" "));
    if e.root {
        println!("{line2_prefix} {}", dim("root()"));
    } else {
        let desc = description_shown(&e.description, &e.description_hidden);
        let desc = if desc.trim().is_empty() {
            dim("(no description set)")
        } else {
            first_line(&desc).into_owned()
        };
        let merge = if e.parents.len() > 1 {
            dim(&format!(
                "  ⇠ merges {}",
                e.parents
                    .iter()
                    .map(|p| match &p.change_short {
                        Some(c) => c.clone(),
                        None => format!("{} (withheld)", p.snapshot_short),
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        } else {
            String::new()
        };
        println!("{line2_prefix} {desc}{merge}");
        if let Some(files) = &e.files {
            let shown: Vec<String> = files.iter().map(|f| safe(f).into_owned()).collect();
            println!("{line2_prefix} {}", dim(&format!("matched in: {}", shown.join(", "))));
        }
    }
}

// ---- diff ------------------------------------------------------------------------

/// `vl diff` of the changes between two trees, rendered one file at a time;
/// stops when stdout goes away.
pub fn diff(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool, r: &Renames) -> Result<()> {
    let changes = diff_changes(repo, from, to)?;
    if changes.is_empty() {
        println!("{}", dim("(no changes)"));
        return Ok(());
    }
    let (items, skipped) = detect_renames(repo, changes, r)?;
    if skipped {
        crate::render::warn(&format!(
            "rename detection skipped: too many files (limit {}); only exact renames are shown",
            r.opts.limit
        ));
    }
    if stat {
        let summary: Vec<Change> = items.iter().map(|c| item_change(repo, c)).collect();
        changes_summary_with(&summary, true);
        return Ok(());
    }
    for c in &items {
        if stdout_closed() {
            break;
        }
        file_diff_text(&item_diff_for_text(repo, c));
    }
    Ok(())
}

pub fn file_diff_text(f: &FileDiff) {
    let from = f.from.as_deref().unwrap_or(&f.path);
    println!("{}", bold(&format!("diff --veil a/{} b/{}", safe(from), safe(&f.path))));
    if let (Some(src), Some(score)) = (&f.from, f.score) {
        let word = if f.status == "copied" { "copy" } else { "rename" };
        println!("{}", dim(&format!("similarity index {score}%")));
        println!("{}", dim(&format!("{word} from {}", safe(src))));
        println!("{}", dim(&format!("{word} to {}", safe(&f.path))));
    }
    match (f.old.as_ref().and_then(|o| o.conflict.as_ref()), f.new.as_ref().and_then(|n| n.conflict.as_ref())) {
        (_, Some(c)) => println!("{}", red(&format!("unresolved conflict ({} sides): content with markers", c.sides))),
        (Some(_), None) => println!("{}", green("conflict resolved")),
        _ => {}
    }
    match (f.status, &f.old, &f.new) {
        ("added", _, Some(n)) => println!("{}", green(&format!("added file {}", vis_label(&n.visibility.visibility())))),
        ("deleted", Some(_), _) => println!("{}", red("deleted file")),
        (_, Some(o), Some(n)) if o.visibility != n.visibility => println!(
            "{}",
            yellow(&format!(
                "visibility: {} → {}",
                safe(&o.visibility.visibility().label()),
                safe(&n.visibility.visibility().label())
            ))
        ),
        _ => {}
    }
    // A symlink's target, never followed (escaped: targets are raw data).
    let shown_target = |e: &crate::api::EntryInfo| match &e.target {
        Some(t) => safe(t).into_owned(),
        None => "(target not shown: you cannot read it)".to_string(),
    };
    let links = f.old.as_ref().is_some_and(|o| o.kind == "symlink") || f.new.as_ref().is_some_and(|n| n.kind == "symlink");
    if let Some(o) = f.old.as_ref().filter(|o| o.kind == "symlink") {
        println!("{}", red(&format!("symlink {} -> {}", safe(&f.path), shown_target(o))));
    }
    if let Some(n) = f.new.as_ref().filter(|n| n.kind == "symlink") {
        println!("{}", green(&format!("symlink {} -> {}", safe(&f.path), shown_target(n))));
    }
    // The executable bit, as Git prints it (BUG-241), and a change of kind.
    match (&f.old, &f.new) {
        (Some(o), Some(n)) if o.mode != n.mode => {
            println!("{}", yellow(&format!("old mode {}", o.mode)));
            println!("{}", yellow(&format!("new mode {}", n.mode)));
        }
        (None, Some(n)) if n.mode != "100644" => {
            println!("{}", green(&format!("new file mode {}", n.mode)))
        }
        (Some(o), None) if o.mode != "100644" => println!("{}", red(&format!("deleted file mode {}", o.mode))),
        _ => {}
    }
    // A link's content is its target, shown above.
    if links {
        return;
    }
    let Some(content) = &f.content else { return };
    if let Some(h) = &content.hidden {
        println!("{}", dim(&format!("  (content hidden: {})", safe(&h.message))));
        return;
    }
    if content.binary {
        println!("{}", dim("  (binary content differs)"));
        return;
    }
    for line in patch_lines(&content.hunks) {
        // File content comes from the repository (possibly a remote).
        let line = safe_content_line(&line);
        let line = line.as_ref();
        let colored = if line.starts_with('+') {
            green(line)
        } else if line.starts_with('-') {
            red(line)
        } else if line.starts_with("@@") {
            cyan(line)
        } else {
            line.to_string()
        };
        println!("{colored}");
    }
}

/// The lines of the unified diff of `hunks`, exactly as
/// `diffy::Patch::to_string().lines()` gives them after the `---`/`+++`
/// header: a blank context line has no leading space, a last line without
/// a line break is followed by `\ No newline at end of file`, and `lines()`
/// drops one `\r` before each line break.
pub fn patch_lines(hunks: &[Hunk]) -> Vec<String> {
    let range = |start: usize, len: usize| if len == 1 { start.to_string() } else { format!("{start},{len}") };
    let mut out = Vec::new();
    for h in hunks {
        out.push(format!("@@ -{} +{} @@", range(h.old_start, h.old_lines), range(h.new_start, h.new_lines)));
        for l in &h.lines {
            let sign = match l.kind {
                "added" => '+',
                "removed" => '-',
                _ => ' ',
            };
            let line = if sign == ' ' && l.newline && l.text.is_empty() { String::new() } else { format!("{sign}{}", l.text) };
            // A `\n` inside a line cannot happen (lines split on it); a `\r`
            // can, and `str::lines` strips one before the line break.
            out.push(line.strip_suffix('\r').map(str::to_string).unwrap_or(line));
            if !l.newline {
                out.push("\\ No newline at end of file".to_string());
            }
        }
    }
    out
}

// ---- show ------------------------------------------------------------------------

/// `vl show`: the header from `s` ([`super::show_header`]), then the diff,
/// rendered one file at a time.
pub fn show(repo: &Repo, s: &Show, r: &Renames) -> Result<()> {
    println!("Change ID : {}", bold(&magenta(&s.change_id)));
    println!("Snapshot  : {}", blue(&s.snapshot_id));
    println!("Author    : {} at {}", safe(&s.author), fmt_time(s.timestamp_ms));
    if let (Some(st), Some(snap)) = (&s.signature_status, &s.snapshot) {
        println!("Signature : {}", signature_detail(st, snap));
    }
    if s.parents.len() > 1 {
        for p in &s.parents {
            println!("Parent    : {}", one_line(p));
        }
    }
    if !s.tags.is_empty() {
        println!("Tags      : {}", cyan(&s.tags.iter().map(|t| safe(t)).collect::<Vec<_>>().join(", ")));
    }
    if let Some(c) = &s.cloak {
        println!("Cloaked   : {}", magenta(&safe(c)));
    }
    if let Some(e) = &s.embargo {
        let state = match (e.state, e.until_ms) {
            ("released", _) => "released".to_string(),
            ("staged", _) => "released here, not pushed yet".to_string(),
            ("pending", Some(u)) => format!("until {}", fmt_deadline(u)),
            ("pending", None) => "until manually released".into(),
            _ => "unknown".into(),
        };
        println!("Embargo   : {} ({state})", yellow(&safe(&e.id)));
    }
    // As `vl log` marks it and `vl status` lists them (BUG-245). A merge's
    // own diff is relative to the merged parents, so it shows no markers.
    if !s.conflicts.is_empty() {
        let paths: Vec<String> = s.conflicts.iter().map(|c| safe(c).into_owned()).collect();
        println!("Conflicts : {}", red(&paths.join(", ")));
    }
    println!();
    let desc = description_shown(&s.description, &s.description_hidden);
    if desc.trim().is_empty() {
        println!("    {}", dim("(no description set)"));
    } else {
        for l in safe_lines(&desc) {
            println!("    {l}");
        }
    }
    println!();
    diff(repo, &s.base_tree, &s.tree, s.diff.stat, r)
}

// ---- lists -----------------------------------------------------------------------

pub fn workspace_list(w: &WorkspaceList) {
    for ws in &w.workspaces {
        let here = if ws.current { green("* ") } else { "  ".into() };
        let cloak = ws.cloak.as_ref().map(|c| magenta(&format!(" [cloaked:{}]", safe(c)))).unwrap_or_default();
        println!("{here}{}{cloak}: {}", bold(&safe(&ws.name)), one_line(&ws.working_copy));
    }
}

pub fn tag_list(t: &TagList) {
    for tag in &t.tags {
        let cloak = tag.cloak.as_ref().map(|c| magenta(&format!(" [cloaked:{}]", safe(c)))).unwrap_or_default();
        println!("{}{cloak}: {}", cyan(&safe(&tag.name)), one_line(&tag.target));
    }
    for tag in &t.remote_tags {
        println!("{}: {}", dim(&safe(&tag.name)), one_line(&tag.target));
    }
}

pub fn op_log(o: &OpLog) {
    for op in &o.operations {
        println!("{} {} {} {}", blue(&op.op_short), dim(&fmt_time(op.timestamp_ms)), yellow(&safe(&op.user)), safe(&op.description));
    }
}

pub fn secret_list(s: &SecretList) {
    for k in &s.secrets {
        println!("{}", k.name);
    }
}

// ---- scan ------------------------------------------------------------------------

pub fn scan(s: &Scan) {
    for p in &s.nested {
        println!("{} {}/  (a repository of its own, never recorded here; run `vl scan` in it)", dim("nested   "), safe(p));
    }
    let gate = s.mode == "gate";
    let policy_from = s.policy_from.clone().unwrap_or_default();
    for f in &s.files {
        if let Some(e) = &f.error {
            println!("{} {}  cannot read it ({}); not scanned", red("UNREAD   "), safe(&f.path), safe(e));
            continue;
        }
        let label = match (gate, f.tier, &f.scope) {
            (true, _, _) | (false, "public", _) => red("PUBLIC   "),
            (false, "cloaked", Some(sc)) => magenta(&format!("cloaked:{}", safe(sc))),
            _ => dim("isolated "),
        };
        let note = match (gate, f.tier) {
            (true, t) if t != "public" => dim(&format!("  ({} by {policy_from}: in a checkout it is published anyway)", f.tier_label)),
            _ => String::new(),
        };
        for x in &f.findings {
            println!("{label} {}:{}  {} {}{note}", safe(&f.path), x.line, x.rule, dim(&safe(&x.excerpt)));
        }
    }
    match (gate, s.clean) {
        (false, true) => println!("{} no secrets in public files ({} protected file(s) contain secrets)", green("ok:"), s.protected),
        (false, false) => println!(
            "{} {} public file(s) contain secrets; they are quarantined from snapshots until cloaked, isolated or fixed",
            red("found:"),
            s.exposed
        ),
        (true, true) => println!("{} no secrets outside the `public!` paths of {policy_from}", green("ok:")),
        (true, false) => println!(
            "{} {} file(s) contain secrets (or could not be scanned); only the `public!` paths of {policy_from} may",
            red("found:"),
            s.exposed
        ),
    }
}

// ---- ls --------------------------------------------------------------------------

/// `vl ls`: one file per line, `TIER  SIZE  PATH  (note)`; stops when
/// stdout goes away.
/// `conflict: 2 sides` and what of it this reader cannot see.
fn conflict_note(c: &ConflictInfo) -> String {
    let mut n = format!("conflict: {} sides", c.sides);
    if c.unreadable_side {
        n.push_str(", a version you cannot read; cannot be resolved here");
    } else if c.redacted {
        n.push_str(", partly redacted");
    }
    n
}

/// `vl resolve --list`.
pub fn resolve_list(r: &ResolveList) {
    if r.conflicts.is_empty() {
        println!("{}", dim(&format!("(no conflicts in {})", r.snapshot.change_short.as_deref().unwrap_or("root()"))));
        return;
    }
    for item in &r.conflicts {
        let Some(c) = &item.conflict else {
            println!("{} {}  {}", red("C"), safe(&item.path), dim("(markers in the file: edit it to resolve)"));
            continue;
        };
        println!("{} {}  {}", red("C"), safe(&item.path), dim(&format!("({})", conflict_note(c))));
        for v in &c.versions {
            let name = match (c.sides, v.role, v.number) {
                (2, "side", 1) => "ours".to_string(),
                (2, "side", _) => "theirs".to_string(),
                (2, _, _) => "base".to_string(),
                (_, role, n) => format!("{role} {n}"),
            };
            let what = match &v.visibility {
                None => "no file".to_string(),
                Some(vis) => {
                    let label = safe(&vis.visibility().label()).into_owned();
                    if v.readable {
                        label
                    } else {
                        format!("{label}, not readable here")
                    }
                }
            };
            println!("    {name:<8} {}", dim(&what));
        }
    }
}

pub fn ls(l: &Ls) {
    for e in &l.entries {
        if stdout_closed() {
            return;
        }
        let label = tier_label(e.tier, e.scope.as_deref(), e.embargo.as_deref());
        let size = e.size.map_or_else(|| "-".to_string(), |s| s.to_string());
        let mut note = Vec::new();
        if let Some(r) = &e.redaction {
            note.push(safe(&r.message).into_owned());
        }
        if let Some(q) = &e.quarantine {
            note.push(format!(
                "{}; {}",
                q.rule,
                match q.state {
                    "held_back" => "edit held back; history keeps the previous version",
                    _ => "never recorded",
                }
            ));
        }
        if let Some(c) = &e.conflict {
            note.push(conflict_note(c));
        }
        if e.tier == "quarantined" && e.recorded {
            if let Some(v) = &e.visibility {
                note.push(format!("recorded as {}", safe(&v.visibility().label())));
            }
        }
        let note = if note.is_empty() { String::new() } else { dim(&format!("  ({})", note.join("; "))) };
        // A symlink with its target (escaped; a redacted link's target is
        // sealed content and never shown), a gitlink as a submodule.
        let leaf = match (e.kind, &e.target) {
            ("symlink", Some(t)) => format!("{}{}", dim(" -> "), safe(t)),
            ("symlink", None) => dim(" -> (target not shown)"),
            ("gitlink", _) => dim(" (submodule)"),
            _ => String::new(),
        };
        println!(
            "{} {:>9}  {}{}{}{leaf}{note}",
            tier_coloured(&format!("{label:<18}"), e.tier),
            size,
            safe(&e.path),
            if e.dir { "/" } else { "" },
            if e.executable { dim(" *") } else { String::new() },
        );
    }
}

// ---- push --dry-run ----------------------------------------------------------------

/// Bytes, for people: `512 B`, `4.1 KiB`, `12.0 MiB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

pub fn push_plan(doc: &PushPlanDoc) {
    for (i, r) in doc.remotes.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!(
            "{} {} {}{}",
            bold(&safe(&r.name)),
            if r.public { yellow("public") } else { green("team") },
            dim(&safe(&r.url)),
            if r.creates_remote { dim(" (no repository there yet: the push creates one)") } else { String::new() }
        );
        if let Some(e) = &r.error {
            println!("  {} {}", red("error:"), safe(e));
            continue;
        }
        for t in &r.tags {
            let name = cyan(&safe(&t.name));
            let from = t.remote_target.as_deref().map(|h| h.get(..8).unwrap_or(h).to_string());
            let reason = t.message.as_deref().map(|w| format!(" ({})", safe(w))).unwrap_or_default();
            match t.action {
                "create" => println!("  {} {name} → {}", green("create   "), t.target_short),
                "update" => println!("  {} {name} {} → {}", green("update   "), from.unwrap_or_default(), t.target_short),
                "unchanged" => println!("  {} {name} {}", dim("unchanged"), dim(&format!("(already at {})", t.target_short))),
                "rejected" => println!("  {} {name}{reason}", red("rejected ")),
                _ => println!("  {} {name}{reason}", yellow("skipped  ")),
            }
        }
        if r.objects == 0 {
            println!("  no objects to send");
        } else {
            println!(
                "  would send {} snapshot(s), {} object(s) ({} tree(s), {} file content(s), {} encrypted): {}, {} packed",
                r.snapshots,
                r.objects,
                r.trees,
                r.blobs,
                r.sealed,
                human_bytes(r.object_bytes),
                human_bytes(r.pack_bytes)
            );
        }
        if r.withheld_objects > 0 {
            println!("  {} {} cloaked/embargoed object(s)", yellow("withheld "), r.withheld_objects);
        }
        let mut by_embargo: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for s in &r.withheld_snapshots {
            *by_embargo.entry(&s.embargo).or_default() += 1;
        }
        for (e, n) in by_embargo {
            println!(
                "  {} {n} snapshot(s) of the history merged under unreleased embargo {} (sent when it is released)",
                yellow("withheld "),
                safe(e)
            );
        }
        for e in &r.releases {
            println!("  {} the release of embargo {} (its key goes into the pushed record)", green("publish  "), safe(e));
        }
        if let Some(f) = &r.files {
            if f.published.is_empty() {
                println!("  no file content becomes public");
            } else {
                println!("  Would become public on {}:", safe(&r.name));
                for p in &f.published {
                    let word = match p.exposure {
                        "new" => green("new     "),
                        "exposed" => yellow("exposed "),
                        _ => cyan("modified"),
                    };
                    let size = p.size.map_or_else(|| "-".to_string(), |s| s.to_string());
                    let note = match (&p.released_embargo, p.exposure) {
                        (Some(e), _) => dim(&format!("  (released embargo {})", safe(e))),
                        (None, "exposed") => dim("  (withheld there until now)"),
                        _ => String::new(),
                    };
                    println!("    {word} {size:>9}  {}{note}", safe(&p.path));
                }
            }
            if !f.withheld.is_empty() || !f.embargoed_trees.is_empty() {
                println!("  Withheld from {}:", safe(&r.name));
                for w in &f.withheld {
                    println!("    {}  {}", safe(&w.path), dim(&format!("({})", safe(&w.message))));
                }
                for t in &f.embargoed_trees {
                    println!(
                        "    {}  {}",
                        t.snapshot_short,
                        dim(&format!("(its tree is under unreleased embargo {}; the remote sees the pre-merge tree)", safe(&t.embargo)))
                    );
                }
            }
        }
        for w in &r.warnings {
            crate::render::warn_untrusted(w);
        }
    }
    println!("{}", dim("Dry run: nothing was sent."));
}

#[cfg(test)]
mod tests {
    #[test]
    fn bytes_for_people() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(2110), "2.1 KiB");
        assert_eq!(human_bytes(5 << 20), "5.0 MiB");
        assert_eq!(human_bytes(3 << 40), "3.0 TiB");
        assert_eq!(tier_label("cloaked", Some("ops"), None), "cloaked:ops");
        assert_eq!(tier_label("embargoed", None, Some("e1")), "embargoed:e1");
        assert_eq!(tier_label("redacted", Some("ops"), None), "redacted");
    }

    use proptest::prelude::*;

    use super::*;

    /// What the text output printed before the hunks existed.
    fn diffy_lines(old: &str, new: &str) -> Vec<String> {
        diffy::create_patch(old, new).to_string().lines().skip(2).map(str::to_string).collect()
    }

    fn check(old: &str, new: &str) {
        let hunks = super::super::hunks(&diffy::create_patch(old, new));
        assert_eq!(patch_lines(&hunks), diffy_lines(old, new), "old {old:?} new {new:?}");
    }

    #[test]
    fn hunks_render_exactly_as_diffy_does() {
        check("", "a\n");
        check("a\n", "");
        check("a\nb\nc\n", "a\nB\nc\n");
        check("a\n\nb\n", "a\n\nc\n");
        check("a", "a\nb");
        check("x\r\ny\r\n", "x\r\nz\r\n");
        check("x\r\r\n", "y\r\n");
        check("1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n", "1\n2\n3\nfour\n5\n6\n7\n8\n9\nten\n");
    }

    proptest! {
        #[test]
        fn hunks_render_exactly_as_diffy_does_for_any_text(
            old in proptest::collection::vec(prop_oneof!["a", "b", "", "\r", "x\r", " "], 0..12),
            new in proptest::collection::vec(prop_oneof!["a", "b", "", "\r", "x\r", "c"], 0..12),
            old_nl in any::<bool>(),
            new_nl in any::<bool>(),
        ) {
            let mut o = old.join("\n");
            let mut n = new.join("\n");
            if old_nl && !o.is_empty() { o.push('\n'); }
            if new_nl && !n.is_empty() { n.push('\n'); }
            check(&o, &n);
        }
    }
}

// ---- blame -----------------------------------------------------------------------

/// `vl blame`: `change (author date line) text`, one line per line of the
/// file; unattributed lines say why. Change ids, never descriptions (a
/// sealed description cannot leak through blame).
pub fn blame(b: &BlameDoc) {
    let width = b.lines.iter().filter_map(|l| l.author.as_deref()).map(|a| a.chars().count().min(20)).max().unwrap_or(0);
    let digits = b.lines.last().map_or(1, |l| l.line.to_string().len());
    for l in &b.lines {
        if stdout_closed() {
            return;
        }
        let text = safe(&l.text);
        match (&l.change_short, &l.unattributed) {
            (Some(c), _) => {
                let author: String = l.author.as_deref().unwrap_or_default().chars().take(20).collect();
                let date = crate::render::fmt_time(l.timestamp_ms);
                let date = date.split(' ').next().unwrap_or_default().to_string();
                println!(
                    "{} ({} {} {:>digits$}) {text}",
                    magenta(&c[..c.len().min(8)]),
                    yellow(&format!("{:<width$}", safe(&author))),
                    dim(&date),
                    l.line
                );
            }
            (None, u) => {
                let why = match u {
                    Some(UnattributedDoc { reason: "sealed", sealed_for: Some(v) }) => format!("sealed:{}", safe(&v.visibility().label())),
                    Some(u) => u.reason.replace('_', "-"),
                    None => "unknown".into(),
                };
                println!("{} ({} {:>digits$}) {text}", dim("????????"), dim(&why), l.line);
            }
        }
    }
    if b.version == "fallback" {
        crate::render::warn("you cannot read the current version of this file: its last public version is annotated (members see newer content)");
    }
    if b.unattributed > 0 {
        let why = match b.stopped {
            Some("max_changes") => "the walk stopped at --max-changes; raise it to go further",
            Some(_) => "the walk ran out of its work budget",
            None => "the history they come from is sealed for you",
        };
        crate::render::warn(&format!("{} line(s) unattributed: {why}", b.unattributed));
    }
    if b.coarse {
        crate::render::warn("some versions differ too much to compare line by line: their changed region is attributed whole");
    }
}

// ---- grep ------------------------------------------------------------------------

/// How `vl grep` prints its result.
#[derive(Clone, Copy, Default)]
pub struct GrepStyle {
    pub line_number: bool,
    pub files_with_matches: bool,
    pub count: bool,
}

/// `vl grep`: `path:text` (`path:line:text` with `-n`), `path` with `-l`,
/// `path:count` with `-c`; "binary file path matches" for binary files.
pub fn grep(g: &GrepDoc, style: GrepStyle) {
    let mut lines = g.matches.iter().peekable();
    for f in &g.files {
        if stdout_closed() {
            return;
        }
        let p = safe(&f.path);
        if style.files_with_matches {
            println!("{}", magenta(&p));
        } else if style.count {
            println!("{}:{}", magenta(&p), f.count);
        }
        let mine: Vec<&GrepMatchDoc> = std::iter::from_fn(|| lines.next_if(|m| m.path == f.path)).collect();
        if style.files_with_matches || style.count {
            continue;
        }
        if f.binary && mine.is_empty() {
            println!("binary file {p} matches");
            continue;
        }
        for m in mine {
            let text = safe(&m.text);
            let cut = if m.truncated { "…" } else { "" };
            match style.line_number {
                true => println!("{}:{}:{text}{cut}", magenta(&p), green(&m.line.to_string())),
                false => println!("{}:{text}{cut}", magenta(&p)),
            }
        }
    }
    let fallback: Vec<String> = g.files.iter().filter(|f| f.tier == "fallback").map(|f| safe(&f.path).into_owned()).collect();
    if !fallback.is_empty() {
        crate::render::warn(&format!(
            "searched the last public version of {} file(s) you cannot read (members see newer content): {}",
            fallback.len(),
            fallback.join(", ")
        ));
    }
    if g.skipped.sealed > 0 {
        crate::render::warn(&format!("{} file(s) not searched: sealed for a scope you are not in", g.skipped.sealed));
    }
    if g.skipped.too_large > 0 {
        crate::render::warn(&format!("{} file(s) over 256 MiB not searched", g.skipped.too_large));
    }
}
