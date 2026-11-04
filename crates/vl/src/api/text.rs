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

pub fn changes_summary(changes: &[Change]) {
    for c in changes {
        let status = match c.status {
            "added" => green("A"),
            "deleted" => red("D"),
            _ => cyan("M"),
        };
        let vis = vis_label(&c.visibility.visibility());
        let hidden = if c.redacted { dim(" (redacted)") } else { String::new() };
        println!("{status} {}{}{hidden}", safe(&c.path), if vis.is_empty() { String::new() } else { format!(" {vis}") });
    }
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
            println!("  {} {}", dim("L"), safe(p));
        }
    }
    if !s.quarantined.is_empty() {
        println!("{}", yellow("Quarantined (secrets detected; kept local):"));
        for q in &s.quarantined {
            let state = match q.state {
                "held_back" => "edit held back; history keeps the previous version",
                _ => "never recorded",
            };
            println!("  {} {}  ({}; {state})", yellow("Q"), safe(&q.path), q.rule);
        }
    }
    if !s.policy_held_back.is_empty() {
        println!("{}", yellow("Policy change not accepted (protection kept; `vl policy accept` applies it):"));
        for h in &s.policy_held_back {
            println!("  {} {}  ({}; .veilpolicy says {})", yellow("P"), safe(&h.path), h.accepted, h.wanted);
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
            println!("  {} {}  ({})", dim("R"), safe(&r.path), safe(&r.redaction.message));
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
            "  {} edit the files to resolve the conflict markers; a conflict is resolved once its file is edited. Fold the resolution into the merge with `vl squash`, or `vl commit` it",
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
    for e in entries.by_ref() {
        if stdout_closed() {
            return Ok(());
        }
        log_entry(&e?, &mut lanes);
    }
    if entries.truncated && !stdout_closed() {
        println!("{}", dim("~  (more snapshots elided)"));
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
    }
}

// ---- diff ------------------------------------------------------------------------

/// `vl diff` of the changes between two trees, rendered one file at a time;
/// stops when stdout goes away.
pub fn diff(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool) -> Result<()> {
    let changes = diff_changes(repo, from, to)?;
    if changes.is_empty() {
        println!("{}", dim("(no changes)"));
        return Ok(());
    }
    if stat {
        let summary: Vec<Change> = changes.iter().map(|c| change(repo, c)).collect();
        changes_summary(&summary);
        return Ok(());
    }
    for c in &changes {
        if stdout_closed() {
            break;
        }
        file_diff_text(&file_diff_for_text(repo, c));
    }
    Ok(())
}

pub fn file_diff_text(f: &FileDiff) {
    println!("{}", bold(&format!("diff --veil a/{0} b/{0}", safe(&f.path))));
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
    // The executable bit, as Git prints it (BUG-241).
    match (&f.old, &f.new) {
        (Some(o), Some(n)) if o.executable != n.executable => {
            println!("{}", yellow(&format!("old mode {}", o.mode)));
            println!("{}", yellow(&format!("new mode {}", n.mode)));
        }
        (None, Some(n)) if n.executable => println!("{}", green(&format!("new file mode {}", n.mode))),
        (Some(o), None) if o.executable => println!("{}", red(&format!("deleted file mode {}", o.mode))),
        _ => {}
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
pub fn show(repo: &Repo, s: &Show) -> Result<()> {
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
    diff(repo, &s.base_tree, &s.tree, s.diff.stat)
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

#[cfg(test)]
mod tests {
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
