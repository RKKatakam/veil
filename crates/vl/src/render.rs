use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Write as _,
    io::IsTerminal,
    sync::OnceLock,
};

use anyhow::Result;
use veil_core::{
    builder::BuildReport,
    keychain::SignatureStatus,
    object::{EntryKind, Snapshot, Visibility},
    secrets::looks_binary,
    tree::{diff_trees, TreeChange},
    ObjectId, Repo, VPath,
};

// ---- untrusted text -------------------------------------------------------

/// Characters that must never reach the terminal raw: C0 and C1 controls
/// (ESC, CSI, BEL, CR, newline, ...), DEL, and the Unicode bidirectional
/// overrides and isolates ("Trojan Source").
fn needs_escape(c: char) -> bool {
    c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Make repository data safe to print on one line: tag, author, signer,
/// scope and file names and descriptions can come from a remote, and raw
/// escape sequences could rewrite earlier output, set the window title or
/// plant hyperlinks. Offending characters are shown as `\x1b`, `\n`,
/// `\u{202e}`, ... Everything else, including our own colours (applied
/// *after* escaping), is unchanged.
pub fn safe(s: &str) -> Cow<'_, str> {
    escape(s, false)
}

/// [`safe`] for one line of file content in a diff: tabs are kept, and a
/// CRLF line ending is dropped rather than shown.
pub fn safe_content_line(s: &str) -> Cow<'_, str> {
    escape(s.strip_suffix('\r').unwrap_or(s), true)
}

fn escape(s: &str, keep_tabs: bool) -> Cow<'_, str> {
    let escaped = |c: char| needs_escape(c) && !(keep_tabs && c == '\t');
    if !s.chars().any(escaped) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            c if !escaped(c) => out.push(c),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x100 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
        }
    }
    Cow::Owned(out)
}

/// [`safe`] for multi-line text (descriptions): one safe line per line.
pub fn safe_lines(s: &str) -> impl Iterator<Item = Cow<'_, str>> {
    s.lines().map(safe)
}

fn color_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal())
}

fn paint(s: &str, code: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint(s, "1")
}
pub fn dim(s: &str) -> String {
    paint(s, "2")
}
pub fn red(s: &str) -> String {
    paint(s, "31")
}
pub fn green(s: &str) -> String {
    paint(s, "32")
}
pub fn yellow(s: &str) -> String {
    paint(s, "33")
}
pub fn blue(s: &str) -> String {
    paint(s, "34")
}
pub fn magenta(s: &str) -> String {
    paint(s, "35")
}
pub fn cyan(s: &str) -> String {
    paint(s, "36")
}

pub fn warn(msg: &str) {
    eprintln!("{} {msg}", yellow("warning:"));
}

/// Warning whose text comes from the engine and may quote repository data
/// (tag names, paths). It is escaped as a whole; it carries no colours.
pub fn warn_untrusted(msg: &str) {
    warn(&safe(msg));
}

pub fn fmt_time(ms: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ms) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => "-".into(),
    }
}

pub fn vis_label(v: &Visibility) -> String {
    match v {
        Visibility::Public => String::new(),
        Visibility::Cloaked { scope } => magenta(&format!("[cloaked:{}]", safe(scope))),
        Visibility::Embargoed { embargo } => yellow(&format!("[embargo:{}]", safe(embargo))),
    }
}

/// First line of `s`, escaped with [`safe`].
pub fn first_line(s: &str) -> Cow<'_, str> {
    safe(s.lines().next().unwrap_or(""))
}

/// `change id  snapshot id  description` on one line.
pub fn one_line(repo: &Repo, id: &ObjectId) -> String {
    match repo.snapshot(id) {
        Ok(s) => {
            let desc = repo.description(&s);
            let desc = if desc.trim().is_empty() {
                dim("(no description set)")
            } else {
                first_line(&desc).into_owned()
            };
            let empty = if repo.is_empty_change(id).unwrap_or(false) && !s.parents.is_empty() {
                format!("{} ", green("(empty)"))
            } else {
                String::new()
            };
            format!("{} {} {empty}{desc}", bold(&magenta(&s.change_id.short())), blue(&id.short()))
        }
        Err(_) => id.short(),
    }
}

pub fn print_build_warnings(r: &BuildReport) {
    for w in &r.policy_warnings {
        warn_untrusted(w);
    }
    for (p, findings) in &r.quarantined {
        let f = &findings[0];
        let held = if r.quarantine_kept.contains(p) {
            "this edit was not snapshotted (history keeps the previous version)"
        } else {
            "not snapshotted"
        };
        let p = safe(p.as_str());
        warn(&format!(
            "{} quarantined: looks like a secret ({} at line {}: {}); {held}. Fix it, or `vl cloak|isolate|expose --force {p}`",
            bold(&p),
            f.rule,
            f.line,
            safe(&f.excerpt)
        ));
    }
    for p in &r.blocked_exposures {
        warn_untrusted(&format!(
            "policy tries to make built-in secret path {p} public; ignored (use `public!` / `vl expose --force` to override)"
        ));
    }
    for (p, why) in &r.cloak_failures {
        warn_untrusted(&format!("could not cloak {p} ({why}); it was kept local-only"));
    }
}

// ---- log -----------------------------------------------------------------

/// Compact signature marker for `vl log`.
pub fn signature_marker(status: &SignatureStatus, author: &str) -> String {
    match status {
        SignatureStatus::Good { name, .. } if name == author => green("✓"),
        SignatureStatus::Good { name, .. } => green(&format!("✓{}", safe(name))),
        SignatureStatus::Unknown { .. } => yellow("?signer"),
        SignatureStatus::Bad => red("✗bad-signature"),
        SignatureStatus::Unsigned => dim("unsigned"),
    }
}

/// One-line signature description for `vl show`.
pub fn signature_detail(status: &SignatureStatus, s: &Snapshot) -> String {
    let key = s
        .signature
        .as_ref()
        .map(|g| dim(&format!(" (key {})", safe(g.key.get(..16).unwrap_or(&g.key)))))
        .unwrap_or_default();
    match status {
        SignatureStatus::Good { name, .. } if *name == s.author => {
            format!("{}{key}", green(&format!("good, signed by {}", safe(name))))
        }
        SignatureStatus::Good { name, .. } => format!(
            "{}{key}",
            green(&format!("good, signed by {} (rewritten; author {})", safe(name), safe(&s.author)))
        ),
        SignatureStatus::Unknown { .. } => {
            format!("{}{key}", yellow("valid, but by a key no key ring knows (signer unverified)"))
        }
        SignatureStatus::Bad => red("BAD: the signature does not match this snapshot"),
        SignatureStatus::Unsigned => dim("unsigned"),
    }
}

pub fn print_log(repo: &Repo, ws: &str, limit: Option<usize>) -> Result<()> {
    let ids = repo.visible_snapshots()?;
    let signers = repo.keys().known_signers();
    let mut tags: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, t) in &repo.view().tags {
        let label = match &t.cloak {
            Some(s) => format!("{}[cloaked:{}]", safe(name), safe(s)),
            None => safe(name).into_owned(),
        };
        tags.entry(t.target).or_default().push(label);
    }
    for (name, t) in &repo.view().remote_tags {
        tags.entry(*t).or_default().push(safe(name).into_owned());
    }
    let mut wss: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, w) in &repo.view().workspaces {
        wss.entry(w.wc).or_default().push(format!("{}@", safe(name)));
    }
    let current = repo.workspace_wc(ws)?;
    let root = repo.root_id();

    let mut lanes: Vec<Option<ObjectId>> = Vec::new();
    for (shown, id) in ids.iter().enumerate() {
        if limit.is_some_and(|l| shown >= l) {
            println!("{}", dim("~  (more snapshots elided)"));
            break;
        }
        let s = repo.snapshot(id)?;
        let col = match lanes.iter().position(|l| *l == Some(*id)) {
            Some(c) => c,
            None => match lanes.iter().position(|l| l.is_none()) {
                Some(c) => {
                    lanes[c] = Some(*id);
                    c
                }
                None => {
                    lanes.push(Some(*id));
                    lanes.len() - 1
                }
            },
        };
        for (j, l) in lanes.iter_mut().enumerate() {
            if j != col && *l == Some(*id) {
                *l = None;
            }
        }
        let marker = if *id == current {
            bold(&green("@"))
        } else if *id == root {
            "◆".to_string()
        } else if !s.conflicts.is_empty() {
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
        let line1_prefix = row(&lanes, Some((col, &marker)));

        let mut header = vec![bold(&magenta(&s.change_id.short()))];
        if *id != root {
            header.push(yellow(&safe(&s.author)));
            header.push(signature_marker(&repo.keys().snapshot_status_with(&s, &signers), &s.author));
            header.push(dim(&fmt_time(s.timestamp)));
        }
        if let Some(w) = wss.get(id) {
            header.push(green(&w.join(" ")));
        }
        if let Some(t) = tags.get(id) {
            header.push(cyan(&t.join(" ")));
        }
        header.push(blue(&id.short()));
        if *id != root && repo.is_empty_change(id).unwrap_or(false) {
            header.push(green("(empty)"));
        }
        if !s.conflicts.is_empty() {
            header.push(red("(conflict)"));
        }
        if let Some(c) = &s.cloak {
            header.push(magenta(&format!("[cloaked:{}]", safe(c))));
        }
        if let Some(e) = &s.embargo {
            let released = repo.keys().embargo_released(e);
            header.push(yellow(&format!("[embargo:{}{}]", safe(e), if released { " released" } else { "" })));
        }

        let parents: Vec<ObjectId> = s.parents.clone();
        lanes[col] = parents.first().copied();
        for p in parents.iter().skip(1) {
            if !lanes.contains(&Some(*p)) {
                match lanes.iter().position(|l| l.is_none()) {
                    Some(c) => lanes[c] = Some(*p),
                    None => lanes.push(Some(*p)),
                }
            }
        }
        while lanes.last() == Some(&None) {
            lanes.pop();
        }
        let mut line2_prefix = row(&lanes, None);
        if line2_prefix.is_empty() {
            line2_prefix = "  ".into();
        }
        println!("{line1_prefix} {}", header.join(" "));
        if *id == root {
            println!("{line2_prefix} {}", dim("root()"));
        } else {
            let desc = repo.description(&s);
            let desc = if desc.trim().is_empty() {
                dim("(no description set)")
            } else {
                first_line(&desc).into_owned()
            };
            let merge = if parents.len() > 1 {
                dim(&format!(
                    "  ⇠ merges {}",
                    parents
                        .iter()
                        // A parent may be withheld (unreleased embargo on a
                        // public clone): name it by snapshot id instead.
                        .map(|p| match repo.snapshot_opt(p) {
                            Ok(Some(s)) => s.change_id.short(),
                            _ => format!("{} (withheld)", p.short()),
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
    Ok(())
}

// ---- diffs ---------------------------------------------------------------

pub fn print_changes_summary(repo: &Repo, changes: &[TreeChange]) {
    for c in changes {
        let status = match c.status() {
            'A' => green("A"),
            'D' => red("D"),
            _ => cyan("M"),
        };
        let vis = c
            .new
            .as_ref()
            .or(c.old.as_ref())
            .map(|e| vis_label(&e.visibility))
            .unwrap_or_default();
        let hidden = c
            .new
            .as_ref()
            .is_some_and(|e| !repo.store().entry_readable(e));
        let hidden = if hidden { dim(" (redacted)") } else { String::new() };
        println!(
            "{status} {}{}{hidden}",
            safe(c.path.as_str()),
            if vis.is_empty() { String::new() } else { format!(" {vis}") }
        );
    }
}

pub fn print_diff(repo: &Repo, from: &ObjectId, to: &ObjectId, stat: bool) -> Result<()> {
    let changes = diff_trees(repo.store(), Some(from), Some(to))?;
    if changes.is_empty() {
        println!("{}", dim("(no changes)"));
        return Ok(());
    }
    if stat {
        print_changes_summary(repo, &changes);
        return Ok(());
    }
    for c in &changes {
        println!("{}", bold(&format!("diff --veil a/{0} b/{0}", safe(c.path.as_str()))));
        let read = |e: &Option<veil_core::TreeEntry>| -> Result<Option<Vec<u8>>, String> {
            match e {
                None => Ok(Some(Vec::new())),
                Some(e) => match repo.store().read_entry(e) {
                    Ok(d) => Ok(Some(d)),
                    Err(err) if err.is_unreadable() => Err(e.visibility.label()),
                    Err(err) => Err(err.to_string()),
                },
            }
        };
        match (c.status(), &c.old, &c.new) {
            ('A', _, Some(n)) => println!("{}", green(&format!("added file {}", vis_label(&n.visibility)))),
            ('D', Some(_), _) => println!("{}", red("deleted file")),
            (_, Some(o), Some(n)) if o.visibility != n.visibility => println!(
                "{}",
                yellow(&format!(
                    "visibility: {} → {}",
                    safe(&o.visibility.label()),
                    safe(&n.visibility.label())
                ))
            ),
            _ => {}
        }
        let (old, new) = match (read(&c.old), read(&c.new)) {
            (Ok(Some(a)), Ok(Some(b))) => (a, b),
            (Err(v), _) | (_, Err(v)) => {
                println!("{}", dim(&format!("  (content hidden: {}; you hold no key)", safe(&v))));
                continue;
            }
            _ => continue,
        };
        if looks_binary(&old) || looks_binary(&new) {
            println!("{}", dim("  (binary content differs)"));
            continue;
        }
        let old_s = String::from_utf8_lossy(&old);
        let new_s = String::from_utf8_lossy(&new);
        let patch = diffy::create_patch(&old_s, &new_s);
        for line in patch.to_string().lines().skip(2) {
            // File content comes from the repository (possibly a remote).
            let line = safe_content_line(line);
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
    Ok(())
}

pub fn print_files(repo: &Repo, tree: &ObjectId) -> Result<()> {
    for (path, e) in veil_core::tree::walk_files(repo.store(), tree)? {
        let readable = repo.store().entry_readable(&e);
        let vis = match &e.visibility {
            Visibility::Public => "public".to_string(),
            v => safe(&v.label()).into_owned(),
        };
        let flag = if !readable {
            dim(" (redacted)")
        } else if e.executable {
            dim(" *")
        } else {
            String::new()
        };
        let vis = match e.visibility {
            Visibility::Public => dim(&format!("{vis:<18}")),
            Visibility::Cloaked { .. } => magenta(&format!("{vis:<18}")),
            Visibility::Embargoed { .. } => yellow(&format!("{vis:<18}")),
        };
        println!("{vis} {:>9}  {}{flag}", e.size, safe(path.as_str()));
    }
    Ok(())
}

/// Paths of every file in a tree (for policy warnings).
pub fn tree_paths(repo: &Repo, tree: &ObjectId) -> Result<Vec<(VPath, Visibility)>> {
    Ok(veil_core::tree::walk_files(repo.store(), tree)?
        .into_iter()
        .filter(|(_, e)| e.kind == EntryKind::File)
        .map(|(p, e)| (p, e.visibility))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_escapes_terminal_controls_and_bidi_overrides() {
        assert!(matches!(safe("plain text, é ✓"), Cow::Borrowed(_)));
        assert_eq!(safe("v1\x1b[1A\x1b[2Kfake"), "v1\\x1b[1A\\x1b[2Kfake");
        assert_eq!(safe("a\nb\rc\td"), "a\\nb\\rc\\td");
        assert_eq!(safe("\x07\x7f\u{9b}"), "\\x07\\x7f\\x9b");
        assert_eq!(safe("abc\u{202e}fed"), "abc\\u{202e}fed");
        let lines: Vec<_> = safe_lines("one\x1b]0;t\x07\ntwo").collect();
        assert_eq!(lines, ["one\\x1b]0;t\\x07", "two"]);
        assert_eq!(first_line("x\x1by\nsecond"), "x\\x1by");
        assert_eq!(safe_content_line("+\tcode\x1b[2J\r"), "+\tcode\\x1b[2J");
        assert_eq!(safe_content_line("a\rb"), "a\\rb");
    }
}
