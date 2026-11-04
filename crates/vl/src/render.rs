use std::{
    collections::HashMap,
    io::IsTerminal,
    sync::OnceLock,
};

use anyhow::Result;
use veil_core::{
    builder::BuildReport,
    object::{EntryKind, Visibility},
    secrets::looks_binary,
    tree::{diff_trees, TreeChange},
    ObjectId, Repo, VPath,
};

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
        Visibility::Cloaked { scope } => magenta(&format!("[cloaked:{scope}]")),
        Visibility::Embargoed { embargo } => yellow(&format!("[embargo:{embargo}]")),
    }
}

pub fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

/// `change id  snapshot id  description` on one line.
pub fn one_line(repo: &Repo, id: &ObjectId) -> String {
    match repo.snapshot(id) {
        Ok(s) => {
            let desc = repo.description(&s);
            let desc = if desc.trim().is_empty() {
                dim("(no description set)")
            } else {
                first_line(&desc).to_string()
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
        warn(w);
    }
    for (p, findings) in &r.quarantined {
        let f = &findings[0];
        let held = if r.quarantine_kept.contains(p) {
            "this edit was not snapshotted (history keeps the previous version)"
        } else {
            "not snapshotted"
        };
        warn(&format!(
            "{} quarantined: looks like a secret ({} at line {}: {}); {held}. Fix it, or `vl cloak|isolate|expose --force {p}`",
            bold(p.as_str()),
            f.rule,
            f.line,
            f.excerpt
        ));
    }
    for p in &r.blocked_exposures {
        warn(&format!(
            "policy tries to make built-in secret path {p} public; ignored (use `public!` / `vl expose --force` to override)"
        ));
    }
    for (p, why) in &r.cloak_failures {
        warn(&format!("could not cloak {p} ({why}); it was kept local-only"));
    }
}

// ---- log -----------------------------------------------------------------

pub fn print_log(repo: &Repo, ws: &str, limit: Option<usize>) -> Result<()> {
    let ids = repo.visible_snapshots()?;
    let mut tags: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, t) in &repo.view().tags {
        let label = match &t.cloak {
            Some(s) => format!("{name}[cloaked:{s}]"),
            None => name.clone(),
        };
        tags.entry(t.target).or_default().push(label);
    }
    for (name, t) in &repo.view().remote_tags {
        tags.entry(*t).or_default().push(name.clone());
    }
    let mut wss: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (name, w) in &repo.view().workspaces {
        wss.entry(w.wc).or_default().push(format!("{name}@"));
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
            header.push(yellow(&s.author));
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
            header.push(magenta(&format!("[cloaked:{c}]")));
        }
        if let Some(e) = &s.embargo {
            let released = repo.keys().embargo_released(e);
            header.push(yellow(&format!("[embargo:{e}{}]", if released { " released" } else { "" })));
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
                first_line(&desc).to_string()
            };
            let merge = if parents.len() > 1 {
                dim(&format!(
                    "  ⇠ merges {}",
                    parents
                        .iter()
                        .map(|p| repo.snapshot(p).map(|s| s.change_id.short()).unwrap_or_default())
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
        println!("{status} {}{}{hidden}", c.path, if vis.is_empty() { String::new() } else { format!(" {vis}") });
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
        println!("{}", bold(&format!("diff --veil a/{0} b/{0}", c.path)));
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
                yellow(&format!("visibility: {} → {}", o.visibility.label(), n.visibility.label()))
            ),
            _ => {}
        }
        let (old, new) = match (read(&c.old), read(&c.new)) {
            (Ok(Some(a)), Ok(Some(b))) => (a, b),
            (Err(v), _) | (_, Err(v)) => {
                println!("{}", dim(&format!("  (content hidden: {v}; you hold no key)")));
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
            v => v.label(),
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
        println!("{vis} {:>9}  {path}{flag}", e.size);
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
