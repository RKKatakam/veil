use std::{
    borrow::Cow,
    fmt::Write as _,
    io::{self, IsTerminal, Write as _},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

use anyhow::Result;
use veil_core::{
    builder::BuildReport,
    keychain::SignatureStatus,
    object::{Snapshot, Visibility},
    policy::{HeldBack, POLICY_FILE},
    ObjectId, Repo, TreeEntry, VPath,
};

// ---- output streams ---------------------------------------------------------
//
// `println!` panics when stdout is gone, as in `vl log | head` once `head`
// exits (Rust ignores SIGPIPE, so the write fails with EPIPE instead of
// killing the process). Every line `vl` prints goes through [`Out`] / [`ErrOut`]
// instead (`main.rs` shadows `println!` and `eprintln!`): a closed stream is
// remembered and further output to it is dropped, so the command still runs
// to completion and leaves the repository and working copy consistent, and
// [`exit_status`] then exits with 141 (128 + SIGPIPE), the status a shell
// reports for Git killed by SIGPIPE. Long listings stop early through
// [`stdout_closed`].
//
// Restoring the default SIGPIPE disposition instead would also kill `vl`
// mid-transaction when an `ssh` or `git` child it writes to exits.

static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);
static PIPE_BROKEN: AtomicBool = AtomicBool::new(false);
/// The first stdout write error that was not a closed pipe (a full disk...).
static STDOUT_ERROR: OnceLock<String> = OnceLock::new();

/// Exit status for output cut short by a closed pipe: 128 + SIGPIPE.
pub const BROKEN_PIPE_STATUS: u8 = 141;

/// Standard output that never fails: see the module notes above.
pub struct Out;

/// Standard error that never fails.
pub struct ErrOut;

fn stream_write(closed: &AtomicBool, stdout: bool, f: impl FnOnce() -> io::Result<usize>, len: usize) -> io::Result<usize> {
    if closed.load(Ordering::Relaxed) {
        return Ok(len);
    }
    match f() {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Err(e),
        Err(e) => {
            closed.store(true, Ordering::Relaxed);
            if e.kind() == io::ErrorKind::BrokenPipe {
                PIPE_BROKEN.store(true, Ordering::Relaxed);
            } else if stdout {
                let _ = STDOUT_ERROR.set(e.to_string());
            }
            Ok(len)
        }
    }
}

impl io::Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        stream_write(&STDOUT_CLOSED, true, || io::stdout().write(buf), buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        stream_write(&STDOUT_CLOSED, true, || io::stdout().flush().map(|()| 0), 0).map(|_| ())
    }
}

impl io::Write for ErrOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        stream_write(&STDERR_CLOSED, false, || io::stderr().write(buf), buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        stream_write(&STDERR_CLOSED, false, || io::stderr().flush().map(|()| 0), 0).map(|_| ())
    }
}

/// What `println!` expands to (see `main.rs`).
pub fn out_line(args: std::fmt::Arguments<'_>) {
    if stdout_closed() {
        return;
    }
    // Held for the whole line, so lines from several threads don't mix
    // (the lock is reentrant: `Out` takes it again).
    let _line = io::stdout().lock();
    let _ = Out.write_fmt(args).and_then(|()| Out.write_all(b"\n"));
}

/// What `eprintln!` expands to (see `main.rs`).
pub fn err_line(args: std::fmt::Arguments<'_>) {
    if STDERR_CLOSED.load(Ordering::Relaxed) {
        return;
    }
    let _line = io::stderr().lock();
    let _ = ErrOut.write_fmt(args).and_then(|()| ErrOut.write_all(b"\n"));
}

/// Is standard output gone? Long listings stop when it is.
pub fn stdout_closed() -> bool {
    STDOUT_CLOSED.load(Ordering::Relaxed)
}

/// The process exit status for a command that ended with `code`: output
/// cut short by a closed pipe turns success into [`BROKEN_PIPE_STATUS`],
/// and a failed write to stdout (not a closed pipe) into a failure.
/// Failures keep their own status.
pub fn exit_status(code: ExitCode) -> ExitCode {
    let _ = Out.flush();
    if code != ExitCode::SUCCESS {
        return code;
    }
    if let Some(e) = STDOUT_ERROR.get() {
        err_line(format_args!("{} could not write to standard output: {e}", red("error:")));
        return ExitCode::FAILURE;
    }
    if PIPE_BROKEN.load(Ordering::Relaxed) {
        return ExitCode::from(BROKEN_PIPE_STATUS);
    }
    code
}

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

/// An absolute deadline, in local time with its UTC offset, plus UTC when
/// the local zone is not UTC: `2026-11-11 09:00:00 +01:00 (08:00:00 UTC)`.
pub fn fmt_deadline(ms: i64) -> String {
    use chrono::{Local, TimeZone, Utc};
    let (Some(local), Some(utc)) = (Local.timestamp_millis_opt(ms).single(), Utc.timestamp_millis_opt(ms).single()) else {
        return "-".into();
    };
    if local.offset().local_minus_utc() == 0 {
        return utc.format("%Y-%m-%d %H:%M:%S UTC").to_string();
    }
    let utc_part = if local.date_naive() == utc.date_naive() {
        utc.format("%H:%M:%S UTC")
    } else {
        utc.format("%Y-%m-%d %H:%M:%S UTC")
    };
    format!("{} ({utc_part})", local.format("%Y-%m-%d %H:%M:%S %:z"))
}

pub fn vis_label(v: &Visibility) -> String {
    match v {
        Visibility::Public => String::new(),
        Visibility::Cloaked { scope } => magenta(&format!("[cloaked:{}]", safe(scope))),
    }
}

/// First line of `s`, escaped with [`safe`].
pub fn first_line(s: &str) -> Cow<'_, str> {
    safe(s.lines().next().unwrap_or(""))
}

/// `change id  snapshot id  description` on one line.
pub fn one_line(repo: &Repo, id: &ObjectId) -> String {
    crate::api::text::one_line(&crate::api::snapshot_ref(repo, id))
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
            "{} quarantined: looks like a secret ({} at line {}: {}); {held}. Move the secret into a secret file (`.env`, …), fix it, or `vl isolate|expose --force {p}`",
            bold(&p),
            f.rule,
            f.line,
            safe(&f.excerpt)
        ));
    }
    for p in &r.blocked_exposures {
        warn_untrusted(&format!(
            "policy tries to make built-in secret path {p} public; ignored (use `public!` to override)"
        ));
    }
    for (p, why) in &r.cloak_failures {
        warn_untrusted(&format!("could not cloak {p} ({why}); it was kept local-only"));
    }
    // A command's held-back edit of `.veilpolicy`: the caller says where
    // it stays and how to accept it (`policy_edit_held_message`).
    if r.policy_edit_held.is_none() {
        print_policy_held_back(&r.policy_held_back, r.policy_edit_pending);
    }
}

/// What to tell the member about an edit of `.veilpolicy` a command made
/// that the recording held back (BUG-560), if there is one. `kept`: where
/// the edit stays (`the sandbox (…)`, `the mount`) and the workspace to
/// accept it in; `None` for a throwaway sandbox, where it is lost.
pub fn policy_edit_held_message(r: &BuildReport, kept: Option<(&str, &str)>) -> Option<String> {
    const SHOWN: usize = 5;
    let why = r.policy_edit_held.as_ref()?;
    let held = &r.policy_held_back;
    let mut list: Vec<String> = held
        .iter()
        .take(SHOWN)
        .map(|h| format!("{} ({} → {})", safe(&h.shown_path()), h.accepted, h.wanted))
        .collect();
    if held.len() > SHOWN {
        list.push(format!("and {} more", held.len() - SHOWN));
    }
    let paths = match list.is_empty() {
        true => String::new(),
        false => format!("; these keep their recorded protection: {}", list.join(", ")),
    };
    let next = match kept {
        Some((place, ws)) => format!(
            "It stays in {place}: review it, then `vl policy accept --workspace {}` records it",
            safe(ws)
        ),
        None => format!(
            "It goes with the throwaway sandbox: to apply it, edit {POLICY_FILE} yourself, or run the command in a \
             workspace and record its edit with `vl policy accept --workspace NAME`"
        ),
    };
    Some(format!(
        "{POLICY_FILE}, as the command left it, {}: the edit is not recorded (a command is not you, so the \
         recorded policy stays, and only the edit's stronger rules apply{paths}). {next}",
        safe(why)
    ))
}

/// Local files kept under the accepted policy because `.veilpolicy` (as
/// changed by a merge, pull, checkout, …) would weaken their protection.
/// `own_edit_pending`: the member's own edit of `.veilpolicy` could not be
/// applied on its own and waits too, so some of `held` may be theirs.
pub fn print_policy_held_back(held: &[HeldBack], own_edit_pending: bool) {
    const SHOWN: usize = 5;
    if held.is_empty() {
        return;
    }
    let mut list: Vec<String> = held
        .iter()
        .take(SHOWN)
        .map(|h| format!("{} ({} → {})", safe(&h.shown_path()), h.accepted, h.wanted))
        .collect();
    if held.len() > SHOWN {
        list.push(format!("and {} more", held.len() - SHOWN));
    }
    let origin = match own_edit_pending {
        false => "and that change came from a merge, pull, checkout, restore or undo (or a symlinked policy file) rather than your own edit",
        true => "through a change from a merge, pull, checkout, restore or undo that you have not accepted, or through your \
                 own edit, which waits for `vl policy accept` because it could not be applied without that change",
    };
    warn(&format!(
        "{} local path(s) keep the protection you accepted: {POLICY_FILE} would weaken it, {origin} ({}). Review it with `vl policy show`; apply it with `vl policy accept`",
        held.len(),
        list.join(", ")
    ));
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

/// The marker of a snapshot signed by the clone's own server (its key
/// pinned at sign-in), in `vl log`.
pub fn server_marker() -> String {
    green("✓server")
}

/// The same, for `vl show`.
pub fn server_detail(s: &Snapshot) -> String {
    let key = s.signature.as_ref().map(|g| dim(&format!(" (key {})", safe(g.key.get(..16).unwrap_or(&g.key))))).unwrap_or_default();
    format!("{}{key}", green(&format!("good, signed by the server (author {})", safe(&s.author))))
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

// `vl log` is rendered by `api::text::log`.

// ---- content this reader cannot see ----------------------------------------

/// What to tell someone who asked for the content of `path` (entry `e`),
/// which this repository cannot show. `None`: no explanation beyond the
/// engine's error (see `api::redaction_for_diff`).
/// Why this reader cannot materialise `e`, in a few words (`cloaked:team;
/// no key`, `cloaked:team; not received`), for listings; [`hidden_explanation`] says what to do.
pub fn hidden_reason(repo: &Repo, e: &TreeEntry) -> Option<String> {
    let present = repo.store().has(&e.id);
    Some(match &e.visibility {
        Visibility::Public => return None,
        Visibility::Cloaked { scope } if present => format!("cloaked:{}; no key", safe(scope)),
        Visibility::Cloaked { scope } => format!("cloaked:{}; not received", safe(scope)),
    })
}

pub fn hidden_explanation(repo: &Repo, path: &VPath, e: &TreeEntry) -> Option<String> {
    let path = safe(path.as_str());
    let present = repo.store().has(&e.id);
    Some(match &e.visibility {
        Visibility::Public => return None,
        Visibility::Cloaked { scope } if present => {
            let scope = safe(scope);
            format!(
                "{path} is cloaked under scope '{scope}' and you hold no key for it. Share your public key \
                 (`vl identity show`) with a member and ask them to run `vl scope grant {scope} <key>` and push; \
                 it becomes readable after your next `vl pull`"
            )
        }
        Visibility::Cloaked { scope } => {
            let scope = safe(scope);
            format!(
                "{path} is cloaked under scope '{scope}' and its content never reached this repository (it came \
                 from a public mirror, which never delivers cloaked content). Once a member grants you '{scope}' \
                 (`vl scope grant {scope} <key>`), clone the project from the Veil server to read it"
            )
        }
    })
}

/// The entry at `path` in `tree`, for a reader: a folder on the way whose
/// tree the server refuses (BUG-1508) is said so, never "not present".
pub fn lookup_shown(repo: &Repo, tree: &ObjectId, path: &VPath) -> Result<Option<TreeEntry>> {
    veil_core::tree::lookup_to_read(repo.store(), tree, path).map_err(|err| match veil_core::tree::refused_tree(repo.store(), &err) {
        true => anyhow::anyhow!(
            "{} is in a folder you no longer have access to (the server refuses its content)",
            safe(path.as_str())
        ),
        false => err.into(),
    })
}

/// The content of the file entry `e` at `path` below `root`, or an error
/// that explains sealed and withheld secrets instead of the store's
/// `object … is not present in this store`. In a thin clone, asked for at
/// that path (BUG-1506).
pub fn read_file(repo: &Repo, root: &ObjectId, path: &VPath, e: &TreeEntry) -> Result<Vec<u8>> {
    veil_core::tree::prefetch_files(repo.store(), root, [(path, e)])?;
    // A conflict: the file with markers this reader is shown.
    match veil_core::conflict::read_file_like(repo.store(), e) {
        Ok(d) => Ok(d),
        Err(err) if err.is_unreadable() => match hidden_explanation(repo, path, e) {
            Some(why) => Err(anyhow::anyhow!(why)),
            None => Err(anyhow::Error::new(err).context(format!(
                "the content of {} is missing from this repository (`vl fsck` checks the store)",
                safe(path.as_str())
            ))),
        },
        Err(err) => Err(err.into()),
    }
}

// ---- diffs ---------------------------------------------------------------

// `vl status`, `vl diff` and `vl show` are rendered by `api::text`.

pub fn print_files(repo: &Repo, tree: &ObjectId) -> Result<()> {
    let (files, hidden) = veil_core::tree::walk_files_hiding(repo.store(), tree)?;
    // A folder the server refuses (BUG-1508): its path only.
    for h in &hidden {
        println!("{} {:>9}  {}{}", dim(&format!("{:<18}", "redacted")), "-", safe(&crate::api::hidden_dir(h)), dim(" (you no longer have access to this folder)"));
    }
    // Readability is read by id: in a thin clone, each asked for at its
    // own path first (BUG-1506).
    veil_core::tree::prefetch_files(repo.store(), tree, files.iter().map(|(p, e)| (p, e)))?;
    for (path, e) in files {
        if stdout_closed() {
            break;
        }
        let readable = repo.store().entry_readable(&e);
        // What the object proves, not the label alone (BUG-482).
        let shown = crate::api::verified_visibility(repo, &e);
        let vis = match &shown {
            Visibility::Public => "public".to_string(),
            v => safe(&v.label()).into_owned(),
        };
        let flag = if e.kind == veil_core::EntryKind::Conflict {
            red(" (conflict)")
        } else if !readable {
            dim(" (redacted)")
        } else if e.executable {
            dim(" *")
        } else {
            String::new()
        };
        let vis = match shown {
            Visibility::Public => dim(&format!("{vis:<18}")),
            Visibility::Cloaked { .. } => magenta(&format!("{vis:<18}")),
        };
        println!("{vis} {:>9}  {}{flag}", e.size, safe(path.as_str()));
    }
    Ok(())
}

/// Paths of every file in a tree (for policy warnings).
pub fn tree_paths(repo: &Repo, tree: &ObjectId) -> Result<Vec<(VPath, Visibility)>> {
    Ok(veil_core::tree::walk_files_hiding(repo.store(), tree)?
        .0
        .into_iter()
        .filter(|(_, e)| e.kind.is_file_like())
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
