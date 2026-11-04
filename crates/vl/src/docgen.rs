//! The command reference in `docs/reference/`, generated from the clap
//! definition of the CLI, and a check that the user guide in `docs/guide/`
//! only uses commands and flags that exist.
//!
//! Both are tests, so the documentation cannot drift from the binary:
//!
//! * `reference_is_up_to_date` fails if a page in `docs/reference/` differs
//!   from what `Cli::command()` produces (or a page is missing or left
//!   over). Regenerate with
//!   `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`.
//! * `guide_commands_parse` parses every `vl …` command in the guide's
//!   shell code blocks (and in inline code) with the real parser.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use clap::{Arg, ArgAction, Command, CommandFactory, Parser};

use crate::cli::Cli;

const BLESS_VAR: &str = "VEIL_BLESS_DOCS";

fn docs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

fn built_cli() -> Command {
    let mut cmd = Cli::command();
    cmd.build();
    cmd
}

/// Subcommands worth documenting (not clap's generated `help`).
fn subcommands(cmd: &Command) -> impl Iterator<Item = &Command> {
    cmd.get_subcommands().filter(|c| c.get_name() != "help" && !c.is_hide_set())
}

/// Arguments worth documenting (not `--help` / `--version`, not hidden).
fn documented_args(cmd: &Command, global: bool) -> Vec<&Arg> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set())
        .filter(|a| !matches!(a.get_action(), ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version))
        .filter(|a| a.is_global_set() == global)
        .collect()
}

/// `vl scope grant` for the command at `path`.
fn full_name(path: &[&str]) -> String {
    path.join(" ")
}

fn usage(cmd: &Command) -> String {
    let mut cmd = cmd.clone();
    let u = cmd.render_usage().to_string();
    u.trim_start_matches("Usage:").trim().to_string()
}

/// The text of a doc comment as Markdown: clap keeps paragraphs, so this
/// only trims.
fn text(s: Option<&clap::builder::StyledStr>) -> String {
    s.map(|s| s.to_string().trim().to_string()).unwrap_or_default()
}

fn about(cmd: &Command) -> String {
    let long = text(cmd.get_long_about());
    if long.is_empty() {
        text(cmd.get_about())
    } else {
        long
    }
}

fn arg_help(a: &Arg) -> String {
    let long = text(a.get_long_help());
    let h = if long.is_empty() { text(a.get_help()) } else { long };
    h.replace('\n', " ")
}

/// `-r, --rev <REV>` / `<PATH>` / `--force`.
fn arg_signature(a: &Arg) -> String {
    let value = || {
        let names = a
            .get_value_names()
            .map(|v| v.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![a.get_id().as_str().to_ascii_uppercase()]);
        let v = names.iter().map(|n| format!("<{n}>")).collect::<Vec<_>>().join(" ");
        let optional = a.get_num_args().is_some_and(|r| r.min_values() == 0);
        if optional {
            format!("[{v}]")
        } else {
            v
        }
    };
    let takes_value = matches!(a.get_action(), ArgAction::Set | ArgAction::Append);
    if a.is_positional() {
        let mut v = value();
        if matches!(a.get_action(), ArgAction::Append) || a.get_num_args().is_some_and(|r| r.max_values() > 1) {
            v.push('…');
        }
        return v;
    }
    let mut names = Vec::new();
    if let Some(s) = a.get_short() {
        names.push(format!("-{s}"));
    }
    if let Some(l) = a.get_long() {
        names.push(format!("--{l}"));
    }
    let mut sig = names.join(", ");
    if takes_value {
        sig.push(' ');
        sig.push_str(&value());
    }
    sig
}

fn arg_notes(a: &Arg) -> Vec<String> {
    let mut notes = Vec::new();
    if a.is_required_set() {
        notes.push("required".to_string());
    }
    let defaults: Vec<String> = a.get_default_values().iter().map(|v| v.to_string_lossy().into_owned()).collect();
    if !defaults.is_empty() && !matches!(a.get_action(), ArgAction::SetTrue | ArgAction::SetFalse) {
        let d = defaults.join(" ");
        notes.push(if d.is_empty() { "default: empty".into() } else { format!("default: `{d}`") });
    }
    let possible: Vec<String> = a
        .get_possible_values()
        .iter()
        .filter(|p| !p.is_hide_set())
        .map(|p| format!("`{}`", p.get_name()))
        .collect();
    if !possible.is_empty() && takes_value_or_positional(a) {
        notes.push(format!("one of {}", possible.join(", ")));
    }
    let aliases: Vec<String> = a
        .get_visible_short_aliases()
        .unwrap_or_default()
        .iter()
        .map(|c| format!("`-{c}`"))
        .chain(
            a.get_visible_aliases()
                .unwrap_or_default()
                .iter()
                .map(|l| format!("`--{l}`")),
        )
        .collect();
    if !aliases.is_empty() {
        notes.push(format!("also {}", aliases.join(", ")));
    }
    if a.is_last_set() {
        notes.push("after `--`".to_string());
    }
    notes
}

fn takes_value_or_positional(a: &Arg) -> bool {
    a.is_positional() || matches!(a.get_action(), ArgAction::Set | ArgAction::Append)
}

/// `|` would end a table cell.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
}

fn arg_table(out: &mut String, title: &str, args: &[&Arg]) {
    if args.is_empty() {
        return;
    }
    let _ = writeln!(out, "{title}\n");
    let _ = writeln!(out, "| | |\n|---|---|");
    for a in args {
        let mut desc = arg_help(a);
        let notes = arg_notes(a);
        if !notes.is_empty() {
            if !desc.is_empty() {
                desc.push(' ');
            }
            let _ = write!(desc, "({})", notes.join("; "));
        }
        let _ = writeln!(out, "| `{}` | {} |", cell(&arg_signature(a)), cell(&desc));
    }
    out.push('\n');
}

/// One command (and, below it, its subcommands) as Markdown.
fn render_command(out: &mut String, cmd: &Command, path: &[&str], level: usize) {
    let hashes = "#".repeat(level);
    let _ = writeln!(out, "{hashes} `{}`\n", full_name(path));
    let a = about(cmd);
    if !a.is_empty() {
        let _ = writeln!(out, "{a}\n");
    }
    let aliases: Vec<String> = cmd.get_visible_aliases().map(|s| format!("`vl {s}`")).collect();
    if !aliases.is_empty() {
        let _ = writeln!(out, "Alias: {}.\n", aliases.join(", "));
    }
    let subs: Vec<&Command> = subcommands(cmd).collect();
    if subs.is_empty() || cmd.get_positionals().next().is_some() || cmd.get_opts().any(|a| !a.is_global_set()) {
        let _ = writeln!(out, "```text\n{}\n```\n", usage(cmd));
    }
    let args = documented_args(cmd, false);
    let positionals: Vec<&Arg> = args.iter().copied().filter(|a| a.is_positional()).collect();
    let options: Vec<&Arg> = args.iter().copied().filter(|a| !a.is_positional()).collect();
    arg_table(out, "Arguments:", &positionals);
    arg_table(out, "Options:", &options);
    if !subs.is_empty() {
        let _ = writeln!(out, "Subcommands:\n");
        for s in &subs {
            let mut p = path.to_vec();
            p.push(s.get_name());
            let _ = writeln!(out, "* [`{}`](#{}): {}", full_name(&p), anchor(&full_name(&p)), text(s.get_about()));
        }
        out.push('\n');
        for s in &subs {
            let mut p = path.to_vec();
            p.push(s.get_name());
            render_command(out, s, &p, level + 1);
        }
    }
}

/// GitHub's heading anchor for "`vl scope grant`".
fn anchor(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

const HEADER: &str = "<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:\n     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->\n\n";

/// File name → content of every page in `docs/reference/`.
pub fn reference_pages() -> BTreeMap<String, String> {
    let cli = built_cli();
    let mut pages = BTreeMap::new();

    let mut index = String::from(HEADER);
    let _ = writeln!(index, "# Command reference\n");
    let _ = writeln!(
        index,
        "Generated from `vl` itself (`vl <command> --help` shows the same text). For\nexplanations and worked examples, read the [user guide](../guide/README.md).\n"
    );
    let _ = writeln!(index, "{}\n", about(&cli));
    let _ = writeln!(index, "```text\n{}\n```\n", usage(&cli));
    arg_table(&mut index, "Global options (accepted by every command):", &documented_args(&cli, true));
    let _ = writeln!(index, "## Commands\n");
    let _ = writeln!(index, "| Command | |\n|---|---|");
    for s in subcommands(&cli) {
        let _ = writeln!(index, "| [`vl {}`]({}.md) | {} |", s.get_name(), s.get_name(), cell(&text(s.get_about())));
    }
    pages.insert("README.md".to_string(), index);

    for s in subcommands(&cli) {
        let mut page = String::from(HEADER);
        render_command(&mut page, s, &["vl", s.get_name()], 1);
        let _ = writeln!(page, "---\n\n[All commands](README.md) · [User guide](../guide/README.md)");
        pages.insert(format!("{}.md", s.get_name()), page);
    }
    pages
}

#[test]
fn reference_is_up_to_date() {
    let dir = docs_dir().join("reference");
    let pages = reference_pages();
    let bless = std::env::var_os(BLESS_VAR).is_some();
    if bless {
        std::fs::create_dir_all(&dir).unwrap();
    }
    let mut problems = Vec::new();
    for (name, want) in &pages {
        let path = dir.join(name);
        let have = std::fs::read_to_string(&path).ok();
        if have.as_deref() != Some(want.as_str()) {
            if bless {
                std::fs::write(&path, want).unwrap();
            } else {
                problems.push(format!("{} is {}", path.display(), if have.is_some() { "out of date" } else { "missing" }));
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".md") && !pages.contains_key(&name) {
                if bless {
                    std::fs::remove_file(e.path()).unwrap();
                } else {
                    problems.push(format!("{} documents no command any more", e.path().display()));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "the command reference does not match the CLI:\n  {}\nRegenerate it with `{BLESS_VAR}=1 cargo test -p vl --bin vl reference_is_up_to_date`",
        problems.join("\n  ")
    );
}

// ---- the guide ------------------------------------------------------------------

/// Split a shell line into words: quotes group, `#` at the start of a word
/// starts a comment. Good enough for documentation examples.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '#' if !in_word => break,
            '\'' | '"' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == c {
                        break;
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// The `vl` invocations on one shell line, each as its argument list.
fn vl_invocations(line: &str) -> Vec<Vec<String>> {
    let line = line.trim_start().trim_start_matches("$ ");
    let mut out = Vec::new();
    let mut seg: Vec<String> = Vec::new();
    let mut flush = |seg: &mut Vec<String>| {
        // Leading `VAR=value` assignments and `as_bob`-style wrappers are not part of the command.
        let start = seg.iter().position(|w| !(w.contains('=') && !w.starts_with('-'))).unwrap_or(seg.len());
        let cmd = &seg[start..];
        if cmd.first().is_some_and(|w| w == "vl") {
            out.push(cmd.to_vec());
        }
        seg.clear();
    };
    let mut skipping = false;
    for w in shell_words(line) {
        let w = w.trim_start_matches("$(").to_string();
        if matches!(w.as_str(), "|" | "||" | "&&" | ";" | "(" | ")") {
            flush(&mut seg);
            skipping = false;
            continue;
        }
        if skipping {
            continue;
        }
        // A redirection ends the arguments (`> file`, `2>&1`, `< in`).
        if w.starts_with('>') || w.starts_with("2>") || w == "<" || w.starts_with("<<") {
            skipping = true;
            continue;
        }
        let w = w.trim_end_matches(')').to_string();
        seg.push(w);
    }
    flush(&mut seg);
    out
}

/// Parse a full command line (`strict`), or check that an inline mention
/// such as `vl scope grant` or `vl push --force` names commands and flags
/// that exist (missing or placeholder values are fine there).
fn check_invocation(args: &[String], strict: bool) -> Result<(), String> {
    use clap::error::ErrorKind as K;
    match Cli::try_parse_from(args) {
        Ok(_) => Ok(()),
        Err(e) if matches!(e.kind(), K::DisplayHelp | K::DisplayVersion) => Ok(()),
        Err(e) if !strict && !matches!(e.kind(), K::InvalidSubcommand | K::UnknownArgument) => Ok(()),
        Err(e) => Err(e.to_string().lines().next().unwrap_or_default().to_string()),
    }
}

/// Every `vl …` command in `markdown`, with its line number and whether it
/// is a complete command line: shell code blocks line by line, and prompt
/// lines (`$ vl …`) of other code blocks (complete),
/// and inline code spans that are a plain mention (no `…`, alternatives
/// `|`, optional `[…]` or `<placeholder>` syntax).
fn guide_commands(markdown: &str) -> Vec<(usize, Vec<String>, bool)> {
    let mut out = Vec::new();
    let mut fence: Option<String> = None;
    let mut continued = String::new();
    for (i, line) in markdown.lines().enumerate() {
        let n = i + 1;
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("```") {
            fence = match fence {
                Some(_) => None,
                None => Some(rest.trim().to_string()),
            };
            continue;
        }
        match fence.as_deref() {
            Some("sh" | "bash" | "shell" | "console") => {
                if let Some(head) = line.strip_suffix('\\') {
                    continued.push_str(head);
                    continue;
                }
                let full = std::mem::take(&mut continued) + line;
                for inv in vl_invocations(&full) {
                    out.push((n, inv, true));
                }
            }
            // Transcripts: `$ vl …` or `bob$ vl …` prompt lines.
            Some(_) => {
                if let Some((user, cmd)) = line.split_once("$ ") {
                    if user.chars().all(|c| c.is_ascii_alphanumeric()) {
                        for inv in vl_invocations(cmd) {
                            out.push((n, inv, true));
                        }
                    }
                }
            }
            None => {
                for (j, span) in line.split('`').enumerate() {
                    if j % 2 == 1 && span.starts_with("vl ") && !span.contains(['…', '|', '[', '<']) {
                        for inv in vl_invocations(span) {
                            out.push((n, inv, false));
                        }
                    }
                }
            }
        }
    }
    out
}

#[test]
fn guide_commands_parse() {
    let dir = docs_dir().join("guide");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no guide pages in {}", dir.display());
    let mut checked = 0;
    let mut bad = Vec::new();
    for f in &files {
        let md = std::fs::read_to_string(f).unwrap();
        for (line, args, strict) in guide_commands(&md) {
            checked += 1;
            if let Err(e) = check_invocation(&args, strict) {
                bad.push(format!("{}:{line}: `{}`: {e}", f.display(), args.join(" ")));
            }
        }
    }
    eprintln!("checked {checked} vl commands in the guide");
    assert!(checked > 100, "only {checked} commands found in the guide; is the parser broken?");
    assert!(bad.is_empty(), "the guide uses commands `vl` does not accept:\n  {}", bad.join("\n  "));
}

#[test]
fn shell_lines_are_split_into_invocations() {
    assert_eq!(
        vl_invocations("echo x | vl ws write agent notes.md && vl log -n 2 > out.txt"),
        vec![
            vec!["vl", "ws", "write", "agent", "notes.md"],
            vec!["vl", "log", "-n", "2"],
        ]
    );
    assert_eq!(vl_invocations("vl commit -m \"Fix it\"   # comment"), vec![vec!["vl", "commit", "-m", "Fix it"]]);
    assert_eq!(vl_invocations("VEIL_USER=bob vl status"), vec![vec!["vl", "status"]]);
    let v = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(check_invocation(&v(&["vl", "nonsense"]), false).is_err());
    assert!(check_invocation(&v(&["vl", "push", "--nonsense"]), false).is_err());
    assert!(check_invocation(&v(&["vl", "commit"]), true).is_err(), "-m is required");
    assert!(check_invocation(&v(&["vl", "commit"]), false).is_ok(), "a mention");
}
