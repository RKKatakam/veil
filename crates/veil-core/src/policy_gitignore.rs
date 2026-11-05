//! The policy in gitignore syntax (the `info/exclude` block of colocated
//! mode) and `vl policy import-gitignore`.
//!
//! Colocated Git mode (feature 9; `docs/design/git-parity/9-colocated-git.md`)
//! keeps Git from picking up what Veil protects: `info/exclude` holds every
//! protective rule of the effective policy, translated to gitignore syntax.
//! The translation only ever **over-excludes**:
//!
//! * no negation is ever written (`!pattern` would re-include);
//! * `public` rules are dropped (an exception inside a cloaked directory
//!   stays excluded; Git still tracks it once Veil exports it);
//! * a case-insensitive rule (cloak, isolate, the built-in secrets) turns
//!   every ASCII letter into a class (`[sS][eE]…`) and every character
//!   class into `?`;
//! * brace alternation (`*.{pem,key}`) is expanded; past
//!   [`MAX_EXPANSIONS`] the group becomes `*`;
//! * a non-ASCII character becomes `*` (macOS may hand Git the name in
//!   another Unicode normalisation), a control character `?`;
//! * editor and backup artefacts of a protected file (`.env.swp`,
//!   `secrets.yml~`, `#notes#`) are excluded with it.
//!
//! [`import_gitignore`] goes the other way, once, when a Git checkout is
//! adopted: one `ignore` rule per `.gitignore` pattern that matches an
//! existing untracked, ignored file, so that `config/master.key` or
//! `*.tfvars` are not recorded just because Veil never read `.gitignore`.
//! Which file `.gitignore` ignores, and by which pattern, is asked of Git
//! itself (`git ls-files --others --ignored`, `git check-ignore -v`).

use std::{
    collections::BTreeSet,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use crate::{
    error::{Result, VeilError},
    policy::{Policy, Rule, Tier, SCRATCH_PATTERNS},
};

/// Brace expansions per pattern before a group is widened to `*`.
pub const MAX_EXPANSIONS: usize = 64;

/// Is `rule` matched case-insensitively (mirrors `policy::case_insensitive`)?
fn case_insensitive(r: &Rule) -> bool {
    (r.builtin && r.secret) || (!r.builtin && matches!(r.tier, Tier::Cloaked(_) | Tier::Isolated))
}

/// Does `rule` protect what it matches (keep it out of Git)?
fn protective(r: &Rule) -> bool {
    !matches!(r.tier, Tier::Public)
}

/// Expand the first top-level `{a,b}` group of `p` (escapes respected),
/// recursively. Unbalanced braces are taken literally (escaped).
fn expand_braces(p: &str, out: &mut Vec<String>, budget: &mut usize) {
    let chars: Vec<char> = p.chars().collect();
    let (mut i, mut start, mut depth, mut in_class) = (0, None, 0usize, false);
    let mut alts: Vec<(usize, usize)> = Vec::new();
    let mut alt_start = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '{' if !in_class => {
                if depth == 0 {
                    start = Some(i);
                    alt_start = i + 1;
                    alts.clear();
                }
                depth += 1;
            }
            ',' if !in_class && depth == 1 => {
                alts.push((alt_start, i));
                alt_start = i + 1;
            }
            '}' if !in_class && depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    alts.push((alt_start, i));
                    let s = start.unwrap();
                    let head: String = chars[..s].iter().collect();
                    let tail: String = chars[i + 1..].iter().collect();
                    if *budget < alts.len() {
                        // Too many: the whole group matches anything in a
                        // component (over-exclusion).
                        out.push(format!("{head}*{tail}"));
                        return;
                    }
                    *budget -= alts.len();
                    for (a, b) in &alts {
                        let mid: String = chars[*a..*b].iter().collect();
                        expand_braces(&format!("{head}{mid}{tail}"), out, budget);
                    }
                    return;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out.push(p.to_string());
}

/// One glob (no braces left) of a policy rule in gitignore syntax: case
/// folding, classes, non-ASCII and control characters as in the module
/// docs. Escapes are kept (`\*` is a literal star in both syntaxes).
fn glob_to_gitignore(p: &str, ci: bool) -> String {
    let mut out = String::with_capacity(p.len() * 2);
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(n) if n.is_ascii_alphabetic() && ci => push_letter(&mut out, n),
                Some(n) if !n.is_ascii() => out.push('*'),
                Some(n) if n.is_control() => out.push('?'),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push_str("\\\\"),
            },
            '[' => {
                // The class, as it is (or `?` when case-folding).
                let mut class = String::from("[");
                let mut closed = false;
                if let Some(&n) = chars.peek() {
                    if n == '!' || n == '^' {
                        class.push('!');
                        chars.next();
                    }
                }
                // The first character is a member even if it is `]`.
                let mut first = true;
                while let Some(n) = chars.next() {
                    class.push(n);
                    if n == '\\' {
                        if let Some(m) = chars.next() {
                            class.push(m);
                        }
                    } else if n == ']' && !first {
                        closed = true;
                        break;
                    }
                    first = false;
                }
                if !closed || ci || !class.is_ascii() || class.chars().any(char::is_control) {
                    out.push('?');
                } else {
                    out.push_str(&class);
                }
            }
            c if c.is_ascii_alphabetic() && ci => push_letter(&mut out, c),
            c if !c.is_ascii() => out.push('*'),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

fn push_letter(out: &mut String, c: char) {
    out.push('[');
    out.push(c.to_ascii_lowercase());
    out.push(c.to_ascii_uppercase());
    out.push(']');
}

/// A gitignore line for `glob` (already translated): a leading `!` or `#`
/// escaped, anchored as the policy anchors it.
fn line_for(glob: &str, anchored: bool, dir_only: bool) -> String {
    let mut s = String::new();
    if anchored {
        s.push('/');
    } else if glob.starts_with('!') || glob.starts_with('#') {
        s.push('\\');
    }
    s.push_str(glob);
    if dir_only {
        s.push('/');
    }
    s
}

/// The artefact variants of a protected file's last component (see
/// `policy::editor_artefact`): `B.*` (backup copies), `B~`, `.B.*`
/// (swap, undo, kate), `#B#`, `.#B`, `.~lock.B#`, `B___jb_*___`.
fn artefacts(dir: &str, base: &str) -> Vec<String> {
    let d = if dir.is_empty() { String::new() } else { format!("{dir}/") };
    vec![
        format!("{d}{base}.*"),
        format!("{d}{base}~"),
        format!("{d}.{base}.*"),
        format!("{d}\\#{base}\\#"),
        format!("{d}.\\#{base}"),
        format!("{d}.~lock.{base}\\#"),
        format!("{d}{base}___jb_*___"),
    ]
}

/// The gitignore lines for one protective policy rule (none for a public
/// one).
pub fn rule_lines(r: &Rule) -> Vec<String> {
    if !protective(r) {
        return Vec::new();
    }
    let ci = case_insensitive(r);
    let raw = r.pattern.trim();
    let dir_only = raw.ends_with('/');
    let p = raw.trim_end_matches('/');
    let anchored = p.starts_with('/') || p.trim_start_matches('/').contains('/');
    let p = p.trim_start_matches('/');
    if p.is_empty() {
        return Vec::new();
    }
    let mut globs = Vec::new();
    let mut budget = MAX_EXPANSIONS;
    expand_braces(p, &mut globs, &mut budget);
    let mut out = Vec::new();
    for g in globs {
        // A glob that grew a slash through its braces is anchored too.
        let anchored = anchored || g.contains('/');
        let (dir, base) = match g.rsplit_once('/') {
            Some((d, b)) => (d.to_string(), b.to_string()),
            None => (String::new(), g.clone()),
        };
        let mut forms = vec![g.clone()];
        if !dir_only && !matches!(r.tier, Tier::Ignored) && !base.is_empty() && base != "**" {
            forms.extend(artefacts(&dir, &base));
        }
        for f in forms {
            let t = glob_to_gitignore(&f, ci);
            out.push(line_for(&t, anchored, dir_only));
        }
    }
    out
}

/// Every protective rule of `policy` (and of the accepted policy guarding
/// it), plus the built-in scratch artefacts and the other VCS directories,
/// as gitignore lines, deduplicated, in a stable order.
pub fn policy_lines(policy: &Policy) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |l: String, out: &mut Vec<String>| {
        if seen.insert(l.clone()) {
            out.push(l);
        }
    };
    // `/.veil` without a trailing slash: in a colocated project it is a
    // symlink (to `.git/veil`), which a directory-only line would miss.
    for l in ["/.veil", ".jj/", ".hg/", ".svn/"] {
        push(l.to_string(), &mut out);
    }
    for p in SCRATCH_PATTERNS {
        push(line_for(&glob_to_gitignore(&escape_hash(p), false), false, false), &mut out);
    }
    let accepted = policy.accepted().map(|a| a.rules().to_vec()).unwrap_or_default();
    for r in policy.rules().iter().chain(accepted.iter()) {
        for l in rule_lines(r) {
            push(l, &mut out);
        }
    }
    out
}

/// `#` inside a built-in scratch pattern is literal for Veil; gitignore
/// needs it escaped at the start of a pattern only, but escaping it
/// everywhere is harmless.
fn escape_hash(p: &str) -> String {
    p.replace('#', "\\#")
}

/// A gitignore line matching exactly the repository path `path` (anchored;
/// glob characters escaped; a non-ASCII character as `*`, a control
/// character as `?`, so the line over-matches rather than misses).
pub fn literal_line(path: &str, is_dir: bool) -> String {
    let mut s = String::from("/");
    for c in path.chars() {
        match c {
            '*' | '?' | '[' | ']' | '\\' | '!' | '#' | '{' | '}' => {
                s.push('\\');
                s.push(c);
            }
            ' ' => s.push_str("\\ "),
            c if !c.is_ascii() => s.push('*'),
            c if c.is_control() => s.push('?'),
            c => s.push(c),
        }
    }
    if is_dir {
        s.push('/');
    }
    s
}

// ---- vl policy import-gitignore ---------------------------------------------------------

/// A `.gitignore` pattern found to ignore an existing untracked file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedPattern {
    /// The `.veilpolicy` pattern (relative to the root, policy syntax).
    pub pattern: String,
    /// Where it came from: `<.gitignore path>:<line>`.
    pub source: String,
    /// One file (or directory) it ignores, as an example.
    pub example: String,
}

/// `git` for the work tree `root` (Git directory `git_dir`), with an
/// environment that cannot point it elsewhere and no fsmonitor command.
fn git_cmd(root: &Path, git_dir: &Path) -> Command {
    let bin = std::env::var_os("VEIL_GIT").unwrap_or_else(|| "git".into());
    let mut c = Command::new(bin);
    for v in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
    ] {
        c.env_remove(v);
    }
    c.arg("--git-dir").arg(git_dir).arg("--work-tree").arg(root).current_dir(root);
    c.args(["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false"]);
    c
}

fn run_git(mut c: Command, input: Option<&[u8]>, what: &str) -> Result<Vec<u8>> {
    c.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c
        .spawn()
        .map_err(|e| VeilError::repo(format!("could not run git for {what}: {e} (is git installed? set VEIL_GIT)")))?;
    if let Some(data) = input {
        let mut stdin = child.stdin.take().expect("piped");
        let data = data.to_vec();
        // Written from a thread: git may fill its stdout before it has
        // read all of its stdin.
        let writer = std::thread::spawn(move || stdin.write_all(&data));
        let out = child.wait_with_output().map_err(|e| VeilError::repo(format!("git {what}: {e}")))?;
        let _ = writer.join();
        return finish(out, what);
    }
    let out = child.wait_with_output().map_err(|e| VeilError::repo(format!("git {what}: {e}")))?;
    finish(out, what)
}

fn finish(out: std::process::Output, what: &str) -> Result<Vec<u8>> {
    // `check-ignore` exits 1 when nothing matched.
    if !out.status.success() && out.status.code() != Some(1) {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(VeilError::repo(format!("git {what} failed: {}", err.trim())));
    }
    Ok(out.stdout)
}

// ---- negations that un-hide protected paths (BUG-742) ---------------------------------

/// Name of the file a probe path ends in when a pattern only names a
/// directory, or a wildcard stands for any name.
const PROBE: &str = "veil-probe";

/// One path each negation (`!pattern`) of the `.gitignore` at `gitignore`
/// (a repository path, `dir/.gitignore`) would re-include, with where the
/// line is (`dir/.gitignore:3: !secrets/`). Git ranks a `.gitignore` above
/// `info/exclude`, so a negation there outranks every line Veil writes; the
/// caller asks Git ([`not_ignored`]) whether each probe is still excluded.
/// A wildcard becomes a plain name (`*.md` probes `veil-probe.md`), a
/// directory pattern a file inside it (`secrets/` probes
/// `secrets/veil-probe`).
pub fn negation_probes(gitignore: &str, text: &str) -> Vec<(String, String)> {
    let dir = gitignore.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        let Some(pat) = line.strip_prefix('!') else { continue };
        // Trailing spaces are not part of a pattern unless escaped.
        let pat = pat.trim_end_matches(' ');
        if pat.is_empty() {
            continue;
        }
        let dir_only = pat.ends_with('/');
        let pat = pat.trim_end_matches('/');
        let pat = pat.strip_prefix('/').unwrap_or(pat);
        let mut name = String::new();
        let mut chars = pat.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => name.extend(chars.next()),
                '*' => {
                    while chars.peek() == Some(&'*') {
                        chars.next();
                    }
                    if !name.ends_with(PROBE) {
                        name.push_str(PROBE);
                    }
                }
                '?' => name.push('x'),
                '[' => {
                    // A character the class matches: its first member, or
                    // for `[!…]` one it does not list.
                    let negated = matches!(chars.peek(), Some('!' | '^'));
                    if negated {
                        chars.next();
                    }
                    let mut members = Vec::new();
                    for d in chars.by_ref() {
                        if d == ']' && !members.is_empty() {
                            break;
                        }
                        members.push(d);
                    }
                    let pick = if negated {
                        "qzj0".chars().find(|c| !members.contains(c))
                    } else {
                        members.first().copied().filter(|c| *c != '/')
                    };
                    name.push(pick.unwrap_or('x'));
                }
                c => name.push(c),
            }
        }
        let name: String = name.split('/').filter(|c| !c.is_empty() && *c != "." && *c != "..").collect::<Vec<_>>().join("/");
        if name.is_empty() {
            continue;
        }
        let mut probe = if dir.is_empty() { name } else { format!("{dir}/{name}") };
        if dir_only {
            probe.push('/');
            probe.push_str(PROBE);
        }
        out.push((probe, format!("{gitignore}:{}: {}", i + 1, line.escape_debug())));
    }
    out
}

/// Which of `paths` (repository paths, which need not exist) Git would
/// **not** ignore in the work tree `root`, by every ignore source it reads
/// (`.gitignore` files, `info/exclude`, `core.excludesFile`), whether or
/// not they are tracked (`git check-ignore --no-index`).
pub fn not_ignored(root: &Path, git_dir: &Path, paths: &[String]) -> Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_bytes());
        input.push(0);
    }
    let mut c = git_cmd(root, git_dir);
    c.args(["check-ignore", "--no-index", "--stdin", "-z"]);
    let out = run_git(c, Some(&input), "check-ignore")?;
    let ignored: BTreeSet<&[u8]> = out.split(|b| *b == 0).filter(|p| !p.is_empty()).collect();
    Ok(paths.iter().filter(|p| !ignored.contains(p.as_bytes())).cloned().collect())
}

/// A gitignore pattern from the `.gitignore` in directory `dir` (`""` at
/// the root) as a `.veilpolicy` pattern relative to the root. `None` for a
/// negation (it never ignores) or an empty line.
pub fn gitignore_to_policy(dir: &str, pattern: &str) -> Option<String> {
    let mut p = pattern.trim_end_matches(['\r', '\n']).to_string();
    // Trailing spaces end the pattern unless escaped.
    while p.ends_with(' ') && !p.ends_with("\\ ") {
        p.pop();
    }
    if p.is_empty() || p.starts_with('!') || p.starts_with('#') {
        return None;
    }
    let dir_only = p.ends_with('/');
    let body = p.trim_end_matches('/');
    let anchored = body.contains('/');
    let body = body.trim_start_matches('/');
    if body.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push('\\');
                    out.push(n);
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                if chars.peek() == Some(&'^') {
                    chars.next();
                    out.push('!');
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            // Policy-only syntax, literal in gitignore.
            '{' | '}' | '#' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_whitespace() => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    let mut full = match (dir.is_empty(), anchored) {
        (true, true) => format!("/{out}"),
        (true, false) => out,
        (false, true) => format!("/{dir}/{out}"),
        (false, false) => format!("/{dir}/**/{out}"),
    };
    if dir_only {
        full.push('/');
    }
    Some(full)
}

/// The `.gitignore` patterns that ignore existing untracked files of the
/// Git work tree `root` (Git directory `git_dir`), as `.veilpolicy`
/// patterns, one per pattern. Patterns from outside the work tree's
/// `.gitignore` files (`info/exclude`, `core.excludesFile`) are not
/// imported: they are this user's, not the project's.
pub fn import_gitignore(root: &Path, git_dir: &Path) -> Result<Vec<ImportedPattern>> {
    let mut ls = git_cmd(root, git_dir);
    // Every file (not `--directory`: an untracked directory would hide
    // the ignored ones inside it).
    ls.args(["ls-files", "-z", "--others", "--ignored", "--exclude-standard"]);
    let listed = run_git(ls, None, "ls-files")?;
    let paths: Vec<&[u8]> = listed.split(|b| *b == 0).filter(|p| !p.is_empty()).collect();
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    for p in &paths {
        input.extend_from_slice(p);
        input.push(0);
    }
    let mut ci = git_cmd(root, git_dir);
    ci.args(["check-ignore", "-z", "-v", "--stdin"]);
    let out = run_git(ci, Some(&input), "check-ignore")?;
    let f: Vec<&[u8]> = out.split(|b| *b == 0).collect();
    let mut found: Vec<ImportedPattern> = Vec::new();
    let mut seen = BTreeSet::new();
    for rec in f.chunks(4) {
        let [source, line, pattern, path] = rec else { continue };
        let (Ok(source), Ok(pattern), Ok(path)) =
            (std::str::from_utf8(source), std::str::from_utf8(pattern), std::str::from_utf8(path))
        else {
            continue;
        };
        if source.is_empty() || !source.ends_with(".gitignore") || Path::new(source).is_absolute() || source.contains("..") {
            continue;
        }
        let dir = source.strip_suffix(".gitignore").unwrap_or("").trim_end_matches('/');
        // A `.gitignore` inside `.git` or `.veil` is nobody's project file.
        if dir.split('/').any(|c| crate::policy::vcs_metadata_name(c).is_some() || c == ".veil") {
            continue;
        }
        let Some(pat) = gitignore_to_policy(dir, pattern) else { continue };
        if !seen.insert(pat.clone()) {
            continue;
        }
        found.push(ImportedPattern {
            pattern: pat,
            source: format!("{source}:{}", String::from_utf8_lossy(line)),
            example: path.to_string(),
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpath::VPath;

    fn rule(text: &str) -> Rule {
        let p = Policy::parse(text);
        p.rules().iter().rev().find(|r| !r.builtin).cloned().unwrap()
    }

    #[test]
    fn cloak_rules_fold_case_and_anchor() {
        let l = rule_lines(&rule("secrets/ cloak ops\n"));
        assert_eq!(l, vec!["[sS][eE][cC][rR][eE][tT][sS]/".to_string()]);
        let l = rule_lines(&rule("/config/db.yml cloak\n"));
        assert!(l.contains(&"/[cC][oO][nN][fF][iI][gG]/[dD][bB].[yY][mM][lL]".to_string()), "{l:?}");
        // Artefacts of a protected file come along.
        assert!(l.iter().any(|x| x.ends_with("~")), "{l:?}");
    }

    #[test]
    fn ignore_rules_keep_case_and_public_rules_vanish() {
        assert_eq!(rule_lines(&rule("target/ ignore\n")), vec!["target/".to_string()]);
        assert!(rule_lines(&rule("docs/ public\n")).is_empty());
        assert!(rule_lines(&rule("x public!\n")).is_empty());
    }

    #[test]
    fn braces_expand_and_overflow_widens() {
        let l = rule_lines(&rule("*.{yml,json} ignore\n"));
        assert_eq!(l, vec!["*.yml".to_string(), "*.json".to_string()]);
        let many: Vec<String> = (0..100).map(|i| format!("a{i}")).collect();
        let l = rule_lines(&rule(&format!("x.{{{}}} ignore\n", many.join(","))));
        assert_eq!(l, vec!["x.*".to_string()]);
    }

    #[test]
    fn hostile_names_never_become_negations_or_comments() {
        for text in ["\\!important cloak\n", "\\#notes cloak\n"] {
            for l in rule_lines(&rule(text)) {
                assert!(!l.starts_with('!') && !l.starts_with('#'), "{l}");
            }
        }
        assert_eq!(literal_line("!x", false), "/\\!x");
        assert_eq!(literal_line("#y", false), "/\\#y");
        assert_eq!(literal_line("a b/[c]*?", true), "/a\\ b/\\[c\\]\\*\\?/");
        assert_eq!(literal_line("caf\u{e9}", false), "/caf*");
        assert_eq!(literal_line("a\nb", false), "/a?b");
        for l in policy_lines(&Policy::parse("\\!x cloak\n")) {
            assert!(!l.starts_with('!'), "{l}");
            assert!(!l.contains('\n'));
        }
    }

    #[test]
    fn negations_become_probes() {
        let p = negation_probes(".gitignore", "*.log\n!secrets/\n!.env\n!*.md\n\\!lit\n!/a/**/b?[!x]c.yml\n!\n");
        let probes: Vec<&str> = p.iter().map(|(x, _)| x.as_str()).collect();
        assert_eq!(probes, vec!["secrets/veil-probe", ".env", "veil-probe.md", "a/veil-probe/bxqc.yml"]);
        assert_eq!(p[0].1, ".gitignore:2: !secrets/");
        let p = negation_probes("config/.gitignore", "!*.key\n");
        assert_eq!(p[0].0, "config/veil-probe.key");
    }

    #[test]
    fn builtin_secrets_are_excluded() {
        let l = policy_lines(&Policy::builtin());
        assert!(l.contains(&"/.veil".to_string()));
        assert!(l.contains(&".[eE][nN][vV]".to_string()), "{l:?}");
        assert!(l.contains(&"*.[pP][eE][mM]".to_string()), "{l:?}");
    }

    /// Every path a protective rule matches is matched by its gitignore
    /// lines, as Git reads them (checked against `git check-ignore`).
    #[test]
    fn translation_over_excludes_against_real_git() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ok = Command::new("git").args(["init", "-q"]).current_dir(root).status().unwrap();
        assert!(ok.success());
        let policy = Policy::parse(
            "secrets/ cloak ops\n*.{tfvars,sql} isolate\nnotes/*.md cloak\nbuild/ ignore\n[Dd]ata?.csv cloak\n",
        );
        let lines = policy_lines(&policy);
        std::fs::write(root.join(".git/info/exclude"), lines.join("\n") + "\n").unwrap();
        let candidates = [
            "secrets/a.yml",
            "SECRETS/b.yml",
            "x/secrets/c",
            "prod.tfvars",
            "deep/dir/PROD.TFVARS",
            "dump.sql",
            "notes/today.md",
            "Notes/Today.MD",
            "build/out.o",
            "data1.csv",
            "DATA2.CSV",
            ".env",
            "sub/.ENV.local",
            "key.pem",
            "secrets/a.yml~",
            ".secrets.swp",
        ];
        for c in candidates {
            let vp = VPath::new(c).unwrap();
            let class = policy.classify(&vp, false);
            if matches!(class.tier, Tier::Public) {
                continue;
            }
            let out = Command::new("git")
                .args(["check-ignore", "-q", "--no-index", c])
                .current_dir(root)
                .status()
                .unwrap();
            assert!(out.success(), "{c} is {:?} for Veil but Git does not exclude it\n{lines:#?}", class.tier);
        }
    }

    #[test]
    fn gitignore_patterns_translate_relative_to_their_directory() {
        assert_eq!(gitignore_to_policy("", "master.key").unwrap(), "master.key");
        assert_eq!(gitignore_to_policy("", "/tmp/").unwrap(), "/tmp/");
        assert_eq!(gitignore_to_policy("config", "master.key").unwrap(), "/config/**/master.key");
        assert_eq!(gitignore_to_policy("config", "a/b").unwrap(), "/config/a/b");
        assert_eq!(gitignore_to_policy("", "*.{x}").unwrap(), "*.\\{x\\}");
        assert_eq!(gitignore_to_policy("", "[^a]b").unwrap(), "[!a]b");
        assert_eq!(gitignore_to_policy("", "a b ").unwrap(), "a\\ b");
        assert!(gitignore_to_policy("", "!keep").is_none());
        assert!(gitignore_to_policy("", "   ").is_none());
        // Every translated pattern parses as a policy rule.
        for p in ["master.key", "/config/**/master.key", "*.\\{x\\}", "a\\ b", "[!a]b"] {
            let pol = Policy::parse(&format!("{p} ignore\n"));
            assert!(pol.warnings.is_empty(), "{p}: {:?}", pol.warnings);
        }
    }
}
