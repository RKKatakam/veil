//! Per-path visibility policy (`.veilpolicy`).
//!
//! ```text
//! # <pattern>        <tier> [scope]        — last matching rule wins
//! secrets/            cloak team
//! config/prod/**      cloak ops
//! *.local.json        isolate
//! target/             ignore
//! tests/fixtures/     public!              — public, secret scanning disabled
//! ```
//!
//! Tiers: `public`, `public!`, `cloak [scope]`, `isolate`, `ignore`.
//!
//! Patterns are globs (`*`, `**`, `?`, `[…]`, `{a,b}`). A backslash escapes
//! the next character, so `config\[prod\].yml` matches that literal name and
//! `my\ file.txt` contains a space; `vl cloak <existing path>` writes such
//! escaped patterns itself (see [`escape_literal`]).
//!
//! **Case.** Built-in secret rules and user `cloak`/`isolate` rules match
//! case-insensitively: on macOS and Windows `.ENV` *is* `.env`, and matching
//! more paths there only ever protects more. Rules that expose (`public`,
//! `public!`, the built-in `.env.example` exceptions) or stop tracking
//! (`ignore`) stay case-sensitive.
//!
//! **Invalid rules fail safe.** A rule that names a reserved or malformed
//! scope (`local`, `embargo/<id>`, `../x`, `UPPER`), an unknown tier, or no
//! tier at all becomes `isolate` for its pattern, with a warning: a typo can
//! keep a file off the record, never publish it.
//!
//! **Engine-enforced defaults** come first and cannot be weakened by a plain
//! `public` rule: `.env`, `*.pem`, private SSH keys, … are `isolated` — they
//! never enter the snapshot graph. They *may* be `cloak`ed (encrypted for a
//! team) or deliberately published with `public!`.
//!
//! **Editor artefacts.** Editor scratch files (`.x.swp`, `x~`, `#x#`, …) are
//! ignored by the engine, and every editor or backup artefact of a file
//! (`.x.swp`, `x~`, `x.bak`, …, see [`editor_artefact`]) takes that file's
//! protection: the swap file of an isolated key is isolated, the backup of
//! a cloaked file is cloaked under the same scope.
//!
//! **Accepted policy.** `.veilpolicy` is shared: it arrives by merge, pull,
//! checkout, rebase, Git import or undo like any other file. Isolated files
//! never enter history, so their protection lives *only* in the policy, and
//! a policy that arrives from someone else must not publish them. Each
//! working copy therefore keeps, device-locally, the policy its member last
//! accepted ([`ACCEPTED_POLICY`]). A snapshot of the working copy classifies
//! every path under both, and where the working copy's `.veilpolicy`
//! [weakens](weakens()) the accepted classification, the accepted one applies
//! and the path is reported as *held back* ([`Classification::held_back`]).
//! Strengthening applies at once. See [`working_copy_policy`] for when the
//! accepted policy moves forward (the member's own edit of `.veilpolicy`, or
//! an explicit `vl policy accept`).

use globset::{GlobBuilder, GlobMatcher, GlobSet, GlobSetBuilder};

use crate::{
    error::{Result, VeilError},
    keychain::validate_scope_name,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const POLICY_FILE: &str = ".veilpolicy";
pub const DEFAULT_SCOPE: &str = "team";

const BUILTIN_SECRETS: &[&str] = &[
    ".env",
    ".env.*",
    ".envrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".netrc",
    ".pgpass",
    ".pypirc",
    ".npmrc",
    ".git-credentials",
    "*.tfstate",
    "*.tfstate.*",
];

const BUILTIN_PUBLIC_EXCEPTIONS: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist"];

/// Metadata of other version control systems, ignored at every depth by
/// the engine: a `.git` directory, or a `.git` *file* (Git worktrees and
/// submodules use one), and `.jj/`, `.hg/`, `.svn/` directories. Names
/// match in any ASCII case and with HFS+-ignorable code points
/// (`.g\u{200C}it`), as the Git bridge's refusal of `.git` entries does: on
/// macOS those all name the same directory. Only a `public!` rule that
/// names such a directory itself (`fixtures/repo/.git/ public!`) records
/// it; no other rule does (a broad `tests/ public!` or `** cloak` does not).
pub const BUILTIN_VCS_DIRS: &[&str] = &[".git", ".jj", ".hg", ".svn"];

/// Is `name` a spelling of `target` (ASCII): any ASCII case, and with
/// HFS+-ignorable code points anywhere.
fn spells(name: &str, target: &str) -> bool {
    if name.is_ascii() {
        return name.eq_ignore_ascii_case(target);
    }
    let mut folded = name.chars().filter(|c| !crate::vpath::is_hfs_ignorable(*c));
    target.chars().all(|r| folded.next().is_some_and(|c| c.eq_ignore_ascii_case(&r))) && folded.next().is_none()
}

/// The VCS metadata directory (`.git`, `.jj`, …) `name` spells, if any
/// (see [`BUILTIN_VCS_DIRS`]).
pub fn vcs_metadata_name(name: &str) -> Option<&'static str> {
    BUILTIN_VCS_DIRS.iter().copied().find(|t| spells(name, t))
}

/// Is `path` VCS metadata: inside one of [`BUILTIN_VCS_DIRS`] at any
/// depth, one of those directories itself, or a `.git` file? Returns the
/// directory's name.
pub fn vcs_metadata(path: &VPath, is_dir: bool) -> Option<&'static str> {
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        let last = parts.peek().is_none();
        if let Some(n) = vcs_metadata_name(part) {
            if !last || is_dir || n == ".git" {
                return Some(n);
            }
        }
    }
    None
}

/// Does a policy pattern name a VCS metadata directory itself (one of its
/// `/`-separated components, escapes removed, is `.git`, `.hg`, …)?
fn names_vcs(pattern: &str) -> bool {
    pattern.split('/').any(|part| {
        let mut plain = String::with_capacity(part.len());
        let mut chars = part.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => plain.extend(chars.next()),
                c => plain.push(c),
            }
        }
        vcs_metadata_name(&plain).is_some()
    })
}

// ---- editor and backup artefacts -----------------------------------------

/// Extensions of backup copies (`<name>.<ext>`, also with a number:
/// `<name>.bak2`, `<name>.save.1`). Such a name is only an artefact of a
/// file that exists by that name, so these have no rule of their own: they
/// take their base's protection (see [`editor_artefact`]).
pub const BACKUP_EXTENSIONS: &[&str] = &["orig", "rej", "bak", "backup", "old", "tmp", "temp", "save", "sav"];

/// The built-in rules for editor scratch files, as patterns (see
/// [`editor_artefact`] for exactly what they match).
pub const SCRATCH_PATTERNS: &[&str] =
    &[".*.sw[a-p]", ".*.un~", ".*.kate-swp", "*~", "#*#", ".#*", "*___jb_tmp___", "*___jb_old___", ".~lock.*#"];

/// How many artefact layers a name is unwrapped (`.env.bak~` → `.env.bak`
/// → `.env`).
const ARTEFACT_DEPTH: usize = 4;

/// What [`editor_artefact`] recognised in a file name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artefact {
    /// An editor's scratch file (swap, undo, auto-save, lock, backup or
    /// safe-write temporary), recognised by its name alone: the pattern
    /// shown as the deciding built-in rule (`.*.swp`, `*~`, …). `None` for
    /// a backup copy (`<name>.bak`, …).
    pub scratch: Option<&'static str>,
    /// The names, in the same directory, of the files it may belong to.
    pub bases: Vec<String>,
}

fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let n = s.len().checked_sub(suffix.len())?;
    (s.is_char_boundary(n) && s[n..].eq_ignore_ascii_case(suffix)).then(|| &s[..n])
}

/// Is `name` an editor or backup artefact of another file in its
/// directory, and of which? Fixed parts match in any ASCII case.
///
/// Editor scratch files (built-in `ignore`, see [`Classification::builtin_artefact`]):
///
/// | name | written by | base |
/// |---|---|---|
/// | `.B.swp`, `.B.swo` … `.B.swa` | Vim, Neovim (swap), nano (lock) | `B`, `.B` |
/// | `.B.un~` | Vim (`undofile`) | `B`, `.B` |
/// | `.B.kate-swp` | Kate, KWrite | `B`, `.B` |
/// | `B~`, `B.~N~` | Emacs, Vim (`backup`), gedit, Kate (backups) | `B` |
/// | `#B#` | Emacs (auto-save) | `B` |
/// | `.#B` | Emacs (lock symlink) | `B` |
/// | `B___jb_tmp___`, `B___jb_old___` | JetBrains IDEs (safe write) | `B` |
/// | `.~lock.B#` | LibreOffice (lock) | `B` |
///
/// (`B`, `.B`: Vim does not add a dot to a name that has one, so the swap
/// file of `.env` is `.env.swp`.) Backup copies: `B.<ext>`, `B.<ext>N` and
/// `B.<ext>.N` for each of [`BACKUP_EXTENSIONS`] (`.env.orig`,
/// `server.pem.bak`, `secrets.yml.tmp`).
pub fn editor_artefact(name: &str) -> Option<Artefact> {
    let ok = |b: &str| !b.is_empty() && b != "." && b != ".." && !b.contains('/');
    let mut bases: Vec<String> = Vec::new();
    let mut scratch = None;
    let mut found = |kind: Option<&'static str>, names: &[&str], bases: &mut Vec<String>| {
        let names: Vec<&str> = names.iter().copied().filter(|b| ok(b)).collect();
        if !names.is_empty() {
            scratch = scratch.or(kind);
            bases.extend(names.into_iter().map(str::to_string));
        }
    };
    // Dotted scratch files: `.B.swp`, `.B.un~`, `.B.kate-swp`.
    if let Some(rest) = name.strip_prefix('.') {
        // (The last byte is checked first: it makes the slice below valid.)
        let swap = rest.len() > 4
            && matches!(rest.as_bytes()[rest.len() - 1].to_ascii_lowercase(), b'a'..=b'p')
            && rest.is_char_boundary(rest.len() - 4)
            && rest[rest.len() - 4..rest.len() - 1].eq_ignore_ascii_case(".sw");
        let dotted = [(".un~", ".*.un~"), (".kate-swp", ".*.kate-swp")];
        let stem = match swap {
            true => Some((&rest[..rest.len() - 4], ".*.sw[a-p]")),
            false => dotted.iter().find_map(|(s, kind)| strip_suffix_ci(rest, s).map(|b| (b, *kind))),
        };
        if let Some((stem, kind)) = stem {
            found(Some(kind), &[stem, &name[..stem.len() + 1]], &mut bases);
        }
        // Emacs lock `.#B`, LibreOffice lock `.~lock.B#`.
        if let Some(b) = rest.strip_prefix('#') {
            found(Some(".#*"), &[b], &mut bases);
        }
        if let Some(b) = rest.strip_prefix("~lock.").and_then(|r| r.strip_suffix('#')) {
            found(Some(".~lock.*#"), &[b], &mut bases);
        }
    }
    // `B~`, Emacs numbered backups `B.~N~`.
    if let Some(b) = name.strip_suffix('~') {
        let numbered = b
            .rfind(".~")
            .filter(|&i| b.len() > i + 2 && b[i + 2..].bytes().all(|c| c.is_ascii_digit()))
            .map(|i| &b[..i]);
        found(Some("*~"), &[numbered.unwrap_or(b)], &mut bases);
    }
    // Emacs auto-save `#B#`.
    if let Some(b) = name.strip_prefix('#').and_then(|r| r.strip_suffix('#')) {
        found(Some("#*#"), &[b], &mut bases);
    }
    for (s, kind) in [("___jb_tmp___", "*___jb_tmp___"), ("___jb_old___", "*___jb_old___")] {
        if let Some(b) = strip_suffix_ci(name, s) {
            found(Some(kind), &[b], &mut bases);
        }
    }
    // Backup copies: `B.bak`, `B.bak2`, `B.save.1`.
    let unnumbered = name.trim_end_matches(|c: char| c.is_ascii_digit());
    let unnumbered = match unnumbered.strip_suffix('.') {
        Some(u) if unnumbered.len() < name.len() => u,
        _ => unnumbered,
    };
    if let Some(dot) = unnumbered.rfind('.') {
        if BACKUP_EXTENSIONS.iter().any(|e| unnumbered[dot + 1..].eq_ignore_ascii_case(e)) {
            found(None, &[&unnumbered[..dot]], &mut bases);
        }
    }
    bases.dedup();
    (!bases.is_empty()).then_some(Artefact { scratch, bases })
}

/// Does a policy pattern's file name itself spell an editor scratch file
/// (`*~`, `.*.swp`, `.*.sw?`, `#*#`)? As `public!`, such a rule records
/// scratch files (see [`Classification::builtin_artefact`]).
fn names_scratch(pattern: &str) -> bool {
    let last = pattern.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    // Escapes removed; a `?` or a character class stands for one letter.
    let mut plain = String::with_capacity(last.len());
    let mut chars = last.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => plain.extend(chars.next()),
            '?' => plain.push('p'),
            '[' => {
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                }
                plain.push('p');
            }
            c => plain.push(c),
        }
    }
    // `*.swp` matches `.x.swp` too (a `*` matches a leading dot).
    let dotted = plain.starts_with('*').then(|| format!(".{plain}"));
    [Some(plain), dotted].into_iter().flatten().any(|n| editor_artefact(&n).is_some_and(|a| a.scratch.is_some()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tier {
    Public,
    Cloaked(String),
    Isolated,
    Ignored,
}

impl Tier {
    pub fn label(&self) -> String {
        match self {
            Tier::Public => "public".into(),
            Tier::Cloaked(s) => format!("cloaked:{s}"),
            Tier::Isolated => "isolated".into(),
            Tier::Ignored => "ignored".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub pattern: String,
    pub tier: Tier,
    /// `public!` — deliberate exposure, secret scanning disabled.
    pub force: bool,
    pub builtin: bool,
    /// Built-in secret rule.
    pub secret: bool,
    /// The pattern names a VCS metadata directory itself (`.git`, …): as
    /// `public!`, it records one (see [`BUILTIN_VCS_DIRS`]).
    names_vcs: bool,
    /// The pattern's file name spells an editor scratch file (`*~`,
    /// `.*.swp`): as `public!`, it records them (see [`editor_artefact`]).
    names_scratch: bool,
    dir_only: bool,
    exact: GlobMatcher,
    under: GlobMatcher,
}

/// The built-in rules, and their glob set, compiled once.
fn builtin_rules() -> &'static (Vec<Rule>, GlobSet) {
    static BUILTIN: std::sync::OnceLock<(Vec<Rule>, GlobSet)> = std::sync::OnceLock::new();
    BUILTIN.get_or_init(|| {
        let mut rules = Vec::new();
        for p in BUILTIN_SECRETS {
            rules.push(Rule::new(p, Tier::Isolated, false, true, true).unwrap());
        }
        for p in BUILTIN_PUBLIC_EXCEPTIONS {
            rules.push(Rule::new(p, Tier::Public, false, true, false).unwrap());
        }
        let set = compile_set(&rules);
        (rules, set)
    })
}

/// Rules' globs compiled into one set (`2i` = rule `i` exact, `2i + 1` =
/// rule `i` under), so classifying a path is one match instead of two per
/// rule. Classification runs for every path on every snapshot. A policy's
/// set holds its user rules; the built-in ones have their own
/// ([`builtin_rules`]).
fn compile_set(rules: &[Rule]) -> GlobSet {
    let mut b = GlobSetBuilder::new();
    for r in rules {
        b.add(r.exact.glob().clone());
        b.add(r.under.glob().clone());
    }
    b.build().expect("globs were already validated individually")
}


/// Characters with a meaning in a policy pattern.
const SPECIAL: &[char] = &['*', '?', '[', ']', '{', '}', '\\', '#'];

/// Does `pattern` use glob syntax (or escapes)?
pub fn has_glob_syntax(pattern: &str) -> bool {
    pattern.contains(SPECIAL)
}

/// A pattern that matches exactly the literal path `path` (directory
/// slashes kept): glob metacharacters, `#` and whitespace are escaped.
pub fn escape_literal(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        if SPECIAL.contains(&c) || c.is_whitespace() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Escape what would otherwise split or end a policy field (whitespace and
/// `#`), keeping glob syntax and existing escapes as they are.
pub fn escape_field(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.push(c);
            if let Some(n) = chars.next() {
                out.push(n);
            }
            continue;
        }
        if c == '#' || c.is_whitespace() {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Split a policy line into fields: whitespace separates fields unless
/// escaped, and an unescaped `#` starts a comment. Escapes are kept in the
/// fields (the glob compiler interprets them).
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '#' => break,
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Protective rules match case-insensitively (see the module docs).
fn case_insensitive(builtin: bool, secret: bool, tier: &Tier) -> bool {
    (builtin && secret) || (!builtin && matches!(tier, Tier::Cloaked(_) | Tier::Isolated))
}

impl Rule {
    fn new(pattern: &str, tier: Tier, force: bool, builtin: bool, secret: bool) -> Result<Rule, String> {
        // Protective rules match case-insensitively (see the module docs).
        let case_insensitive = case_insensitive(builtin, secret, &tier);
        // Patterns and paths are compared in NFC, so a rule typed in one
        // Unicode normalisation form matches a name recorded in the other
        // (macOS file names often come back in NFD).
        let mut p = crate::vpath::nfc(pattern.trim()).into_owned();
        let dir_only = p.ends_with('/');
        while p.ends_with('/') {
            p.pop();
        }
        let anchored = p.starts_with('/');
        let p = p.trim_start_matches('/').to_string();
        if p.is_empty() {
            return Err(format!("empty pattern '{pattern}'"));
        }
        let base = if anchored || p.contains('/') || p.starts_with("**") {
            p.clone()
        } else {
            format!("**/{p}")
        };
        let build = |g: &str| {
            GlobBuilder::new(g)
                .literal_separator(true)
                .backslash_escape(true)
                .case_insensitive(case_insensitive)
                .build()
                .map(|g| g.compile_matcher())
                .map_err(|e| format!("bad pattern '{pattern}': {e}"))
        };
        Ok(Rule {
            pattern: pattern.trim().to_string(),
            exact: build(&base)?,
            under: build(&format!("{base}/**"))?,
            tier,
            force,
            builtin,
            secret,
            names_vcs: names_vcs(pattern),
            names_scratch: names_scratch(pattern),
            dir_only,
        })
    }

    /// Does this rule match case-insensitively (see the module docs)?
    fn case_insensitive(&self) -> bool {
        case_insensitive(self.builtin, self.secret, &self.tier)
    }

    pub fn matches(&self, path: &VPath, is_dir: bool) -> bool {
        let s = &*crate::vpath::nfc(path.as_str());
        (self.exact.is_match(s) && (!self.dir_only || is_dir)) || self.under.is_match(s)
    }

    pub fn to_line(&self) -> String {
        format_rule(&self.pattern, &self.tier, self.force)
    }
}

pub fn format_rule(pattern: &str, tier: &Tier, force: bool) -> String {
    format!("{pattern:<24} {}", tier_keyword(tier, force))
}

/// The tier keyword as written in `.veilpolicy` (`public!`, `cloak ops`, …).
pub fn tier_keyword(tier: &Tier, force: bool) -> String {
    match tier {
        Tier::Public if force => "public!".to_string(),
        Tier::Public => "public".to_string(),
        Tier::Cloaked(s) => format!("cloak {s}"),
        Tier::Isolated => "isolate".to_string(),
        Tier::Ignored => "ignore".to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classification {
    pub tier: Tier,
    pub allow_secrets: bool,
    /// Pattern of the deciding rule, if any.
    pub rule: Option<String>,
    pub builtin_secret: bool,
    /// A user rule tried to make a built-in secret public without `public!`,
    /// and no later rule decided the path.
    pub blocked_exposure: bool,
    /// VCS metadata (`.git`, `.jj`, …), ignored by the engine (see
    /// [`BUILTIN_VCS_DIRS`]).
    pub builtin_vcs: bool,
    /// An editor scratch file ([`editor_artefact`]: `.x.swp`, `x~`, `#x#`,
    /// …), ignored by the engine, or an artefact that took an ignored
    /// built-in secret's or VCS metadata's protection. Only an `isolate`
    /// rule, or a `public!` rule whose own file name spells a scratch file
    /// (`*~ public!`), applies to a scratch file; lifting the ignore is a
    /// weakening (see [`weakens`]).
    pub builtin_artefact: bool,
    /// This path is an editor or backup artefact of `artefact_of` (in the
    /// same directory) and has that path's protection, which it would not
    /// have by its own rules: `rule` is the rule that decided the base.
    pub artefact_of: Option<VPath>,
    /// The working copy's `.veilpolicy` would weaken this path's protection
    /// (see [`weakens`]), and the member has not accepted it: this is the
    /// *accepted* classification, and `held_back` holds what the working
    /// copy's policy wanted (`(tier, public!)`).
    pub held_back: Option<(Tier, bool)>,
}

impl Classification {
    /// `public!`, `cloak ops`, …
    pub fn keyword(&self) -> String {
        tier_keyword(&self.tier, self.allow_secrets)
    }
}

/// A path kept under its accepted classification because the working
/// copy's `.veilpolicy` would weaken its protection (see [`weakens`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldBack {
    pub path: VPath,
    /// Accepted classification, as a policy keyword (`isolate`, `cloak ops`).
    pub accepted: String,
    /// What the working copy's `.veilpolicy` wants (`public!`, …).
    pub wanted: String,
    /// A directory the accepted policy ignores (`.git/`, `target/`), held
    /// back as a whole: what is in it is not listed.
    pub dir: bool,
}

impl HeldBack {
    /// The path, with a `/` after a directory.
    pub fn shown_path(&self) -> String {
        match self.dir {
            true => format!("{}/", self.path),
            false => self.path.to_string(),
        }
    }
}

/// Does moving a path from the `accepted` classification to `current`
/// weaken its protection? That is: isolated → cloaked or public, cloaked →
/// public or to another scope (another audience), secret scanning turned
/// off (`public` → `public!`), or an `ignore` lifted from a built-in secret,
/// from VCS metadata or from an editor scratch file (other than to
/// `isolate`). Moving to `isolate` or `ignore` never weakens anything: the
/// file stays on this device either way. An editor or backup artefact of a
/// protected file ([`editor_artefact`]) has that file's protection, so a
/// policy that would publish it, or its base, weakens it too.
pub fn weakens(accepted: &Classification, current: &Classification) -> bool {
    match (&accepted.tier, &current.tier) {
        (_, Tier::Isolated | Tier::Ignored) => false,
        (Tier::Isolated, _) => true,
        (Tier::Ignored, _) => accepted.builtin_secret || accepted.builtin_vcs || accepted.builtin_artefact,
        (Tier::Cloaked(_), Tier::Public) => true,
        (Tier::Cloaked(a), Tier::Cloaked(c)) => a != c,
        (Tier::Public, Tier::Public) => current.allow_secrets && !accepted.allow_secrets,
        (Tier::Public, Tier::Cloaked(_)) => false,
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    set: GlobSet,
    pub warnings: Vec<String>,
    /// The member's own edit of `.veilpolicy` could not be folded into the
    /// accepted policy and waits for `vl policy accept` (see
    /// [`working_copy_policy`]): some of what is held back may be the
    /// member's own change.
    pub own_edit_pending: bool,
    /// The policy the member accepted, if this one is guarded by it (see
    /// [`Policy::guarded_by`]).
    accepted: Option<Box<Policy>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Policy {
    pub fn builtin() -> Policy {
        Policy {
            rules: builtin_rules().0.clone(),
            set: GlobSet::empty(),
            warnings: vec![],
            own_edit_pending: false,
            accepted: None,
        }
    }

    pub fn parse(text: &str) -> Policy {
        let mut policy = Self::builtin();
        for (n, line) in text.lines().enumerate() {
            let parts = fields(line);
            if parts.is_empty() {
                continue;
            }
            let at = format!("{POLICY_FILE}:{}", n + 1);
            // Invalid rules fail safe: isolate what they name.
            let mut invalid = |why: String| {
                policy.warnings.push(format!("{at}: {why}; treating '{}' as isolate", parts[0]));
                (Tier::Isolated, false)
            };
            let (tier, force) = match parts.get(1).map(String::as_str) {
                None => invalid("expected '<pattern> <tier>'".into()),
                Some("public") => (Tier::Public, false),
                Some("public!") => (Tier::Public, true),
                Some("cloak" | "cloaked") => {
                    let scope = parts.get(2).map(String::as_str).unwrap_or(DEFAULT_SCOPE);
                    match validate_scope_name(scope) {
                        Ok(()) => (Tier::Cloaked(scope.to_string()), false),
                        Err(VeilError::Policy(why)) => invalid(why),
                        Err(e) => invalid(e.to_string()),
                    }
                }
                Some("isolate" | "isolated" | "local") => (Tier::Isolated, false),
                Some("ignore" | "ignored") => (Tier::Ignored, false),
                Some(other) => invalid(format!("unknown tier '{other}'")),
            };
            match Rule::new(&parts[0], tier.clone(), force, false, false) {
                Ok(r) => policy.rules.push(r),
                // Not a valid glob. A protective rule falls back to the
                // literal name (`config[prod.yml`), so it still protects
                // what it names; an exposing one is dropped.
                Err(e) if tier != Tier::Public => {
                    match Rule::new(&escape_literal(&parts[0]), tier, force, false, false) {
                        Ok(mut r) => {
                            policy.warnings.push(format!("{at}: {e}; matching '{}' as a literal name", parts[0]));
                            r.pattern = parts[0].clone();
                            policy.rules.push(r);
                        }
                        Err(_) => policy.warnings.push(format!("{at}: {e}")),
                    }
                }
                Err(e) => policy.warnings.push(format!("{at}: {e}")),
            }
        }
        policy.set = compile_set(&policy.rules[builtin_rules().0.len()..]);
        policy
    }

    /// Load `.veilpolicy` from the root of a tree or of a backend that is
    /// not the member's working copy (a symlink is followed, see
    /// [`read_policy_file`]). A policy file that cannot be read is an error:
    /// without the accepted policy there is nothing safe to fall back to.
    /// The member's own working copy goes through [`working_copy_policy`].
    pub fn load(fs: &dyn StorageBackend) -> Result<Policy> {
        Ok(match read_policy_file(fs)? {
            PolicyFile::File(b) | PolicyFile::Linked(b) => Self::parse(&String::from_utf8_lossy(&b)),
            PolicyFile::Absent => Self::builtin(),
            PolicyFile::Unavailable(why) => return Err(VeilError::Policy(format!("cannot read {POLICY_FILE}: {why}"))),
        })
    }

    /// [`Policy::load`] for a tree that came from someone else (a checkout
    /// target, a merge, a Git commit): a `.veilpolicy` that cannot be read
    /// there (a directory, a symlink, sealed for a scope this reader lacks:
    /// only a hostile or corrupt tree records one) never blocks the
    /// command. The policy the member last accepted (`accepted`, the text
    /// of [`ACCEPTED_POLICY`]; the built-in rules if none) applies instead,
    /// with a warning, which is returned too (and added to the policy's
    /// own [`Policy::warnings`]).
    pub fn load_or_accepted(fs: &dyn StorageBackend, accepted: Option<&[u8]>) -> Result<(Policy, Option<String>)> {
        Ok(match read_policy_file(fs)? {
            PolicyFile::File(b) | PolicyFile::Linked(b) => (Self::parse(&String::from_utf8_lossy(&b)), None),
            PolicyFile::Absent => (Self::builtin(), None),
            PolicyFile::Unavailable(why) => {
                let mut p = match accepted {
                    Some(t) => Self::parse(&String::from_utf8_lossy(t)),
                    None => Self::builtin(),
                };
                let w = format!(
                    "cannot read {POLICY_FILE} in this revision ({why}); the policy you accepted applies instead \
                     (a remote or an import may have recorded a broken one)"
                );
                p.warnings.push(w.clone());
                (p, Some(w))
            }
        })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// This policy, except that wherever it [weakens] the classification
    /// `accepted` gives a path, `accepted`'s classification applies (with
    /// [`Classification::held_back`] set).
    pub fn guarded_by(mut self, accepted: Policy) -> Policy {
        self.accepted = Some(Box::new(accepted.unguarded()));
        self
    }

    /// The accepted policy guarding this one, if any.
    pub fn accepted(&self) -> Option<&Policy> {
        self.accepted.as_deref()
    }

    /// This policy's own rules, without the accepted policy guarding them.
    pub fn unguarded(mut self) -> Policy {
        self.accepted = None;
        self
    }

    /// The user rules, normalised (comments and spacing do not count).
    fn rule_lines(&self) -> Vec<String> {
        self.rules.iter().filter(|r| !r.builtin).map(Rule::to_line).collect()
    }

    /// Do both policies have the same user rules (spacing and comments
    /// aside)?
    pub fn same_rules(&self, other: &Policy) -> bool {
        self.rule_lines() == other.rule_lines()
    }

    /// Is this policy `accepted` without some of its `public!` rules, plus
    /// appended rules that only isolate or ignore? Neither can weaken any
    /// path's protection (see [`weakens`]): a path a removed `public!` rule
    /// decided was as exposed as it gets, and falls back to an earlier rule.
    pub fn only_adds_protection_to(&self, accepted: &Policy) -> bool {
        let mine: Vec<&Rule> = self.rules.iter().filter(|r| !r.builtin).collect();
        let mut i = 0;
        for r in accepted.rules.iter().filter(|r| !r.builtin) {
            if mine.get(i).is_some_and(|m| m.to_line() == r.to_line()) {
                i += 1;
            } else if !(r.tier == Tier::Public && r.force) {
                return false;
            }
        }
        mine[i..].iter().all(|r| matches!(r.tier, Tier::Isolated | Tier::Ignored))
    }

    pub fn classify(&self, path: &VPath, is_dir: bool) -> Classification {
        let c = self.classify_own(path, is_dir);
        if let Some(accepted) = &self.accepted {
            let a = accepted.classify_own(path, is_dir);
            if weakens(&a, &c) {
                return Classification {
                    held_back: Some((c.tier, c.allow_secrets)),
                    ..a
                };
            }
        }
        c
    }

    fn classify_own(&self, path: &VPath, is_dir: bool) -> Classification {
        self.classify_depth(path, is_dir, ARTEFACT_DEPTH)
    }

    /// [`Policy::classify_rules`], then, for an editor or backup artefact
    /// ([`editor_artefact`]), the protection of the file it belongs to
    /// ([`Classification::inherit`]), unwrapping up to `depth` layers.
    fn classify_depth(&self, path: &VPath, is_dir: bool, depth: usize) -> Classification {
        // The policy file itself is always public: everyone must agree on it.
        if path.as_str() == POLICY_FILE {
            return Classification::unmatched();
        }
        let artefact = match is_dir {
            true => None,
            false => editor_artefact(path.file_name()),
        };
        let mut c = self.classify_rules(path, is_dir, artefact.as_ref().and_then(|a| a.scratch));
        let Some(artefact) = artefact.filter(|_| depth > 0) else { return c };
        let dir = path.parent().unwrap_or_else(VPath::root);
        for base in &artefact.bases {
            let base = dir.join(base);
            let b = self.classify_depth(&base, false, depth - 1);
            c.inherit(&b, &base);
        }
        c
    }

    /// The classification by the rules alone. `scratch`: the path is an
    /// editor scratch file, with this built-in pattern.
    fn classify_rules(&self, path: &VPath, is_dir: bool, scratch: Option<&'static str>) -> Classification {
        let mut c = Classification::unmatched();
        let name = crate::vpath::nfc(path.as_str());
        let (builtin, builtin_set) = builtin_rules();
        let hits = builtin_set.matches(&*name).into_iter().chain(self.set.matches(&*name).into_iter().map(|i| i + 2 * builtin.len()));
        let mut matched = vec![false; self.rules.len()];
        for i in hits {
            let r = &self.rules[i / 2];
            if i % 2 == 1 || !r.dir_only || is_dir {
                matched[i / 2] = true;
            }
        }
        let mut hit = self.rules.iter().zip(&matched).filter(|(_, m)| **m).map(|(r, _)| r).peekable();
        // Built-in rules come first.
        while let Some(r) = hit.next_if(|r| r.builtin) {
            c.builtin_secret = r.secret;
            c.tier = r.tier.clone();
            c.allow_secrets = false;
            c.rule = Some(r.pattern.clone());
        }
        if let Some(name) = vcs_metadata(path, is_dir) {
            c.mark_vcs(name);
        }
        if let Some(kind) = scratch {
            c.mark_scratch(kind);
        }
        for r in hit {
            c.apply(r);
        }
        c
    }
}

impl Classification {
    /// A path no rule matches.
    fn unmatched() -> Classification {
        Classification {
            tier: Tier::Public,
            allow_secrets: false,
            rule: None,
            builtin_secret: false,
            blocked_exposure: false,
            builtin_vcs: false,
            builtin_artefact: false,
            artefact_of: None,
            held_back: None,
        }
    }

    fn mark_vcs(&mut self, name: &str) {
        self.tier = Tier::Ignored;
        self.allow_secrets = false;
        self.rule = Some(name.to_string());
        self.builtin_vcs = true;
    }

    /// An editor scratch file, unless a built-in secret rule or the VCS
    /// metadata rule (which are no weaker) already decided it.
    fn mark_scratch(&mut self, kind: &str) {
        if self.builtin_secret || self.builtin_vcs {
            return;
        }
        self.tier = Tier::Ignored;
        self.allow_secrets = false;
        self.rule = Some(kind.to_string());
        self.builtin_artefact = true;
    }

    /// This path is an editor or backup artefact of `base_path`, classified
    /// `base`: it gets the base's protection where its own is weaker. An
    /// artefact of an isolated file is isolated (listed and backed up as
    /// local-only, like the file). An artefact of a cloaked file is cloaked
    /// under the same scope, unless its own classification keeps it on the
    /// device (ignored, as editor scratch files are, or isolated). An
    /// artefact of an ignored file is ignored, unless it is isolated. No
    /// rule of the artefact's own can undo this: only a change of the base's
    /// classification does.
    fn inherit(&mut self, base: &Classification, base_path: &VPath) {
        let stronger = match (&self.tier, &base.tier) {
            (_, Tier::Public) | (Tier::Isolated, _) => false,
            (_, Tier::Isolated) => true,
            (Tier::Ignored, _) => false,
            (_, Tier::Ignored) => true,
            (Tier::Public, Tier::Cloaked(_)) => true,
            (Tier::Cloaked(own), Tier::Cloaked(theirs)) => own != theirs,
        };
        // Lifting an ignore that protects the base protects the artefact.
        if base.tier == Tier::Ignored && (stronger || self.tier == Tier::Ignored) {
            self.builtin_artefact |= base.builtin_secret || base.builtin_vcs || base.builtin_artefact;
        }
        if stronger {
            self.tier = base.tier.clone();
            self.allow_secrets = false;
            self.rule = base.rule.clone();
            self.blocked_exposure = false;
            self.builtin_secret = base.builtin_secret;
            self.artefact_of = Some(base.artefact_of.clone().unwrap_or_else(|| base_path.clone()));
        }
    }

    /// Apply matching user rule `r` (rules are applied in order; the last
    /// one that applies decides). Did it apply?
    fn apply(&mut self, r: &Rule) -> bool {
        // VCS metadata: only a `public!` rule naming the directory records it.
        if self.builtin_vcs && !(r.force && r.names_vcs) {
            return false;
        }
        // Editor scratch files: only `isolate`, or a `public!` rule naming
        // scratch files, applies.
        if self.builtin_artefact && !(r.tier == Tier::Isolated || (r.force && r.names_scratch)) {
            return false;
        }
        // A built-in secret: a plain `public` rule cannot expose it.
        if r.tier == Tier::Public && self.builtin_secret && !r.force {
            self.blocked_exposure = true;
            return false;
        }
        self.tier = r.tier.clone();
        self.allow_secrets = r.force;
        self.rule = Some(r.pattern.clone());
        // A later rule decides: an ignored `public` before it no longer matters.
        self.blocked_exposure = false;
        if r.force {
            self.builtin_secret = false;
            self.builtin_vcs = false;
            self.builtin_artefact = false;
        }
        true
    }
}

// ---- folding the member's own edit into the accepted policy ---------------

/// Upper bound on the work [`fold_edit`] may do (alignment cells, checked
/// rule combinations); beyond it the edit is not folded automatically.
const FOLD_BUDGET: usize = 4_000_000;

/// A normalised rule line for a message (without the column padding).
fn shown(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Longest common subsequence of `a` and `b`, as increasing index pairs.
fn lcs(a: &[String], b: &[String]) -> Vec<(usize, usize)> {
    let (n, m) = (a.len(), b.len());
    let mut t = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[at(i, j)] = if a[i] == b[j] {
                t[at(i + 1, j + 1)] + 1
            } else {
                t[at(i + 1, j)].max(t[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((i, j));
            i += 1;
            j += 1;
        } else if t[at(i + 1, j)] >= t[at(i, j + 1)] {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Apply the edit `parent` → `current` to `accepted`, *in place*: every
/// rule the member removed goes, and every rule they added lands at the
/// same position relative to the rules around it, so last-match-wins gives
/// it the meaning it has in their file. The pending change (`accepted` →
/// `parent`) is not applied: rules it added stay out, rules it removed stay
/// in.
///
/// Where the member added rules exactly where the pending change removed
/// others, their order relative to those is unknown: they go after them
/// (`after`, so the member's rules decide where both match, as in their
/// file, where the removed ones are gone) or before them; the second value
/// returned describes the first such place. Refused (with the reason) where
/// a rule the member "added" is one the pending change added (they moved
/// it: accepting it would accept that change).
fn positional_edit(
    accepted: &[String],
    parent: &[String],
    current: &[String],
    after: bool,
) -> std::result::Result<(Vec<String>, Option<String>), String> {
    if (accepted.len() + 1) * (parent.len() + 1) + (parent.len() + 1) * (current.len() + 1) > FOLD_BUDGET {
        return Err("the policies are too large to compare".into());
    }
    // Where each rule of `parent` is in `accepted` (`None`: the pending
    // change added it).
    let mut in_accepted = vec![None; parent.len()];
    for (a, p) in lcs(accepted, parent) {
        in_accepted[p] = Some(a);
    }
    // The member's edit as hunks: `parent[s..e]` replaced by `ins`.
    let mut hunks: Vec<(usize, usize, &[String])> = Vec::new();
    let (mut pi, mut ci) = (0, 0);
    for (pm, cm) in lcs(parent, current).into_iter().chain([(parent.len(), current.len())]) {
        if pm > pi || cm > ci {
            hunks.push((pi, pm, &current[ci..cm]));
        }
        (pi, ci) = (pm + 1, cm + 1);
    }
    let mut delete = vec![false; accepted.len()];
    let mut insert: Vec<Vec<String>> = vec![Vec::new(); accepted.len() + 1];
    let mut ambiguous = None;
    let mut k = 0;
    while k < hunks.len() {
        // Hunks separated only by rules `accepted` does not have land in
        // the same place there: take them together.
        let mut group = vec![hunks[k]];
        while let Some(next) = hunks.get(k + 1) {
            let prev = group.last().expect("non-empty").1;
            if (prev..next.0).any(|i| in_accepted[i].is_some()) {
                break;
            }
            group.push(*next);
            k += 1;
        }
        k += 1;
        let (s, e) = (group[0].0, group.last().expect("non-empty").1);
        let lo = (0..s).rev().find_map(|i| in_accepted[i]).map_or(0, |a| a + 1);
        let hi = (e..parent.len()).find_map(|i| in_accepted[i]).unwrap_or(accepted.len());
        for &(hs, he, _) in &group {
            for a in (hs..he).filter_map(|i| in_accepted[i]) {
                delete[a] = true;
            }
        }
        let added: Vec<String> = group.iter().flat_map(|h| h.2.iter().cloned()).collect();
        // A rule of the pending change, moved: not the member's to accept.
        if let Some(l) = added.iter().find(|l| (0..parent.len()).any(|i| in_accepted[i].is_none() && parent[i] == **l)) {
            return Err(format!("you moved or copied '{}', a rule of the change you have not accepted", shown(l)));
        }
        // Rules of `accepted` here that the pending change removed.
        let removed: Vec<String> = (lo..hi).filter(|a| !delete[*a]).map(|a| accepted[a].clone()).collect();
        if added.is_empty() || added == removed {
            // A pure removal, or already applied (folding is idempotent).
            continue;
        }
        let at = match (removed.is_empty(), after) {
            (true, _) => lo,
            (false, after) => {
                ambiguous.get_or_insert_with(|| format!("you added '{}' where it removed '{}'", shown(&added[0]), shown(&removed[0])));
                match after {
                    // After the last of them (the ones the member deleted
                    // go anyway).
                    true => (lo..hi).rev().find(|a| !delete[*a]).map_or(lo, |a| a + 1),
                    false => lo,
                }
            }
        };
        insert[at].extend(added);
    }
    let mut out = Vec::new();
    for (a, line) in accepted.iter().enumerate() {
        out.append(&mut insert[a]);
        if !delete[a] {
            out.push(line.clone());
        }
    }
    out.append(&mut insert[accepted.len()]);
    Ok((out, ambiguous))
}

/// A classification, with the position of the last rule that applied.
type Applied = (Option<usize>, Classification);

/// Check that `folded` (the accepted policy with the member's edit folded
/// in) never classifies a path more weakly than both `accepted` and
/// `current` (the member's own file) do: a rule's meaning depends on the
/// rules around it, and the member's edit, applied next to rules other than
/// the ones they saw, must not end up meaning something neither policy
/// says.
///
/// Exhaustive over every combination of rules a path could match, not over
/// paths, so any overlap of globs is covered (rules with the same pattern
/// and case handling are matched together; any others are assumed to
/// overlap in every way). A path's classification only depends on its
/// built-in state (built-in secret, VCS metadata, editor scratch file), on
/// which `public!` rules
/// it matches (they decide which other rules apply), and on the last rule
/// that applies. So a path that breaks the property has a witness that
/// matches its `public!` rules plus at most one other rule per policy (the
/// last one applying there), and with its `public!` rules fixed, each
/// policy's classification of the witness is the one of the single rule
/// (or none) that applies latest. That makes the check every built-in
/// state × every set of `public!` rules × one rule (or none) per policy.
///
/// An editor or backup artefact then takes its base's protection where that
/// is stronger ([`Classification::inherit`]); the check covers the base and
/// the artefact's own rules, each on its own.
fn verify_fold(accepted: &Policy, current: &Policy, folded: &Policy) -> std::result::Result<(), String> {
    let policies = [accepted, current, folded];
    // Rules with the same pattern that match case the same way match the
    // same paths (`notes/ isolate` and `notes/ cloak`): one atom, matched
    // or not together. Any other two rules are taken as independent (an
    // over-approximation: every combination is checked, possible or not).
    let mut universe: Vec<(String, bool)> = Vec::new();
    let mut has_bang: Vec<bool> = Vec::new();
    let lists: Vec<Vec<(usize, &Rule)>> = policies
        .iter()
        .map(|p| {
            p.rules
                .iter()
                .filter(|r| !r.builtin)
                .map(|r| {
                    let key = (r.pattern.clone(), r.case_insensitive());
                    let i = universe.iter().position(|u| *u == key).unwrap_or_else(|| {
                        universe.push(key);
                        has_bang.push(false);
                        universe.len() - 1
                    });
                    has_bang[i] |= r.force;
                    (i, r)
                })
                .collect()
        })
        .collect();
    let bangs: Vec<usize> = (0..universe.len()).filter(|i| has_bang[*i]).collect();
    let others: Vec<usize> = (0..universe.len()).filter(|i| !has_bang[*i]).collect();
    // Per policy: no atom, or one of its own atoms without a `public!` rule
    // (those are in the set of matched `public!` atoms).
    let candidates: Vec<Vec<Option<usize>>> = lists
        .iter()
        .map(|l| {
            let mut c: Vec<Option<usize>> = l.iter().filter(|(i, _)| !has_bang[*i]).map(|(i, _)| Some(*i)).collect();
            c.sort_unstable();
            c.dedup();
            c.insert(0, None);
            c
        })
        .collect();
    let longest = lists.iter().map(Vec::len).max().unwrap_or(0);
    // Per set of `public!` rules: every combination, plus one pass over each
    // policy per rule to precompute the single-rule classifications.
    let per_set = candidates.iter().map(Vec::len).product::<usize>() + 3 * (others.len() + 1) * (longest + 1) * (longest + 1);
    let sets = 1usize.checked_shl(bangs.len() as u32).filter(|_| bangs.len() < 24);
    match sets.and_then(|n| n.checked_mul(5)).and_then(|n| n.checked_mul(per_set)) {
        Some(work) if work <= FOLD_BUDGET => {}
        _ => return Err("the policies have too many rules to check".into()),
    }
    // The classification of `list` for a path matching the rules in
    // `member`, with the position of the last rule applied.
    let classify = |list: &[(usize, &Rule)], member: &[bool], secret: bool, vcs: bool, scratch: bool| {
        let mut c = Classification::unmatched();
        if secret {
            c.tier = Tier::Isolated;
            c.builtin_secret = true;
        }
        if vcs {
            c.mark_vcs(".git");
        }
        if scratch {
            c.mark_scratch("*~");
        }
        let mut last = None;
        for (pos, (i, r)) in list.iter().enumerate() {
            if member[*i] && c.apply(r) {
                last = Some(pos);
            }
        }
        (last, c)
    };
    let mut member = vec![false; universe.len()];
    for state in 0..8u8 {
        let (secret, vcs, scratch) = (state & 1 != 0, state & 2 != 0, state & 4 != 0);
        // The scratch rule only applies where the other two do not.
        if scratch && (secret || vcs) {
            continue;
        }
        for set in 0..sets.unwrap_or(0) {
            for (bit, &i) in bangs.iter().enumerate() {
                member[i] = set & (1 << bit) != 0;
            }
            // single[policy][rule]: the classification with that one rule
            // (other than `public!`) added; `none[policy]` with none.
            let none: Vec<_> = lists.iter().map(|l| classify(l, &member, secret, vcs, scratch)).collect();
            let mut single: Vec<Vec<Option<Applied>>> = vec![vec![None; universe.len()]; 3];
            for &e in &others {
                member[e] = true;
                for (k, l) in lists.iter().enumerate() {
                    single[k][e] = Some(classify(l, &member, secret, vcs, scratch));
                }
                member[e] = false;
            }
            let pick = |k: usize, rules: [Option<usize>; 3]| -> &Classification {
                let mut best = &none[k];
                for e in rules.into_iter().flatten() {
                    let s = single[k][e].as_ref().expect("computed for every atom without public!");
                    if s.0 > best.0 {
                        best = s;
                    }
                }
                &best.1
            };
            for &a in &candidates[0] {
                for &c in &candidates[1] {
                    for &f in &candidates[2] {
                        let rules = [a, c, f];
                        let x = pick(2, rules);
                        if weakens(pick(0, rules), x) && weakens(pick(1, rules), x) {
                            let rule = x.rule.as_deref().map_or_else(|| "no rule".to_string(), |r| format!("rule '{r}'"));
                            return Err(format!(
                                "next to the rules you accepted, your edit would leave {rule} deciding some paths more weakly \
                                 than both that policy and your own file do"
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// How an edit of `.veilpolicy` that a command made (in a `vl ws exec`
/// sandbox or a mount, where the editor is not the member) relates to the
/// recorded policy it started from (see [`command_edit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandEdit {
    /// Classifies no path more weakly than the recorded policy (the rules
    /// are the same, or only protect more, or the exhaustive check of
    /// `verify_fold` proves it): recorded and applied.
    Strengthens,
    /// Only inserts `cloak`, `isolate` or `ignore` rules (and drops
    /// `public!` ones). Such a rule weakens a path only where it overrides
    /// an earlier, stronger rule for it (`secret/a cloak team` after
    /// `secret/ isolate`, a cloak rule lifting `target/ ignore`), which
    /// the paths of the snapshot show: recorded unless one of them is held
    /// back.
    Adds,
    /// Anything else (a rule removed, moved or changed, a `public` rule
    /// added): it may weaken paths, existing or not, so it is held back.
    Weakens,
}

/// Classify the edit `recorded` → `edited` of `.veilpolicy` made by a
/// command (see [`CommandEdit`]).
pub fn command_edit(recorded: &Policy, edited: &Policy) -> CommandEdit {
    if edited.same_rules(recorded) || edited.only_adds_protection_to(recorded) {
        return CommandEdit::Strengthens;
    }
    // `recorded`'s rules, in order, where only `public!` ones may be
    // missing; every other rule of `edited` an inserted protective one.
    let rec: Vec<&Rule> = recorded.rules.iter().filter(|r| !r.builtin).collect();
    let mut i = 0;
    let mut only_inserts = true;
    for m in edited.rules.iter().filter(|r| !r.builtin) {
        while i < rec.len() && rec[i].to_line() != m.to_line() && rec[i].tier == Tier::Public && rec[i].force {
            i += 1;
        }
        if i < rec.len() && rec[i].to_line() == m.to_line() {
            i += 1;
        } else if m.tier == Tier::Public {
            only_inserts = false;
            break;
        }
    }
    only_inserts &= rec[i.min(rec.len())..].iter().all(|r| r.tier == Tier::Public && r.force);
    if verify_fold(recorded, recorded, edited).is_ok() {
        return CommandEdit::Strengthens;
    }
    match only_inserts {
        true => CommandEdit::Adds,
        false => CommandEdit::Weakens,
    }
}

/// The accepted policy (`accepted`) with the member's own edit of
/// `.veilpolicy` (`parent` → `current`, where `parent` is the policy the
/// working copy was checked out with) folded in, as the text of a
/// `.veilpolicy`. Exactly their edit: what the pending change (`accepted`
/// → `parent`) did is not accepted with it.
///
/// The edit is applied in place (`positional_edit`), then checked to
/// mean, next to the accepted rules, nothing weaker than both the accepted
/// policy and the member's file (`verify_fold`). Where its place is
/// ambiguous, the member's rules are tried after the rules the pending
/// change removed, then before them. `Err` (why) when nothing passes: the
/// edit then waits for `vl policy accept`.
pub fn fold_edit(accepted: &Policy, parent: &Policy, current: &Policy) -> std::result::Result<String, String> {
    let (acc, par, cur) = (accepted.rule_lines(), parent.rule_lines(), current.rule_lines());
    let mut why = String::new();
    for after in [true, false] {
        let (lines, ambiguous) = positional_edit(&acc, &par, &cur, after)?;
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        match verify_fold(accepted, current, &Policy::parse(&text)) {
            Ok(()) => return Ok(text),
            Err(e) => why = e,
        }
        match ambiguous {
            None => break,
            Some(place) if !after => why = format!("{place}, and in either order {why}"),
            Some(_) => {}
        }
    }
    Err(why)
}

/// The first line of an accepted policy into which [`working_copy_policy`]
/// folded the member's edit `parent` → `current` (a comment, so the text
/// stays a `.veilpolicy`): folding again would not be idempotent where
/// identical rules repeat, so it is not done twice.
fn edit_id(parent: &Policy, current: &Policy) -> String {
    let digest = |p: &Policy| {
        let h = blake3::hash(p.rule_lines().join("\n").as_bytes());
        h.to_hex()[..16].to_string()
    };
    format!("# vl: your edit {}..{}", digest(parent), digest(current))
}

/// When [`fold_edit`] refuses: the accepted policy plus the `isolate` and
/// `ignore` rules the member added, appended (an appended rule that keeps
/// files on the device never weakens anything), so the protection they
/// asked for holds while the rest of their edit waits for
/// `vl policy accept`.
fn fold_protection_only(accepted: &Policy, parent: &Policy, current: &Policy) -> String {
    let (acc, par, cur) = (accepted.rule_lines(), parent.rule_lines(), current.rule_lines());
    // Too large to compare: take every protective rule of the member's file
    // (appending more of them only adds protection).
    let kept: Vec<usize> = match (par.len() + 1) * (cur.len() + 1) > FOLD_BUDGET {
        true => Vec::new(),
        false => lcs(&par, &cur).into_iter().map(|(_, c)| c).collect(),
    };
    // Normalised lines ([`Rule::to_line`]): the tier is the second field.
    let protective = |l: &String| matches!(fields(l).get(1).map(String::as_str), Some("isolate" | "ignore"));
    let tail: Vec<String> = cur
        .iter()
        .enumerate()
        .filter(|(i, l)| !kept.contains(i) && protective(l))
        .map(|(_, l)| l.clone())
        .collect();
    let mut out = acc;
    if !out.ends_with(&tail) {
        out.extend(tail);
    }
    out.iter().map(|l| format!("{l}\n")).collect()
}

// ---- reading the policy file ------------------------------------------------------

/// The largest policy file read through a symlink (a regular `.veilpolicy`
/// is read whatever its size, like any file of the working copy).
pub const MAX_LINKED_POLICY: u64 = 1 << 20;

/// What is at `.veilpolicy` in a working copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyFile {
    /// Nothing.
    Absent,
    /// A regular file.
    File(Vec<u8>),
    /// A symlink (a dotfiles manager, `stow`, a monorepo's shared policy),
    /// followed to the regular file it leads to, inside or outside the
    /// repository. Its rules apply, but a change in it is never taken as
    /// the member's own edit (see [`working_copy_policy`]): the target can
    /// change by routes Veil does not see.
    Linked(Vec<u8>),
    /// Something that cannot be read as a policy (why): an unreadable file,
    /// a directory, a dangling or looping symlink, a FIFO. Never "no
    /// policy": snapshots fall back to the accepted policy.
    Unavailable(String),
}

/// Read `.veilpolicy` at the root of `fs`. Errors reading it are reported
/// as [`PolicyFile::Unavailable`], never propagated: nothing in the working
/// copy may fail a snapshot.
pub fn read_policy_file(fs: &dyn StorageBackend) -> Result<PolicyFile> {
    let path = VPath::new(POLICY_FILE)?;
    match fs.read_through_link(&path, MAX_LINKED_POLICY) {
        // Only to a file whose name says it is a policy: a hostile Git
        // checkout's `.veilpolicy -> /proc/self/environ` (or
        // `~/.aws/credentials`) must not be parsed, and its lines echoed
        // in warnings, by `vl init` in CI.
        Ok(Some((target, _)))
            if !std::path::Path::new(&target)
                .file_name()
                .is_some_and(|n| n.to_string_lossy().to_lowercase().contains("veilpolicy")) =>
        {
            return Ok(PolicyFile::Unavailable(format!(
                "a symlink to {target}, whose name does not say it is a policy file; Veil only follows a link to a \
                 file named like `.veilpolicy`"
            )))
        }
        Ok(Some((_, b))) => return Ok(PolicyFile::Linked(b)),
        Ok(None) => {}
        Err(e) => return Ok(PolicyFile::Unavailable(e.to_string())),
    }
    Ok(match fs.metadata(&path) {
        // Nothing, or something the backend cannot show (a symlink in a
        // Git tree): its `read` says which.
        Ok(None) => match fs.read_opt(&path) {
            Ok(None) => PolicyFile::Absent,
            Ok(Some(b)) => PolicyFile::File(b),
            Err(e) => PolicyFile::Unavailable(e.to_string()),
        },
        Ok(Some(m)) if m.kind == crate::vfs::NodeKind::Dir => PolicyFile::Unavailable("it is a directory".into()),
        Ok(Some(_)) => match fs.read(&path) {
            Ok(b) => PolicyFile::File(b),
            // Gone since `metadata`: a concurrent `rm`.
            Err(e) if e.is_not_found() => PolicyFile::Absent,
            Err(e) => PolicyFile::Unavailable(e.to_string()),
        },
        Err(e) => PolicyFile::Unavailable(e.to_string()),
    })
}

// ---- the accepted policy of a working copy -------------------------------------

/// Device-local copy of the `.veilpolicy` the member of this working copy
/// last accepted (in the repository's `.veil/`, never synced).
pub const ACCEPTED_POLICY: &str = ".veil/local/accepted-policy";

/// The accepted policy's text, if one was ever recorded.
pub fn load_accepted(local: &dyn StorageBackend) -> Result<Option<Vec<u8>>> {
    local.read_opt(&VPath::new(ACCEPTED_POLICY)?)
}

/// Record `text` (a `.veilpolicy`; empty for none) as the accepted policy.
pub fn save_accepted(local: &dyn StorageBackend, text: &[u8]) -> Result<()> {
    local.write(&VPath::new(ACCEPTED_POLICY)?, text)
}

/// The policy a snapshot of a working copy applies, and what to record as
/// accepted once it is taken.
#[derive(Debug)]
pub struct WorkingCopyPolicy {
    /// The working copy's `.veilpolicy`, guarded by the accepted policy
    /// when it would weaken it.
    pub policy: Policy,
    /// New accepted-policy text to record ([`save_accepted`]).
    pub accept: Option<Vec<u8>>,
}

/// The working copy's `.veilpolicy`, guarded by the accepted one.
///
/// The accepted policy moves forward to the working copy's when
/// * none was recorded yet (a new repository, a fresh clone, or the first
///   snapshot after upgrading: there is no change to protect against);
/// * the rules are the same, or the new ones only append `isolate` /
///   `ignore` rules and drop `public!` rules
///   ([`Policy::only_adds_protection_to`]; comments and spacing never
///   matter);
/// * the member edited `.veilpolicy` themselves (by hand, or with
///   `vl cloak`, `vl expose`, …): `parent_policy` is given (the text of
///   `.veilpolicy` in the tree the working copy was checked out from,
///   `None` inside for no file) and the working copy's differs from it.
///   Their edit is accepted, and only their edit: the rules it removed and
///   added are applied to the accepted policy in place ([`fold_edit`]), so
///   editing a policy that arrived from someone else does not accept what
///   that someone else changed. Where their edit cannot be applied on its
///   own (it sits where the pending change removed rules, or next to the
///   accepted rules it would mean something weaker than both policies),
///   only the `isolate`/`ignore` rules it adds are accepted, the rest waits
///   for `vl policy accept`, and the policy carries a warning saying so.
///   Pass `None` when it is not known that the working copy's file can
///   only differ from that tree by a local edit (a command wrote
///   `.veilpolicy` from another revision, as `vl restore --from` does).
///
/// Otherwise, notably when the policy came from someone else by any route,
/// it is guarded until the member runs `vl policy accept`.
///
/// What is at `.veilpolicy` never makes a snapshot less protected than the
/// accepted policy says ([`read_policy_file`]):
/// * a **missing** file is not taken as the member's edit (deleting every
///   rule at once is an accident far more often than a decision): the
///   accepted policy guards the built-in rules until `vl policy accept`;
/// * a **symlink** is followed, but a change in the file it leads to is
///   never taken as the member's edit (a dotfiles sync or a monorepo pull
///   changes it by routes Veil does not see): what weakens the accepted
///   policy waits for `vl policy accept`;
/// * an **unreadable** file, a directory, a dangling or looping symlink:
///   the accepted policy applies as it is, with a warning, and nothing is
///   accepted.
pub fn working_copy_policy(
    local: &dyn StorageBackend,
    fs: &dyn StorageBackend,
    parent_policy: Option<Option<&[u8]>>,
) -> Result<WorkingCopyPolicy> {
    let acc = load_accepted(local)?;
    let (text, own_edit) = match read_policy_file(fs)? {
        PolicyFile::File(t) => (t, parent_policy),
        PolicyFile::Linked(t) => {
            let mut wp = guarded_policy(acc, t, None);
            wp.policy.warnings.push(format!(
                "{POLICY_FILE} is a symlink: Veil applies the rules of the file it leads to, but records no change \
                 to it (history keeps the recorded version, so teammates do not get your edits), and a change there \
                 that weakens the policy you accepted on this device waits for `vl policy accept`. Replace the link \
                 with a copy to record and share the policy"
            ));
            return Ok(wp);
        }
        PolicyFile::Absent => {
            let mut wp = guarded_policy(acc, Vec::new(), None);
            if wp.policy.accepted().is_some_and(|a| !a.rule_lines().is_empty()) {
                wp.policy.warnings.push(format!(
                    "{POLICY_FILE} is missing: the policy you accepted on this device still applies (a deleted \
                     policy file never lifts protection). `vl restore {POLICY_FILE}` brings it back; \
                     `vl policy accept` accepts having none"
                ));
            }
            return Ok(wp);
        }
        PolicyFile::Unavailable(why) => {
            let (policy, what) = match (&acc, parent_policy) {
                (Some(a), _) => (Policy::parse(&String::from_utf8_lossy(a)), "the policy you accepted on this device"),
                (None, Some(Some(p))) => (Policy::parse(&String::from_utf8_lossy(p)), "the recorded version"),
                (None, _) => (Policy::builtin(), "the built-in rules only"),
            };
            let mut policy = policy.unguarded();
            policy.warnings.push(format!(
                "cannot read {POLICY_FILE} ({why}); until it is fixed, snapshots apply {what}"
            ));
            return Ok(WorkingCopyPolicy { policy, accept: None });
        }
    };
    Ok(guarded_policy(acc, text, own_edit))
}

/// [`working_copy_policy`] for a readable `.veilpolicy` (`text`; empty for
/// none), the accepted policy `acc` and, when the member may have edited
/// the file, the policy of the tree it was checked out from.
fn guarded_policy(acc: Option<Vec<u8>>, text: Vec<u8>, parent_policy: Option<Option<&[u8]>>) -> WorkingCopyPolicy {
    let current = Policy::parse(&String::from_utf8_lossy(&text));
    let Some(acc) = acc else {
        return WorkingCopyPolicy {
            policy: current,
            accept: Some(text),
        };
    };
    let accepted = Policy::parse(&String::from_utf8_lossy(&acc));
    let take_all = || WorkingCopyPolicy {
        policy: current.clone(),
        accept: (acc != text).then(|| text.clone()),
    };
    if current.same_rules(&accepted) || current.only_adds_protection_to(&accepted) {
        return take_all();
    }
    let parent = parent_policy.map(|p| Policy::parse(&String::from_utf8_lossy(p.unwrap_or_default())));
    if let Some(parent) = parent.filter(|p| !p.same_rules(&current)) {
        if parent.same_rules(&accepted) {
            return take_all();
        }
        // Folded already (a snapshot that saved the accepted policy but was
        // not recorded): the accepted policy says which edit it holds.
        let id = edit_id(&parent, &current);
        let done = String::from_utf8_lossy(&acc).lines().next().and_then(|l| l.strip_prefix(&id)).map(str::to_string);
        let (pin, notice) = match done {
            Some(outcome) => (None, outcome.strip_prefix(" not applied: ").map(str::to_string)),
            None => match fold_edit(&accepted, &parent, &current) {
                Ok(text) => (Some(format!("{id} applied\n{text}")), None),
                Err(why) => (
                    Some(format!("{id} not applied: {why}\n{}", fold_protection_only(&accepted, &parent, &current))),
                    Some(why),
                ),
            },
        };
        let mut policy = current.guarded_by(pin.as_deref().map_or(accepted, Policy::parse));
        if let Some(why) = notice {
            policy.own_edit_pending = true;
            policy.warnings.push(format!(
                "your edit of {POLICY_FILE} was not applied to the policy you accepted on this device, because a change \
                 you have not accepted is pending: {why}. Until `vl policy accept`, files your edit exposes keep the \
                 protection you accepted (the `isolate`/`ignore` rules you added apply). Review with `vl policy show`"
            ));
        }
        return WorkingCopyPolicy {
            policy,
            accept: pin.map(String::into_bytes),
        };
    }
    WorkingCopyPolicy {
        policy: current.guarded_by(accepted),
        accept: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(p: &Policy, path: &str) -> Tier {
        p.classify(&VPath::new(path).unwrap(), false).tier
    }

    /// BUG-560: how a command's edit of `.veilpolicy` is judged.
    #[test]
    fn command_edits_are_judged_against_the_recorded_policy() {
        let rec = Policy::parse("target/ ignore\nsecret/ cloak team\ndocs/x.md public!\n");
        let kind = |text: &str| command_edit(&rec, &Policy::parse(text));
        // Comments, appended ignores, a dropped `public!`: never weaker.
        assert_eq!(kind("# c\ntarget/ ignore\nsecret/ cloak team\ndocs/x.md public!\n"), CommandEdit::Strengthens);
        assert_eq!(kind("target/ ignore\nsecret/ cloak team\ndocs/x.md public!\nbuild/ ignore\n"), CommandEdit::Strengthens);
        assert_eq!(kind("target/ ignore\nsecret/ cloak team\n"), CommandEdit::Strengthens);
        // Moving `ignore` last only protects more (the exhaustive check).
        assert_eq!(kind("secret/ cloak team\ntarget/ ignore\ndocs/x.md public!\n"), CommandEdit::Strengthens);
        // An inserted cloak rule: up to the snapshot's paths.
        assert_eq!(kind("target/ ignore\nsecret/ cloak team\ndocs/x.md public!\nsrc/ cloak team\n"), CommandEdit::Adds);
        // Every weakening shape.
        for text in [
            "",
            "target/ ignore\ndocs/x.md public!\n",
            "target/ ignore\nsecret/ cloak team\ndocs/x.md public!\nsecret/** public!\n",
            "target/ ignore\nsecret/ cloak team\ndocs/x.md public!\n** public\n",
            "target/ ignore\nsecret/ cloak ops\ndocs/x.md public!\n",
            "target/ ignore\nsecret/ cloak team\nsecret/a.md public\ndocs/x.md public!\n",
        ] {
            assert_eq!(kind(text), CommandEdit::Weakens, "{text:?}");
        }
    }

    #[test]
    fn builtin_secrets_are_isolated() {
        let p = Policy::builtin();
        assert_eq!(class(&p, ".env"), Tier::Isolated);
        assert_eq!(class(&p, "svc/api/.env.production"), Tier::Isolated);
        assert_eq!(class(&p, "certs/server.pem"), Tier::Isolated);
        assert_eq!(class(&p, ".env.example"), Tier::Public);
        assert_eq!(class(&p, "src/main.rs"), Tier::Public);
        // BUG-493: registry credentials, like .netrc and .pypirc.
        for f in [".npmrc", "web/.npmrc", ".netrc", ".pypirc"] {
            assert_eq!(class(&p, f), Tier::Isolated, "{f}");
        }
    }

    #[test]
    fn user_rules() {
        let p = Policy::parse(
            "secrets/  cloak ops\n*.log ignore\n.env public\nconfig/.env cloak\nfixtures/ public!\ntarget/ ignore\n",
        );
        assert_eq!(class(&p, "secrets/db.yml"), Tier::Cloaked("ops".into()));
        assert_eq!(class(&p, "a/b/x.log"), Tier::Ignored);
        let c = p.classify(&VPath::new(".env").unwrap(), false);
        assert_eq!(c.tier, Tier::Isolated, "plain `public` cannot expose a builtin secret");
        assert!(c.blocked_exposure);
        assert_eq!(class(&p, "config/.env"), Tier::Cloaked("team".into()));
        let f = p.classify(&VPath::new("fixtures/key.pem").unwrap(), false);
        assert_eq!(f.tier, Tier::Public);
        assert!(f.allow_secrets);
        assert_eq!(p.classify(&VPath::new("target").unwrap(), true).tier, Tier::Ignored);
        assert_eq!(class(&p, "target"), Tier::Public, "dir-only rule does not match a file");
    }

    #[test]
    fn escapes_and_fields() {
        let p = Policy::parse(&format!(
            "{} cloak\n{} isolate # comment\nissue\\#1.md ignore\n",
            escape_literal("config[prod].yml"),
            escape_literal("my notes.txt")
        ));
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        assert_eq!(class(&p, "config[prod].yml"), Tier::Cloaked("team".into()));
        assert_eq!(class(&p, "configp.yml"), Tier::Public, "no longer a character class");
        assert_eq!(class(&p, "my notes.txt"), Tier::Isolated);
        assert_eq!(class(&p, "issue#1.md"), Tier::Ignored);
        assert_eq!(escape_field("a b#c\\#d*"), "a\\ b\\#c\\#d*");
    }

    #[test]
    fn protective_rules_ignore_case_exposing_rules_do_not() {
        let p = Policy::parse("secrets/ cloak\nkeys/ isolate\nfixtures/ public!\nbuild/ ignore\n");
        assert_eq!(class(&p, "Secrets/a"), Tier::Cloaked("team".into()));
        assert_eq!(class(&p, "KEYS/a"), Tier::Isolated);
        assert_eq!(class(&p, "Fixtures/a"), Tier::Public);
        assert_eq!(p.classify(&VPath::new("Fixtures/a.pem").unwrap(), false).tier, Tier::Isolated);
        assert_eq!(class(&p, "Build/a"), Tier::Public);
        assert_eq!(class(&p, ".Env.Example"), Tier::Isolated, "exceptions to secret rules stay exact");
        assert_eq!(class(&p, ".env.example"), Tier::Public);
    }

    #[test]
    fn weakening() {
        let c = |p: &str, path: &str| Policy::parse(p).classify(&VPath::new(path).unwrap(), false);
        let w = |a: &str, b: &str, path: &str| weakens(&c(a, path), &c(b, path));
        assert!(w("", ".env public!\n", ".env"), "isolated → public");
        assert!(w("", ".env cloak\n", ".env"), "isolated → cloaked");
        assert!(!w("", ".env ignore\n", ".env"), "isolated → ignored stays local");
        assert!(w("s/ cloak ops\n", "", "s/a"), "cloaked → public");
        assert!(w("s/ cloak ops\n", "s/ cloak team\n", "s/a"), "another audience");
        assert!(!w("s/ cloak ops\n", "s/ isolate\n", "s/a"));
        assert!(w("", "t/ public!\n", "t/a"), "scanning turned off");
        assert!(!w("t/ public!\n", "", "t/a"));
        assert!(w("k/ ignore\n", "k/ public!\n", "k/id_rsa"), "ignore lifted from a built-in secret");
        assert!(!w("build/ ignore\n", "", "build/out.txt"), "ignore lifted from an ordinary file");
        assert!(!w("", "x/ cloak\n", "x/a"), "public → cloaked strengthens");
        let g = Policy::parse(".env public!\nsecrets/ public\n").guarded_by(Policy::parse("secrets/ cloak\n"));
        let e = g.classify(&VPath::new(".env").unwrap(), false);
        assert_eq!((e.tier.clone(), e.held_back.clone()), (Tier::Isolated, Some((Tier::Public, true))));
        assert_eq!(g.classify(&VPath::new("secrets/a").unwrap(), false).tier, Tier::Cloaked("team".into()));
        assert_eq!(g.classify(&VPath::new("src/a").unwrap(), false).held_back, None);
    }

    #[test]
    fn policy_changes_that_cannot_weaken() {
        let p = Policy::parse;
        let acc = p("fixtures/ public!\nsecrets/ cloak\n# c\n");
        assert!(p("fixtures/   public!   # spacing\nsecrets/ cloak\n").same_rules(&acc));
        assert!(p("fixtures/ public!\nsecrets/ cloak\ndrafts/ isolate\nbuild/ ignore\n").only_adds_protection_to(&acc));
        assert!(p("secrets/ cloak\n").only_adds_protection_to(&acc), "a public! rule removed");
        assert!(!p("fixtures/ public!\n").only_adds_protection_to(&acc), "a cloak rule removed");
        assert!(!p("fixtures/ public!\nsecrets/ cloak\nx/ cloak\n").only_adds_protection_to(&acc));
        assert!(!p("fixtures/ public!\nsecrets/ cloak\n.env public!\n").only_adds_protection_to(&acc));
        // The member's edit on top of a policy from someone else.
        let theirs = p(".env public!\nsecrets/ cloak\n");
        let mine = p(".env public!\nsecrets/ cloak\nnotes/ public!\n");
        let edited = p(&fold_edit(&acc, &theirs, &mine).unwrap());
        assert!(edited.same_rules(&p("fixtures/ public!\nsecrets/ cloak\nnotes/ public!\n")), "{:?}", edited.rule_lines());
        let mine = p(".env public!\n");
        let edited = p(&fold_edit(&p("secrets/ cloak\n"), &theirs, &mine).unwrap());
        assert!(edited.same_rules(&p("")), "the removed rule goes: {:?}", edited.rule_lines());
        // Not next to `fixtures/ public!`, which the member's file no longer
        // has: there it would leave `fixtures/secrets/x` public and unscanned,
        // weaker than both the accepted policy and the member's file.
        assert!(fold_edit(&acc, &theirs, &mine).is_err());
    }

    #[test]
    fn vcs_metadata_is_ignored_at_any_depth() {
        let p = Policy::parse("** public\nsrc/ cloak\ntests/ public!\nkeep/ isolate\n");
        let c = |path: &str, dir: bool| p.classify(&VPath::new(path).unwrap(), dir);
        for (path, dir) in [
            (".git", true),
            (".git/HEAD", false),
            (".git", false),
            ("sub/.git", false),
            ("src/vendor/.git/config", false),
            ("tests/fixture/.git/objects/ab/cd", false),
            ("keep/.hg/store", false),
            (".jj", true),
            (".svn/entries", false),
            (".GIT/config", false),
            (".g\u{200C}it/config", false),
            (".git/k.pem", false),
        ] {
            let k = c(path, dir);
            assert_eq!((k.tier.clone(), k.builtin_vcs), (Tier::Ignored, true), "{path}");
        }
        assert_eq!(c(".hg", false).tier, Tier::Public, "only a .git file counts, not a .hg file");
        assert_eq!(c("a.git/x", false).tier, Tier::Public);
        assert_eq!(c("src/main.rs", false).tier, Tier::Cloaked("team".into()));
        // Only a `public!` naming the directory records it.
        let p = Policy::parse("fixtures/repo/.git/ public!\n**/.hg public!\n");
        let c = |path: &str| p.classify(&VPath::new(path).unwrap(), false);
        assert_eq!(c("fixtures/repo/.git/HEAD").tier, Tier::Public);
        assert!(!c("fixtures/repo/.git/HEAD").builtin_vcs);
        assert_eq!(c("x/.hg/store").tier, Tier::Public);
        assert_eq!(c(".git/HEAD").tier, Tier::Ignored);
        assert!(names_vcs("a/\\.git/") && names_vcs("**/.JJ") && !names_vcs("x.git") && !names_vcs("*"));
        // An incoming policy that records the member's `.git` weakens it.
        let w = |a: &str, b: &str, path: &str| {
            let v = VPath::new(path).unwrap();
            weakens(&Policy::parse(a).classify(&v, false), &Policy::parse(b).classify(&v, false))
        };
        assert!(w("", ".git public!\n", ".git/config"));
        assert!(!w("", ".git public\n", ".git/config"));
    }

    #[test]
    fn vcs_names() {
        for name in [".git", ".GIT", ".gIt", ".g\u{200C}it", "\u{FEFF}.git", ".git\u{200D}"] {
            assert_eq!(vcs_metadata_name(name), Some(".git"), "{name:?}");
        }
        for name in ["git", ".gitx", ".gi", "..git", ".gitignore", ".github"] {
            assert_eq!(vcs_metadata_name(name), None, "{name:?}");
        }
        assert_eq!(vcs_metadata_name(".JJ"), Some(".jj"));
    }

    #[test]
    fn a_later_rule_settles_an_ignored_public_rule() {
        let c = |p: &str| Policy::parse(p).classify(&VPath::new("t.pem").unwrap(), false);
        assert!(c("t.pem public\n").blocked_exposure);
        let k = c("t.pem public\nt.pem public!\n");
        assert!(!k.blocked_exposure && k.allow_secrets && k.tier == Tier::Public);
        assert!(!c("t.pem public\nt.pem cloak\n").blocked_exposure);
        assert!(c("t.pem cloak\nt.pem public\n").blocked_exposure, "the ignored rule is the last one");
    }

    #[test]
    fn the_members_edit_is_folded_in_place() {
        let p = Policy::parse;
        let lines = |t: &str| p(t).rule_lines();
        // BUG-073: a general rule written above the exception stays above it.
        let acc = p("notes/private.md isolate\n");
        let parent = p("notes/private.md isolate\n.env public!\n");
        let mine = p("notes/** public\nnotes/private.md isolate\n.env public!\n");
        let folded = fold_edit(&acc, &parent, &mine).unwrap();
        assert_eq!(p(&folded).rule_lines(), lines("notes/** public\nnotes/private.md isolate\n"));
        assert_eq!(p(&folded).classify(&VPath::new("notes/private.md").unwrap(), false).tier, Tier::Isolated);
        // Idempotent: folding again onto the result changes nothing.
        assert_eq!(fold_edit(&p(&folded), &parent, &mine).unwrap(), folded);
        // Next to rules the pending change added: kept in place.
        let parent = p("a/ cloak\n.env public!\nb/ cloak\n");
        let mine = p("a/ cloak\n.env public!\nb/x public\nb/ cloak\n");
        let folded = fold_edit(&p("a/ cloak\nb/ cloak\n"), &parent, &mine).unwrap();
        assert_eq!(p(&folded).rule_lines(), lines("a/ cloak\nb/x public\nb/ cloak\n"));
        // Where the pending change removed a rule, the place is ambiguous:
        // after it (the member's rule decides, as in their file) ...
        let acc = p("x/ cloak\ny/ public!\nz/ cloak\n");
        let folded = fold_edit(&acc, &p("x/ cloak\nz/ cloak\n"), &p("x/ cloak\nw/ isolate\nz/ cloak\n")).unwrap();
        assert_eq!(p(&folded).rule_lines(), lines("x/ cloak\ny/ public!\nw/ isolate\nz/ cloak\n"));
        // ... unless that is weaker than both policies somewhere: then before.
        // (Here `a/x public!` after `a/ isolate` would publish `a/x`, which
        // the member's file cloaks by the pending change's `a/ cloak`.)
        let folded = fold_edit(&p("a/ isolate\n"), &p("a/ cloak\n"), &p("a/x public!\na/ cloak\n")).unwrap();
        assert_eq!(p(&folded).rule_lines(), lines("a/x public!\na/ isolate\n"));
        // A rule of the pending change, moved by the member: not theirs.
        let err = fold_edit(&p("a/ isolate\n"), &p("a/ isolate\nb/ public!\nc/ cloak\n"), &p("a/ isolate\nc/ cloak\nb/ public!\n"))
            .unwrap_err();
        assert!(err.contains("moved"), "{err}");
        // A removal that only meant something next to the pending change's
        // rules: dropping it from the accepted policy would expose `a/x`.
        let acc = p("a/x isolate\n");
        let parent = p("a/x isolate\na/** isolate\n.env public!\n");
        let mine = p("a/** isolate\n.env public!\n");
        let err = fold_edit(&acc, &parent, &mine).unwrap_err();
        assert!(err.contains("more weakly"), "{err}");
        // ... and then only the protective rules it added are accepted.
        let mine = p("a/x isolate\na/** isolate\n.env public!\nb/ public!\nlogs/ ignore\n");
        let only = fold_protection_only(&acc, &parent, &mine);
        assert_eq!(p(&only).rule_lines(), lines("a/x isolate\nlogs/ ignore\n"));
        assert_eq!(fold_protection_only(&p(&only), &parent, &mine), only, "idempotent");
    }

    #[test]
    fn editor_artefact_names() {
        let a = |n: &str| editor_artefact(n).map(|a| (a.scratch.is_some(), a.bases));
        let v = |b: &[&str]| b.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(a(".id_ed25519.swp"), Some((true, v(&["id_ed25519", ".id_ed25519"]))));
        assert_eq!(a(".env.swo"), Some((true, v(&["env", ".env"]))));
        assert_eq!(a(".server.pem.SWN"), Some((true, v(&["server.pem", ".server.pem"]))));
        assert_eq!(a(".x.swa").map(|x| x.0), Some(true));
        assert_eq!(a(".x.swq"), None, "Vim stops at .swa");
        assert_eq!(a(".x.un~").map(|x| x.1[..2].to_vec()), Some(v(&["x", ".x"])));
        assert_eq!(a(".env.kate-swp"), Some((true, v(&["env", ".env"]))));
        assert_eq!(a(".env~"), Some((true, v(&[".env"]))));
        assert_eq!(a("notes.md.~12~"), Some((true, v(&["notes.md"]))));
        assert_eq!(a("#.env#"), Some((true, v(&[".env"]))));
        assert_eq!(a(".#.env"), Some((true, v(&[".env"]))));
        assert_eq!(a("id_rsa___jb_tmp___"), Some((true, v(&["id_rsa"]))));
        assert_eq!(a("id_rsa___jb_old___"), Some((true, v(&["id_rsa"]))));
        assert_eq!(a(".~lock.keys.ods#"), Some((true, v(&["keys.ods"]))));
        for (n, b) in [(".env.orig", ".env"), ("server.pem.bak", "server.pem"), ("s.yml.tmp", "s.yml"), ("k.BAK2", "k"), ("k.save.1", "k")] {
            assert_eq!(a(n), Some((false, v(&[b]))), "{n}");
        }
        for n in ["main.rs", "~", "#", "##", ".#", ".swp", "..swp", ".bak", "x.1", "v1.2.3", ".svg.icon", "a.swp", "x.bakery", "é.swp", ".é"] {
            assert_eq!(a(n), None, "{n}");
        }
        assert!(names_scratch("*~") && names_scratch("*.swp") && names_scratch("dir/.*.sw?") && names_scratch(".*.sw[a-p]") && names_scratch(r"\#*\#"));
        assert!(!names_scratch("*.bak") && !names_scratch("tests/") && !names_scratch("**"));
        for name in [".a.swp", ".a.un~", ".a.kate-swp", "a~", "#a#", ".#a", "a___jb_tmp___", "a___jb_old___", ".~lock.a#"] {
            let kind = editor_artefact(name).and_then(|a| a.scratch);
            assert!(kind.is_some_and(|k| SCRATCH_PATTERNS.contains(&k)), "{name}: {kind:?}");
        }
    }

    #[test]
    fn editor_artefacts_take_their_bases_protection() {
        let p = Policy::parse("notes/** public\nnotes/private.md isolate\nsecrets/ cloak ops\nx/ cloak team\nbuild.log ignore\n");
        let c = |path: &str| p.classify(&VPath::new(path).unwrap(), false);
        for path in [
            "deploy/.id_ed25519.swp",
            "deploy/.id_ed25519.swo",
            "deploy/.server.pem.swp",
            "deploy/.server.pem.un~",
            "deploy/id_ed25519~",
            ".env~",
            "#.env#",
            ".#.env",
            "a/b/.env.kate-swp",
            "id_rsa___jb_tmp___",
            "deploy/server.pem.bak",
            "deploy/id_ed25519.orig",
            "k/server.key.tmp",
            ".envrc.bak~",
            "notes/.private.md.swp",
            "notes/private.md~",
            "notes/#private.md#",
            "notes/private.md.orig",
        ] {
            let k = c(path);
            assert_eq!(k.tier, Tier::Isolated, "{path}: {k:?}");
            assert!(k.artefact_of.is_some() || path.contains(".env"), "{path}: {k:?}");
        }
        assert_eq!(c("notes/.private.md.swp").artefact_of, Some(VPath::new("notes/private.md").unwrap()));
        assert_eq!(c(".envrc.bak~").artefact_of, Some(VPath::new(".envrc").unwrap()), "unwrapped twice");
        // Cloaked bases: backup copies get the same scope; scratch files stay
        // ignored (they never leave the device) unless a rule lifts that.
        assert_eq!(c("secrets/db.yml.bak").tier, Tier::Cloaked("ops".into()));
        assert_eq!(c("secrets/.db.yml.swp").tier, Tier::Ignored);
        assert_eq!(c("secrets/.db.yml.swp").rule.as_deref(), Some(".*.sw[a-p]"));
        assert_eq!(c("x/.db.yml.swp").tier, Tier::Ignored, "a plain cloak does not lift the scratch rule");
        let lifted = Policy::parse("secrets/ cloak ops\n*.sw? public!\nx/ cloak team\nx/*.bak cloak ops\n");
        let k = lifted.classify(&VPath::new("secrets/.db.yml.swp").unwrap(), false);
        assert_eq!(k.tier, Tier::Cloaked("ops".into()), "the base's scope, not public: {k:?}");
        assert_eq!(lifted.classify(&VPath::new("src/.main.rs.swp").unwrap(), false).tier, Tier::Public);
        let k = lifted.classify(&VPath::new("x/db.yml.bak").unwrap(), false);
        assert_eq!(k.tier, Tier::Cloaked("team".into()), "the base's scope, not the artefact's: {k:?}");
        // Ignored bases.
        assert_eq!(c("build.log.old").tier, Tier::Ignored);
        // Public bases: scratch files are ignored, backup copies are ordinary.
        assert_eq!(c("src/.main.rs.swp").tier, Tier::Ignored);
        assert!(c("src/.main.rs.swp").builtin_artefact);
        assert_eq!(c("src/main.rs~").tier, Tier::Ignored);
        assert_eq!(c("src/main.rs.orig").tier, Tier::Public);
        assert_eq!(c("notes/a.md.bak").tier, Tier::Public);
        // Whatever the artefact's own rules say.
        let p = Policy::parse("** public!\n.env* public!\n*~ public!\nnotes/x isolate\n");
        let k = p.classify(&VPath::new("notes/x~").unwrap(), false);
        assert_eq!(k.tier, Tier::Isolated, "{k:?}");
        assert_eq!(p.classify(&VPath::new(".env~").unwrap(), false).tier, Tier::Public, ".env itself is public! here");
        assert_eq!(p.classify(&VPath::new("src/a~").unwrap(), false).tier, Tier::Public, "*~ public! names scratch files");
        // Directories are not artefacts.
        assert_eq!(Policy::parse("").classify(&VPath::new("x~").unwrap(), true).tier, Tier::Public);
    }

    #[test]
    fn publishing_an_artefact_is_a_weakening() {
        let c = |p: &str, path: &str| Policy::parse(p).classify(&VPath::new(path).unwrap(), false);
        let w = |a: &str, b: &str, path: &str| weakens(&c(a, path), &c(b, path));
        assert!(!w("", "*.swp public!\n", "deploy/.id_ed25519.swp"), "still isolated through its base");
        assert!(!w("", "id_ed25519 public!\n", "deploy/.id_ed25519.swp"), "still an ignored scratch file");
        assert!(w("", "id_ed25519 public!\n*.swp public!\n", "deploy/.id_ed25519.swp"), "published with its base");
        assert!(w("", "*.swp public!\n", "src/.main.rs.swp"), "the scratch rule lifted");
        assert!(w("", "id_ed25519 public!\n", "deploy/id_ed25519.bak"), "its base published");
        assert!(w("s/ cloak ops\n", "s/ cloak team\n", "s/a.yml.bak"), "another audience");
        assert!(w("k/ ignore\n", "k/ public!\n", "k/id_rsa.bak"), "ignore lifted from a built-in secret's artefact");
        assert!(!w("k/ ignore\n", "k/ public!\n", "k/.id_rsa.swp"), "the scratch rule still ignores it");
        assert!(!w("", "*.swp isolate\n", "src/.main.rs.swp"));
        assert!(!w("", "notes/ isolate\n", "notes/a.md.bak"), "strengthening");
        let g = Policy::parse("id_ed25519 public!\n*.swp public!\n").guarded_by(Policy::parse(""));
        let k = g.classify(&VPath::new("deploy/.id_ed25519.swp").unwrap(), false);
        assert_eq!((k.tier, k.held_back), (Tier::Isolated, Some((Tier::Public, true))));
    }

    #[test]
    fn a_refused_fold_says_the_members_edit_is_pending() {
        let (local, fs) = (crate::MemoryBackend::new(), crate::MemoryBackend::new());
        save_accepted(&local, b"a/x isolate\n").unwrap();
        fs.write(&VPath::new(POLICY_FILE).unwrap(), b"a/** isolate\n.env public!\n").unwrap();
        let parent = b"a/x isolate\na/** isolate\n.env public!\n";
        let wp = working_copy_policy(&local, &fs, Some(Some(parent))).unwrap();
        assert!(wp.policy.own_edit_pending);
        let wp = working_copy_policy(&local, &fs, None).unwrap();
        assert!(!wp.policy.own_edit_pending, "nothing of the member's is pending");
    }

    #[test]
    fn invalid_rules_fail_safe() {
        let p = Policy::parse("a/ cloak local\nb/ cloak embargo/x\nc/ clok\nd/\ne[ cloak\nf[ public!\n");
        for path in ["a/x", "b/x", "c/x", "d/x"] {
            assert_eq!(class(&p, path), Tier::Isolated, "{path}: {:?}", p.warnings);
        }
        assert_eq!(class(&p, "e["), Tier::Cloaked("team".into()), "a bad glob still protects its literal name");
        assert_eq!(class(&p, "f[/k.pem"), Tier::Isolated, "an invalid exposing rule is dropped");
        assert_eq!(p.warnings.len(), 6, "{:?}", p.warnings);
    }
}
