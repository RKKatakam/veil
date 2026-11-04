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
    ".git-credentials",
    "*.tfstate",
    "*.tfstate.*",
];

const BUILTIN_PUBLIC_EXCEPTIONS: &[&str] = &[".env.example", ".env.sample", ".env.template", ".env.dist"];

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
    dir_only: bool,
    exact: GlobMatcher,
    under: GlobMatcher,
}

/// All rules' globs compiled into one set (`2i` = rule `i` exact, `2i + 1` =
/// rule `i` under), so classifying a path is one match instead of two per
/// rule. Classification runs for every path on every snapshot.
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

impl Rule {
    fn new(pattern: &str, tier: Tier, force: bool, builtin: bool, secret: bool) -> Result<Rule, String> {
        // Protective rules match case-insensitively (see the module docs).
        let case_insensitive = (builtin && secret) || (!builtin && matches!(tier, Tier::Cloaked(_) | Tier::Isolated));
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
            dir_only,
        })
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
    /// A user rule tried to make a built-in secret public without `public!`.
    pub blocked_exposure: bool,
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
}

/// Does moving a path from the `accepted` classification to `current`
/// weaken its protection? That is: isolated → cloaked or public, cloaked →
/// public or to another scope (another audience), secret scanning turned
/// off (`public` → `public!`), or an `ignore` lifted from a built-in secret
/// (other than to `isolate`). Moving to `isolate` or `ignore` never weakens
/// anything: the file stays on this device either way.
pub fn weakens(accepted: &Classification, current: &Classification) -> bool {
    match (&accepted.tier, &current.tier) {
        (_, Tier::Isolated | Tier::Ignored) => false,
        (Tier::Isolated, _) => true,
        (Tier::Ignored, _) => accepted.builtin_secret,
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
        let mut rules = Vec::new();
        for p in BUILTIN_SECRETS {
            rules.push(Rule::new(p, Tier::Isolated, false, true, true).unwrap());
        }
        for p in BUILTIN_PUBLIC_EXCEPTIONS {
            rules.push(Rule::new(p, Tier::Public, false, true, false).unwrap());
        }
        Policy {
            set: compile_set(&rules),
            rules,
            warnings: vec![],
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
        policy.set = compile_set(&policy.rules);
        policy
    }

    /// Load `.veilpolicy` from the root of a working copy.
    pub fn load(fs: &dyn StorageBackend) -> Result<Policy> {
        let path = VPath::new(POLICY_FILE)?;
        Ok(match fs.read_opt(&path)? {
            Some(b) => Self::parse(&String::from_utf8_lossy(&b)),
            None => Self::builtin(),
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

    /// This policy's rules with the edit that turned `from` into `to`
    /// applied: rules `to` dropped are removed, rules it added are appended
    /// (so they win where they match). The text of a `.veilpolicy`.
    pub fn with_edit(&self, from: &Policy, to: &Policy) -> String {
        let (from, to) = (from.rule_lines(), to.rule_lines());
        let mut removed = from.clone();
        let mut added = Vec::new();
        for l in to {
            match removed.iter().position(|r| *r == l) {
                Some(i) => {
                    removed.remove(i);
                }
                None => added.push(l),
            }
        }
        let mut out = self.rule_lines();
        for r in removed {
            if let Some(i) = out.iter().position(|l| *l == r) {
                out.remove(i);
            }
        }
        out.extend(added);
        out.iter().map(|l| format!("{l}\n")).collect()
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
        let mut c = Classification {
            tier: Tier::Public,
            allow_secrets: false,
            rule: None,
            builtin_secret: false,
            blocked_exposure: false,
            held_back: None,
        };
        // The policy file itself is always public: everyone must agree on it.
        if path.as_str() == POLICY_FILE {
            return c;
        }
        let hits = self.set.matches(&*crate::vpath::nfc(path.as_str()));
        let mut matched = vec![false; self.rules.len()];
        for i in hits {
            let r = &self.rules[i / 2];
            if i % 2 == 1 || !r.dir_only || is_dir {
                matched[i / 2] = true;
            }
        }
        for (r, _) in self.rules.iter().zip(&matched).filter(|(_, m)| **m) {
            if r.builtin {
                c.builtin_secret = r.secret;
                c.tier = r.tier.clone();
                c.allow_secrets = false;
                c.rule = Some(r.pattern.clone());
                continue;
            }
            if r.tier == Tier::Public && c.builtin_secret && !r.force {
                c.blocked_exposure = true;
                continue;
            }
            c.tier = r.tier.clone();
            c.allow_secrets = r.force;
            c.rule = Some(r.pattern.clone());
            if r.force {
                c.builtin_secret = false;
            }
        }
        c
    }
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
///   added are applied to the accepted policy ([`Policy::with_edit`]), so
///   editing a policy that arrived from someone else does not accept what
///   that someone else changed. Pass `None` when it is not known that the
///   working copy's file can only differ from that tree by a local edit.
///
/// Otherwise, notably when the policy came from someone else by any route,
/// it is guarded until the member runs `vl policy accept`.
pub fn working_copy_policy(
    local: &dyn StorageBackend,
    fs: &dyn StorageBackend,
    parent_policy: Option<Option<&[u8]>>,
) -> Result<WorkingCopyPolicy> {
    let text = fs.read_opt(&VPath::new(POLICY_FILE)?)?.unwrap_or_default();
    let current = Policy::parse(&String::from_utf8_lossy(&text));
    let Some(acc) = load_accepted(local)? else {
        return Ok(WorkingCopyPolicy {
            policy: current,
            accept: Some(text),
        });
    };
    let accepted = Policy::parse(&String::from_utf8_lossy(&acc));
    let take_all = || WorkingCopyPolicy {
        policy: current.clone(),
        accept: (acc != text).then(|| text.clone()),
    };
    if current.same_rules(&accepted) || current.only_adds_protection_to(&accepted) {
        return Ok(take_all());
    }
    let parent = parent_policy.map(|p| Policy::parse(&String::from_utf8_lossy(p.unwrap_or_default())));
    if let Some(parent) = parent.filter(|p| !p.same_rules(&current)) {
        if parent.same_rules(&accepted) {
            return Ok(take_all());
        }
        let edited = accepted.with_edit(&parent, &current);
        return Ok(WorkingCopyPolicy {
            policy: current.guarded_by(Policy::parse(&edited)),
            accept: Some(edited.into_bytes()),
        });
    }
    Ok(WorkingCopyPolicy {
        policy: current.guarded_by(accepted),
        accept: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(p: &Policy, path: &str) -> Tier {
        p.classify(&VPath::new(path).unwrap(), false).tier
    }

    #[test]
    fn builtin_secrets_are_isolated() {
        let p = Policy::builtin();
        assert_eq!(class(&p, ".env"), Tier::Isolated);
        assert_eq!(class(&p, "svc/api/.env.production"), Tier::Isolated);
        assert_eq!(class(&p, "certs/server.pem"), Tier::Isolated);
        assert_eq!(class(&p, ".env.example"), Tier::Public);
        assert_eq!(class(&p, "src/main.rs"), Tier::Public);
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
        let edited = p(&acc.with_edit(&theirs, &mine));
        assert!(edited.same_rules(&p("fixtures/ public!\nsecrets/ cloak\nnotes/ public!\n")), "{:?}", edited.rule_lines());
        let mine = p(".env public!\n");
        let edited = p(&acc.with_edit(&theirs, &mine));
        assert!(edited.same_rules(&p("fixtures/ public!\n")), "the removed rule goes: {:?}", edited.rule_lines());
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
