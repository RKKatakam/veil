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
    let t = match tier {
        Tier::Public if force => "public!".to_string(),
        Tier::Public => "public".to_string(),
        Tier::Cloaked(s) => format!("cloak {s}"),
        Tier::Isolated => "isolate".to_string(),
        Tier::Ignored => "ignore".to_string(),
    };
    format!("{pattern:<24} {t}")
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
}

#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    set: GlobSet,
    pub warnings: Vec<String>,
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

    pub fn classify(&self, path: &VPath, is_dir: bool) -> Classification {
        let mut c = Classification {
            tier: Tier::Public,
            allow_secrets: false,
            rule: None,
            builtin_secret: false,
            blocked_exposure: false,
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
