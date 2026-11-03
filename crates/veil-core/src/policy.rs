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
//! **Engine-enforced defaults** come first and cannot be weakened by a plain
//! `public` rule: `.env`, `*.pem`, private SSH keys, … are `isolated` — they
//! never enter the snapshot graph. They *may* be `cloak`ed (encrypted for a
//! team) or deliberately published with `public!`.

use globset::{GlobBuilder, GlobMatcher};

use crate::{error::Result, vfs::StorageBackend, vpath::VPath};

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

impl Rule {
    fn new(pattern: &str, tier: Tier, force: bool, builtin: bool, secret: bool) -> Result<Rule, String> {
        let mut p = pattern.trim().to_string();
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
        let s = path.as_str();
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
            rules,
            warnings: vec![],
        }
    }

    pub fn parse(text: &str) -> Policy {
        let mut policy = Self::builtin();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                policy.warnings.push(format!("{POLICY_FILE}:{}: expected '<pattern> <tier>'", n + 1));
                continue;
            }
            let (tier, force) = match parts[1] {
                "public" => (Tier::Public, false),
                "public!" => (Tier::Public, true),
                "cloak" | "cloaked" => (
                    Tier::Cloaked(parts.get(2).copied().unwrap_or(DEFAULT_SCOPE).to_string()),
                    false,
                ),
                "isolate" | "isolated" | "local" => (Tier::Isolated, false),
                "ignore" | "ignored" => (Tier::Ignored, false),
                other => {
                    policy
                        .warnings
                        .push(format!("{POLICY_FILE}:{}: unknown tier '{other}'", n + 1));
                    continue;
                }
            };
            match Rule::new(parts[0], tier, force, false, false) {
                Ok(r) => policy.rules.push(r),
                Err(e) => policy.warnings.push(format!("{POLICY_FILE}:{}: {e}", n + 1)),
            }
        }
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
        for r in &self.rules {
            if !r.matches(path, is_dir) {
                continue;
            }
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
}
