//! The `[review]` section of `.veilrules`, and a revision's risk
//! (phase-4 design §4.9; product decisions 12 and 14).
//!
//! ```toml
//! [review]
//! low = { approvals = 0 }
//! normal = { approvals = 1 }
//! high = { approvals = 1, people_only = true }
//! high_risk_paths = ["src/auth/", "infra/"]
//! ```
//!
//! * **Only this section is read here.** The landing service (S17) reads
//!   `[branches.…]` with its own parser; neither reads the other's keys.
//! * **Where it is read from:** `.veilrules` at the root of the default
//!   branch's tip, the real tree. The file is changed like any file at the
//!   root: by admins (nobody else may write a path no access line names),
//!   and S17's push check refuses anyone but an admin whatever the lines.
//! * **The defaults** (no file, or no `[review]`): low risk needs no
//!   approval, normal one, high one from a person (an agent's never counts
//!   for high risk). **A file that does not parse** never weakens review:
//!   every risk then needs one person's approval, and every answer says
//!   why.
//! * **Risk** ([`classify`]): **high** if any file is `.veilpolicy`,
//!   `.veilrules`, under `.ci/`, a dependency manifest or lock file, a
//!   secret, under a `high_risk_paths` entry, or there are more than
//!   [`LARGE_FILES`] files; else **low** if every file is documentation or
//!   tests, or changed only whitespace; else **normal**. Comment-only
//!   changes are not detected (phase-4 open question 4).

use veil_core::hub::access::{covers, normalize_access_path};

pub const RULES_FILE: &str = ".veilrules";

/// More files than this make a revision high risk.
pub const LARGE_FILES: usize = 1_000;

/// The most approvals a rule may ask for.
pub const MAX_APPROVALS: i64 = 10;

/// What one risk needs before the PR may land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Need {
    pub approvals: u32,
    /// Only people's approvals count, never an agent session's.
    pub people_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    pub low: Need,
    pub normal: Need,
    pub high: Need,
    pub high_risk_paths: Vec<String>,
    /// Why the file was not used as written, if it was not.
    pub warnings: Vec<String>,
}

impl Default for Review {
    fn default() -> Self {
        Review {
            low: Need { approvals: 0, people_only: false },
            normal: Need { approvals: 1, people_only: false },
            high: Need { approvals: 1, people_only: true },
            high_risk_paths: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Low,
    Normal,
    High,
}

impl Risk {
    pub fn name(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Normal => "normal",
            Risk::High => "high",
        }
    }

    pub fn parse(s: &str) -> Risk {
        match s {
            "low" => Risk::Low,
            "normal" => Risk::Normal,
            _ => Risk::High,
        }
    }
}

impl Review {
    pub fn need(&self, risk: Risk) -> Need {
        match risk {
            Risk::Low => self.low,
            Risk::Normal => self.normal,
            Risk::High => self.high,
        }
    }

    /// Every risk needs one person's approval: what a file that does not
    /// parse gives.
    fn strict(why: String) -> Review {
        let one = Need { approvals: 1, people_only: true };
        Review {
            low: one,
            normal: one,
            high: one,
            high_risk_paths: Vec::new(),
            warnings: vec![format!("{RULES_FILE}: {why}; until it is fixed, every PR needs one person's approval")],
        }
    }

    /// The `[review]` section of a `.veilrules`; [`Review::default`] for
    /// `None` (no file).
    pub fn parse(text: Option<&[u8]>) -> Review {
        let Some(bytes) = text else { return Review::default() };
        let Ok(text) = std::str::from_utf8(bytes) else { return Review::strict("not UTF-8".into()) };
        let doc = match text.parse::<toml_edit::DocumentMut>() {
            Ok(d) => d,
            Err(e) => return Review::strict(format!("not valid TOML ({})", e.message())),
        };
        let mut out = Review::default();
        let Some(review) = doc.get("review") else { return out };
        let Some(t) = review.as_table_like() else { return Review::strict("[review] is not a table".into()) };
        for (key, item) in t.iter() {
            match key {
                "low" | "normal" | "high" => {
                    let Some(n) = item.as_table_like() else {
                        return Review::strict(format!("review.{key} is not a table like {{ approvals = 1 }}"));
                    };
                    let mut need = out.need(Risk::parse(key));
                    for (k, v) in n.iter() {
                        match (k, v.as_integer(), v.as_bool()) {
                            ("approvals", Some(a), _) if (0..=MAX_APPROVALS).contains(&a) => need.approvals = a as u32,
                            ("people_only", _, Some(b)) => need.people_only = b,
                            _ => return Review::strict(format!("review.{key}.{k}: expected approvals = 0..={MAX_APPROVALS} or people_only = true|false")),
                        }
                    }
                    // Agents' approvals never count for high risk
                    // (product decision 12), whatever the file says.
                    if key == "high" {
                        need.people_only = true;
                    }
                    match key {
                        "low" => out.low = need,
                        "normal" => out.normal = need,
                        _ => out.high = need,
                    }
                }
                "high_risk_paths" => {
                    let Some(a) = item.as_array() else { return Review::strict("review.high_risk_paths is not a list of paths".into()) };
                    for v in a.iter() {
                        let p = v.as_str().map(normalize_access_path);
                        match p {
                            Some(Ok(p)) => out.high_risk_paths.push(p),
                            _ => return Review::strict(format!("review.high_risk_paths: {} is not a folder or file path", v.as_str().map_or("an entry that is not a string".to_string(), |s| format!("{s:?}")))),
                        }
                    }
                }
                // Keys of later milestones are not this parser's to judge.
                other => out.warnings.push(format!("{RULES_FILE}: review.{other} is not a review rule; ignored")),
            }
        }
        out
    }
}

/// One changed file of a revision, as risk sees it.
#[derive(Clone, Debug)]
pub struct FileChange {
    pub path: String,
    /// A secret (sealed) on either side.
    pub secret: bool,
    /// Both sides are text that differ only in whitespace.
    pub whitespace_only: bool,
}

const MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "uv.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "flake.lock",
    "Package.resolved",
    "mix.lock",
];

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_docs(path: &str) -> bool {
    let name = name_of(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    let upper = name.to_ascii_uppercase();
    path.split('/').rev().skip(1).any(|c| c == "docs" || c == "doc")
        || matches!(ext.as_str(), "md" | "markdown" | "rst" | "adoc" | "txt")
        || ["README", "LICENSE", "CHANGELOG", "CONTRIBUTING", "AUTHORS", "NOTICE"].iter().any(|p| upper.starts_with(p))
}

fn is_test(path: &str) -> bool {
    let name = name_of(path);
    let stem = name.split('.').next().unwrap_or(name);
    path.split('/').rev().skip(1).any(|c| matches!(c, "test" | "tests" | "__tests__" | "spec" | "testdata"))
        || stem.ends_with("_test")
        || stem.starts_with("test_")
        || name.contains(".test.")
        || name.contains(".spec.")
}

/// Why `f` makes a revision high risk, if it does.
fn high_reason(f: &FileChange, rules: &Review) -> Option<String> {
    let p = f.path.as_str();
    if p == ".veilpolicy" || p == RULES_FILE {
        return Some(format!("changes {p}"));
    }
    if covers(".ci", p) {
        return Some(format!("changes CI configuration ({p})"));
    }
    if MANIFESTS.contains(&name_of(p)) {
        return Some(format!("changes a dependency manifest or lock file ({p})"));
    }
    if f.secret {
        return Some(format!("changes a secret ({p})"));
    }
    if let Some(h) = rules.high_risk_paths.iter().find(|h| covers(h, p)) {
        return Some(format!("changes {p}, under {h}/ (high_risk_paths)"));
    }
    None
}

/// A revision's risk from its files (every change's, together), and why.
pub fn classify(files: &[FileChange], rules: &Review) -> (Risk, Vec<String>) {
    let mut high: Vec<String> = files.iter().filter_map(|f| high_reason(f, rules)).collect();
    if files.len() > LARGE_FILES {
        high.push(format!("changes {} files (more than {LARGE_FILES})", files.len()));
    }
    if !high.is_empty() {
        high.truncate(20);
        return (Risk::High, high);
    }
    if files.iter().all(|f| is_docs(&f.path) || is_test(&f.path) || f.whitespace_only) {
        return (Risk::Low, vec!["only documentation, tests or whitespace".into()]);
    }
    (Risk::Normal, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: &str) -> FileChange {
        FileChange { path: p.into(), secret: false, whitespace_only: false }
    }

    #[test]
    fn defaults_and_parsing() {
        assert_eq!(Review::parse(None), Review::default());
        let r = Review::parse(Some(b"[branches.main]\nprotected = true\n"));
        assert_eq!(r, Review::default(), "S17's keys are not ours");
        let r = Review::parse(Some(
            b"[review]\nlow = { approvals = 1 }\nnormal = { approvals = 2, people_only = true }\nhigh = { approvals = 3, people_only = false }\nhigh_risk_paths = [\"src/auth/\", \"infra\"]\n",
        ));
        assert_eq!(r.low, Need { approvals: 1, people_only: false });
        assert_eq!(r.normal, Need { approvals: 2, people_only: true });
        // Agents never count for high risk, whatever the file says.
        assert_eq!(r.high, Need { approvals: 3, people_only: true });
        assert_eq!(r.high_risk_paths, vec!["src/auth".to_string(), "infra".to_string()]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_broken_file_never_weakens_review() {
        for bad in [
            &b"[review\nlow = 0"[..],
            b"[review]\nlow = { approvals = -1 }\n",
            b"[review]\nlow = { approvals = 11 }\n",
            b"[review]\nlow = 0\n",
            b"[review]\nhigh_risk_paths = [\"../x\"]\n",
            b"[review]\nhigh_risk_paths = [\"src/*\"]\n",
            b"\xff\xfe",
            b"review = 3\n",
        ] {
            let r = Review::parse(Some(bad));
            for risk in [Risk::Low, Risk::Normal, Risk::High] {
                assert_eq!(r.need(risk), Need { approvals: 1, people_only: true }, "{:?}", String::from_utf8_lossy(bad));
            }
            assert_eq!(r.warnings.len(), 1);
        }
    }

    #[test]
    fn risk() {
        let rules = Review::parse(Some(b"[review]\nhigh_risk_paths = [\"src/auth/\"]\n"));
        assert_eq!(classify(&[f("docs/guide.md"), f("src/tests/a.rs"), f("README")], &rules).0, Risk::Low);
        assert_eq!(classify(&[f("src/lib_test.go"), f("web/a.test.ts"), f("tests/x.rs")], &rules).0, Risk::Low);
        assert_eq!(classify(&[f("src/lib.rs"), f("docs/a.md")], &rules).0, Risk::Normal);
        let ws = FileChange { whitespace_only: true, ..f("src/lib.rs") };
        assert_eq!(classify(&[ws], &rules).0, Risk::Low);
        for p in [".veilpolicy", ".veilrules", ".ci/build.yml", "web/package.json", "Cargo.lock", "src/auth/login.rs", "src/auth"] {
            assert_eq!(classify(&[f(p), f("docs/a.md")], &rules).0, Risk::High, "{p}");
        }
        assert_eq!(classify(&[f("src/authx.rs")], &rules).0, Risk::Normal);
        let secret = FileChange { secret: true, ..f("docs/.env") };
        assert_eq!(classify(&[secret], &rules).0, Risk::High);
        let many: Vec<FileChange> = (0..=LARGE_FILES).map(|i| f(&format!("docs/{i}.md"))).collect();
        assert_eq!(classify(&many, &rules).0, Risk::High);
    }
}
