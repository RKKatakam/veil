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
//! * **The defaults** (no file, or no `[review]`; BUG-1325): low risk
//!   needs one approval from someone other than the author, an agent's
//!   counting; normal and high one person's. Only paths the admins list as
//!   `checks_only` need none. **A file that does not parse** never weakens review:
//!   the state recorded at the last landing on the default branch applies
//!   (`state`: a file, its absence, or strict); with none, every risk needs
//!   one person's approval. Only admins are told why.
//! * **Risk** ([`classify`]): **high** if any file is `.veilpolicy`,
//!   `.veilrules`, `CODEOWNERS`, CI or container configuration (anywhere),
//!   a dependency manifest or lock file, a secret, under a
//!   `high_risk_paths` entry, or there are more than [`LARGE_FILES`]
//!   files; else **low** only by an allow-list (documentation under the
//!   top-level `docs/` and the root's `README`-like files; test source
//!   code in test folders outside `src/`, Go's `*_test.go`); everything
//!   else **normal**. Whitespace changes are rated like any other, and
//!   agent instructions are code. Comment-only changes are not detected
//!   (phase-4 open question 4).

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
    /// Paths the admins say need checks only (BUG-1325): `*` within a
    /// name, `**` for any folders, a trailing `/` for everything below.
    pub checks_only: Vec<String>,
    /// Why the file was not used as written, if it was not.
    pub warnings: Vec<String>,
    /// The file did not parse: these are the strict rules, or the state
    /// recorded at the last landing (`state::review_of`).
    pub broken: bool,
}

impl Default for Review {
    fn default() -> Self {
        Review {
            // Product decision 12 (as decided under the owner's delegation,
            // 2026-11-08, BUG-1325): low risk needs one approval from
            // someone other than the author, an agent's counting; normal
            // and high need a person's. Only the paths the admins list as
            // `checks_only` need none.
            low: Need { approvals: 1, people_only: false },
            normal: Need { approvals: 1, people_only: true },
            high: Need { approvals: 1, people_only: true },
            high_risk_paths: Vec::new(),
            checks_only: Vec::new(),
            warnings: Vec::new(),
            broken: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    /// Every file is under a path the admins list as `checks_only`.
    ChecksOnly,
    Low,
    Normal,
    High,
}

impl Risk {
    pub fn name(self) -> &'static str {
        match self {
            Risk::ChecksOnly => "checks-only",
            Risk::Low => "low",
            Risk::Normal => "normal",
            Risk::High => "high",
        }
    }

    pub fn parse(s: &str) -> Risk {
        match s {
            "checks-only" => Risk::ChecksOnly,
            "low" => Risk::Low,
            "normal" => Risk::Normal,
            _ => Risk::High,
        }
    }
}

impl Review {
    pub fn need(&self, risk: Risk) -> Need {
        match risk {
            Risk::ChecksOnly => Need { approvals: 0, people_only: false },
            Risk::Low => self.low,
            Risk::Normal => self.normal,
            Risk::High => self.high,
        }
    }

    /// Every risk needs one person's approval: what a file that does not
    /// parse gives when no earlier version of it did (the strictest of the
    /// defaults).
    pub fn strict(why: String) -> Review {
        let one = Need { approvals: 1, people_only: true };
        Review {
            low: one,
            normal: one,
            high: one,
            high_risk_paths: Vec::new(),
            checks_only: Vec::new(),
            warnings: vec![format!("{RULES_FILE}: {why}")],
            broken: true,
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
                "checks_only" => {
                    let Some(a) = item.as_array() else { return Review::strict("review.checks_only is not a list of paths".into()) };
                    for v in a.iter() {
                        match v.as_str().filter(|p| valid_glob(p)) {
                            Some(p) => out.checks_only.push(p.to_string()),
                            None => return Review::strict("review.checks_only: an entry is not a path pattern".into()),
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
    /// Executable on the new side, in any change.
    pub executable: bool,
    /// A regular file on every side, in every change (BUG-1324: never a
    /// link, a folder or a conflict).
    pub regular: bool,
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

/// Build and configuration files, whatever their name looks like: never
/// documentation or tests (BUG-1252).
fn is_build(path: &str) -> bool {
    let name = name_of(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    matches!(
        name,
        "CMakeLists.txt" | "Makefile" | "makefile" | "GNUmakefile" | "build.rs" | "setup.py" | "setup.cfg" | "conftest.py"
            | "Dockerfile" | "Containerfile" | "Justfile" | "justfile" | "Rakefile" | "BUILD" | "BUILD.bazel" | "WORKSPACE"
            | "MODULE.bazel" | "meson.build" | "meson_options.txt" | "Taskfile.yml" | "tox.ini" | "noxfile.py" | "Vagrantfile"
            | "conf.py" | "mkdocs.yml" | "book.toml" | ".envrc"
    ) || matches!(ext.as_str(), "cmake" | "mk" | "bzl" | "gradle" | "nix")
}

/// Documentation, an allow-list (BUG-1276): Markdown, reStructuredText,
/// AsciiDoc or an image under the top-level `docs/` folder (not inside a
/// dot-folder there, and not an agent's instructions), or `README*`,
/// `LICENSE*`, `CHANGELOG*`, `CONTRIBUTING*` at the project root with no
/// extension or a text one. Nothing else, wherever it sits.
fn is_docs(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let name = name_of(path);
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, e.to_ascii_lowercase()),
        _ => (name, String::new()),
    };
    if parts.len() == 1 {
        let upper = stem.to_ascii_uppercase();
        return ["README", "LICENSE", "LICENCE", "CHANGELOG", "CONTRIBUTING"].iter().any(|p| upper == *p || upper.starts_with(&format!("{p}-")) || upper.starts_with(&format!("{p}_")))
            && matches!(ext.as_str(), "" | "txt" | "md" | "markdown" | "rst" | "adoc");
    }
    parts[0] == "docs"
        && !parts[1..parts.len() - 1].iter().any(|d| d.starts_with('.'))
        && !name.starts_with('.')
        && !is_agent_instructions(path)
        && matches!(ext.as_str(), "md" | "markdown" | "rst" | "adoc" | "asciidoc" | "png" | "jpg" | "jpeg" | "gif" | "webp")
}

/// Instructions agents execute (`CLAUDE.md`, `AGENTS.md`, `.claude/`,
/// `SKILL.md`, …): code for agents, never documentation (owner, 2026-11-07,
/// BUG-1257).
fn is_agent_instructions(path: &str) -> bool {
    let name = name_of(path);
    let upper = name.to_ascii_uppercase();
    path.split('/').rev().skip(1).any(|c| matches!(c, ".claude" | ".cursor" | ".codex" | ".gemini" | ".windsurf" | ".aider" | ".agents"))
        || matches!(upper.as_str(), "CLAUDE.MD" | "AGENTS.MD" | "AGENT.MD" | "GEMINI.MD" | "SKILL.MD" | "COPILOT-INSTRUCTIONS.MD" | "CONVENTIONS.MD")
        || matches!(name, ".cursorrules" | ".windsurfrules" | ".clinerules" | ".aider.conf.yml")
}

/// Source code of a programming language (by extension): what a test may
/// be. Data, configuration, specifications and Markdown never are.
const SOURCE: &[&str] = &[
    "rs", "py", "js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts", "rb", "java", "kt", "scala", "swift", "c", "cc", "cpp", "cxx", "h",
    "hpp", "cs", "fs", "php", "ex", "exs", "erl", "hs", "ml", "lua", "dart", "zig", "nim", "jl", "r", "clj", "go",
];

/// Test source code, an allow-list (BUG-1277): a source file of a
/// programming language under a `tests`, `test` or `__tests__` folder that
/// is not inside `src/` (where a test module may be compiled into the
/// program), or a Go `*_test.go` (the Go compiler builds those for tests
/// only). Never anything under `spec/`, `testdata/` or `fixtures/`
/// (specifications and inputs the build may read), and a Go file under a
/// tests folder only if it is a `_test.go`.
fn is_test(path: &str) -> bool {
    let name = name_of(path);
    let dirs: Vec<&str> = path.split('/').collect();
    let dirs = &dirs[..dirs.len() - 1];
    if dirs.iter().any(|c| matches!(*c, "spec" | "specs" | "testdata" | "fixtures" | "fixture" | "data" | "snapshots")) {
        return false;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    if ext == "go" {
        return name.ends_with("_test.go");
    }
    let under_tests = dirs.iter().any(|c| matches!(*c, "test" | "tests" | "__tests__"));
    under_tests && !dirs.contains(&"src") && SOURCE.contains(&ext.as_str())
}

/// CI and container configuration, anywhere (BUG-1257): run by the CI on
/// every push, with its secrets.
fn is_ci(path: &str) -> bool {
    let name = name_of(path);
    let first = path.split('/').next().unwrap_or(path);
    matches!(first, ".ci" | ".github" | ".gitlab" | ".circleci" | ".buildkite" | ".woodpecker" | ".forgejo" | ".gitea" | ".azure-pipelines")
        || path.split('/').any(|c| matches!(c, ".github" | ".circleci" | ".buildkite" | ".woodpecker"))
        || name.starts_with(".gitlab-ci")
        || name.starts_with("docker-compose")
        || ((name.starts_with("compose.") || name.starts_with("compose-")) && (name.ends_with(".yml") || name.ends_with(".yaml")))
        || matches!(
            name,
            "Jenkinsfile" | ".travis.yml" | "azure-pipelines.yml" | "azure-pipelines.yaml" | "bitbucket-pipelines.yml" | ".drone.yml" | "appveyor.yml"
                | ".appveyor.yml" | "cloudbuild.yaml" | "cloudbuild.yml" | ".cirrus.yml" | "buildspec.yml" | "codemagic.yaml"
        )
}

/// A `checks_only` pattern: `/`-separated names, `*` within a name, `**`
/// as a whole name for any folders; a trailing `/` stands for `/**`. No
/// empty, `.` or `..` names.
fn valid_glob(p: &str) -> bool {
    let p = p.strip_suffix('/').unwrap_or(p);
    !p.is_empty() && p.len() <= 1024 && p.split('/').all(|n| !n.is_empty() && n != "." && n != ".." && (n == "**" || !n.contains("**")))
}

/// Does `path` match pattern `p` (see `valid_glob`)?
pub fn glob_matches(p: &str, path: &str) -> bool {
    let p = match p.strip_suffix('/') {
        Some(d) => format!("{d}/**"),
        None => p.to_string(),
    };
    let pat: Vec<&str> = p.split('/').collect();
    let names: Vec<&str> = path.split('/').collect();
    fn name_matches(p: &str, n: &str) -> bool {
        // `*` matches any run of characters within one name.
        let parts: Vec<&str> = p.split('*').collect();
        if parts.len() == 1 {
            return p == n;
        }
        let (first, last) = (parts[0], parts[parts.len() - 1]);
        if !n.starts_with(first) || n.len() < first.len() + last.len() || !n.ends_with(last) {
            return false;
        }
        let mut rest = &n[first.len()..n.len() - last.len()];
        for mid in &parts[1..parts.len() - 1] {
            match rest.find(mid) {
                Some(i) => rest = &rest[i + mid.len()..],
                None => return false,
            }
        }
        true
    }
    fn go(pat: &[&str], names: &[&str]) -> bool {
        match pat.first() {
            None => names.is_empty(),
            // A trailing `**` is everything below: at least one name.
            Some(&"**") if pat.len() == 1 => !names.is_empty(),
            Some(&"**") => (0..=names.len()).any(|k| go(&pat[1..], &names[k..])),
            Some(p) => !names.is_empty() && name_matches(p, names[0]) && go(&pat[1..], &names[1..]),
        }
    }
    go(&pat, &names)
}

/// Why `f` makes a revision high risk, if it does.
fn high_reason(f: &FileChange, rules: &Review) -> Option<String> {
    let p = f.path.as_str();
    if p == ".veilpolicy" || p == RULES_FILE || name_of(p) == "CODEOWNERS" {
        return Some(format!("changes {p}"));
    }
    if is_ci(p) {
        return Some(format!("changes CI or container configuration ({p})"));
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
    // Low, an allow-list: every file documentation or test source code;
    // never a build file, agent instructions or anything executable.
    // Everything else is normal. Whitespace changes are rated like any
    // other (BUG-1256: they change what scripts do).
    // Only regular, non-executable files are ever below normal (BUG-1324:
    // a link is rated by what it points at, which the name does not say).
    let plain = |f: &FileChange| f.regular && !f.executable;
    if files.iter().all(|f| plain(f) && rules.checks_only.iter().any(|p| glob_matches(p, &f.path))) {
        return (Risk::ChecksOnly, vec!["only paths the admins list as checks_only".into()]);
    }
    let low = |f: &FileChange| plain(f) && !is_build(&f.path) && !is_agent_instructions(&f.path) && (is_docs(&f.path) || is_test(&f.path));
    if files.iter().all(low) {
        return (Risk::Low, vec!["only documentation or tests".into()]);
    }
    (Risk::Normal, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: &str) -> FileChange {
        FileChange { path: p.into(), secret: false, executable: false, regular: true }
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
        assert_eq!(classify(&[f("docs/guide.md"), f("tests/a.rs"), f("README")], &rules).0, Risk::Low);
        assert_eq!(classify(&[f("pkg/lib_test.go"), f("web/__tests__/a.ts"), f("tests/x.rs"), f("crates/vl/tests/cli.rs")], &rules).0, Risk::Low);
        assert_eq!(classify(&[f("src/lib.rs"), f("docs/a.md")], &rules).0, Risk::Normal);
        // BUG-1257: names alone, and test folders inside src/, are code.
        for p in ["src/tests/a.rs", "web/a.test.ts", "pub/src/test_mode.rs", "lib/test_utils.py", "a.spec.js", "src/__tests__/a.ts"] {
            assert_eq!(classify(&[f(p)], &rules).0, Risk::Normal, "{p}");
        }
        // Agent instructions are code for agents.
        for p in ["CLAUDE.md", "AGENTS.md", ".claude/skills/review/SKILL.md", "tools/SKILL.md", ".claude/settings.json", "docs/.cursor/rules.md", ".cursorrules"] {
            assert_eq!(classify(&[f(p)], &rules).0, Risk::Normal, "{p}");
        }
        for p in [
            ".veilpolicy", ".veilrules", ".ci/build.yml", "web/package.json", "Cargo.lock", "src/auth/login.rs", "src/auth",
            ".github/workflows/integration_test.yml", ".github/workflows/test_release.yml", "tests/.github/workflows/a.yml", ".gitlab-ci.yml",
            ".circleci/config.yml", "Jenkinsfile", "docker-compose.test.yml", "deploy/compose.yaml", ".travis.yml", "azure-pipelines.yml",
        ] {
            assert_eq!(classify(&[f(p), f("docs/a.md")], &rules).0, Risk::High, "{p}");
        }
        assert_eq!(classify(&[f("src/authx.rs")], &rules).0, Risk::Normal);
        // BUG-1252: build inputs that look like documentation or tests.
        for p in ["pub/CMakeLists.txt", "notes.txt", "docs/conf.py", "docs/Makefile", "tests/CMakeLists.txt", "tests/build.rs", "README.sh", "docs/x.svg", "cmake/x.cmake"] {
            assert_eq!(classify(&[f(p)], &rules).0, Risk::Normal, "{p}");
        }
        for p in ["README", "LICENSE.txt", "docs/a.rst", "docs/img/a.png", "CHANGELOG.md"] {
            assert_eq!(classify(&[f(p)], &rules).0, Risk::Low, "{p}");
        }
        let exe = FileChange { executable: true, ..f("tests/run.md") };
        assert_eq!(classify(&[exe], &rules).0, Risk::Normal, "an executable file is never documentation");
        let secret = FileChange { secret: true, ..f("docs/.env") };
        assert_eq!(classify(&[secret], &rules).0, Risk::High);
        let many: Vec<FileChange> = (0..=LARGE_FILES).map(|i| f(&format!("docs/{i}.md"))).collect();
        assert_eq!(classify(&many, &rules).0, Risk::High);
    }

    /// The allow-list against a corpus of real layouts (BUG-1276, 1277):
    /// low is only documentation under the top-level `docs/`, the root's
    /// README-like files, and test source code in test folders.
    #[test]
    fn low_is_an_allow_list() {
        let rules = Review::default();
        let low = [
            "README", "README.md", "LICENSE", "LICENSE.txt", "LICENSE-MIT", "CHANGELOG.md", "CONTRIBUTING.md", "docs/guide.md", "docs/a/b.rst",
            "docs/book.adoc", "docs/img/a.png", "docs/_static/logo.png", "tests/cli.rs", "tests/test_api.py", "test/user_test.rb",
            "web/__tests__/a.ts", "crates/vl/tests/cli_security.rs", "crates/x/tests/common/mod.rs", "pkg/auth/auth_test.go",
            "internal/x/x_linux_test.go", "tests/unit/a.spec.ts",
        ];
        let normal = [
            // Markdown agents execute or programs include.
            "skills/deploy/reference.md", "skills/deploy/SKILL.md", "plugins/ops/commands/release.md", "plugins/ops/agents/reviewer.md",
            ".clinerules/security.md", ".roo/rules/deploy.md", ".kiro/steering/tech.md", ".junie/guidelines.md", "AGENTS.override.md",
            "app/src/prompts/system.md", "prompts/system.md", "CLAUDE.md", "docs/CLAUDE.md", "docs/SKILL.md", "docs/.vitepress/x.md",
            "docs/.claude/commands/ship.md", "sub/README.md", "crates/x/README.md", "book/src/intro.md", "notes.md", "README.sh",
            // Build inputs in test-named folders.
            "api/spec/openapi.yaml", "spec/openapi.json", "spec/models/user_spec.rb", "internal/assets/testdata/default_policy.json",
            "crates/server/tests/fixtures/default.toml", "tests/fixtures/a.rs", "tests/data/x.csv", "tests/snapshots/x.snap",
            "testdata/x_test.go", "tests/a.json", "tests/a.yaml", "tests/a.md", "tests/helpers.sh", "tests/pkg/main.go",
            // Test configuration, build scripts, sources.
            "tests/conftest.py", "build.rs", "tests/build.rs", "tests/Makefile", "tests/CMakeLists.txt", "benches/scale.rs", "examples/a.rs",
            "src/tests/a.rs", "crates/x/src/tests.rs", "packages/web/src/__tests__/login.ts", "pub/src/test_mode.rs", "lib/test_utils.py",
            "a.test.ts", "docs/conf.py", "docs/index.html", "docs/x.svg", "notes.txt", "pub/CMakeLists.txt",
        ];
        let high = ["CODEOWNERS", "docs/CODEOWNERS", ".github/CODEOWNERS", "tests/package.json", "tests/Cargo.toml", "tests/docker-compose.yml"];
        for (want, paths) in [(Risk::Low, &low[..]), (Risk::Normal, &normal[..]), (Risk::High, &high[..])] {
            for p in paths {
                assert_eq!(classify(&[f(p)], &rules).0, want, "{p}");
            }
        }
        let exe = FileChange { executable: true, ..f("tests/run.py") };
        assert_eq!(classify(&[exe], &rules).0, Risk::Normal);
    }

    /// BUG-1324, BUG-1325: links are never below normal; `checks_only`
    /// paths (admins') need checks only; the defaults' low needs one
    /// approval, an agent's counting, and normal a person's.
    #[test]
    fn checks_only_links_and_the_defaults() {
        let d = Review::default();
        assert_eq!(d.need(Risk::Low), Need { approvals: 1, people_only: false });
        assert_eq!(d.need(Risk::Normal), Need { approvals: 1, people_only: true });
        assert_eq!(d.need(Risk::ChecksOnly), Need { approvals: 0, people_only: false });
        for p in ["docs/env.md", "README.md", "tests/x.rs"] {
            let link = FileChange { regular: false, ..f(p) };
            assert_eq!(classify(&[link], &d).0, Risk::Normal, "a link at {p}");
        }
        let r = Review::parse(Some(b"[review]\nchecks_only = [\"docs/**\", \"CHANGELOG.md\", \"site/*.md\", \"assets/\"]\n"));
        assert!(!r.broken, "{r:?}");
        for p in ["docs/a.md", "docs/a/b/c.png", "CHANGELOG.md", "site/x.md", "assets/a/b.svg"] {
            assert_eq!(classify(&[f(p)], &r).0, Risk::ChecksOnly, "{p}");
        }
        for p in ["docs", "site/a/x.md", "site/x.mdx", "src/docs/a.md", "CHANGELOG.md.sh"] {
            assert_ne!(classify(&[f(p)], &r).0, Risk::ChecksOnly, "{p}");
        }
        // High wins; one file outside makes it the next class down.
        assert_eq!(classify(&[f("docs/a.md"), f(".github/CODEOWNERS")], &r).0, Risk::High);
        assert_eq!(classify(&[f("docs/a.md"), f("src/a.rs")], &r).0, Risk::Normal);
        let exe = FileChange { executable: true, ..f("docs/run.md") };
        assert_eq!(classify(&[exe], &r).0, Risk::Normal);
        for bad in [&b"[review]\nchecks_only = [\"../x\"]\n"[..], b"[review]\nchecks_only = [\"a/**b\"]\n", b"[review]\nchecks_only = \"docs\"\n", b"[review]\nchecks_only = [\"\"]\n"] {
            assert!(Review::parse(Some(bad)).broken, "{}", String::from_utf8_lossy(bad));
        }
        assert!(glob_matches("**", "a/b") && glob_matches("a/**/z.md", "a/z.md") && glob_matches("a/**/z.md", "a/b/c/z.md") && !glob_matches("a/*", "a/b/c"));
    }
}
