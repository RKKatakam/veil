//! Access lines of `.veilpolicy` and a viewer's decisions
//! (`docs/VISIBILITY.md`; `docs/HUB.md` §5).
//!
//! ```text
//! src/          public
//! billing/      finance
//! infra/        ops carol
//! ```
//!
//! * An **access line** is a path from the project root, then `public`
//!   and/or the names of groups or people. `public!` counts as `public`.
//! * Paths are **literal folder or file paths**: a rule for `billing/`
//!   covers `billing` and everything below it. A line whose pattern uses
//!   glob syntax grants nothing on the server (it may still be a tier rule
//!   for the device); [`AccessPolicy::warnings`] says so.
//! * **The last matching line decides.** A path no line matches is
//!   private: only admins see it. The project root itself is never matched,
//!   so only admins see all of it.
//! * **Folder access means read and write.** `public` is read-only: anyone
//!   may read, and only the groups and people the line names (and admins)
//!   may write.
//! * Other lines of the file (`cloak`, `isolate`, `ignore`, …) are about
//!   the device and grant nothing on the server.

use crate::policy::{has_glob_syntax, split_fields, valid_principal_name};

/// One access line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRule {
    /// Normalised path: no leading or trailing `/`, never empty.
    pub path: String,
    /// Everyone may read.
    pub public: bool,
    /// The groups or people the line names, in order.
    pub names: Vec<String>,
    /// 1-based line number in `.veilpolicy`.
    pub line: usize,
}

impl AccessRule {
    /// Does this rule cover `path` (the path itself, or anything below it)?
    pub fn covers(&self, path: &str) -> bool {
        covers(&self.path, path)
    }
}

/// Does a rule for `rule` cover `path`?
pub fn covers(rule: &str, path: &str) -> bool {
    path == rule || (path.len() > rule.len() && path.starts_with(rule) && path.as_bytes()[rule.len()] == b'/')
}

/// The access lines of one `.veilpolicy`, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessPolicy {
    pub rules: Vec<AccessRule>,
    /// Lines that look like access lines but grant nothing, with why.
    pub warnings: Vec<String>,
}

/// Normalise the pattern of an access line to a root-relative path, or say
/// why it cannot be one.
pub fn normalize_access_path(pattern: &str) -> Result<String, String> {
    if has_glob_syntax(pattern) {
        return Err(format!(
            "'{pattern}' is a pattern; access lines take a folder or file path, so it grants nothing on the server"
        ));
    }
    let p = crate::vpath::nfc(pattern.trim()).into_owned();
    let p = p.trim_matches('/');
    if p.is_empty() {
        return Err(format!("'{pattern}' names the project root; give a folder or file path"));
    }
    for part in p.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\0') {
            return Err(format!("'{pattern}' is not a valid path"));
        }
    }
    Ok(p.to_string())
}

impl AccessPolicy {
    /// The access lines of `text` (a `.veilpolicy`).
    pub fn parse(text: &str) -> AccessPolicy {
        let mut out = AccessPolicy::default();
        for (n, line) in text.lines().enumerate() {
            let fields = split_fields(line);
            if fields.len() < 2 {
                continue;
            }
            let grants = &fields[1..];
            let is_access = grants
                .iter()
                .all(|f| f == "public" || f == "public!" || valid_principal_name(f))
                // `public!` with names is not a line the device reads as access.
                && !(grants.len() > 1 && grants.iter().any(|f| f == "public!"));
            if !is_access {
                continue;
            }
            match normalize_access_path(&fields[0]) {
                Ok(path) => out.rules.push(AccessRule {
                    path,
                    public: grants.iter().any(|f| f == "public" || f == "public!"),
                    names: grants.iter().filter(|f| !f.starts_with("public")).cloned().collect(),
                    line: n + 1,
                }),
                Err(why) => out.warnings.push(format!(".veilpolicy:{}: {why}", n + 1)),
            }
        }
        out
    }

    /// The same access, ignoring comments, spacing and line numbers.
    pub fn same_rules(&self, other: &AccessPolicy) -> bool {
        self.rules.len() == other.rules.len()
            && self.rules.iter().zip(&other.rules).all(|(a, b)| a.path == b.path && a.public == b.public && a.names == b.names)
    }

    /// Index of the rule that decides `path` (the last that covers it).
    pub fn deciding(&self, path: &str) -> Option<usize> {
        let path = crate::vpath::nfc(path);
        self.rules.iter().rposition(|r| r.covers(&path))
    }

    /// Is there a rule for a path strictly below directory `dir` (`""` is
    /// the root)? Without one, everything below `dir` is decided like `dir`.
    pub fn rule_below(&self, dir: &str) -> bool {
        if dir.is_empty() {
            return !self.rules.is_empty();
        }
        let dir = crate::vpath::nfc(dir);
        self.rules
            .iter()
            .any(|r| r.path.len() > dir.len() && r.path.starts_with(&*dir) && r.path.as_bytes()[dir.len()] == b'/')
    }

    /// Every name the rules mention, once each.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in &self.rules {
            for n in &r.names {
                if !out.contains(n) {
                    out.push(n.clone());
                }
            }
        }
        out
    }
}

/// One viewer's access under one accepted policy: admin, a person, or
/// anyone on Earth (no person).
#[derive(Clone, Debug)]
pub struct View<'a> {
    pub policy: &'a AccessPolicy,
    pub admin: bool,
    /// Per rule: the rule lets this viewer read.
    read: Vec<bool>,
    /// Per rule: the rule lets this viewer write.
    write: Vec<bool>,
}

impl<'a> View<'a> {
    /// The view of someone for whom `is_me(rule, name)` says whether a name
    /// on rule `rule` is them or a group they are in (the server binds
    /// names when it accepts a policy).
    pub fn new(policy: &'a AccessPolicy, admin: bool, is_me: impl Fn(usize, &str) -> bool) -> View<'a> {
        let write: Vec<bool> = policy
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| r.names.iter().any(|n| is_me(i, n)))
            .collect();
        let read = policy.rules.iter().zip(&write).map(|(r, w)| r.public || *w).collect();
        View { policy, admin, read, write }
    }

    /// Anyone on Earth: `public` folders only.
    pub fn anonymous(policy: &'a AccessPolicy) -> View<'a> {
        View::new(policy, false, |_, _| false)
    }

    /// An admin: everything.
    pub fn admin(policy: &'a AccessPolicy) -> View<'a> {
        View::new(policy, true, |_, _| false)
    }

    /// May this viewer read `path` (a file, or a directory as a whole)?
    pub fn read(&self, path: &str) -> bool {
        self.admin || self.policy.deciding(path).is_some_and(|i| self.read[i])
    }

    /// May this viewer write `path`?
    pub fn write(&self, path: &str) -> bool {
        self.admin || self.policy.deciding(path).is_some_and(|i| self.write[i])
    }

    /// Is there a rule below directory `dir` (see [`AccessPolicy::rule_below`])?
    pub fn rule_below(&self, dir: &str) -> bool {
        !self.admin && self.policy.rule_below(dir)
    }

    /// Does this viewer see anything at all of the project?
    pub fn sees_anything(&self) -> bool {
        self.admin || self.read.iter().any(|r| *r)
    }

    /// A key that is equal for two viewers exactly when they read the same
    /// paths: projections are cached under it.
    pub fn key(&self) -> String {
        if self.admin {
            return "admin".into();
        }
        let mut h = blake3::Hasher::new_derive_key(crate::crypto::domains::HUB_VIEW_KEY);
        for (r, read) in self.policy.rules.iter().zip(&self.read) {
            h.update(&(r.path.len() as u64).to_le_bytes());
            h.update(r.path.as_bytes());
            h.update(&[*read as u8]);
        }
        h.finalize().to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "\
# comment
target/        ignore
.env           cloak team
src/           public devs
src/secret/    security
billing/       finance
infra/         ops carol
docs/*.md      public
/notes.txt     carol   # a file
";

    #[test]
    fn parses_access_lines_only() {
        let p = AccessPolicy::parse(POLICY);
        let paths: Vec<&str> = p.rules.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["src", "src/secret", "billing", "infra", "notes.txt"]);
        assert!(p.rules[0].public && p.rules[0].names == ["devs"]);
        assert_eq!(p.rules[3].names, ["ops", "carol"]);
        assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
        assert!(p.warnings[0].contains("docs/*.md"));
    }

    #[test]
    fn last_matching_rule_decides() {
        let p = AccessPolicy::parse(POLICY);
        assert_eq!(p.deciding("src/a.rs"), Some(0));
        assert_eq!(p.deciding("src/secret/k"), Some(1));
        assert_eq!(p.deciding("src/secretive"), Some(0));
        assert_eq!(p.deciding("README"), None);
        assert_eq!(p.deciding(""), None);
        // Order matters: a later broader rule wins.
        let q = AccessPolicy::parse("src/secret/ security\nsrc/ public\n");
        assert_eq!(q.deciding("src/secret/k"), Some(1));
    }

    #[test]
    fn views() {
        let p = AccessPolicy::parse(POLICY);
        let anon = View::anonymous(&p);
        assert!(anon.read("src/a.rs") && !anon.write("src/a.rs"));
        assert!(!anon.read("src/secret/k") && !anon.read("billing/x") && !anon.read("README"));
        let fin = View::new(&p, false, |_, n| n == "finance");
        assert!(fin.read("billing/x") && fin.write("billing/x") && !fin.write("src/a.rs"));
        let carol = View::new(&p, false, |_, n| n == "carol");
        assert!(carol.write("infra/a") && carol.read("notes.txt") && !carol.read("notes.txt.bak"));
        let admin = View::admin(&p);
        assert!(admin.read("") && admin.write("anything"));
        assert_ne!(anon.key(), fin.key());
        assert_eq!(anon.key(), View::new(&p, false, |_, n| n == "nobody").key());
        assert!(p.rule_below("") && p.rule_below("src") && !p.rule_below("src/secret") && !p.rule_below("billing"));
    }

    #[test]
    fn hostile_paths_grant_nothing() {
        let p = AccessPolicy::parse("../x public\n/ public\n./a public\na//b public\nok/ public\n");
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.warnings.len(), 4);
    }
}
