//! Branch rules: the `.veilrules` file at the project root
//! (`docs/design/server/phase-4-agent-scale.md` §4.6, §4.9; product
//! decision 7). S17 reads one rule:
//!
//! ```toml
//! [branches.main]
//! protected = true
//! ```
//!
//! A protected branch is moved only by the landing service (and by an
//! admin's `vl push --force`). The file is tracked like any other, and only
//! admins change it, on any branch (`sync::complete`), so the default
//! branch's current `.veilrules` is the accepted one. Other tables
//! (`[review]`, `[checks]`, later milestones') are left for them; an unknown
//! key under `[branches.NAME]` is refused, so a misspelt `protected` never
//! leaves a branch open silently.

use std::collections::{BTreeMap, BTreeSet};

/// The file's name, at the project root.
pub const RULES_FILE: &str = ".veilrules";

/// The branch and check rules of a project.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    /// The protected branches.
    pub protected: BTreeSet<String>,
    /// Protected branches where automatic revert is disabled (`auto_revert = false`).
    pub no_auto_revert: BTreeSet<String>,
    /// Whether `[branches] delete_merged = false` disables automatic deletion of
    /// a PR's merged source branch when the PR lands (`BUG-1885`).
    pub keep_merged_branches: bool,
    /// Branch → the check names that must pass before `<branch>@tested`
    /// moves to a tip (`[branches.<name>] required_checks = [...]`).
    pub required_checks: BTreeMap<String, Vec<String>>,
    /// Check name → the paths its runner reads (`[checks.<name>] paths = [...]`),
    /// normalised with [`veil_core::hub::agent::normalize_only`].
    pub checks: BTreeMap<String, Vec<String>>,
    /// Check name → number of parallel bisect probes (`[checks.<name>] parallel = k`, 1..=8).
    pub check_parallel: BTreeMap<String, usize>,
}

impl Rules {
    /// Does `branch` allow automatic revert of a confirmed culprit?
    /// True when `branch` is protected and `auto_revert` is not set to `false`
    /// (product decision 11).
    pub fn allows_auto_revert(&self, branch: &str) -> bool {
        self.protected.contains(branch) && !self.no_auto_revert.contains(branch)
    }

    /// Should landing a PR delete its merged source branch (`[branches] delete_merged`, default `true`)?
    pub fn delete_merged(&self) -> bool {
        !self.keep_merged_branches
    }

    /// Parse `.veilrules`; the error says what is wrong (never echoing more
    /// than the key it names).
    pub fn parse(text: &str) -> Result<Rules, String> {
        let doc = text.parse::<toml_edit::DocumentMut>().map_err(|e| format!("{RULES_FILE} is not valid TOML: {}", e.message()))?;
        let mut out = Rules::default();
        if let Some(branches) = doc.get("branches") {
            let branches = branches.as_table_like().ok_or_else(|| format!("{RULES_FILE}: `branches` must be a table"))?;
            for (name, rules) in branches.iter() {
                if name == "delete_merged" && rules.as_table_like().is_none() {
                    match rules.as_bool() {
                        Some(b) => out.keep_merged_branches = !b,
                        None => return Err(format!("{RULES_FILE}: `branches.delete_merged` is true or false")),
                    }
                    continue;
                }
                veil_core::commands::validate_tag_name(name).map_err(|_| format!("{RULES_FILE}: {name:?} is not a branch name"))?;
                let rules = rules.as_table_like().ok_or_else(|| format!("{RULES_FILE}: `branches.{name}` must be a table"))?;
                for (key, value) in rules.iter() {
                    match key {
                        "protected" => match value.as_bool() {
                            Some(true) => {
                                out.protected.insert(name.to_string());
                            }
                            Some(false) => {}
                            None => return Err(format!("{RULES_FILE}: `branches.{name}.protected` is true or false")),
                        },
                        "auto_revert" | "revert" => match value.as_bool() {
                            Some(true) => {
                                out.no_auto_revert.remove(name);
                            }
                            Some(false) => {
                                out.no_auto_revert.insert(name.to_string());
                            }
                            None => return Err(format!("{RULES_FILE}: `branches.{name}.{key}` is true or false")),
                        },
                        "required_checks" => {
                            let arr = value
                                .as_array()
                                .ok_or_else(|| format!("{RULES_FILE}: `branches.{name}.required_checks` must be a list of check names"))?;
                            if arr.len() > veil_core::hub::ci::MAX_CHECKS_PER_SNAPSHOT {
                                return Err(format!(
                                    "{RULES_FILE}: `branches.{name}.required_checks` has at most {} checks",
                                    veil_core::hub::ci::MAX_CHECKS_PER_SNAPSHOT
                                ));
                            }
                            let mut names = Vec::with_capacity(arr.len());
                            for item in arr.iter() {
                                let Some(s) = item.as_str() else {
                                    return Err(format!("{RULES_FILE}: `branches.{name}.required_checks` must contain strings"));
                                };
                                veil_core::hub::ci::validate_check_name(s).map_err(|e| format!("{RULES_FILE}: `branches.{name}.required_checks`: {e}"))?;
                                if !names.iter().any(|x| x == s) {
                                    names.push(s.to_string());
                                }
                            }
                            if !names.is_empty() {
                                out.required_checks.insert(name.to_string(), names);
                            }
                        }
                        _ => return Err(format!("{RULES_FILE}: unknown rule `branches.{name}.{key}` (known: protected, required_checks, auto_revert)")),
                    }
                }
            }
        }
        if let Some(checks) = doc.get("checks") {
            let checks = checks.as_table_like().ok_or_else(|| format!("{RULES_FILE}: `checks` must be a table"))?;
            for (name, spec) in checks.iter() {
                veil_core::hub::ci::validate_check_name(name).map_err(|e| format!("{RULES_FILE}: check {name:?}: {e}"))?;
                let spec = spec.as_table_like().ok_or_else(|| format!("{RULES_FILE}: `checks.{name}` must be a table"))?;
                for (key, value) in spec.iter() {
                    match key {
                        "paths" => {
                            let arr = value
                                .as_array()
                                .ok_or_else(|| format!("{RULES_FILE}: `checks.{name}.paths` must be a list of paths"))?;
                            let mut raw = Vec::with_capacity(arr.len());
                            for item in arr.iter() {
                                let Some(s) = item.as_str() else {
                                    return Err(format!("{RULES_FILE}: `checks.{name}.paths` must contain strings"));
                                };
                                raw.push(s.to_string());
                            }
                            let norm = veil_core::hub::agent::normalize_only(&raw)
                                .map_err(|e| format!("{RULES_FILE}: `checks.{name}.paths`: {e}"))?;
                            out.checks.insert(name.to_string(), norm);
                        }
                        "parallel" => {
                            let n = value
                                .as_integer()
                                .filter(|&n| (1..=8).contains(&n))
                                .ok_or_else(|| format!("{RULES_FILE}: `checks.{name}.parallel` must be an integer between 1 and 8"))?;
                            out.check_parallel.insert(name.to_string(), n as usize);
                        }
                        _ => return Err(format!("{RULES_FILE}: unknown rule `checks.{name}.{key}` (known: paths, parallel)")),
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_branches_and_refusals() {
        let r = Rules::parse(
            "# rules\n[branches.main]\nprotected = true\nrequired_checks = [\"ci/build\", \"ci/test\"]\n\
             [branches.release]\nprotected = false\n\
             [branches.staging]\nprotected = true\nauto_revert = false\n\
             [checks.\"ci/test\"]\npaths = [\"src/api/\", \"Cargo.lock\"]\nparallel = 3\n\
             [review]\nlow = 0\n",
        )
        .unwrap();
        assert_eq!(r.protected.iter().map(String::as_str).collect::<Vec<_>>(), ["main", "staging"]);
        assert!(r.allows_auto_revert("main"));
        assert!(!r.allows_auto_revert("staging"));
        assert!(!r.allows_auto_revert("release"));
        assert_eq!(r.required_checks["main"], vec!["ci/build", "ci/test"]);
        assert_eq!(r.checks["ci/test"], vec!["Cargo.lock", "src/api"]);
        assert_eq!(r.check_parallel["ci/test"], 3);
        assert_eq!(Rules::parse("").unwrap(), Rules::default());
        assert!(Rules::parse("[branches.main]\nprotcted = true\n").unwrap_err().contains("unknown rule"));
        assert!(Rules::parse("[branches.main]\nprotected = \"yes\"\n").is_err());
        assert!(Rules::parse("[branches.main]\nauto_revert = \"yes\"\n").is_err());
        assert!(Rules::parse("[branches.main]\nrequired_checks = [\"bad name\"]\n").is_err());
        assert!(Rules::parse("[checks.test]\npaths = [\"..\"]\n").is_err());
        assert!(Rules::parse("[checks.test]\nparallel = 0\n").is_err());
        assert!(Rules::parse("[checks.test]\nunknown = 1\n").is_err());
        assert!(Rules::parse("[branches]\nmain = 1\n").is_err());
        assert!(Rules::parse("[branches]\ndelete_merged = \"no\"\n").is_err());
        assert!(Rules::parse("").unwrap().delete_merged());
        assert!(!Rules::parse("[branches]\ndelete_merged = false\n[branches.main]\nprotected = true\n").unwrap().delete_merged());
        assert!(Rules::parse("[branches]\ndelete_merged = true\n").unwrap().delete_merged());
        assert!(Rules::parse("[branches.\"a b\"]\nprotected = true\n").is_err());
        assert!(Rules::parse("[branches.main\n").is_err());
        let inline = Rules::parse("branches = { main = { protected = true } }\n").unwrap();
        assert!(inline.protected.contains("main"));
    }
}
