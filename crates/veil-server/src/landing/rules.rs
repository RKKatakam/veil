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

use std::collections::BTreeSet;

/// The file's name, at the project root.
pub const RULES_FILE: &str = ".veilrules";

/// The branch rules of a project.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    /// The protected branches.
    pub protected: BTreeSet<String>,
}

impl Rules {
    /// Parse `.veilrules`; the error says what is wrong (never echoing more
    /// than the key it names).
    pub fn parse(text: &str) -> Result<Rules, String> {
        let doc = text.parse::<toml_edit::DocumentMut>().map_err(|e| format!("{RULES_FILE} is not valid TOML: {}", e.message()))?;
        let mut out = Rules::default();
        let Some(branches) = doc.get("branches") else { return Ok(out) };
        let branches = branches.as_table_like().ok_or_else(|| format!("{RULES_FILE}: `branches` must be a table"))?;
        for (name, rules) in branches.iter() {
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
                    _ => return Err(format!("{RULES_FILE}: unknown rule `branches.{name}.{key}` (known: protected)")),
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
        let r = Rules::parse("# rules\n[branches.main]\nprotected = true\n[branches.release]\nprotected = false\n[review]\nlow = 0\n").unwrap();
        assert_eq!(r.protected.iter().map(String::as_str).collect::<Vec<_>>(), ["main"]);
        assert_eq!(Rules::parse("").unwrap(), Rules::default());
        assert!(Rules::parse("[branches.main]\nprotcted = true\n").unwrap_err().contains("unknown rule"));
        assert!(Rules::parse("[branches.main]\nprotected = \"yes\"\n").is_err());
        assert!(Rules::parse("[branches]\nmain = 1\n").is_err());
        assert!(Rules::parse("[branches.\"a b\"]\nprotected = true\n").is_err());
        assert!(Rules::parse("[branches.main\n").is_err());
        let inline = Rules::parse("branches = { main = { protected = true } }\n").unwrap();
        assert!(inline.protected.contains("main"));
    }
}
