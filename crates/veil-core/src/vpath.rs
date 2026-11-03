use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, VeilError};

/// A normalised, relative, `/`-separated path inside a storage backend.
///
/// Invariants: no leading/trailing `/`, no empty, `.` or `..` components.
/// The empty string is the root. Because the ordering is plain string
/// ordering, all descendants of `a/` are contiguous in a `BTreeMap`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VPath(String);

impl VPath {
    pub fn root() -> Self {
        VPath(String::new())
    }

    pub fn new(s: &str) -> Result<Self> {
        let mut parts = Vec::new();
        for c in s.split('/') {
            match c {
                "" | "." => continue,
                ".." => return Err(VeilError::InvalidPath(format!("'{s}' escapes its root"))),
                c if c.contains('\0') => {
                    return Err(VeilError::InvalidPath(format!("'{s}' contains NUL")))
                }
                c => parts.push(c),
            }
        }
        Ok(VPath(parts.join("/")))
    }

    /// Construct from a raw string without normalisation. Used for range-scan
    /// bounds such as `"a/"`; never exposed as a real path.
    pub(crate) fn from_raw(s: String) -> Self {
        VPath(s)
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Append a single component (which must not contain `/`).
    pub fn join(&self, name: &str) -> VPath {
        debug_assert!(!name.contains('/') && !name.is_empty());
        if self.0.is_empty() {
            VPath(name.to_string())
        } else {
            VPath(format!("{}/{}", self.0, name))
        }
    }

    pub fn parent(&self) -> Option<VPath> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.rfind('/') {
            Some(i) => VPath(self.0[..i].to_string()),
            None => VPath::root(),
        })
    }

    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or("")
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// All proper ancestors except the root, outermost first.
    pub fn ancestors(&self) -> Vec<VPath> {
        let mut out = Vec::new();
        let mut cur = self.parent();
        while let Some(p) = cur {
            if p.is_root() {
                break;
            }
            cur = p.parent();
            out.push(p);
        }
        out.reverse();
        out
    }

    /// Component-wise prefix test (`a/b` starts with `a`, but `ab` does not).
    pub fn starts_with(&self, other: &VPath) -> bool {
        other.is_root()
            || self.0 == other.0
            || (self.0.len() > other.0.len()
                && self.0.starts_with(&other.0)
                && self.0.as_bytes()[other.0.len()] == b'/')
    }

    /// Prefix string that all strict descendants share (`""` for root).
    pub fn child_prefix(&self) -> String {
        if self.is_root() {
            String::new()
        } else {
            format!("{}/", self.0)
        }
    }
}

impl fmt::Display for VPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str(".")
        } else {
            f.write_str(&self.0)
        }
    }
}

impl fmt::Debug for VPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VPath({:?})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(VPath::new("/a//b/./c/").unwrap().as_str(), "a/b/c");
        assert!(VPath::new("a/../b").is_err());
        assert!(VPath::new("").unwrap().is_root());
    }

    #[test]
    fn relations() {
        let p = VPath::new("a/b/c").unwrap();
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert_eq!(p.file_name(), "c");
        assert_eq!(
            p.ancestors().iter().map(|a| a.as_str()).collect::<Vec<_>>(),
            vec!["a", "a/b"]
        );
        assert!(p.starts_with(&VPath::new("a").unwrap()));
        assert!(!VPath::new("ab").unwrap().starts_with(&VPath::new("a").unwrap()));
    }
}
