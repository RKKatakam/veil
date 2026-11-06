use std::{borrow::Cow, fmt};

use serde::{Deserialize, Serialize};
use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};

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
        // Already normal (the common case: every path of a scan, of a
        // stat cache): one copy, no split and join.
        if !s.is_empty() && s.split('/').all(|c| !matches!(c, "" | "." | "..") && !c.contains('\0')) {
            return Ok(VPath(s.to_string()));
        }
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

    /// Append a single component.
    ///
    /// # Panics
    ///
    /// If `name` is not a single normal component (empty, `.`, `..`, or
    /// containing `/` or NUL). This is checked in release builds too: a
    /// malformed component would let a path escape its root. Names from
    /// trees are validated when the tree is decoded, so this is defence in
    /// depth, not input validation.
    pub fn join(&self, name: &str) -> VPath {
        assert!(
            !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0']),
            "invalid path component {name:?}"
        );
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

// ---- name normalisation and folding ----------------------------------------
//
// Veil records names byte-exactly as the working copy reports them, with
// two exceptions on filesystems that *fold* names (macOS APFS and HFS+ are
// case-insensitive and Unicode-normalisation-insensitive by default):
//
// * a name that folds to the same key as the parent snapshot's entry keeps
//   the parent's spelling, so HFS+ handing back `café` in NFD for a file
//   checked out in NFC (or a case drift) is never recorded as a rename;
// * a new name on a normalisation-insensitive filesystem is recorded in NFC,
//   as Git does with `core.precomposeUnicode` (the macOS default).
//
// Trees already in the store are never re-normalised: that would change
// their ids. Two entries of one directory whose fold keys collide cannot
// both exist on such a filesystem, so checkout refuses them there.

/// How a backend compares names. `Default` is exact (byte-wise), the
/// behaviour of Linux filesystems and of the in-memory backends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NameFolding {
    /// `README` and `readme` name the same entry (APFS, HFS+, FAT, SMB…).
    pub case_insensitive: bool,
    /// Canonically equivalent Unicode spellings (NFC `é` vs NFD `e` + U+0301)
    /// name the same entry, and HFS+-ignorable code points (zero-width
    /// joiners and similar) are ignored (APFS and HFS+).
    pub unicode_insensitive: bool,
}

impl NameFolding {
    /// Byte-exact names.
    pub const EXACT: NameFolding = NameFolding {
        case_insensitive: false,
        unicode_insensitive: false,
    };

    /// What a default macOS volume (APFS or HFS+) does.
    pub const MACOS: NameFolding = NameFolding {
        case_insensitive: true,
        unicode_insensitive: true,
    };

    /// Does this backend treat any two different strings as one name?
    pub fn folds(&self) -> bool {
        self.case_insensitive || self.unicode_insensitive
    }

    /// The key two names share exactly when this backend treats them as
    /// the same entry. Exact backends return the name itself.
    pub fn key<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if !self.folds() || (name.is_ascii() && !(self.case_insensitive && name.bytes().any(|b| b.is_ascii_uppercase()))) {
            return Cow::Borrowed(name);
        }
        let mut s: String = if self.unicode_insensitive {
            name.chars().filter(|c| !is_hfs_ignorable(*c)).nfd().collect()
        } else {
            name.to_string()
        };
        if self.case_insensitive {
            s = s.to_lowercase();
            if self.unicode_insensitive {
                s = s.nfd().collect();
            }
        }
        Cow::Owned(s)
    }

    /// The spelling to record for a *new* name read from this backend: NFC
    /// on normalisation-insensitive backends (so a repository made on macOS
    /// holds the form Linux tools expect), unchanged otherwise.
    pub fn record<'a>(&self, name: &'a str) -> Cow<'a, str> {
        if self.unicode_insensitive {
            nfc(name)
        } else {
            Cow::Borrowed(name)
        }
    }

    /// Short human description (`case-insensitive, normalisation-insensitive`).
    pub fn describe(&self) -> &'static str {
        match (self.case_insensitive, self.unicode_insensitive) {
            (false, false) => "case-sensitive, byte-exact names",
            (true, false) => "case-insensitive",
            (false, true) => "Unicode-normalisation-insensitive",
            (true, true) => "case-insensitive and Unicode-normalisation-insensitive",
        }
    }
}

/// `name` in Unicode Normalization Form C (borrowed when it already is).
pub fn nfc(name: &str) -> Cow<'_, str> {
    if name.is_ascii() || is_nfc_quick(name.chars()) == IsNormalized::Yes {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(name.nfc().collect())
    }
}

/// Code points HFS+ ignores when comparing names (as Git's `is_hfs_dotgit`
/// does): zero-width (non-)joiners, directional marks and embeddings, the
/// deprecated format characters U+206A–U+206F, and the byte-order mark.
/// `.v\u{200C}eil` is the metadata directory on HFS+.
pub fn is_hfs_ignorable(c: char) -> bool {
    matches!(c,
        '\u{200C}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{206A}'..='\u{206F}' | '\u{FEFF}')
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

    /// The fast path for a path that is already normal gives what the
    /// general one does, and leaves everything else to it.
    #[test]
    fn already_normal_paths_are_taken_as_they_are() {
        for s in ["a", "a/b", "d001/f001.txt", ".env", "..a/b..", "a.b/.c", "x/y/z/w"] {
            assert_eq!(VPath::new(s).unwrap().as_str(), s);
        }
        for (s, want) in [("a/", "a"), ("/a", "a"), ("a//b", "a/b"), ("./a", "a"), ("a/.", "a"), (".", "")] {
            assert_eq!(VPath::new(s).unwrap().as_str(), want, "{s:?}");
        }
        for s in ["..", "a/..", "../a", "a/../b", "a\0b", "\0"] {
            assert!(VPath::new(s).is_err(), "{s:?}");
        }
    }

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

    #[test]
    fn folding_keys() {
        let exact = NameFolding::EXACT;
        assert_ne!(exact.key("README"), exact.key("readme"));
        let ci = NameFolding {
            case_insensitive: true,
            unicode_insensitive: false,
        };
        assert_eq!(ci.key("README"), ci.key("readme"));
        assert_ne!(ci.key("caf\u{e9}"), ci.key("cafe\u{301}"));
        let mac = NameFolding::MACOS;
        assert_eq!(mac.key("README"), mac.key("readme"));
        assert_eq!(mac.key("caf\u{e9}"), mac.key("cafe\u{301}"));
        assert_eq!(mac.key("CAF\u{c9}"), mac.key("cafe\u{301}"));
        assert_eq!(mac.key("a\u{200d}b"), mac.key("ab"));
        assert_ne!(mac.key("a"), mac.key("b"));
        assert!(matches!(mac.key("plain.txt"), Cow::Borrowed(_)));
        assert_eq!(mac.record("cafe\u{301}"), "caf\u{e9}");
        assert_eq!(exact.record("cafe\u{301}"), "cafe\u{301}");
        assert_eq!(nfc("cafe\u{301}"), "caf\u{e9}");
    }
}
