//! History search: the `vl log` filters (paths, `--author`, `--signed-by`,
//! `-S`, `-G`, `--follow`).
//!
//! **As this reader sees history.** File content is read through [`readable_version`](crate::blame::readable_version) only, so the
//! pickaxe never runs on ciphertext; a snapshot whose relevant version is
//! redacted is not listed (with [`Match::Skipped`] the caller may say "not
//! searched") rather than counted on something the reader cannot read
//! (threat review 3).
//!
//! **Authors are claims.** `--author` matches the free-form `author` field,
//! which whoever wrote the snapshot chose; `--signed-by` matches the signer
//! the keychain verifies.
//!
//! **Bounded.** Regexes use the `regex` crate (linear time) with compile
//! limits; a pattern over [`MAX_PATTERN`] bytes is refused. Counting is
//! linear (`memchr::memmem`), `-G`'s line diff is bounded as every diff
//! (`textmerge`), files over [`MAX_SEARCHED_FILE`] are not searched. The
//! per-object memo holds counts only, never plaintext, and dies with the
//! process: nothing derived from sealed content is ever written to disk
//! (threat review 8).

use std::collections::{BTreeMap, HashMap};

use regex::bytes::{Regex, RegexBuilder};

use crate::{
    blame::{line_ranges, map_lines, readable_version_counted, ReadStats, Readable, Reader},
    error::{Result, VeilError},
    id::ObjectId,
    keychain::SignatureStatus,
    object::{EntryKind, Snapshot, TreeEntry, Visibility},
    rename::{self, RenameOptions},
    repo::Repo,
    tree::{diff_trees_hiding, lookup, prefetch_changes, TreeChange},
    vpath::VPath,
};

/// Longest pattern accepted (threat review 6).
pub const MAX_PATTERN: usize = 64 << 10;
/// Compiled-program limit of a pattern.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Lazy-DFA cache limit of a pattern.
pub const REGEX_DFA_LIMIT: usize = 8 << 20;
/// Largest file version `-S` / `-G` read.
pub const MAX_SEARCHED_FILE: usize = 256 << 20;

/// A regular expression under the limits above.
pub fn compile_regex(pattern: &str, ignore_case: bool) -> Result<Regex> {
    if pattern.len() > MAX_PATTERN {
        return Err(VeilError::Policy(format!("the pattern is {} bytes; at most {MAX_PATTERN} are accepted", pattern.len())));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .build()
        .map_err(|e| VeilError::Policy(format!("invalid regular expression: {e}")))
}

/// `-S` or `-G`.
#[derive(Clone, Debug)]
pub enum Pickaxe {
    /// Snapshots that change the number of occurrences of the string.
    Count { needle: Vec<u8>, ignore_case: Option<Regex> },
    /// Snapshots that add or remove a line matching the regex.
    Lines(Regex),
}

impl Pickaxe {
    /// `-S STRING` (with `-i`, case-insensitively).
    pub fn string(needle: &str, ignore_case: bool) -> Result<Pickaxe> {
        if needle.is_empty() {
            return Err(VeilError::Policy("-S needs a non-empty string".into()));
        }
        let ci = if ignore_case { Some(compile_regex(&regex::escape(needle), true)?) } else { None };
        if needle.len() > MAX_PATTERN {
            return Err(VeilError::Policy(format!("the string is {} bytes; at most {MAX_PATTERN} are accepted", needle.len())));
        }
        Ok(Pickaxe::Count { needle: needle.as_bytes().to_vec(), ignore_case: ci })
    }

    /// `-G REGEX`.
    pub fn regex(pattern: &str, ignore_case: bool) -> Result<Pickaxe> {
        Ok(Pickaxe::Lines(compile_regex(pattern, ignore_case)?))
    }
}

/// The filters of one `vl log`.
#[derive(Clone, Debug, Default)]
pub struct LogFilter {
    /// Only snapshots changing these files or directories.
    pub paths: Vec<VPath>,
    pub author: Option<Regex>,
    /// Only snapshots whose agent attribution matches (`vl log --agent`,
    /// the `agent()` revset's matcher).
    pub agent: Option<globset::GlobMatcher>,
    /// A member name or member id the snapshot's verified signer must be.
    pub signed_by: Option<String>,
    pub pickaxe: Option<Pickaxe>,
    /// With a pickaxe, report every changed file of a matching snapshot.
    pub pickaxe_all: bool,
    /// Follow the single path in `paths` across renames.
    pub follow: bool,
    pub reader: Reader,
    pub renames: RenameOptions,
    /// Restrict tree lookups, pickaxe searches and rename following to this
    /// sparse set (for a `--only` sandbox's workspace socket).
    pub within: Option<crate::vfs::SparseSet>,
}

impl LogFilter {
    /// Does any filter apply?
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.author.is_none() && self.agent.is_none() && self.signed_by.is_none() && self.pickaxe.is_none()
    }
}

/// The verdict on one snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    No,
    /// It matches; with a pickaxe, the files that matched (or, with
    /// `pickaxe_all`, every changed file).
    Yes { files: Vec<VPath> },
    /// Not listed: the versions the pickaxe would have to read are
    /// redacted for this reader (who they are for; never their content).
    Skipped { sealed_for: Vec<Visibility> },
}

/// Applies a [`LogFilter`] to snapshots, newest first; remembers the path
/// `--follow` is at for each snapshot still to come.
pub struct Searcher<'a> {
    repo: &'a Repo,
    filter: LogFilter,
    signers: BTreeMap<String, (String, String)>,
    /// `--follow`: the path a snapshot's children passed down.
    followed: HashMap<ObjectId, VPath>,
    /// `-S` counts per object read (no plaintext).
    counts: HashMap<ObjectId, usize>,
    pub searched: usize,
    pub stats: ReadStats,
}

impl<'a> Searcher<'a> {
    pub fn new(repo: &'a Repo, filter: LogFilter) -> Searcher<'a> {
        Searcher { repo, signers: repo.keys().known_signers(), filter, followed: HashMap::new(), counts: HashMap::new(), searched: 0, stats: ReadStats::default() }
    }

    pub fn filter(&self) -> &LogFilter {
        &self.filter
    }

    /// The verdict on snapshot `id`. Call in log order (children first) so
    /// that `--follow` hands each parent the right name.
    pub fn check(&mut self, id: &ObjectId) -> Result<Match> {
        self.searched += 1;
        let repo = self.repo;
        let s = repo.snapshot(id)?;
        if *id == repo.root_id() {
            return Ok(if self.filter.is_empty() { Match::Yes { files: Vec::new() } } else { Match::No });
        }
        if let Some(m) = &self.filter.agent {
            if !crate::revset::agent_matches(&s, m) {
                self.pass_followed(id, &s);
                return Ok(Match::No);
            }
        }
        if let Some(re) = &self.filter.author {
            if !re.is_match(s.author.as_bytes()) {
                self.pass_followed(id, &s);
                return Ok(Match::No);
            }
        }
        if let Some(who) = &self.filter.signed_by {
            let ok = match repo.keys().snapshot_status_with(&s, &self.signers) {
                SignatureStatus::Good { member, name } => member == *who || name == *who,
                _ => false,
            };
            if !ok {
                self.pass_followed(id, &s);
                return Ok(Match::No);
            }
        }
        if self.filter.paths.is_empty() && self.filter.pickaxe.is_none() {
            return Ok(Match::Yes { files: Vec::new() });
        }
        let paths: Vec<VPath> = match (self.filter.follow, self.followed.remove(id)) {
            (true, Some(p)) => vec![p],
            _ => self.filter.paths.clone(),
        };
        let store = repo.store();
        let restrict = |tree: ObjectId| -> Result<ObjectId> {
            match &self.filter.within {
                Some(set) => crate::vfs::restrict(store, &tree, set),
                None => Ok(tree),
            }
        };
        let s_tree = restrict(s.tree)?;
        let parent_trees: Vec<Option<ObjectId>> = s
            .parents
            .iter()
            .map(|p| match repo.exact().snapshot(p)? {
                Some(ps) => Ok(Some(restrict(ps.tree)?)),
                None => Ok(None),
            })
            .collect::<Result<_>>()?;
        // The path filter: changed against every parent (a merge is listed
        // only where it differs from all of them).
        if !paths.is_empty() {
            let mut touched = false;
            for p in &paths {
                let here = lookup_entry(repo, &s_tree, p)?;
                let differs = |t: &Option<ObjectId>| -> Result<bool> {
                    Ok(match t {
                        Some(t) => !same(&lookup_entry(repo, t, p)?, &here),
                        None => here.is_some(),
                    })
                };
                let mut all = !parent_trees.is_empty() || here.is_some();
                for t in &parent_trees {
                    all &= differs(t)?;
                }
                touched |= all;
            }
            if self.filter.follow {
                self.follow(&s, &s_tree, &paths, &parent_trees)?;
            }
            if !touched {
                return Ok(Match::No);
            }
        }
        let Some(pickaxe) = self.filter.pickaxe.clone() else {
            return Ok(Match::Yes { files: Vec::new() });
        };
        // As `git log -S` without `-m`: merges are not searched.
        if s.parents.len() > 1 {
            return Ok(Match::No);
        }
        let base = match parent_trees.first() {
            Some(Some(t)) => Some(*t),
            _ => None,
        };
        // A folder the server refuses is not searched (BUG-1508).
        let changes: Vec<TreeChange> = diff_trees_hiding(store, base.as_ref(), Some(&s_tree))?
            .0
            .into_iter()
            .filter(|c| paths.is_empty() || paths.iter().any(|p| c.path == *p || c.path.starts_with(p)))
            .collect();
        // As Git does, renames are paired first: a moved file changes no
        // count.
        // In a thin clone, what the pickaxe and the pairing read, each at
        // its own path (BUG-1506).
        prefetch_changes(store, base.as_ref(), Some(&s_tree), changes.iter().filter(|c| [&c.old, &c.new].into_iter().flatten().all(|e| e.size <= MAX_SEARCHED_FILE as u64)))?;
        let d = rename::detect(store, base.as_ref(), Some(&s_tree), &changes, self.filter.reader, &self.filter.renames)?;
        self.stats.add(&d.stats);
        let changes: Vec<TreeChange> = d
            .items()
            .into_iter()
            .map(|i| match i {
                rename::Item::Change(c) => c,
                rename::Item::Pair(p) => TreeChange { path: p.to, old: Some(p.old), new: Some(p.new) },
            })
            .collect();
        let mut matched = Vec::new();
        let mut sealed_for = Vec::new();
        for c in &changes {
            let old = self.read(c.old.as_ref())?;
            let new = self.read(c.new.as_ref())?;
            let (old, new) = match (old, new) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(v), _) | (_, Err(v)) => {
                    if let Some(v) = v {
                        sealed_for.push(v);
                    }
                    continue;
                }
            };
            let hit = match &pickaxe {
                Pickaxe::Count { needle, ignore_case } => {
                    let mut count = |v: &Option<(ObjectId, Vec<u8>)>| -> usize {
                        let Some((id, data)) = v else { return 0 };
                        *self.counts.entry(*id).or_insert_with(|| match ignore_case {
                            Some(re) => re.find_iter(data).count(),
                            None => memchr::memmem::find_iter(data, needle).count(),
                        })
                    };
                    count(&old) != count(&new)
                }
                Pickaxe::Lines(re) => {
                    let empty = Vec::new();
                    let a = old.as_ref().map_or(&empty, |v| &v.1);
                    let b = new.as_ref().map_or(&empty, |v| &v.1);
                    lines_changed_match(a, b, re)
                }
            };
            if hit {
                matched.push(c.path.clone());
            }
        }
        if !matched.is_empty() {
            let files = if self.filter.pickaxe_all { changes.iter().map(|c| c.path.clone()).collect() } else { matched };
            return Ok(Match::Yes { files });
        }
        if !sealed_for.is_empty() {
            sealed_for.dedup();
            return Ok(Match::Skipped { sealed_for });
        }
        Ok(Match::No)
    }

    /// The version a pickaxe reads: `Ok(None)` for no file (or a file too
    /// large to search, or not a file), `Err(Some(for whom))` when redacted.
    #[allow(clippy::type_complexity)]
    fn read(&mut self, e: Option<&TreeEntry>) -> Result<std::result::Result<Option<(ObjectId, Vec<u8>)>, Option<Visibility>>> {
        let Some(e) = e else { return Ok(Ok(None)) };
        if !e.kind.is_file_like() || e.size > MAX_SEARCHED_FILE as u64 {
            return Ok(Ok(None));
        }
        Ok(match readable_version_counted(self.repo.store(), e, self.filter.reader, &mut self.stats)? {
            Readable::Plain { id, data, .. } if data.len() <= MAX_SEARCHED_FILE => Ok(Some((id, data))),
            Readable::Plain { .. } => Ok(None),
            Readable::Redacted(h) => Err(Some(h.visibility)),
        })
    }

    /// A snapshot left out before its paths were looked at still hands
    /// its followed name down to its parents.
    fn pass_followed(&mut self, id: &ObjectId, s: &Snapshot) {
        if !self.filter.follow {
            return;
        }
        let Some(p) = self.followed.remove(id).or_else(|| self.filter.paths.first().cloned()) else { return };
        for parent in &s.parents {
            self.followed.entry(*parent).or_insert_with(|| p.clone());
        }
    }

    /// `--follow`: hand each parent the name the file had there (renamed
    /// in this snapshot: the rename's source).
    fn follow(&mut self, s: &Snapshot, s_tree: &ObjectId, paths: &[VPath], parent_trees: &[Option<ObjectId>]) -> Result<()> {
        let Some(p) = paths.first() else { return Ok(()) };
        let store = self.repo.store();
        let here = lookup_entry(self.repo, s_tree, p)?;
        for (parent, tree) in s.parents.iter().zip(parent_trees) {
            let mut name = p.clone();
            if let (Some(_), Some(t)) = (&here, tree) {
                if lookup_entry(self.repo, t, p)?.is_none() {
                    let (changes, _) = diff_trees_hiding(store, Some(t), Some(s_tree))?;
                    let d = rename::detect(store, Some(t), Some(s_tree), &changes, self.filter.reader, &self.filter.renames)?;
                    self.stats.add(&d.stats);
                    if let Some(pair) = d.pairs.iter().find(|x| x.to == *p && !x.copy) {
                        name = pair.from.clone();
                    }
                }
            }
            self.followed.entry(*parent).or_insert(name);
        }
        Ok(())
    }
}

/// The entry at `p` in `tree` as this reader's tree shows it; a directory
/// on the way this reader cannot open counts as no entry.
fn lookup_entry(repo: &Repo, tree: &ObjectId, p: &VPath) -> Result<Option<TreeEntry>> {
    match lookup(repo.store(), tree, p) {
        Ok(e) => Ok(e),
        Err(err) if err.is_unreadable() => Ok(None),
        Err(err) => Err(err),
    }
}

fn same(a: &Option<TreeEntry>, b: &Option<TreeEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same_content(y),
        _ => false,
    }
}

/// Does a line `re` matches get added or removed between `old` and `new`?
fn lines_changed_match(old: &[u8], new: &[u8], re: &Regex) -> bool {
    if old == new {
        return false;
    }
    let (ol, nl) = (line_ranges(old), line_ranges(new));
    let (map, _) = map_lines(old, new, nl.len());
    let mut kept = vec![false; ol.len()];
    let strip = |l: &[u8]| -> usize { l.len() - usize::from(l.ends_with(b"\n")) };
    for (i, m) in map.iter().enumerate() {
        match m {
            Some(o) => kept[*o as usize] = true,
            None => {
                let (a, b) = nl[i];
                if re.is_match(&new[a..a + strip(&new[a..b])]) {
                    return true;
                }
            }
        }
    }
    ol.iter().zip(kept).any(|(&(a, b), k)| !k && re.is_match(&old[a..a + strip(&old[a..b])]))
}

/// Does entry kind `k` hold searchable content?
pub fn searchable(k: EntryKind) -> bool {
    k.is_file_like()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g_matches_added_and_removed_lines_only() {
        let re = compile_regex("^fn ", false).unwrap();
        assert!(lines_changed_match(b"a\n", b"a\nfn x\n", &re));
        assert!(lines_changed_match(b"fn x\na\n", b"a\n", &re));
        assert!(!lines_changed_match(b"fn x\na\n", b"fn x\nb\n", &re));
        assert!(!lines_changed_match(b"same", b"same", &re));
    }

    #[test]
    fn hostile_patterns_are_refused_or_linear() {
        assert!(compile_regex(&"a".repeat(MAX_PATTERN + 1), false).is_err());
        assert!(compile_regex("(", false).is_err());
        // Exponential for a backtracking engine; linear here.
        let re = compile_regex("(a*)*b", false).unwrap();
        let hay = vec![b'a'; 1 << 20];
        let t = std::time::Instant::now();
        assert!(!re.is_match(&hay));
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        // A pattern whose program is too large is refused.
        assert!(compile_regex("\\w{1000}{1000}", false).is_err());
        assert!(Pickaxe::string("", false).is_err());
    }
}
