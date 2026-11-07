//! `vl grep`: search the files of a snapshot (never the working copy) as
//! this reader may see them.
//!
//! * **Snapshots only.** The files searched are those of a recorded tree
//!   ([`walk_files`]), so isolated, quarantined and ignored files, which
//!   never enter a snapshot, are never searched, and not counted either
//!   (no existence oracle). There is no option to read the disk.
//! * **One reader.** Content is read through [`readable_version`](crate::blame::readable_version):
//!   [`Readable::Plain`] is searched, [`Readable::Redacted`] is counted in
//!   [`Skipped::sealed`] and never searched. Ciphertext never reaches the
//!   matcher.
//! * **Bounded.** The regex is linear-time with compile limits
//!   ([`crate::search::compile_regex`]); files over [`MAX_FILE`] are
//!   skipped (`too_large`); a matching line over [`MAX_LINE`] is reported
//!   cut there.
//! * **Deterministic.** Files are searched on worker threads (with the
//!   `os` feature) and reported sorted by path.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use regex::bytes::Regex;

use crate::{
    blame::{readable_version_counted, ReadStats, Readable, Reader},
    error::Result,
    id::ObjectId,
    object::{EntryKind, TreeEntry, Visibility},
    search::compile_regex,
    secrets::looks_binary,
    store::ObjectStore,
    tree::walk_files,
    vpath::VPath,
};

/// Largest file searched.
pub const MAX_FILE: usize = 256 << 20;
/// A matching line longer than this is reported cut here.
pub const MAX_LINE: usize = 1 << 20;

#[derive(Clone, Debug, Default)]
pub struct GrepOptions {
    pub ignore_case: bool,
    /// The pattern is a literal string.
    pub fixed: bool,
    /// Match whole words only.
    pub word: bool,
    /// Stop after this many matching lines per file.
    pub max_count: Option<usize>,
    /// Search binary files as text (print their lines).
    pub text: bool,
    /// Only files at or below these paths.
    pub paths: Vec<VPath>,
    pub reader: Reader,
}

/// Compile `pattern` for [`grep`] (`-F`, `-i`, `-w`).
pub fn compile(pattern: &str, o: &GrepOptions) -> Result<Regex> {
    let body = if o.fixed { regex::escape(pattern) } else { pattern.to_string() };
    // Git's -w: the match starts at the line's start or after a non-word
    // character, and ends at its end or before one.
    let body = if o.word { format!("(?-u:(?:^|[^A-Za-z0-9_]))(?:{body})(?-u:(?:[^A-Za-z0-9_]|$))") } else { body };
    if pattern.len() > crate::search::MAX_PATTERN {
        return compile_regex(pattern, o.ignore_case);
    }
    compile_regex(&body, o.ignore_case)
}

/// Who can read the version searched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tier {
    Public,
    Cloaked(String),
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Public => "public",
            Tier::Cloaked(_) => "cloaked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrepLine {
    /// 1-based.
    pub number: usize,
    /// The line without its line break, cut at [`MAX_LINE`].
    pub text: Vec<u8>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrepFile {
    pub path: VPath,
    pub tier: Tier,
    /// A conflict, searched in its rendering for this reader.
    pub conflict: bool,
    /// Binary content (no lines are reported unless `text`).
    pub binary: bool,
    /// Matching lines (up to `max_count`).
    pub count: usize,
    pub lines: Vec<GrepLine>,
}

/// What was not searched. Only files of the snapshot are ever counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Skipped {
    /// Unreadable for this reader.
    pub sealed: usize,
    /// Binary files that matched (their lines are not shown).
    pub binary: usize,
    pub too_large: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Grep {
    /// Files with at least one match, sorted by path.
    pub files: Vec<GrepFile>,
    pub skipped: Skipped,
    pub searched: usize,
    pub stats: ReadStats,
}

fn under(paths: &[VPath], p: &VPath) -> bool {
    paths.is_empty() || paths.iter().any(|f| f.is_root() || p == f || p.starts_with(f))
}

enum One {
    Hit(GrepFile),
    Miss,
    Sealed,
    TooLarge,
}

fn search_one(store: &ObjectStore, path: &VPath, e: &TreeEntry, re: &Regex, o: &GrepOptions, stats: &mut ReadStats) -> Result<One> {
    if e.kind == EntryKind::File && e.size > MAX_FILE as u64 {
        return Ok(One::TooLarge);
    }
    let (data, tier) = match readable_version_counted(store, e, o.reader, stats)? {
        Readable::Plain { data, visibility, .. } => {
            let tier = match visibility {
                Visibility::Public => Tier::Public,
                Visibility::Cloaked { scope } => Tier::Cloaked(scope),
            };
            (data, tier)
        }
        Readable::Redacted(_) => return Ok(One::Sealed),
    };
    if data.len() > MAX_FILE {
        return Ok(One::TooLarge);
    }
    let binary = looks_binary(&data);
    let mut f = GrepFile { path: path.clone(), tier, conflict: e.kind == EntryKind::Conflict, binary, count: 0, lines: Vec::new() };
    let max = o.max_count.unwrap_or(usize::MAX);
    if max == 0 {
        return Ok(One::Miss);
    }
    for (i, line) in data.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        if !re.is_match(line) {
            continue;
        }
        f.count += 1;
        if !binary || o.text {
            let truncated = line.len() > MAX_LINE;
            f.lines.push(GrepLine { number: i + 1, text: line[..line.len().min(MAX_LINE)].to_vec(), truncated });
        }
        if f.count >= max {
            break;
        }
    }
    Ok(if f.count > 0 { One::Hit(f) } else { One::Miss })
}

/// Search the files of `tree` (see the module docs).
pub fn grep(store: &ObjectStore, tree: &ObjectId, re: &Regex, o: &GrepOptions) -> Result<Grep> {
    let files: Vec<(VPath, TreeEntry)> = walk_files(store, tree)?.into_iter().filter(|(p, e)| e.kind.is_file_like() && under(&o.paths, p)).collect();
    let threads = if cfg!(feature = "os") { std::thread::available_parallelism().map_or(1, |n| n.get()).clamp(1, 8) } else { 1 };
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<Result<One>>>> = files.iter().map(|_| Mutex::new(None)).collect();
    let all_stats = Mutex::new(ReadStats::default());
    let work = || {
        let mut stats = ReadStats::default();
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some((p, e)) = files.get(i) else { break };
            *results[i].lock().unwrap() = Some(search_one(store, p, e, re, o, &mut stats));
        }
        all_stats.lock().unwrap().add(&stats);
    };
    if threads <= 1 || files.len() <= 1 {
        work();
    } else {
        std::thread::scope(|s| {
            for _ in 0..threads.min(files.len()) {
                s.spawn(work);
            }
        });
    }
    let mut out = Grep { searched: files.len(), stats: all_stats.into_inner().unwrap(), ..Grep::default() };
    for r in results {
        match r.into_inner().unwrap().expect("every file searched")? {
            One::Hit(f) => {
                if f.binary && !o.text {
                    out.skipped.binary += 1;
                }
                out.files.push(f);
            }
            One::Miss => {}
            One::Sealed => out.skipped.sealed += 1,
            One::TooLarge => out.skipped.too_large += 1,
        }
    }
    out.files.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_and_fixed_patterns() {
        let o = GrepOptions { word: true, ..GrepOptions::default() };
        let re = compile("key", &o).unwrap();
        assert!(re.is_match(b"the key is"));
        assert!(re.is_match(b"key"));
        assert!(!re.is_match(b"keys"));
        assert!(!re.is_match(b"monkey"));
        let o = GrepOptions { fixed: true, ..GrepOptions::default() };
        let re = compile("a.b(", &o).unwrap();
        assert!(re.is_match(b"x a.b( y"));
        assert!(!re.is_match(b"axb("));
        let o = GrepOptions { ignore_case: true, ..GrepOptions::default() };
        assert!(compile("KEY", &o).unwrap().is_match(b"a key"));
    }
}
