//! What a query asks for (milestone S15): the words of a ranked search, a
//! grep's regular expression, and the trigrams that narrow either to
//! candidate documents. Narrowing is only ever sound: every document that
//! matches holds every trigram asked for (trigrams are ASCII case folded,
//! and taken only from text every match must contain), and every
//! candidate is confirmed against its content.

use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};

use super::segment::grams;
use crate::error::{Error, Result};

/// Bounds of what a query may ask (row 10).
pub const MAX_QUERY_BYTES: usize = 256;
pub const MAX_TERMS: usize = 8;
pub const MAX_PATTERN_BYTES: usize = 4096;
/// The compiled regular expression's size limits (the `regex` crate runs
/// in linear time; these bound its memory).
const REGEX_SIZE: usize = 1 << 20;
const REGEX_DFA_SIZE: usize = 4 << 20;

/// The words of a ranked search: all must occur (ASCII case folded).
#[derive(Clone, Debug)]
pub struct Terms {
    /// Lower-case words.
    pub words: Vec<Vec<u8>>,
    /// Per word, its trigrams.
    pub grams: Vec<Vec<u32>>,
    /// Per word, a literal search for it (in lower-case text).
    finders: Vec<Regex>,
}

impl Terms {
    pub fn parse(q: &str) -> Result<Terms> {
        if q.len() > MAX_QUERY_BYTES {
            return Err(Error::bad_request(format!("a search is at most {MAX_QUERY_BYTES} bytes")));
        }
        let words: Vec<Vec<u8>> = q.split_whitespace().map(|w| w.as_bytes().to_ascii_lowercase()).collect();
        if words.is_empty() {
            return Err(Error::bad_request("search for at least one word"));
        }
        if words.len() > MAX_TERMS {
            return Err(Error::bad_request(format!("a search has at most {MAX_TERMS} words")));
        }
        let grams = words.iter().map(|w| grams(w)).collect();
        let finders = words
            .iter()
            .map(|w| {
                RegexBuilder::new(&regex::escape(&String::from_utf8_lossy(w)))
                    .unicode(false)
                    .build()
                    .map_err(|e| Error::bad_request(format!("invalid search: {e}")))
            })
            .collect::<Result<_>>()?;
        Ok(Terms { words, grams, finders })
    }

    /// How often word `t` occurs in `lower` (lower-case text), not
    /// overlapping.
    pub fn count(&self, t: usize, lower: &[u8]) -> u64 {
        self.finders[t].find_iter(lower).count() as u64
    }

    /// Every word's trigrams, together (a candidate holds them all).
    pub fn all_grams(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.grams.iter().flatten().copied().collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Does any word occur in `lower`?
    pub fn any(&self, lower: &[u8]) -> bool {
        self.finders.iter().any(|f| f.is_match(lower))
    }
}

/// Most bytes of compiled pattern times bytes of a line one search may
/// cover (BUG-1230): the linear-time engine's worst case is linear in
/// both (a pattern the lazy DFA gives up on runs on the PikeVM), and one
/// call cannot be stopped, so a line longer than this allows for the
/// pattern is not searched (and is counted in the answer).
pub const SCAN_COST: u64 = 1 << 31;

/// A grep: a regular expression, the trigrams every match contains, and
/// the longest line it searches.
pub struct Pattern {
    pub regex: Regex,
    pub grams: Vec<u32>,
    /// About the size of the compiled pattern (a power of two, at least 1 KiB).
    pub cost: u64,
    pub max_line: usize,
}

/// The smallest power of two (from 1 KiB) the compiled pattern fits in.
fn compiled_size(pattern: &str, ignore_case: bool) -> u64 {
    let mut size = 1u64 << 10;
    while size < REGEX_SIZE as u64 {
        if RegexBuilder::new(pattern).case_insensitive(ignore_case).size_limit(size as usize).build().is_ok() {
            return size;
        }
        size <<= 1;
    }
    REGEX_SIZE as u64
}

impl Pattern {
    pub fn parse(pattern: &str, ignore_case: bool) -> Result<Pattern> {
        if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES {
            return Err(Error::bad_request(format!("a pattern is 1 to {MAX_PATTERN_BYTES} bytes")));
        }
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(ignore_case)
            .size_limit(REGEX_SIZE)
            .dfa_size_limit(REGEX_DFA_SIZE)
            .build()
            .map_err(|e| Error::bad_request(format!("invalid pattern: {}", first_line(&e.to_string()))))?;
        let hir = regex_syntax::ParserBuilder::new()
            .case_insensitive(ignore_case)
            .utf8(false)
            .build()
            .parse(pattern)
            .map_err(|e| Error::bad_request(format!("invalid pattern: {}", first_line(&e.to_string()))))?;
        let mut runs = Vec::new();
        let mut cur = Vec::new();
        required(&hir, &mut runs, &mut cur);
        flush(&mut cur, &mut runs);
        let mut g: Vec<u32> = runs.iter().flat_map(|r| grams(r)).collect();
        g.sort_unstable();
        g.dedup();
        let cost = compiled_size(pattern, ignore_case);
        Ok(Pattern {
            regex,
            grams: g,
            cost,
            max_line: (SCAN_COST / cost) as usize,
        })
    }
}

fn first_line(s: &str) -> String {
    s.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").chars().take(200).collect()
}

fn flush(cur: &mut Vec<u8>, runs: &mut Vec<Vec<u8>>) {
    if cur.len() >= 3 {
        runs.push(std::mem::take(cur));
    }
    cur.clear();
}

/// A class every member of which folds to the same ASCII byte (`[Kk]`, a
/// letter under `(?i)`): that byte. A class with any non-ASCII member is
/// none (`(?i)k` holds the Kelvin sign).
fn one_byte(c: &Class) -> Option<u8> {
    let mut out: Option<u8> = None;
    let mut each = |b: u32| -> bool {
        if b > 0x7f {
            return false;
        }
        let f = (b as u8).to_ascii_lowercase();
        match out {
            None => {
                out = Some(f);
                true
            }
            Some(o) => o == f,
        }
    };
    match c {
        Class::Unicode(u) => {
            for r in u.ranges() {
                let (a, b) = (r.start() as u32, r.end() as u32);
                if b - a > 3 || !(a..=b).all(&mut each) {
                    return None;
                }
            }
        }
        Class::Bytes(u) => {
            for r in u.ranges() {
                let (a, b) = (r.start() as u32, r.end() as u32);
                if b - a > 3 || !(a..=b).all(&mut each) {
                    return None;
                }
            }
        }
    }
    out
}

/// Collect the runs of bytes (ASCII case folded) that every match of `h`
/// contains: literals next to each other in a concatenation, across
/// zero-width assertions; repetitions of at least one and groups add their
/// own; alternations add nothing.
fn required(h: &Hir, runs: &mut Vec<Vec<u8>>, cur: &mut Vec<u8>) {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(l) => cur.extend(l.0.iter().map(|b| b.to_ascii_lowercase())),
        HirKind::Class(c) => match one_byte(c) {
            Some(b) => cur.push(b),
            None => flush(cur, runs),
        },
        HirKind::Capture(c) => required(&c.sub, runs, cur),
        HirKind::Concat(v) => {
            for x in v {
                required(x, runs, cur);
            }
        }
        HirKind::Repetition(r) => {
            flush(cur, runs);
            if r.min >= 1 {
                let mut inner = Vec::new();
                required(&r.sub, runs, &mut inner);
                flush(&mut inner, runs);
            }
        }
        HirKind::Alternation(_) => flush(cur, runs),
    }
}

/// The file extensions of a language name (`--lang`).
pub fn extensions(lang: &str) -> Result<&'static [&'static str]> {
    Ok(match lang.to_ascii_lowercase().as_str() {
        "rust" | "rs" => &["rs"],
        "python" | "py" => &["py", "pyi"],
        "go" => &["go"],
        "javascript" | "js" => &["js", "mjs", "cjs", "jsx"],
        "typescript" | "ts" => &["ts", "tsx", "mts", "cts"],
        "c" => &["c", "h"],
        "c++" | "cpp" => &["cc", "cpp", "cxx", "hh", "hpp", "hxx", "h"],
        "java" => &["java"],
        "kotlin" => &["kt", "kts"],
        "swift" => &["swift"],
        "ruby" | "rb" => &["rb"],
        "shell" | "sh" | "bash" => &["sh", "bash", "zsh"],
        "markdown" | "md" => &["md", "markdown"],
        "toml" => &["toml"],
        "yaml" => &["yaml", "yml"],
        "json" => &["json"],
        "sql" => &["sql"],
        "html" => &["html", "htm"],
        "css" => &["css", "scss"],
        _ => return Err(Error::bad_request("unknown language (rust, python, go, javascript, typescript, c, cpp, java, kotlin, swift, ruby, shell, markdown, toml, yaml, json, sql, html, css)")),
    })
}

/// Is `path` a file of one of `exts`?
pub fn has_extension(path: &str, exts: &[&str]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => exts.iter().any(|e| e.eq_ignore_ascii_case(ext)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(s: &str) -> Vec<u32> {
        grams(s.as_bytes())
    }

    #[test]
    fn required_trigrams_are_sound() {
        let p = Pattern::parse("fn\\s+handle_[a-z]+", false).unwrap();
        assert_eq!(p.grams, g("handle_"));
        let p = Pattern::parse("(?i)HandLer", false).unwrap();
        assert_eq!(p.grams, g("handler"));
        let p = Pattern::parse("handler", true).unwrap();
        assert_eq!(p.grams, g("handler"));
        // Alternations and optional parts narrow nothing.
        assert!(Pattern::parse("foo|bar", false).unwrap().grams.is_empty());
        assert!(Pattern::parse("(abcd)?", false).unwrap().grams.is_empty());
        assert_eq!(Pattern::parse("x(abcd)+y", false).unwrap().grams, g("abcd"));
        assert_eq!(Pattern::parse("^abc$", false).unwrap().grams, g("abc"));
        // Under (?i), letters with non-ASCII case variants break a run.
        let p = Pattern::parse("(?i)sk", false).unwrap();
        assert!(p.grams.is_empty());
        // Every match holds every trigram (folded).
        for (pat, text) in [("Hello\\s+World", "say HELLO   world"), ("(?i)k[0-9]x", "K7X"), ("abc.def", "ABC-DEF")] {
            let p = Pattern::parse(pat, true).unwrap();
            assert!(p.regex.is_match(text.as_bytes()));
            let have = grams(text.as_bytes());
            assert!(p.grams.iter().all(|x| have.contains(x)), "{pat}");
        }
    }

    #[test]
    fn a_costly_pattern_searches_shorter_lines() {
        let cheap = Pattern::parse("handler", false).unwrap();
        let costly = Pattern::parse(r"(?-u)[\x00-\xff]*[a-f][\x00-\xff]{1000}[A-Z]", false).unwrap();
        println!("costs: {} {}", cheap.cost, costly.cost);
        assert!(cheap.max_line >= 1 << 20, "{}", cheap.max_line);
        assert!(costly.max_line < 1 << 17, "{}", costly.max_line);
    }

    #[test]
    fn hostile_patterns_are_refused_or_bounded() {
        assert!(Pattern::parse("", false).is_err());
        assert!(Pattern::parse(&"a".repeat(MAX_PATTERN_BYTES + 1), false).is_err());
        assert!(Pattern::parse("(", false).is_err());
        // A pattern whose compiled form is too large.
        assert!(Pattern::parse("(\\w{100}){100}", false).is_err());
        assert!(Terms::parse("").is_err());
        assert!(Terms::parse(&"x ".repeat(9)).is_err());
        assert!(Terms::parse(&"x".repeat(MAX_QUERY_BYTES + 1)).is_err());
    }

    #[test]
    fn occurrences_and_languages() {
        let t = Terms::parse("aa Ab.c").unwrap();
        assert_eq!(t.count(0, b"aaaa"), 2);
        assert_eq!(t.count(1, b"ab.c abxc"), 1);
        assert!(t.any(b"xx ab.c") && !t.any(b"abc"));
        assert!(has_extension("src/main.rs", extensions("rust").unwrap()));
        assert!(!has_extension("src/.rs", extensions("rust").unwrap()));
        assert!(!has_extension("rs", extensions("rust").unwrap()));
        assert!(extensions("cobol").is_err());
    }
}
