//! Per-path attributes from `.veilattributes` (line endings, binary, diff
//! and merge drivers) and the conversions they imply.
//!
//! Feature 7 of the Git-parity round
//! (`docs/design/git-parity/7-attributes-line-endings.md`).
//!
//! **Source.** Veil reads `.veilattributes` itself, at the root and in every
//! directory, with Git's rules: a pattern without a `/` matches a file name
//! at any depth below its file's directory, one with a `/` is matched
//! against the path relative to that directory (Git's `wildmatch`, with
//! `*` never crossing a `/` and `**/` matching any number of directories);
//! a deeper file wins over a shallower one, a later line over an earlier
//! one, and the device-local `.veil/local/attributes` (as Git's
//! `.git/info/attributes`) over everything. Macros (`[attr]name …`) are
//! defined only at the root and in the local file; `binary` is built in
//! (`-diff -merge -text`). No `core.autocrlf` or `core.eol` equivalent
//! exists: what is recorded never depends on device configuration, and the
//! native line ending is LF (Linux and macOS).
//!
//! **Limits.** A `.veilattributes` larger than [`MAX_FILE`] is ignored as a
//! whole (with a warning), and so is a line of [`MAX_LINE`] bytes or more
//! (as Git does). A symlinked `.veilattributes` is never followed, and one
//! this reader cannot open (sealed for a scope it is not in) counts as
//! absent, with a warning: attributes never block a command.
//!
//! **Line endings** ([`Conversion`]). Recording normalises CRLF to LF
//! ([`to_odb`]) for paths with `text`, `text=auto` (when the content looks
//! like text) or `eol`; checkout writes CRLF ([`to_worktree`]) for
//! `eol=crlf`. The rules are those of Git's `convert.c` with
//! `core.autocrlf=false`, except that Veil never converts unless the
//! conversion is lossless: a file whose line endings are mixed (CRLF and
//! lone LF), or that holds a lone CR, is recorded exactly as it is, with a
//! warning ([`ToOdb::Lossy`]; Git's `core.safecrlf=warn` converts it
//! anyway).
//!
//! **Drivers.** `diff=<name>` and `merge=<name>` only *name* a driver. A
//! name means something only if this device defines it ([`DeviceDrivers`],
//! registered on the [`ObjectStore`] by the CLI from its own configuration
//! files); nothing in a tree, `.veilattributes` included, can ever define a
//! command. An unknown name falls back to the built-in behaviour.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    id::ObjectId,
    object::EntryKind,
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// The name of an attributes file (read in every directory).
pub const ATTRIBUTES_FILE: &str = ".veilattributes";
/// The device-local attributes file (as `.git/info/attributes`): highest
/// priority, never synced.
pub const LOCAL_ATTRIBUTES: &str = ".veil/local/attributes";
/// An attributes file larger than this is ignored as a whole.
pub const MAX_FILE: usize = 1 << 20;
/// A line of this many bytes or more is ignored (Git's
/// `ATTR_MAX_LINE_LENGTH`).
pub const MAX_LINE: usize = 2048;

/// Attributes Veil acts on.
pub const SUPPORTED: &[&str] = &["text", "eol", "binary", "diff", "merge", "crlf"];

/// Attributes Veil knows of but does not implement: `vl attr check` lists
/// them as "not supported by Veil".
pub fn unsupported_note(name: &str) -> Option<&'static str> {
    Some(match name {
        "filter" => "not supported by Veil: Veil records the file's bytes as they are on disk, unfiltered",
        "ident" => "not supported by Veil: `$Id$` is never expanded",
        "working-tree-encoding" => "not supported by Veil: the file is recorded in its working-tree encoding",
        "export-ignore" | "export-subst" | "whitespace" | "conflict-marker-size" | "delta" | "encoding" => "not supported by Veil",
        n if n.starts_with("linguist-") => "not supported by Veil",
        _ => return None,
    })
}

// ---- values -------------------------------------------------------------------------------

/// The state of one attribute for a path (Git's set / unset / value;
/// "unspecified" is the absence of a state).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// `name`
    Set,
    /// `-name`
    Unset,
    /// `name=value`
    Value(String),
    /// `!name`: explicitly back to unspecified (hides lower-priority lines).
    Unspecified,
}

impl State {
    /// As `git check-attr` prints it.
    pub fn display(&self) -> &str {
        match self {
            State::Set => "set",
            State::Unset => "unset",
            State::Value(v) => v,
            State::Unspecified => "unspecified",
        }
    }
}

// ---- wildmatch (Git's wildmatch.c, without case folding) ------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wm {
    Match,
    NoMatch,
    AbortAll,
    AbortToStarStar,
}

fn is_glob_special(c: u8) -> bool {
    matches!(c, b'*' | b'?' | b'[' | b'\\')
}

/// Byte `i` of `s`, or NUL past the end (wildmatch walks C strings).
#[inline]
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// Git's `wildmatch(pattern, text, pathname ? WM_PATHNAME : 0)`.
pub fn wildmatch(pattern: &[u8], text: &[u8], pathname: bool) -> bool {
    // A NUL inside either ends it, as in C.
    let cut = |s: &[u8]| -> usize { memchr::memchr(0, s).unwrap_or(s.len()) };
    let p = &pattern[..cut(pattern)];
    let t = &text[..cut(text)];
    dowild(p, 0, t, 0, pathname) == Wm::Match
}

fn dowild(pat: &[u8], mut p: usize, text: &[u8], mut t: usize, pathname: bool) -> Wm {
    let start = p;
    while at(pat, p) != 0 {
        let mut p_ch = at(pat, p);
        let t_ch = at(text, t);
        if t_ch == 0 && p_ch != b'*' {
            return Wm::AbortAll;
        }
        match p_ch {
            b'\\' => {
                p += 1;
                p_ch = at(pat, p);
                if t_ch != p_ch {
                    return Wm::NoMatch;
                }
            }
            b'?' => {
                if pathname && t_ch == b'/' {
                    return Wm::NoMatch;
                }
            }
            b'*' => {
                let match_slash;
                p += 1;
                if at(pat, p) == b'*' {
                    let prev_p = p as isize - 2;
                    while at(pat, p + 1) == b'*' {
                        p += 1;
                    }
                    p += 1;
                    let after = at(pat, p);
                    if (prev_p < start as isize || at(pat, prev_p as usize) == b'/')
                        && (after == 0 || after == b'/' || (after == b'\\' && at(pat, p + 1) == b'/'))
                    {
                        if after == b'/' && dowild(pat, p + 1, text, t, pathname) == Wm::Match {
                            return Wm::Match;
                        }
                        match_slash = true;
                    } else {
                        match_slash = false;
                    }
                } else {
                    match_slash = !pathname;
                }
                if at(pat, p) == 0 {
                    if !match_slash && text[t..].contains(&b'/') {
                        return Wm::NoMatch;
                    }
                    return Wm::Match;
                } else if !match_slash && at(pat, p) == b'/' {
                    match memchr::memchr(b'/', &text[t..]) {
                        None => return Wm::NoMatch,
                        Some(i) => t += i,
                    }
                    // The slash is consumed by the loop.
                    p += 1;
                    t += 1;
                    continue;
                }
                let mut t_ch = at(text, t);
                loop {
                    if t_ch == 0 {
                        break;
                    }
                    let next = at(pat, p);
                    if !is_glob_special(next) {
                        while {
                            t_ch = at(text, t);
                            t_ch != 0 && (match_slash || t_ch != b'/')
                        } {
                            if t_ch == next {
                                break;
                            }
                            t += 1;
                        }
                        if t_ch != next {
                            return if match_slash { Wm::AbortAll } else { Wm::AbortToStarStar };
                        }
                    }
                    let matched = dowild(pat, p, text, t, pathname);
                    if matched != Wm::NoMatch {
                        if !match_slash || matched != Wm::AbortToStarStar {
                            return matched;
                        }
                    } else if !match_slash && t_ch == b'/' {
                        return Wm::AbortToStarStar;
                    }
                    t += 1;
                    t_ch = at(text, t);
                }
                return Wm::AbortAll;
            }
            b'[' => {
                p += 1;
                p_ch = at(pat, p);
                if p_ch == b'^' {
                    p_ch = b'!';
                }
                let negated = p_ch == b'!';
                if negated {
                    p += 1;
                    p_ch = at(pat, p);
                }
                let mut prev_ch: u8 = 0;
                let mut matched = false;
                loop {
                    if p_ch == 0 {
                        return Wm::AbortAll;
                    }
                    if p_ch == b'\\' {
                        p += 1;
                        p_ch = at(pat, p);
                        if p_ch == 0 {
                            return Wm::AbortAll;
                        }
                        if t_ch == p_ch {
                            matched = true;
                        }
                    } else if p_ch == b'-' && prev_ch != 0 && at(pat, p + 1) != 0 && at(pat, p + 1) != b']' {
                        p += 1;
                        p_ch = at(pat, p);
                        if p_ch == b'\\' {
                            p += 1;
                            p_ch = at(pat, p);
                            if p_ch == 0 {
                                return Wm::AbortAll;
                            }
                        }
                        if t_ch <= p_ch && t_ch >= prev_ch {
                            matched = true;
                        }
                        p_ch = 0;
                    } else if p_ch == b'[' && at(pat, p + 1) == b':' {
                        p += 2;
                        let s = p;
                        while at(pat, p) != 0 && at(pat, p) != b']' {
                            p += 1;
                        }
                        if at(pat, p) == 0 {
                            return Wm::AbortAll;
                        }
                        let i = p as isize - s as isize - 1;
                        if i < 0 || at(pat, p - 1) != b':' {
                            // Not `[:class:]`: a plain `[` in the set.
                            p = s - 2;
                            p_ch = b'[';
                            if t_ch == p_ch {
                                matched = true;
                            }
                            prev_ch = p_ch;
                            p += 1;
                            p_ch = at(pat, p);
                            if p_ch == b']' {
                                break;
                            }
                            continue;
                        }
                        let class = &pat[s..s + i as usize];
                        let c = t_ch;
                        let hit = match class {
                            b"alnum" => c.is_ascii_alphanumeric(),
                            b"alpha" => c.is_ascii_alphabetic(),
                            b"blank" => c == b' ' || c == b'\t',
                            b"cntrl" => c.is_ascii_control(),
                            b"digit" => c.is_ascii_digit(),
                            b"graph" => c.is_ascii_graphic(),
                            b"lower" => c.is_ascii_lowercase(),
                            b"print" => c.is_ascii_graphic() || c == b' ',
                            b"punct" => c.is_ascii_punctuation(),
                            b"space" => matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c),
                            b"upper" => c.is_ascii_uppercase(),
                            b"xdigit" => c.is_ascii_hexdigit(),
                            _ => return Wm::AbortAll,
                        };
                        if hit {
                            matched = true;
                        }
                        p_ch = 0;
                    } else if t_ch == p_ch {
                        matched = true;
                    }
                    prev_ch = p_ch;
                    p += 1;
                    p_ch = at(pat, p);
                    if p_ch == b']' {
                        break;
                    }
                }
                if matched == negated || (pathname && t_ch == b'/') {
                    return Wm::NoMatch;
                }
            }
            _ => {
                if t_ch != p_ch {
                    return Wm::NoMatch;
                }
            }
        }
        p += 1;
        t += 1;
    }
    if at(text, t) != 0 {
        Wm::NoMatch
    } else {
        Wm::Match
    }
}

// ---- patterns (Git's dir.c parse_path_pattern, attr.c path_matches) -------------------------

#[derive(Clone, Debug)]
struct Pattern {
    /// Without the trailing `/` (and the `!` of a negative pattern).
    pat: Vec<u8>,
    /// Bytes before the first wildcard character.
    nowild: usize,
    /// No `/` (other than a trailing one): matched against the file name.
    nodir: bool,
    /// `*literal`.
    endswith: bool,
    /// Ended with `/`: matches only directories, so never a file.
    mustbedir: bool,
}

fn simple_length(p: &[u8]) -> usize {
    p.iter().position(|&c| is_glob_special(c)).unwrap_or(p.len())
}

impl Pattern {
    /// `None` for a negative pattern (ignored by Git, with a warning).
    fn parse(raw: &[u8]) -> Option<Pattern> {
        if raw.first() == Some(&b'!') {
            return None;
        }
        let mut p = raw;
        let mut mustbedir = false;
        if p.last() == Some(&b'/') {
            p = &p[..p.len() - 1];
            mustbedir = true;
        }
        let nodir = !p.contains(&b'/');
        let nowild = simple_length(p).min(p.len());
        let endswith = p.first() == Some(&b'*') && simple_length(&p[1..]) == p.len() - 1;
        Some(Pattern {
            pat: p.to_vec(),
            nowild,
            nodir,
            endswith,
            mustbedir,
        })
    }

    /// Does the pattern, from a file in directory `base` (`""` = root),
    /// match file `path` (whose name starts at `name_at`)?
    fn matches(&self, path: &[u8], name_at: usize, base: &[u8]) -> bool {
        if self.mustbedir {
            return false;
        }
        if self.nodir {
            let name = &path[name_at..];
            let pat = &self.pat;
            if self.nowild == pat.len() {
                return name == pat.as_slice();
            }
            if self.endswith {
                return name.len() + 1 >= pat.len() && name.ends_with(&pat[1..]);
            }
            return wildmatch(pat, name, false);
        }
        let mut pat: &[u8] = &self.pat;
        let mut prefix = self.nowild;
        if pat.first() == Some(&b'/') {
            pat = &pat[1..];
            prefix = prefix.saturating_sub(1);
        }
        let baselen = base.len();
        if path.len() < baselen + 1 || (baselen > 0 && path[baselen] != b'/') || &path[..baselen] != base {
            return false;
        }
        let name = if baselen > 0 { &path[baselen + 1..] } else { path };
        if prefix > 0 {
            // A quick rejection only: the whole pattern is matched below
            // (a `**` right after the literal prefix is no boundary).
            if prefix > name.len() || name[..prefix] != pat[..prefix] {
                return false;
            }
            if prefix == pat.len() {
                return prefix == name.len();
            }
        }
        wildmatch(pat, name, true)
    }

    /// The literal file name this pattern can only match, if any.
    fn exact_name(&self) -> Option<&[u8]> {
        (self.nodir && !self.mustbedir && self.nowild == self.pat.len()).then_some(self.pat.as_slice())
    }

    /// The literal suffix of a `*literal` file-name pattern.
    fn suffix(&self) -> Option<&[u8]> {
        (self.nodir && !self.mustbedir && self.endswith && self.nowild != self.pat.len()).then(|| &self.pat[1..])
    }
}

// ---- files --------------------------------------------------------------------------------

/// The states one line (or macro) assigns, in order.
type States = Vec<(Arc<str>, State)>;

#[derive(Clone, Debug)]
struct Line {
    pattern: Pattern,
    states: States,
}

/// One parsed attributes file.
#[derive(Clone, Debug, Default)]
pub struct AttrFile {
    lines: Vec<Line>,
    /// `(macro name, its states)`, in file order.
    macros: Vec<(Arc<str>, States)>,
    /// Line indices of patterns matching only one exact file name.
    by_name: HashMap<Vec<u8>, Vec<u32>>,
    /// Line indices of `*suffix` patterns, by suffix, with every suffix
    /// length that occurs.
    by_suffix: HashMap<Vec<u8>, Vec<u32>>,
    suffix_lens: Vec<usize>,
    /// Every other line index, in order.
    general: Vec<u32>,
    /// Problems found while parsing (with the file's name and line).
    pub warnings: Vec<String>,
}

const BLANK: &[u8] = b" \t\r\n";

fn is_blank(c: u8) -> bool {
    BLANK.contains(&c)
}

fn skip_blank(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| is_blank(c)).count();
    &s[n..]
}

fn until_blank(s: &[u8]) -> usize {
    s.iter().position(|&c| is_blank(c)).unwrap_or(s.len())
}

fn attr_name_valid(n: &[u8]) -> bool {
    !n.is_empty() && n[0] != b'-' && n.iter().all(|&c| c == b'-' || c == b'.' || c == b'_' || c.is_ascii_alphanumeric())
}

/// Git's `unquote_c_style`: the unquoted pattern and the rest of the line
/// after the closing quote, or `None` if `s` is not a well-formed quoted
/// string.
fn unquote_c(s: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut out = Vec::new();
    let mut i = 1;
    loop {
        let c = *s.get(i)?;
        i += 1;
        match c {
            b'"' => return Some((out, &s[i..])),
            b'\\' => {
                let e = *s.get(i)?;
                i += 1;
                match e {
                    b'a' => out.push(7),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'v' => out.push(11),
                    b'\\' | b'"' => out.push(e),
                    b'0'..=b'3' => {
                        let d1 = *s.get(i)?;
                        let d2 = *s.get(i + 1)?;
                        if !(b'0'..=b'7').contains(&d1) || !(b'0'..=b'7').contains(&d2) {
                            return None;
                        }
                        i += 2;
                        out.push(((e - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0'));
                    }
                    _ => return None,
                }
            }
            c => out.push(c),
        }
    }
}

/// Parse the states of a line (Git's `parse_attr`); `None` if one is
/// invalid (Git then ignores the whole line).
fn parse_states(mut s: &[u8]) -> Option<States> {
    let mut out = Vec::new();
    s = skip_blank(s);
    while !s.is_empty() {
        let end = until_blank(s);
        let tok = &s[..end];
        let (head, value) = match tok.iter().position(|&c| c == b'=') {
            Some(i) => (&tok[..i], Some(&tok[i + 1..])),
            None => (tok, None),
        };
        let (name, state) = match head.first() {
            Some(b'-') => (&head[1..], State::Unset),
            Some(b'!') => (&head[1..], State::Unspecified),
            _ => (
                head,
                match value {
                    None => State::Set,
                    Some(v) => State::Value(String::from_utf8_lossy(v).into_owned()),
                },
            ),
        };
        if !attr_name_valid(name) || name.starts_with(b"builtin_") {
            return None;
        }
        out.push((Arc::from(std::str::from_utf8(name).ok()?), state));
        s = skip_blank(&s[end..]);
    }
    Some(out)
}

impl AttrFile {
    /// Parse `data`, the content of attributes file `src` (named in
    /// warnings). `macros_ok`: `[attr]` lines define macros (the root file
    /// and the local file); elsewhere they are ignored, as Git does.
    pub fn parse(data: &[u8], src: &str, macros_ok: bool) -> AttrFile {
        let mut f = AttrFile::default();
        if data.len() > MAX_FILE {
            f.warnings.push(format!("{src} is larger than {} KiB; ignored (no attributes from it apply)", MAX_FILE >> 10));
            return f;
        }
        // Git stops at a NUL byte.
        let data = &data[..memchr::memchr(0, data).unwrap_or(data.len())];
        let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
        for (n, line) in data.split(|&c| c == b'\n').enumerate() {
            let lineno = n + 1;
            let cp = skip_blank(line);
            if cp.is_empty() || cp[0] == b'#' {
                continue;
            }
            if line.len() >= MAX_LINE {
                f.warnings.push(format!("{src}:{lineno}: line of {MAX_LINE} bytes or more; ignored"));
                continue;
            }
            let (name, rest): (Vec<u8>, &[u8]) = match (cp[0] == b'"').then(|| unquote_c(cp)).flatten() {
                Some((p, rest)) => (p, rest),
                None => {
                    let e = until_blank(cp);
                    (cp[..e].to_vec(), &cp[e..])
                }
            };
            if name.len() > 6 && name.starts_with(b"[attr]") {
                let m = skip_blank(&name[6..]);
                let mlen = until_blank(m);
                let mname = &m[..mlen];
                if !macros_ok {
                    f.warnings.push(format!(
                        "{src}:{lineno}: macro {} not allowed outside the top-level {ATTRIBUTES_FILE}; ignored",
                        String::from_utf8_lossy(&name)
                    ));
                    continue;
                }
                if !attr_name_valid(mname) {
                    f.warnings.push(format!("{src}:{lineno}: {} is not a valid attribute name; line ignored", String::from_utf8_lossy(mname)));
                    continue;
                }
                // The states follow the pattern token (anything after the
                // name inside a quoted token is dropped, as Git does).
                let Some(states) = parse_states(rest) else {
                    f.warnings.push(format!("{src}:{lineno}: invalid attribute name; line ignored"));
                    continue;
                };
                let mname: Arc<str> = Arc::from(std::str::from_utf8(mname).expect("validated ASCII"));
                f.macros.push((mname, states));
                continue;
            }
            let Some(states) = parse_states(rest) else {
                f.warnings.push(format!("{src}:{lineno}: invalid attribute name; line ignored"));
                continue;
            };
            let Some(pattern) = Pattern::parse(&name) else {
                f.warnings.push(format!(
                    "{src}:{lineno}: negative patterns are ignored in attributes (use '\\!' for a literal leading '!')"
                ));
                continue;
            };
            let idx = f.lines.len() as u32;
            if let Some(n) = pattern.exact_name() {
                f.by_name.entry(n.to_vec()).or_default().push(idx);
            } else if let Some(s) = pattern.suffix() {
                if !f.suffix_lens.contains(&s.len()) {
                    f.suffix_lens.push(s.len());
                }
                f.by_suffix.entry(s.to_vec()).or_default().push(idx);
            } else if !pattern.mustbedir {
                f.general.push(idx);
            }
            f.lines.push(Line { pattern, states });
        }
        f
    }

    /// Indices of the lines matching `path` (relative to the repository),
    /// for a file in directory `base`, in no particular order.
    fn matching(&self, path: &[u8], name_at: usize, base: &[u8], out: &mut Vec<u32>) {
        let name = &path[name_at..];
        if let Some(v) = self.by_name.get(name) {
            out.extend_from_slice(v);
        }
        for &l in &self.suffix_lens {
            if name.len() >= l {
                if let Some(v) = self.by_suffix.get(&name[name.len() - l..]) {
                    out.extend_from_slice(v);
                }
            }
        }
        for &i in &self.general {
            if self.lines[i as usize].pattern.matches(path, name_at, base) {
                out.push(i);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.macros.is_empty()
    }
}

// ---- where attributes files come from -------------------------------------------------------

/// Where the attributes files of a working copy or tree are read from.
pub trait AttrSource {
    /// The content of `dir/.veilattributes` if it is a regular file (never
    /// through or at a symlink); `Err` with the reason when it exists but
    /// cannot be read (sealed for a scope this reader is not in).
    fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String>;
}

/// No attributes anywhere.
struct NoSource;

impl AttrSource for NoSource {
    fn read_attributes(&self, _: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

/// The `.veilattributes` files of a working copy (or any backend).
pub struct BackendSource<'a>(pub &'a dyn StorageBackend);

impl AttrSource for BackendSource<'_> {
    fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
        let path = dir.join(ATTRIBUTES_FILE);
        match self.0.metadata(&path) {
            // Never read a huge file only to drop it.
            Ok(Some(m)) if m.kind == NodeKind::File && m.len > MAX_FILE as u64 => return Err(too_large()),
            Ok(Some(m)) if m.kind == NodeKind::File => {}
            Ok(_) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        }
        match self.0.read(&path) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn too_large() -> String {
    format!("it is larger than {} KiB", MAX_FILE >> 10)
}

/// The `.veilattributes` files of a recorded tree.
pub struct TreeSource<'a> {
    pub store: &'a ObjectStore,
    pub tree: ObjectId,
}

impl AttrSource for TreeSource<'_> {
    fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
        let path = dir.join(ATTRIBUTES_FILE);
        let e = match crate::tree::lookup(self.store, &self.tree, &path) {
            Ok(Some(e)) => e,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if e.kind != EntryKind::File {
            return Ok(None);
        }
        if e.size > MAX_FILE as u64 {
            return Err(too_large());
        }
        // Readers without the key see the last public version of a sealed
        // edit, as everywhere else.
        match self.store.read_entry(&e) {
            Ok(d) => Ok(Some(d)),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// The `.veilattributes` files of a recorded tree as one **audience** reads
/// them (BUG-705): a file whose content is public (or under a released
/// embargo), or sealed exactly for `audience`, is read as it is; a file
/// sealed for anyone else gives its last public version (its fallback), or
/// nothing. Attributes that shape a merged result therefore come only from
/// what the result's readers can read: a sealed `merge=union` never decides
/// a public merge (the rule public patches already follow).
pub struct AudienceTreeSource<'a> {
    pub store: &'a ObjectStore,
    pub tree: ObjectId,
    /// [`crate::object::Visibility::Public`] for a public result.
    pub audience: crate::object::Visibility,
}

impl AttrSource for AudienceTreeSource<'_> {
    fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
        use crate::blame::{readable_version, Readable, Reader};
        let path = dir.join(ATTRIBUTES_FILE);
        let e = match crate::tree::lookup(self.store, &self.tree, &path) {
            Ok(Some(e)) => e,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if e.kind != EntryKind::File {
            return Ok(None);
        }
        if e.size > MAX_FILE as u64 {
            return Err(too_large());
        }
        let shown = |v: &crate::object::Visibility| match v {
            crate::object::Visibility::Public => true,
            crate::object::Visibility::Embargoed { embargo } if self.store.keys.embargo_released(embargo) => true,
            v => *v == self.audience,
        };
        // What it really is sealed for (the visibility the opened object
        // proves, never the entry's label).
        let data = match readable_version(self.store, &e, Reader::Me).map_err(|e| e.to_string())? {
            Readable::Plain { data, visibility, .. } if shown(&visibility) => Some(data),
            _ => match readable_version(self.store, &e, Reader::Public).map_err(|e| e.to_string())? {
                Readable::Plain { data, .. } | Readable::Fallback { data, .. } => Some(data),
                Readable::Redacted(_) => None,
            },
        };
        match data {
            Some(d) if d.len() > MAX_FILE => Err(too_large()),
            d => Ok(d),
        }
    }
}

// ---- the attributes of a working copy or tree -----------------------------------------------

/// One directory's attributes file, read once, parsed on first need.
struct DirFile {
    /// The bytes, or why they cannot be read; `None` when there is no file.
    data: Option<std::result::Result<Vec<u8>, String>>,
    parsed: std::sync::OnceLock<Option<Arc<AttrFile>>>,
}

/// A fingerprint of the attributes files a path is under (see
/// [`Attrs::fingerprint`]).
pub type Fingerprint = [u8; 16];

/// The attributes in force for every path of one working copy or tree,
/// read lazily (only the directories of paths asked about), each file once
/// and parsed only when an attribute is asked for.
pub struct Attrs<'a> {
    source: Box<dyn AttrSource + Send + Sync + 'a>,
    local: Option<Arc<AttrFile>>,
    local_hash: Fingerprint,
    files: Mutex<HashMap<VPath, Arc<DirFile>>>,
    chains: Mutex<HashMap<VPath, Fingerprint>>,
    warnings: Mutex<Vec<String>>,
}

fn fingerprint_of(parts: &[&[u8]]) -> Fingerprint {
    let mut h = blake3::Hasher::new();
    h.update(b"veil attributes fingerprint v1\0");
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize().as_bytes()[..16]);
    out
}

impl std::fmt::Debug for Attrs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Attrs")
    }
}

/// Every attribute assigned to one path, by name.
pub type Assigned = Vec<(Arc<str>, State)>;

impl<'a> Attrs<'a> {
    /// No attributes at all: no conversion, built-in diff and merge (Git
    /// imports, patches applied to recorded bytes).
    pub fn none() -> Attrs<'static> {
        Attrs::with_source(Box::new(NoSource), None)
    }

    /// Attributes read through `source`, under `local` (the device-local
    /// file's content, highest priority).
    pub fn with_source(source: Box<dyn AttrSource + Send + Sync + 'a>, local: Option<&[u8]>) -> Attrs<'a> {
        Attrs {
            source,
            local: local.map(|d| Arc::new(AttrFile::parse(d, LOCAL_ATTRIBUTES, true))),
            local_hash: fingerprint_of(&[local.unwrap_or(b"\0none")]),
            files: Mutex::new(HashMap::new()),
            chains: Mutex::new(HashMap::new()),
            warnings: Mutex::new(Vec::new()),
        }
    }

    /// The attributes of working copy `fs`, with the device-local file of
    /// the repository `store` belongs to.
    pub fn for_backend(store: &ObjectStore, fs: &'a dyn StorageBackend) -> Attrs<'a> {
        Attrs::with_source(Box::new(BackendSource(fs)), store.local_attributes().as_deref())
    }

    /// The attributes of recorded tree `tree`, with the device-local file.
    pub fn for_tree(store: &'a ObjectStore, tree: ObjectId) -> Attrs<'a> {
        Attrs::with_source(Box::new(TreeSource { store, tree }), store.local_attributes().as_deref())
    }

    /// The attributes of recorded tree `tree` as `audience` reads them
    /// ([`AudienceTreeSource`]), with the device-local file.
    pub fn for_audience(store: &'a ObjectStore, tree: ObjectId, audience: crate::object::Visibility) -> Attrs<'a> {
        Attrs::with_source(Box::new(AudienceTreeSource { store, tree, audience }), store.local_attributes().as_deref())
    }

    /// Warnings so far (files unreadable or too large, ignored lines), each
    /// once.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = self.local.as_ref().map(|l| l.warnings.clone()).unwrap_or_default();
        w.extend(self.warnings.lock().expect("attrs warnings").iter().cloned());
        w
    }

    /// The attributes file of `dir`, read (not parsed) once.
    fn raw(&self, dir: &VPath) -> Arc<DirFile> {
        if let Some(f) = self.files.lock().expect("attrs files").get(dir) {
            return f.clone();
        }
        let f = Arc::new(DirFile {
            data: self.source.read_attributes(dir).transpose(),
            parsed: std::sync::OnceLock::new(),
        });
        self.files.lock().expect("attrs files").insert(dir.clone(), f.clone());
        f
    }

    fn file(&self, dir: &VPath) -> Option<Arc<AttrFile>> {
        let raw = self.raw(dir);
        raw.parsed
            .get_or_init(|| {
                let shown = if dir.is_root() {
                    ATTRIBUTES_FILE.to_string()
                } else {
                    format!("{dir}/{ATTRIBUTES_FILE}")
                };
                match &raw.data {
                    Some(Ok(d)) => {
                        let f = AttrFile::parse(d, &shown, dir.is_root());
                        self.warnings.lock().expect("attrs warnings").extend(f.warnings.iter().cloned());
                        Some(Arc::new(f))
                    }
                    None => None,
                    Some(Err(why)) => {
                        self.warnings
                            .lock()
                            .expect("attrs warnings")
                            .push(format!("{shown} cannot be read ({why}); its attributes do not apply here"));
                        None
                    }
                }
            })
            .clone()
    }

    /// A fingerprint of every attributes file `path` (a file) is under, and
    /// of the local file: equal fingerprints mean equal attributes, and
    /// nothing is parsed to compute one (the stat cache keys line-ending
    /// facts on it).
    pub fn fingerprint(&self, path: &VPath) -> Fingerprint {
        let dir = path.parent().unwrap_or_default();
        self.chain(&dir)
    }

    fn chain(&self, dir: &VPath) -> Fingerprint {
        if let Some(c) = self.chains.lock().expect("attrs chains").get(dir) {
            return *c;
        }
        // From the root down (iteratively: paths can be deep).
        let mut dirs = vec![VPath::root()];
        dirs.extend(dir.ancestors());
        if !dir.is_root() {
            dirs.push(dir.clone());
        }
        let mut up = self.local_hash;
        for d in dirs {
            if let Some(c) = self.chains.lock().expect("attrs chains").get(&d) {
                up = *c;
                continue;
            }
            let raw = self.raw(&d);
            let c = match &raw.data {
                None => fingerprint_of(&[&up, b"\0none"]),
                Some(Ok(data)) => fingerprint_of(&[&up, data]),
                Some(Err(e)) => fingerprint_of(&[&up, b"\0unreadable", e.as_bytes()]),
            };
            self.chains.lock().expect("attrs chains").insert(d, c);
            up = c;
        }
        up
    }

    /// Every attribute assigned to `path` (a file), in the order Git's
    /// `check-attr -a` lists them is not kept: sorted by name. Explicitly
    /// unspecified attributes (`!name`) are included as
    /// [`State::Unspecified`].
    pub fn assigned(&self, path: &VPath) -> Assigned {
        if path.is_root() {
            return Vec::new();
        }
        // Files from the highest priority to the lowest: local, the
        // deepest directory, …, the root.
        let mut dirs = vec![VPath::root()];
        dirs.extend(path.ancestors());
        let mut stack: Vec<(Arc<AttrFile>, VPath)> = Vec::new();
        for d in dirs {
            if let Some(f) = self.file(&d) {
                stack.push((f, d));
            }
        }
        if stack.is_empty() && self.local.is_none() {
            return Vec::new();
        }
        // Macros: the highest-priority definition wins (root and local
        // only), the built-in `binary` lowest.
        let mut macros: HashMap<Arc<str>, States> = HashMap::new();
        let mut define = |f: &AttrFile| {
            for (name, states) in f.macros.iter().rev() {
                macros.entry(name.clone()).or_insert_with(|| states.clone());
            }
        };
        if let Some(l) = &self.local {
            define(l);
        }
        if let Some((root, _)) = stack.first() {
            define(root);
        }
        macros
            .entry(Arc::from("binary"))
            .or_insert_with(|| vec![(Arc::from("diff"), State::Unset), (Arc::from("merge"), State::Unset), (Arc::from("text"), State::Unset)]);

        let bytes = path.as_str().as_bytes();
        let name_at = bytes.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
        let mut out: HashMap<Arc<str>, State> = HashMap::new();
        let mut order: Vec<Arc<str>> = Vec::new();
        let mut hits = Vec::new();
        let local = self.local.clone().map(|l| (l, VPath::root()));
        for (f, dir) in local.iter().chain(stack.iter().rev()) {
            hits.clear();
            f.matching(bytes, name_at, dir.as_str().as_bytes(), &mut hits);
            hits.sort_unstable();
            hits.dedup();
            for &i in hits.iter().rev() {
                fill(&f.lines[i as usize].states, &macros, &mut out, &mut order);
            }
        }
        let mut v: Assigned = order.into_iter().map(|n| (n.clone(), out.remove(&n).expect("filled"))).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// What Veil does with `path`.
    pub fn for_path(&self, path: &VPath) -> PathAttrs {
        PathAttrs::from_assigned(&self.assigned(path))
    }
}

/// Git's `fill_one` + `macroexpand_one`, iteratively: each attribute takes
/// the first state met, a macro set to true expands in place.
fn fill(
    states: &States,
    macros: &HashMap<Arc<str>, States>,
    out: &mut HashMap<Arc<str>, State>,
    order: &mut Vec<Arc<str>>,
) {
    let mut stack: Vec<(&States, usize)> = vec![(states, states.len())];
    while let Some((s, i)) = stack.last_mut() {
        if *i == 0 {
            stack.pop();
            continue;
        }
        *i -= 1;
        let (name, v) = &s[*i];
        if out.contains_key(name) {
            continue;
        }
        out.insert(name.clone(), v.clone());
        order.push(name.clone());
        if *v == State::Set {
            if let Some(m) = macros.get(name) {
                stack.push((m, m.len()));
            }
        }
    }
}

// ---- what Veil does with a path -------------------------------------------------------------

/// How a file's content is diffed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffAttr {
    /// Text if it looks like text (no NUL in its first 8 000 bytes).
    Auto,
    /// `-diff` / `binary`: "binary files differ".
    Binary,
    /// `diff=<name>`: a device-local textconv if this device defines one.
    Driver(String),
}

/// How a file's content is merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeAttr {
    /// The built-in line merge (a binary-looking file conflicts as a whole).
    Text,
    /// `-merge` / `binary` / `merge=binary`: a whole-file conflict.
    Binary,
    /// `merge=union`: both sides' lines of a conflicting hunk, ours first.
    Union,
    /// `merge=<name>`: a device-local merge driver if this device defines
    /// one (else the built-in text merge).
    Driver(String),
}

/// Git's resolved `crlf_action`, with `core.autocrlf=false` and LF as the
/// native line ending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Conversion {
    /// No line-ending conversion.
    None,
    /// `text` (or `eol`): CRLF → LF when recording; LF → CRLF at checkout
    /// when `crlf`.
    Text { crlf: bool },
    /// `text=auto`: as `Text`, for content that looks like text only.
    Auto { crlf: bool },
}

impl Conversion {
    /// The line ending written at checkout.
    pub fn writes_crlf(&self) -> bool {
        matches!(self, Conversion::Text { crlf: true } | Conversion::Auto { crlf: true })
    }

    pub fn is_none(&self) -> bool {
        *self == Conversion::None
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Conversion::None => "none",
            Conversion::Text { crlf: false } => "text, LF in the working copy",
            Conversion::Text { crlf: true } => "text, CRLF in the working copy",
            Conversion::Auto { crlf: false } => "auto (if text), LF in the working copy",
            Conversion::Auto { crlf: true } => "auto (if text), CRLF in the working copy",
        }
    }
}

/// What the attributes of one path mean to Veil.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathAttrs {
    pub conversion: Conversion,
    pub diff: DiffAttr,
    pub merge: MergeAttr,
}

impl Default for PathAttrs {
    fn default() -> Self {
        PathAttrs {
            conversion: Conversion::None,
            diff: DiffAttr::Auto,
            merge: MergeAttr::Text,
        }
    }
}

impl PathAttrs {
    pub fn from_assigned(a: &Assigned) -> PathAttrs {
        let get = |n: &str| a.iter().find(|(k, _)| &**k == n).map(|(_, v)| v);
        #[derive(PartialEq)]
        enum Crlf {
            Undefined,
            Binary,
            Text,
            Input,
            Auto,
        }
        let check = |s: Option<&State>| match s {
            Some(State::Set) => Crlf::Text,
            Some(State::Unset) => Crlf::Binary,
            Some(State::Value(v)) if v == "input" => Crlf::Input,
            Some(State::Value(v)) if v == "auto" => Crlf::Auto,
            _ => Crlf::Undefined,
        };
        let mut action = check(get("text"));
        if action == Crlf::Undefined {
            action = check(get("crlf"));
        }
        let eol = match get("eol") {
            Some(State::Value(v)) if v == "lf" => Some(false),
            Some(State::Value(v)) if v == "crlf" => Some(true),
            _ => None,
        };
        let conversion = match (action, eol) {
            (Crlf::Binary, _) => Conversion::None,
            (Crlf::Auto, e) => Conversion::Auto { crlf: e == Some(true) },
            (_, Some(crlf)) => Conversion::Text { crlf },
            (Crlf::Text | Crlf::Input, None) => Conversion::Text { crlf: false },
            (Crlf::Undefined, None) => Conversion::None,
        };
        let diff = match get("diff") {
            Some(State::Unset) => DiffAttr::Binary,
            Some(State::Value(v)) => DiffAttr::Driver(v.clone()),
            _ => DiffAttr::Auto,
        };
        let merge = match get("merge") {
            Some(State::Unset) => MergeAttr::Binary,
            Some(State::Value(v)) if v == "text" => MergeAttr::Text,
            Some(State::Value(v)) if v == "binary" => MergeAttr::Binary,
            Some(State::Value(v)) if v == "union" => MergeAttr::Union,
            Some(State::Value(v)) => MergeAttr::Driver(v.clone()),
            _ => MergeAttr::Text,
        };
        PathAttrs { conversion, diff, merge }
    }
}

// ---- line-ending conversion (Git's convert.c) -----------------------------------------------

/// Git's `text_stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextStat {
    pub nul: usize,
    pub lonecr: usize,
    pub lonelf: usize,
    pub crlf: usize,
    pub printable: usize,
    pub nonprintable: usize,
}

impl TextStat {
    /// Git's `gather_stats`.
    pub fn of(buf: &[u8]) -> TextStat {
        let mut s = TextStat::default();
        let mut i = 0;
        while i < buf.len() {
            let c = buf[i];
            if c == b'\r' {
                if buf.get(i + 1) == Some(&b'\n') {
                    s.crlf += 1;
                    i += 2;
                } else {
                    s.lonecr += 1;
                    i += 1;
                }
                continue;
            }
            if c == b'\n' {
                s.lonelf += 1;
            } else if c == 127 {
                s.nonprintable += 1;
            } else if c < 32 {
                match c {
                    8 | 9 | 27 | 12 => s.printable += 1,
                    0 => {
                        s.nul += 1;
                        s.nonprintable += 1;
                    }
                    _ => s.nonprintable += 1,
                }
            } else {
                s.printable += 1;
            }
            i += 1;
        }
        if buf.last() == Some(&0x1a) {
            s.nonprintable = s.nonprintable.saturating_sub(1);
        }
        s
    }

    /// Git's `convert_is_binary`.
    pub fn is_binary(&self) -> bool {
        self.lonecr > 0 || self.nul > 0 || (self.printable >> 7) < self.nonprintable
    }
}

/// What recording does to a file's bytes ([`to_odb`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToOdb {
    /// Recorded as they are (nothing to convert).
    Unchanged,
    /// Recorded as these bytes (CRLF → LF).
    Converted(Vec<u8>),
    /// The conversion would lose information (mixed line endings, a lone
    /// CR): recorded as they are, and the user is told why.
    Lossy(&'static str),
}

/// The bytes recorded for working-copy content `data` under `conv`: CRLF
/// normalised to LF where the attributes ask for it and the conversion is
/// lossless (every line ending CRLF, no lone CR), as Git's `crlf_to_git`.
/// `recorded_has_cr` says whether the recorded version of the path (the
/// parent entry) holds a CR; under `text=auto` such a file is never
/// normalised (Git's "safer autocrlf"). It is only called when needed.
pub fn to_odb(data: &[u8], conv: Conversion, recorded_has_cr: impl FnOnce() -> bool) -> ToOdb {
    if conv.is_none() || data.is_empty() || memchr::memchr(b'\r', data).is_none() {
        return ToOdb::Unchanged;
    }
    let st = TextStat::of(data);
    if st.crlf == 0 {
        return ToOdb::Unchanged;
    }
    if let Conversion::Auto { .. } = conv {
        if st.is_binary() || recorded_has_cr() {
            return ToOdb::Unchanged;
        }
    }
    if st.lonecr > 0 {
        return ToOdb::Lossy("it holds a lone CR");
    }
    if st.lonelf > 0 {
        return ToOdb::Lossy("its line endings are mixed (CRLF and LF)");
    }
    ToOdb::Converted(strip_cr_before_lf(data))
}

fn strip_cr_before_lf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

/// The bytes checkout writes for recorded content `data` under `conv`
/// (Git's `crlf_to_worktree`), or `None` when they are `data` itself.
pub fn to_worktree(data: &[u8], conv: Conversion) -> Option<Vec<u8>> {
    if !conv.writes_crlf() || data.is_empty() {
        return None;
    }
    let st = TextStat::of(data);
    if st.lonelf == 0 {
        return None;
    }
    if let Conversion::Auto { .. } = conv {
        if st.lonecr > 0 || st.crlf > 0 || st.is_binary() {
            return None;
        }
    }
    Some(lf_to_crlf(data))
}

/// Insert a CR before every LF not already preceded by one.
pub fn lf_to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 16);
    for (i, &c) in data.iter().enumerate() {
        if c == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(c);
    }
    out
}

// ---- device-local drivers -------------------------------------------------------------------

/// What a merge driver produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriverMerge {
    /// The merged content (the driver exited 0).
    Clean(Vec<u8>),
    /// The driver reported a conflict (non-zero exit), or failed.
    Conflict,
}

/// The inputs of a merge driver. `base` is empty when the base's audience
/// is not the result's (it must never reach a result it could leak into).
pub struct DriverInput<'x> {
    pub path: &'x VPath,
    pub base: &'x [u8],
    pub ours: &'x [u8],
    pub theirs: &'x [u8],
}

/// Driver definitions of this device (never of a repository): the CLI
/// reads them from `.veil/local/config.toml` and `$VEIL_HOME/config.toml`
/// and registers them with [`ObjectStore::set_device_drivers`].
pub trait DeviceDrivers: Send + Sync {
    /// Is a merge driver called `name` defined on this device?
    fn has_merge(&self, name: &str) -> bool;
    /// Run merge driver `name`. Never called for a name `has_merge` denies.
    fn merge(&self, name: &str, input: &DriverInput<'_>) -> DriverMerge;
    /// Is a diff driver with a `textconv` called `name` defined here?
    fn has_textconv(&self, name: &str) -> bool;
    /// Run textconv `name` on `data`; `None` if it failed.
    fn textconv(&self, name: &str, path: &VPath, data: &[u8]) -> Option<Vec<u8>>;
    /// A path's attributes name a driver this device does not define (said
    /// once per name and kind by the implementation).
    fn undefined(&self, kind: &str, name: &str, path: &VPath);
}

/// How the built-in merge treats `path` under `attrs`, resolving a named
/// driver against this device's definitions: an undefined name is the
/// built-in text merge (with a warning).
pub fn merge_strategy(store: &ObjectStore, attrs: &Attrs<'_>, path: &VPath) -> MergeAttr {
    match attrs.for_path(path).merge {
        MergeAttr::Driver(name) => match store.device_drivers() {
            Some(d) if d.has_merge(&name) => MergeAttr::Driver(name),
            Some(d) => {
                d.undefined("merge", &name, path);
                MergeAttr::Text
            }
            None => MergeAttr::Text,
        },
        m => m,
    }
}

/// How `path` is diffed under `attrs`, resolving a named driver against
/// this device's textconv definitions: an undefined name is the built-in
/// diff (with a warning).
pub fn diff_strategy(store: &ObjectStore, attrs: &Attrs<'_>, path: &VPath) -> DiffAttr {
    match attrs.for_path(path).diff {
        DiffAttr::Driver(name) => match store.device_drivers() {
            Some(d) if d.has_textconv(&name) => DiffAttr::Driver(name),
            Some(d) => {
                d.undefined("diff", &name, path);
                DiffAttr::Auto
            }
            None => DiffAttr::Auto,
        },
        d => d,
    }
}

/// The union merge of `ours` and `theirs` over `base`: every clean hunk of
/// the line merge, and for a conflicting one ours' lines then theirs'
/// (Git's `merge=union`). Lines only the base holds never appear.
pub fn union_merge(base: &[u8], ours: &[u8], theirs: &[u8]) -> Vec<u8> {
    crate::textmerge::merge_union(base, ours, theirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wm(p: &str, t: &str) -> bool {
        wildmatch(p.as_bytes(), t.as_bytes(), true)
    }

    #[test]
    fn wildmatch_basics() {
        assert!(wm("foo", "foo"));
        assert!(!wm("foo", "bar"));
        assert!(wm("*", "foo"));
        assert!(!wm("*", "foo/bar"));
        assert!(wm("**", "foo/bar"));
        assert!(wm("**/foo", "foo"));
        assert!(wm("**/foo", "a/b/foo"));
        assert!(wm("a/**/b", "a/b"));
        assert!(wm("a/**/b", "a/x/y/b"));
        assert!(wm("a/**", "a/x/y"));
        assert!(!wm("a/**", "a"));
        assert!(wm("[a-c]x", "bx"));
        assert!(!wm("[!a-c]x", "bx"));
        assert!(wm("[[:digit:]]", "5"));
        assert!(wm("\\*", "*"));
        assert!(!wm("a?b", "a/b"));
        assert!(wm("*.txt", "x.txt"));
        assert!(!wm("*/*.txt", "x.txt"));
    }

    #[test]
    fn hostile_patterns_terminate_quickly() {
        let p = "*a".repeat(500) + "b";
        let t = "a".repeat(4000);
        let start = std::time::Instant::now();
        assert!(!wm(&p, &t));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    fn attrs(files: &[(&str, &str)]) -> Attrs<'static> {
        struct Map(HashMap<VPath, Vec<u8>>);
        impl AttrSource for Map {
            fn read_attributes(&self, dir: &VPath) -> std::result::Result<Option<Vec<u8>>, String> {
                Ok(self.0.get(dir).cloned())
            }
        }
        let m = files.iter().map(|(d, c)| (VPath::new(d).unwrap(), c.as_bytes().to_vec())).collect();
        Attrs::with_source(Box::new(Map(m)), None)
    }

    fn check(a: &Attrs, p: &str) -> Vec<(String, String)> {
        a.assigned(&VPath::new(p).unwrap()).into_iter().map(|(n, v)| (n.to_string(), v.display().to_string())).collect()
    }

    #[test]
    fn precedence_and_macros() {
        let a = attrs(&[("", "* text\n*.png binary\n[attr]crlfy text eol=crlf\n*.bat crlfy\n"), ("sub", "*.png text\n")]);
        assert_eq!(check(&a, "x.c"), vec![("text".into(), "set".into())]);
        assert_eq!(
            check(&a, "i.png"),
            vec![("binary".into(), "set".into()), ("diff".into(), "unset".into()), ("merge".into(), "unset".into()), ("text".into(), "unset".into())]
        );
        // The deeper file wins for `text`, the macro's other states stay.
        let s = check(&a, "sub/i.png");
        assert!(s.contains(&("text".into(), "set".into())));
        assert!(s.contains(&("diff".into(), "unset".into())));
        assert_eq!(a.for_path(&VPath::new("run.bat").unwrap()).conversion, Conversion::Text { crlf: true });
        // Macros are not defined in subdirectories.
        let b = attrs(&[("sub", "[attr]m text\n*.x m\n")]);
        assert_eq!(check(&b, "sub/a.x"), vec![("m".into(), "set".into())]);
        assert!(!b.warnings().is_empty());
    }

    #[test]
    fn conversions_round_trip_or_refuse() {
        let crlf = Conversion::Text { crlf: true };
        assert_eq!(to_odb(b"a\r\nb\r\n", crlf, || false), ToOdb::Converted(b"a\nb\n".to_vec()));
        assert!(matches!(to_odb(b"a\r\nb\n", crlf, || false), ToOdb::Lossy(_)));
        assert!(matches!(to_odb(b"a\r\rb\r\n", crlf, || false), ToOdb::Lossy(_)));
        assert_eq!(to_odb(b"a\nb\n", crlf, || false), ToOdb::Unchanged);
        assert_eq!(to_worktree(b"a\nb\n", crlf), Some(b"a\r\nb\r\n".to_vec()));
        assert_eq!(to_worktree(b"a\nb\n", Conversion::Text { crlf: false }), None);
        // auto: binary content and a recorded CR are left alone.
        let auto = Conversion::Auto { crlf: false };
        assert_eq!(to_odb(b"a\0\r\n", auto, || false), ToOdb::Unchanged);
        assert_eq!(to_odb(b"a\r\n", auto, || true), ToOdb::Unchanged);
        assert_eq!(to_odb(b"a\r\n", auto, || false), ToOdb::Converted(b"a\n".to_vec()));
    }
}
