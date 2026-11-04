//! Patches: the strict parser of Git's mbox format, the overlay applier
//! behind `vl am`, and the mbox writer behind `vl format-patch`.
//!
//! Feature 4 of the Git-parity round (`docs/design/git-parity/4-patches.md`).
//!
//! # Import (`vl am`)
//!
//! [`parse`] reads Git's `format-patch` output (one or more messages in an
//! mbox), a single mail without a postmark, or a plain unified diff. It is
//! written by hand, without regexes, and refuses anything it does not
//! understand exactly:
//!
//! * mail headers `From`, `Date` and `Subject` (RFC 2047 encoded words in
//!   UTF-8, US-ASCII or ISO-8859-1); a decoded header holding a control
//!   character (other than tab), a C1 control or a bidirectional override is
//!   refused, so nothing a patch says can rewrite a terminal line;
//! * `[PATCH n/m]` numbering and in-body `From:`/`Date:`/`Subject:` lines;
//! * `diff --git` sections with every extended header Git writes (modes,
//!   new and deleted files, renames, copies, similarity, `index`), Git's
//!   C-quoted paths, text hunks and "no newline at end of file" markers.
//!   Symlinks (mode 120000) and submodules (160000) are read as Git writes
//!   them (the target, or `Subproject commit <id>`, as the content); a type
//!   change is a deletion and a creation of the same path, as Git writes
//!   it. `GIT binary patch` sections (literal and delta blocks) are checked
//!   line by line and their declared sizes bounded before anything is
//!   inflated (`binary`);
//! * every path is checked before it becomes a [`VPath`]: no absolute
//!   path, no empty, `.` or `..` component, no NUL or control character,
//!   no component spelling `.veil` or a VCS directory (`.git`, `.jj`, …,
//!   in any case and with HFS+-ignorable code points), no temp-file name,
//!   at most [`Limits::max_path`] bytes and 255 per component. Nothing is
//!   ever joined to an operating-system path: the applier works in memory.
//!
//! Memory and time are bounded: the input is capped ([`Limits`]), every
//! line, header, hunk count and file count too, and hunks are stored as
//! byte ranges of the input (40 bytes each), not as copies of their lines.
//! Parsing is one pass.
//!
//! [`apply_series`] then records one new change per patch, on top of a
//! destination snapshot, in **one transaction** (all or nothing: a patch
//! that fails anywhere aborts the whole series before anything is recorded,
//! so there is no partial state to resume or clean up, and `vl undo` takes
//! back a whole applied series). Each patch is applied to an
//! [`OverlayBackend`] over a [`TreeView`] of the previous tree, never to the
//! working copy, and the overlay is recorded by the **builder** with the
//! policy guarded by the one this device accepted, as any incoming change
//! is: a `.veilpolicy` edit that would weaken protection is recorded but
//! held back until `vl policy accept` (`P` in `vl status`), isolation,
//! secret scanning and cloaking apply as for any snapshot, and a sealed
//! file edited by a patch stays sealed under its scope. A patch whose
//! content the builder would not record as written (a secret it
//! quarantines, an isolated or ignored path) aborts the series.
//!
//! Symlinks are written to the overlay as links (never followed, never
//! written through: a path below a link is "not a directory", in the
//! patch's own tree or in the one it applies to), with the targets the
//! recording accepts. A submodule is recorded as a pin only: nothing is
//! fetched or cloned. With [`AmOptions::three_way`], a hunk that does not
//! apply falls back to a three-way merge with the pre-image the `index`
//! line names, when this repository's history of the file holds it, and a
//! conflict is recorded as a first-class conflict.
//!
//! # Export (`vl format-patch`)
//!
//! [`format_patches`] writes Git's mbox format. The default audience is
//! the **public** one: trees go through the Git bridge's public projection
//! (`GitBridge::project`) and descriptions through the same
//! placeholder rule as the Git export, so a patch shows exactly what a
//! public remote or a Git push shows. Rename and copy detection (`-M`,
//! `-C`) runs on those projected sides only, so a pair never involves
//! content the audience cannot see. Snapshots a public push withholds
//! (merged-in history of an unreleased embargo) are refused before anything
//! is written. The `me` audience shows this reader's view and says which
//! scopes and embargoes it includes; it never writes sealed content as a
//! `GIT binary patch`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    ops::Range,
    sync::Arc,
};

use crate::{
    builder::{build_tree, BuildOptions, BuildReport},
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    object::{ConflictTerm, EntryKind, Snapshot, TreeEntry},
    policy::{self, Policy},
    repo::Repo,
    store::ObjectStore,
    tree::TreeView,
    vfs::{OverlayBackend, StorageBackend},
    vpath::{NameFolding, VPath},
};

mod binary;

// ---- limits ----------------------------------------------------------------

/// Largest patch input [`parse`] reads by default (1 GiB).
pub const MAX_INPUT: usize = 1 << 30;

/// Bytes all binary sections of a series may inflate to, by default (2 GiB).
pub const MAX_INFLATED: u64 = 2 << 30;

/// Bounds on what [`parse`] and the applier accept.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Bytes of input.
    pub max_input: usize,
    /// Messages in one series.
    pub max_patches: usize,
    /// File sections in all patches together.
    pub max_files: usize,
    /// Hunks in one file section.
    pub max_hunks_per_file: usize,
    /// Hunks in all patches together.
    pub max_hunks: usize,
    /// Bytes in one line of input.
    pub max_line: usize,
    /// Bytes in one (unfolded) mail header.
    pub max_header: usize,
    /// Bytes in one path.
    pub max_path: usize,
    /// Bytes of a file the applier writes (and size a binary section may
    /// declare): `VEIL_MAX_OBJECT`.
    pub max_file_size: u64,
    /// Lines a hunk may be moved by when it does not apply where it says.
    pub max_offset: usize,
    /// Work the applier may spend on the whole series, in compared lines
    /// or 64-byte runs of them (one try of a hunk at one position costs
    /// its line count plus its bytes / 64).
    pub max_work: u64,
    /// Bytes the binary sections of a whole series may inflate to (the
    /// declared sizes are added up while parsing, before anything is
    /// inflated; the results of deltas are counted as they are made).
    pub max_inflated: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input: MAX_INPUT,
            max_patches: 100_000,
            max_files: 1_000_000,
            max_hunks_per_file: 1_000_000,
            max_hunks: 4_000_000,
            max_line: 16 << 20,
            max_header: 64 << 10,
            max_path: 4096,
            max_file_size: crate::pack::max_object_size(),
            max_offset: 1000,
            max_work: 1 << 28,
            max_inflated: MAX_INFLATED,
        }
    }
}

/// Longest path component accepted (what Linux and macOS filesystems hold).
const MAX_COMPONENT: usize = 255;

fn malformed(line: usize, why: impl Display) -> VeilError {
    VeilError::Repo(format!("malformed patch: line {line}: {why}"))
}

/// `bytes` for an error message: lossy UTF-8, at most 80 characters (the
/// CLI escapes control characters when it prints errors).
fn shown(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n == 80 {
            out.push('…');
            break;
        }
        if c.is_control() || forbidden_in_header(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

// ---- what a patch is -------------------------------------------------------

/// What a file section does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOp {
    Modify,
    Create,
    Delete,
    Rename,
    Copy,
}

/// The mode of a section's file: a regular file, an executable one, a
/// symlink (its content is the target) or a submodule (a gitlink: its
/// content is `Subproject commit <id>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Regular,
    Executable,
    Symlink,
    Gitlink,
}

impl Mode {
    pub fn git(self) -> &'static str {
        match self {
            Mode::Regular => "100644",
            Mode::Executable => "100755",
            Mode::Symlink => "120000",
            Mode::Gitlink => "160000",
        }
    }

    fn of(executable: bool) -> Mode {
        if executable {
            Mode::Executable
        } else {
            Mode::Regular
        }
    }

    /// The mode of a file, symlink or gitlink entry.
    fn of_entry(e: &TreeEntry) -> Option<Mode> {
        match e.kind {
            EntryKind::File => Some(Mode::of(e.executable)),
            EntryKind::Symlink => Some(Mode::Symlink),
            EntryKind::Gitlink => Some(Mode::Gitlink),
            _ => None,
        }
    }

    /// The tree entry kind of this mode.
    pub fn kind(self) -> EntryKind {
        match self {
            Mode::Regular | Mode::Executable => EntryKind::File,
            Mode::Symlink => EntryKind::Symlink,
            Mode::Gitlink => EntryKind::Gitlink,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Mode::Regular | Mode::Executable => "regular file",
            Mode::Symlink => "symlink",
            Mode::Gitlink => "submodule",
        }
    }
}

/// A `literal` or `delta` block of a `GIT binary patch` section. Its data
/// is a range of the input, decoded only when the applier needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryKind {
    Literal,
    Delta,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryBlock {
    pub kind: BinaryKind,
    /// The declared size: the file's, for a literal; the delta's, for a
    /// delta (what the zlib stream inflates to).
    pub size: usize,
    /// The base85 lines.
    data: Range<usize>,
}

/// A `GIT binary patch` section: the block that makes the new file, and
/// the one that would make the old one again (only checked: `vl am` reads
/// the forward block).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryPatch {
    pub forward: BinaryBlock,
    pub reverse: Option<BinaryBlock>,
}

/// One hunk. Its lines are not copied: they are a range of the input, read
/// again through [`Series::hunk_lines`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hunk {
    /// As written in `@@ -old_start,old_len +new_start,new_len @@` (an
    /// empty range names the line before it, as in Git).
    pub old_start: usize,
    pub old_len: usize,
    pub new_start: usize,
    pub new_len: usize,
    body: Range<usize>,
    /// Input line of the `@@` header.
    pub line: usize,
}

/// Which side a hunk line belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    Context,
    Delete,
    Insert,
}

/// One `diff --git` (or plain `---`/`+++`) section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePatch {
    pub op: FileOp,
    /// `None` for a new file.
    pub old_path: Option<VPath>,
    /// `None` for a deleted file.
    pub new_path: Option<VPath>,
    pub old_mode: Option<Mode>,
    pub new_mode: Option<Mode>,
    /// The `index <old>..<new>` blob ids, if given.
    pub index: Option<(String, String)>,
    /// A `Binary files … differ` or `GIT binary patch` section.
    pub binary: bool,
    /// The data of a `GIT binary patch` section (`None` for `Binary files
    /// … differ`, which holds none).
    pub binary_patch: Option<BinaryPatch>,
    pub hunks: Vec<Hunk>,
    /// Input line where the section starts.
    pub line: usize,
}

impl FilePatch {
    /// The path the section is about (the new one, for a rename).
    pub fn path(&self) -> &VPath {
        self.new_path.as_ref().or(self.old_path.as_ref()).expect("a section has a path")
    }
}

/// One message of a series.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    /// `n/m` from `[PATCH n/m]`.
    pub number: Option<(u32, u32)>,
    /// The `From:` header, as `Name <email>` (or a bare name or address).
    pub author: Option<String>,
    /// The `Date:` header, in milliseconds since the Unix epoch.
    pub date: Option<i64>,
    /// The subject, with `Re:` and leading `[…]` tags removed.
    pub subject: String,
    /// The message body (up to the `---` line), trimmed.
    pub body: String,
    pub files: Vec<FilePatch>,
    /// Input line where the message starts.
    pub line: usize,
}

impl Patch {
    /// Subject and body as one description.
    pub fn description(&self) -> String {
        match (self.subject.is_empty(), self.body.is_empty()) {
            (_, true) => self.subject.clone(),
            (true, false) => self.body.clone(),
            (false, false) => format!("{}\n\n{}", self.subject, self.body),
        }
    }

    /// A cover letter (`[PATCH 0/m]` with no diff), which `vl am` skips.
    pub fn is_cover_letter(&self) -> bool {
        self.files.is_empty() && matches!(self.number, Some((0, _)))
    }
}

/// A parsed series: the input and what it holds.
#[derive(Clone, Debug)]
pub struct Series {
    data: Vec<u8>,
    pub patches: Vec<Patch>,
}

impl Series {
    /// The bytes block `b` inflates to (exactly its declared size), decoded
    /// from the input now.
    pub fn binary_data(&self, b: &BinaryBlock) -> Result<Vec<u8>> {
        let deflated = binary::decode_lines(&self.data[b.data.clone()]).map_err(VeilError::Repo)?;
        binary::inflate(&deflated, b.size).map_err(VeilError::Repo)
    }

    /// The lines of `h`, each with its `\n` unless a "no newline at end of
    /// file" marker follows it.
    pub fn hunk_lines<'a>(&'a self, h: &Hunk) -> HunkLines<'a> {
        HunkLines {
            data: &self.data,
            pos: h.body.start,
            end: h.body.end,
        }
    }
}

/// Iterator over a hunk's lines (see [`Series::hunk_lines`]). The hunk was
/// validated when it was parsed, so this cannot fail.
pub struct HunkLines<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Iterator for HunkLines<'a> {
    type Item = (LineKind, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.end {
                return None;
            }
            let rest = &self.data[self.pos..self.end];
            let len = memchr::memchr(b'\n', rest).map_or(rest.len(), |i| i + 1);
            let start = self.pos;
            let next = start + len;
            self.pos = next;
            let line = &self.data[start..next];
            let (kind, from) = match line[0] {
                b'\\' => continue,
                b'\n' => (LineKind::Context, start),
                b' ' => (LineKind::Context, start + 1),
                b'-' => (LineKind::Delete, start + 1),
                _ => (LineKind::Insert, start + 1),
            };
            let mut to = next;
            if next < self.end && self.data[next] == b'\\' {
                to -= 1; // drop the `\n`: no newline at end of file
            }
            return Some((kind, &self.data[from..to]));
        }
    }
}

// ---- the parser ------------------------------------------------------------

/// Parse a patch series (see the module documentation). Never panics; any
/// input it does not understand exactly is refused with the line number.
pub fn parse(data: Vec<u8>, limits: &Limits) -> Result<Series> {
    if data.len() > limits.max_input {
        return Err(VeilError::Repo(format!(
            "the patch input is {} bytes, more than the {} accepted",
            data.len(),
            limits.max_input
        )));
    }
    let patches = Parser::new(&data, limits)?.series()?;
    Ok(Series { data, patches })
}

struct Parser<'a> {
    d: &'a [u8],
    lim: &'a Limits,
    /// The current line: `d[start..end]` (without its `\n`), the next one
    /// at `next`.
    start: usize,
    end: usize,
    next: usize,
    has_nl: bool,
    eof: bool,
    /// 1-based number of the current line.
    line: usize,
    files: usize,
    hunks: usize,
    /// Bytes the forward binary blocks so far declare.
    inflated: u64,
}

/// Raw extended headers of one `diff --git` section.
#[derive(Default)]
struct Ext {
    old_mode: Option<Mode>,
    new_mode: Option<Mode>,
    deleted: Option<Mode>,
    created: Option<Mode>,
    rename_from: Option<Vec<u8>>,
    rename_to: Option<Vec<u8>>,
    copy_from: Option<Vec<u8>>,
    copy_to: Option<Vec<u8>>,
    similarity: bool,
    dissimilarity: bool,
    index: Option<(String, String, Option<Mode>)>,
}

/// The header fields of one message.
#[derive(Default)]
struct Headers {
    from: Option<String>,
    date: Option<i64>,
    subject: Option<String>,
}

fn set_once<T>(slot: &mut Option<T>, v: T, line: usize, what: &str) -> Result<()> {
    if slot.is_some() {
        return Err(malformed(line, format!("'{what}' given twice")));
    }
    *slot = Some(v);
    Ok(())
}

impl<'a> Parser<'a> {
    fn new(d: &'a [u8], lim: &'a Limits) -> Result<Parser<'a>> {
        let mut p = Parser {
            d,
            lim,
            start: 0,
            end: 0,
            next: 0,
            has_nl: false,
            eof: false,
            line: 1,
            files: 0,
            hunks: 0,
            inflated: 0,
        };
        p.load(0)?;
        Ok(p)
    }

    fn load(&mut self, pos: usize) -> Result<()> {
        if pos >= self.d.len() {
            self.eof = true;
            self.start = self.d.len();
            self.end = self.d.len();
            self.next = self.d.len();
            self.has_nl = false;
            return Ok(());
        }
        let rest = &self.d[pos..];
        let (end, next, nl) = match memchr::memchr(b'\n', rest) {
            Some(i) => (pos + i, pos + i + 1, true),
            None => (self.d.len(), self.d.len(), false),
        };
        if end - pos > self.lim.max_line {
            return Err(malformed(self.line, format!("line longer than {} bytes", self.lim.max_line)));
        }
        self.start = pos;
        self.end = end;
        self.next = next;
        self.has_nl = nl;
        self.eof = false;
        Ok(())
    }

    fn cur(&self) -> Option<&'a [u8]> {
        (!self.eof).then(|| &self.d[self.start..self.end])
    }

    fn bump(&mut self) -> Result<()> {
        self.line += 1;
        self.load(self.next)
    }

    /// The line after the current one (without its `\n`), if any.
    fn peek_next(&self) -> Option<&'a [u8]> {
        if self.eof || self.next >= self.d.len() {
            return None;
        }
        let rest = &self.d[self.next..];
        let len = memchr::memchr(b'\n', rest).unwrap_or(rest.len());
        Some(&rest[..len.min(self.lim.max_line)])
    }

    fn starts(&self, prefix: &[u8]) -> bool {
        self.cur().is_some_and(|l| l.starts_with(prefix))
    }

    /// Is the current line an mbox postmark starting a new message? At the
    /// start of the input any `From ` line is; later only Git's own
    /// (`From <hex id> Mon Sep 17 00:00:00 2001`) or one followed by a mail
    /// header (a message body's own `From …` line is neither).
    fn at_postmark(&self) -> bool {
        let Some(l) = self.cur() else { return false };
        if !l.starts_with(b"From ") {
            return false;
        }
        is_git_postmark(l) || self.peek_next().is_some_and(is_header_line)
    }

    fn series(mut self) -> Result<Vec<Patch>> {
        // Blank lines before the first message (a saved mail) are skipped.
        while self.cur().is_some_and(|l| l.is_empty()) {
            self.bump()?;
        }
        if self.eof {
            return Err(VeilError::Repo("no patch in the input (it is empty)".into()));
        }
        let mut out = Vec::new();
        if self.starts(b"From ") {
            while !self.eof {
                if !self.starts(b"From ") {
                    return Err(malformed(self.line, "expected the 'From ' line of the next message"));
                }
                self.push(&mut out, true)?;
            }
        } else if self.cur().is_some_and(is_mail_header) {
            self.push(&mut out, false)?;
            while !self.eof {
                self.push(&mut out, true)?;
            }
        } else {
            let line = self.line;
            let files = self.diffs(true)?;
            if files.is_empty() {
                return Err(malformed(line, "no 'diff --git' or '---'/'+++' section: this is not a patch"));
            }
            self.trailer()?;
            if !self.eof {
                return Err(malformed(self.line, "a plain diff followed by a mail message"));
            }
            out.push(Patch {
                number: None,
                author: None,
                date: None,
                subject: String::new(),
                body: String::new(),
                files,
                line,
            });
        }
        Ok(out)
    }

    fn push(&mut self, out: &mut Vec<Patch>, postmark: bool) -> Result<()> {
        if out.len() >= self.lim.max_patches {
            return Err(malformed(self.line, format!("more than {} patches", self.lim.max_patches)));
        }
        let p = self.message(postmark)?;
        out.push(p);
        Ok(())
    }

    /// One mail: postmark (if any), headers, body, diff, signature.
    fn message(&mut self, postmark: bool) -> Result<Patch> {
        let line = self.line;
        if postmark {
            self.bump()?;
        }
        let mut h = Headers::default();
        self.headers(&mut h, true)?;
        // The body, up to `---` (or the diff itself).
        let mut body: Vec<&[u8]> = Vec::new();
        let mut separated = false;
        while let Some(l) = self.cur() {
            if is_separator(l) {
                self.bump()?;
                separated = true;
                break;
            }
            // `-- ` is the signature (a cover letter has no `---`).
            if l.starts_with(b"diff --git ") || l == b"-- " || self.at_plain_diff() || self.at_postmark() {
                break;
            }
            if l.contains(&0) {
                return Err(malformed(self.line, "NUL byte in the message"));
            }
            body.push(l);
            self.bump()?;
        }
        // In-body headers (`From:`, `Date:`, `Subject:` first in the body,
        // as `git am` reads them) take precedence over the mail's.
        let mut start = 0;
        while body.get(start).is_some_and(|l| l.is_empty()) {
            start += 1;
        }
        let in_body = |l: &[u8]| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with(b"from: ") || lower.starts_with(b"date: ") || lower.starts_with(b"subject: ")
        };
        if body.get(start).is_some_and(|l| in_body(l)) {
            let mut ib = Headers::default();
            let mut i = start;
            while let Some(l) = body.get(i).filter(|l| !l.is_empty()) {
                if !in_body(l) {
                    return Err(malformed(line, format!("in-body header block holds '{}'", shown(l))));
                }
                header_field(&mut ib, l, line, self.lim)?;
                i += 1;
            }
            h.from = ib.from.or(h.from);
            h.date = ib.date.or(h.date);
            h.subject = ib.subject.or(h.subject);
            start = i;
        }
        let mut text = String::new();
        for l in &body[start..] {
            let s = std::str::from_utf8(l).map_err(|_| malformed(line, "the message body is not UTF-8"))?;
            text.push_str(s);
            text.push('\n');
        }
        let body = text.trim().to_string();
        let (subject, number) = clean_subject(h.subject.as_deref().unwrap_or(""));
        // After `---`: the diffstat and notes, up to the first section.
        if separated {
            while let Some(l) = self.cur() {
                if l.starts_with(b"diff --git ") || self.at_plain_diff() || self.at_postmark() || l == b"-- " {
                    break;
                }
                self.bump()?;
            }
        }
        let files = self.diffs(false)?;
        self.trailer()?;
        Ok(Patch {
            number,
            author: h.from,
            date: h.date,
            subject,
            body,
            files,
            line,
        })
    }

    /// Mail headers up to the blank line that ends them.
    fn headers(&mut self, h: &mut Headers, top: bool) -> Result<()> {
        let mut content_type = None;
        let mut encoding = None;
        loop {
            let Some(l) = self.cur() else {
                return Err(malformed(self.line, "the message ends inside its headers"));
            };
            if l.is_empty() {
                self.bump()?;
                break;
            }
            let at = self.line;
            if l.ends_with(b"\r") {
                return Err(malformed(at, "the mail has CRLF line endings; convert it to LF line endings first"));
            }
            if !is_header_line(l) {
                return Err(malformed(at, format!("not a mail header: '{}'", shown(l))));
            }
            // Unfold continuation lines.
            let mut full = l.to_vec();
            self.bump()?;
            while let Some(c) = self.cur().filter(|c| c.first().is_some_and(|b| *b == b' ' || *b == b'\t')) {
                full.extend_from_slice(c);
                if full.len() > self.lim.max_header {
                    return Err(malformed(at, format!("a header longer than {} bytes", self.lim.max_header)));
                }
                self.bump()?;
            }
            let colon = full.iter().position(|b| *b == b':').expect("checked by is_header_line");
            let name = full[..colon].to_ascii_lowercase();
            let value = trim_ascii(&full[colon + 1..]);
            match name.as_slice() {
                b"content-type" if top => set_once(&mut content_type, value.to_ascii_lowercase(), at, "Content-Type")?,
                b"content-transfer-encoding" if top => {
                    set_once(&mut encoding, value.to_ascii_lowercase(), at, "Content-Transfer-Encoding")?
                }
                _ => header_field(h, &full, at, self.lim)?,
            }
        }
        if let Some(ct) = content_type {
            let mut parts = ct.split(|b| *b == b';');
            let kind = trim_ascii(parts.next().unwrap_or_default());
            if kind != b"text/plain" {
                return Err(VeilError::Repo(format!(
                    "unsupported patch mail: Content-Type '{}' (attachments and multipart mail are not supported; \
                     export with `git format-patch` without --attach)",
                    shown(kind)
                )));
            }
            for p in parts {
                let p = trim_ascii(p);
                if let Some(cs) = p.strip_prefix(b"charset=") {
                    let cs: Vec<u8> = cs.iter().copied().filter(|b| *b != b'"').collect();
                    if !matches!(cs.as_slice(), b"utf-8" | b"us-ascii") {
                        return Err(VeilError::Repo(format!("unsupported patch mail: charset '{}' (only UTF-8)", shown(&cs))));
                    }
                }
            }
        }
        if let Some(e) = encoding {
            if !matches!(e.as_slice(), b"7bit" | b"8bit" | b"binary") {
                return Err(VeilError::Repo(format!(
                    "unsupported patch mail: Content-Transfer-Encoding '{}' (only 7bit and 8bit)",
                    shown(&e)
                )));
            }
        }
        Ok(())
    }

    /// Is the current line `--- …` followed by `+++ …` (a plain diff)?
    fn at_plain_diff(&self) -> bool {
        self.starts(b"--- ") && self.peek_next().is_some_and(|n| n.starts_with(b"+++ "))
    }

    /// File sections, as many as follow (blank lines between them allowed).
    fn diffs(&mut self, plain_preamble: bool) -> Result<Vec<FilePatch>> {
        let mut files: Vec<FilePatch> = Vec::new();
        if plain_preamble {
            // A plain diff may start with text (`Index:` lines, a command).
            while let Some(l) = self.cur() {
                if l.starts_with(b"diff --git ") || self.at_plain_diff() {
                    break;
                }
                self.bump()?;
            }
        }
        while let Some(l) = self.cur() {
            let f = if l.starts_with(b"diff --git ") {
                self.git_section()?
            } else if self.at_plain_diff() {
                self.plain_section()?
            } else if l.is_empty() {
                // Blank lines between sections, or before the end.
                let save = (self.start, self.line);
                while self.cur().is_some_and(|l| l.is_empty()) {
                    self.bump()?;
                }
                if self.starts(b"diff --git ") || self.at_plain_diff() {
                    continue;
                }
                // Not followed by another section: let the caller see them.
                self.line = save.1;
                self.load(save.0)?;
                break;
            } else {
                break;
            };
            self.files += 1;
            if self.files > self.lim.max_files {
                return Err(malformed(f.line, format!("more than {} file sections", self.lim.max_files)));
            }
            // Each path is claimed by at most one section of a patch: its
            // new path, and its old path unless it is a copy (every section
            // reads the pre-image, so a copy's source may also be changed).
            let claims = |x: &FilePatch| -> Vec<VPath> {
                let mut c: Vec<VPath> = x.new_path.iter().cloned().collect();
                if x.op != FileOp::Copy {
                    c.extend(x.old_path.iter().filter(|o| Some(*o) != x.new_path.as_ref()).cloned());
                }
                c
            };
            let mine = claims(&f);
            // Git writes a type change (a file becoming a symlink, …) as a
            // deletion followed by a creation of the same path.
            let type_change = |x: &FilePatch| {
                x.op == FileOp::Delete
                    && f.op == FileOp::Create
                    && x.old_path == f.new_path
                    && x.old_mode.zip(f.new_mode).is_some_and(|(a, b)| a.kind() != b.kind())
            };
            if let Some(p) = files.iter().filter(|x| !type_change(x)).flat_map(claims).find(|p| mine.contains(p)) {
                return Err(malformed(f.line, format!("'{p}' appears in two sections of one patch")));
            }
            files.push(f);
        }
        Ok(files)
    }

    /// What may follow the last section: blank lines, the `-- ` signature
    /// (anything up to the next message), then the next message or the end.
    fn trailer(&mut self) -> Result<()> {
        while self.cur().is_some_and(|l| l.is_empty()) {
            self.bump()?;
        }
        if self.cur() == Some(b"-- ") {
            self.bump()?;
            while !self.eof && !self.at_postmark() {
                self.bump()?;
            }
        }
        if self.eof || self.at_postmark() {
            return Ok(());
        }
        Err(malformed(
            self.line,
            format!("unexpected text after the diff: '{}'", shown(self.cur().unwrap_or_default())),
        ))
    }

    fn git_section(&mut self) -> Result<FilePatch> {
        let line = self.line;
        let names = git_line_names(&self.cur().expect("a line")[b"diff --git ".len()..], line)?;
        self.bump()?;
        let mut x = Ext::default();
        while let Some(l) = self.cur() {
            let at = self.line;
            if let Some(v) = l.strip_prefix(b"old mode ") {
                set_once(&mut x.old_mode, parse_mode(v, at)?, at, "old mode")?;
            } else if let Some(v) = l.strip_prefix(b"new mode ") {
                set_once(&mut x.new_mode, parse_mode(v, at)?, at, "new mode")?;
            } else if let Some(v) = l.strip_prefix(b"deleted file mode ") {
                set_once(&mut x.deleted, parse_mode(v, at)?, at, "deleted file mode")?;
            } else if let Some(v) = l.strip_prefix(b"new file mode ") {
                set_once(&mut x.created, parse_mode(v, at)?, at, "new file mode")?;
            } else if let Some(v) = l.strip_prefix(b"rename from ").or_else(|| l.strip_prefix(b"rename old ")) {
                set_once(&mut x.rename_from, header_path(v, at)?, at, "rename from")?;
            } else if let Some(v) = l.strip_prefix(b"rename to ").or_else(|| l.strip_prefix(b"rename new ")) {
                set_once(&mut x.rename_to, header_path(v, at)?, at, "rename to")?;
            } else if let Some(v) = l.strip_prefix(b"copy from ") {
                set_once(&mut x.copy_from, header_path(v, at)?, at, "copy from")?;
            } else if let Some(v) = l.strip_prefix(b"copy to ") {
                set_once(&mut x.copy_to, header_path(v, at)?, at, "copy to")?;
            } else if let Some(v) = l.strip_prefix(b"similarity index ") {
                parse_percent(v, at)?;
                if std::mem::replace(&mut x.similarity, true) {
                    return Err(malformed(at, "'similarity index' given twice"));
                }
            } else if let Some(v) = l.strip_prefix(b"dissimilarity index ") {
                parse_percent(v, at)?;
                if std::mem::replace(&mut x.dissimilarity, true) {
                    return Err(malformed(at, "'dissimilarity index' given twice"));
                }
            } else if let Some(v) = l.strip_prefix(b"index ") {
                set_once(&mut x.index, parse_index(v, at)?, at, "index")?;
            } else {
                break;
            }
            self.bump()?;
        }
        // The file names: `---`/`+++`, hunks, or a binary section.
        let mut minus_plus = None;
        let mut hunks = Vec::new();
        let mut binary = false;
        let mut binary_patch = None;
        if self.starts(b"--- ") {
            minus_plus = Some(self.minus_plus(false)?);
            hunks = self.hunks()?;
        } else if self.starts(b"Binary files ") {
            let l = self.cur().expect("a line");
            if !l.ends_with(b" differ") {
                return Err(malformed(self.line, "malformed 'Binary files … differ' line"));
            }
            binary = true;
            self.bump()?;
        } else if self.cur() == Some(b"GIT binary patch") {
            binary_patch = Some(self.binary_patch()?);
            binary = true;
        }
        let mut f = self.finish_git(line, names, x, minus_plus, hunks, binary)?;
        f.binary_patch = binary_patch;
        Ok(f)
    }

    #[allow(clippy::type_complexity)]
    fn finish_git(
        &mut self,
        line: usize,
        names: Option<(Vec<u8>, Vec<u8>)>,
        x: Ext,
        minus_plus: Option<(Option<Vec<u8>>, Option<Vec<u8>>)>,
        hunks: Vec<Hunk>,
        binary: bool,
    ) -> Result<FilePatch> {
        let lim = self.lim;
        let path = |raw: &[u8]| check_path(raw, line, lim);
        let renamed = x.rename_from.is_some() || x.rename_to.is_some();
        let copied = x.copy_from.is_some() || x.copy_to.is_some();
        let op = match (x.created.is_some(), x.deleted.is_some(), renamed, copied) {
            (true, false, false, false) => FileOp::Create,
            (false, true, false, false) => FileOp::Delete,
            (false, false, true, false) => FileOp::Rename,
            (false, false, false, true) => FileOp::Copy,
            (false, false, false, false) => FileOp::Modify,
            _ => return Err(malformed(line, "contradictory extended headers (new, deleted, renamed, copied)")),
        };
        if matches!(op, FileOp::Create | FileOp::Delete) && (x.old_mode.is_some() || x.new_mode.is_some()) {
            return Err(malformed(line, "'old mode'/'new mode' on a new or deleted file"));
        }
        if x.old_mode.is_some() != x.new_mode.is_some() {
            return Err(malformed(line, "'old mode' without 'new mode', or the reverse"));
        }
        if let (Some(a), Some(b)) = (x.old_mode, x.new_mode) {
            if a.kind() != b.kind() {
                return Err(malformed(
                    line,
                    "'old mode'/'new mode' change the file's type (Git writes a type change as a deletion and a creation)",
                ));
            }
        }
        // Names from the strongest source available.
        let (mut old, mut new): (Option<Vec<u8>>, Option<Vec<u8>>) = match op {
            FileOp::Rename => (
                Some(x.rename_from.clone().ok_or_else(|| malformed(line, "'rename to' without 'rename from'"))?),
                Some(x.rename_to.clone().ok_or_else(|| malformed(line, "'rename from' without 'rename to'"))?),
            ),
            FileOp::Copy => (
                Some(x.copy_from.clone().ok_or_else(|| malformed(line, "'copy to' without 'copy from'"))?),
                Some(x.copy_to.clone().ok_or_else(|| malformed(line, "'copy from' without 'copy to'"))?),
            ),
            _ => (None, None),
        };
        if let Some((m, p)) = &minus_plus {
            match op {
                FileOp::Create if m.is_some() => return Err(malformed(line, "a new file's '---' line is not /dev/null")),
                FileOp::Delete if p.is_some() => return Err(malformed(line, "a deleted file's '+++' line is not /dev/null")),
                FileOp::Modify | FileOp::Rename | FileOp::Copy if m.is_none() || p.is_none() => {
                    return Err(malformed(line, "/dev/null in '---'/'+++' without 'new file mode' or 'deleted file mode'"))
                }
                _ => {}
            }
            for (slot, got) in [(&mut old, m), (&mut new, p)] {
                if let Some(got) = got {
                    match slot {
                        Some(want) if want != got => {
                            return Err(malformed(line, "the '---'/'+++' names disagree with the extended headers"))
                        }
                        Some(_) => {}
                        None => *slot = Some(got.clone()),
                    }
                }
            }
        }
        if let Some((a, b)) = &names {
            for (slot, got) in [(&mut old, a), (&mut new, b)] {
                match slot {
                    Some(want) if want != got => {
                        return Err(malformed(line, "the 'diff --git' names disagree with the rest of the section"))
                    }
                    Some(_) => {}
                    None => *slot = Some(got.clone()),
                }
            }
        }
        match op {
            FileOp::Create => old = None,
            FileOp::Delete => new = None,
            _ => {}
        }
        let old_path = old.as_deref().map(path).transpose()?;
        let new_path = new.as_deref().map(path).transpose()?;
        match op {
            FileOp::Create if new_path.is_none() => return Err(malformed(line, "cannot tell the new file's name")),
            FileOp::Delete if old_path.is_none() => return Err(malformed(line, "cannot tell the deleted file's name")),
            FileOp::Modify => {
                if old_path.is_none() || old_path != new_path {
                    return Err(malformed(line, "cannot tell which file the section changes (names differ without 'rename')"));
                }
            }
            FileOp::Rename | FileOp::Copy if old_path == new_path => {
                return Err(malformed(line, "a rename or copy onto the same path"))
            }
            _ => {}
        }
        let (old_mode, new_mode) = match op {
            FileOp::Create => (None, x.created),
            FileOp::Delete => (x.deleted, None),
            _ => {
                let same = x.index.as_ref().and_then(|i| i.2);
                if same.is_some() && x.old_mode.is_some() {
                    return Err(malformed(line, "a mode on the 'index' line and a mode change"));
                }
                (x.old_mode.or(same), x.new_mode.or(same))
            }
        };
        if let Some((_, _, Some(m))) = &x.index {
            if matches!(op, FileOp::Create | FileOp::Delete) && Some(*m) != new_mode.or(old_mode) {
                return Err(malformed(line, "the 'index' line's mode disagrees with the file's"));
            }
        }
        check_hunks(op, &hunks, line)?;
        if binary && !hunks.is_empty() {
            return Err(malformed(line, "a binary section with text hunks"));
        }
        let mode_change = old_mode.is_some() && old_mode != new_mode;
        if op == FileOp::Modify && hunks.is_empty() && !binary && !mode_change {
            return Err(malformed(line, "a section that changes nothing"));
        }
        if binary && [old_mode, new_mode].iter().flatten().any(|m| m.kind() != EntryKind::File) {
            return Err(malformed(line, "binary data for a symlink or a submodule"));
        }
        Ok(FilePatch {
            op,
            old_path,
            new_path,
            old_mode,
            new_mode,
            index: x.index.map(|(a, b, _)| (a, b)),
            binary,
            binary_patch: None,
            hunks,
            line,
        })
    }

    /// `--- name` and `+++ name` (names with their `a/`, `b/` prefixes
    /// removed; `None` for /dev/null). With `plain`, the first component is
    /// stripped, whatever it is (`-p1`).
    #[allow(clippy::type_complexity)]
    fn minus_plus(&mut self, plain: bool) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
        let at = self.line;
        let m = self.cur().expect("a line");
        let old = file_line_name(&m[4..], at)?;
        self.bump()?;
        let Some(p) = self.cur().and_then(|p| p.strip_prefix(b"+++ ")) else {
            return Err(malformed(self.line, "'---' line not followed by '+++'"));
        };
        let new = file_line_name(p, self.line)?;
        let strip = |n: Option<Vec<u8>>, prefix: &[u8], line: usize| -> Result<Option<Vec<u8>>> {
            let Some(n) = n else { return Ok(None) };
            if plain {
                return match n.iter().position(|b| *b == b'/') {
                    Some(i) if i > 0 => Ok(Some(n[i + 1..].to_vec())),
                    _ => Err(malformed(line, format!("'{}' has no leading directory to strip (-p1)", shown(&n)))),
                };
            }
            match n.strip_prefix(prefix) {
                Some(rest) => Ok(Some(rest.to_vec())),
                None => Err(malformed(
                    line,
                    format!("'{}' lacks the '{}' prefix (patches made with --no-prefix are not supported)", shown(&n), shown(prefix)),
                )),
            }
        };
        let old = strip(old, b"a/", at)?;
        let new = strip(new, b"b/", self.line)?;
        if old.is_none() && new.is_none() {
            return Err(malformed(at, "both '---' and '+++' are /dev/null"));
        }
        self.bump()?;
        Ok((old, new))
    }

    /// A plain unified diff section (no `diff --git` line).
    fn plain_section(&mut self) -> Result<FilePatch> {
        let line = self.line;
        let (old, new) = self.minus_plus(true)?;
        let hunks = self.hunks()?;
        let lim = self.lim;
        let path = |raw: &[u8]| check_path(raw, line, lim);
        let (op, old_path, new_path) = match (&old, &new) {
            (None, Some(n)) => (FileOp::Create, None, Some(path(n)?)),
            (Some(o), None) => (FileOp::Delete, Some(path(o)?), None),
            (Some(o), Some(n)) => {
                let (o, n) = (path(o)?, path(n)?);
                if o != n {
                    return Err(malformed(line, "the '---' and '+++' names differ (a rename needs a Git diff)"));
                }
                (FileOp::Modify, Some(o), Some(n))
            }
            (None, None) => unreachable!("refused by minus_plus"),
        };
        if hunks.is_empty() {
            return Err(malformed(line, "a '---'/'+++' pair without hunks"));
        }
        check_hunks(op, &hunks, line)?;
        Ok(FilePatch {
            op,
            old_path,
            new_path,
            old_mode: None,
            new_mode: if op == FileOp::Create { Some(Mode::Regular) } else { None },
            index: None,
            binary: false,
            binary_patch: None,
            hunks,
            line,
        })
    }

    fn hunks(&mut self) -> Result<Vec<Hunk>> {
        let mut out: Vec<Hunk> = Vec::new();
        while self.starts(b"@@ ") {
            if out.len() >= self.lim.max_hunks_per_file {
                return Err(malformed(self.line, format!("more than {} hunks in one file", self.lim.max_hunks_per_file)));
            }
            self.hunks += 1;
            if self.hunks > self.lim.max_hunks {
                return Err(malformed(self.line, format!("more than {} hunks", self.lim.max_hunks)));
            }
            out.push(self.hunk()?);
        }
        Ok(out)
    }

    fn hunk(&mut self) -> Result<Hunk> {
        let line = self.line;
        let (old_start, old_len, new_start, new_len) = parse_hunk_header(self.cur().expect("a line"), line)?;
        self.bump()?;
        let body_start = self.start;
        let (mut o, mut n) = (old_len, new_len);
        // A side ends at its "no newline" marker: nothing of it may follow.
        let (mut old_done, mut new_done) = (false, false);
        let mut last: Option<LineKind> = None;
        let mark = |last: Option<LineKind>, old_done: &mut bool, new_done: &mut bool, at: usize| -> Result<()> {
            let (o_end, n_end) = match last {
                Some(LineKind::Context) => (true, true),
                Some(LineKind::Delete) => (true, false),
                Some(LineKind::Insert) => (false, true),
                None => return Err(malformed(at, "'\\ No newline at end of file' before any line")),
            };
            if (o_end && *old_done) || (n_end && *new_done) {
                return Err(malformed(at, "a second 'no newline' marker"));
            }
            *old_done |= o_end;
            *new_done |= n_end;
            Ok(())
        };
        while o > 0 || n > 0 {
            let at = self.line;
            let Some(l) = self.cur() else {
                return Err(malformed(at, "the patch ends inside a hunk (truncated?)"));
            };
            if !self.has_nl {
                return Err(malformed(at, "the patch ends without a newline inside a hunk (truncated?)"));
            }
            match l.first() {
                None | Some(b' ') => {
                    if o == 0 || n == 0 || old_done || new_done {
                        return Err(malformed(at, "a hunk with more lines than its header says"));
                    }
                    o -= 1;
                    n -= 1;
                    last = Some(LineKind::Context);
                }
                Some(b'-') => {
                    if o == 0 || old_done {
                        return Err(malformed(at, "a hunk with more removed lines than its header says"));
                    }
                    o -= 1;
                    last = Some(LineKind::Delete);
                }
                Some(b'+') => {
                    if n == 0 || new_done {
                        return Err(malformed(at, "a hunk with more added lines than its header says"));
                    }
                    n -= 1;
                    last = Some(LineKind::Insert);
                }
                Some(b'\\') => mark(last, &mut old_done, &mut new_done, at)?,
                Some(_) => return Err(malformed(at, format!("not a hunk line: '{}'", shown(l)))),
            }
            self.bump()?;
        }
        if self.starts(b"\\") {
            if !self.has_nl {
                return Err(malformed(self.line, "the patch ends without a newline inside a hunk (truncated?)"));
            }
            mark(last, &mut old_done, &mut new_done, self.line)?;
            self.bump()?;
        }
        Ok(Hunk {
            old_start,
            old_len,
            new_start,
            new_len,
            body: body_start..self.start,
            line,
        })
    }

    /// A `GIT binary patch` section: one or two `literal N`/`delta N`
    /// blocks of base85 lines, each ended by a blank line. Each line's
    /// shape and every declared size are checked (and the forward sizes
    /// of the whole series added up against [`Limits::max_inflated`]);
    /// nothing is decoded or inflated here.
    fn binary_patch(&mut self) -> Result<BinaryPatch> {
        self.bump()?;
        let mut blocks: Vec<BinaryBlock> = Vec::new();
        for block in 0..2 {
            let at = self.line;
            let Some(l) = self.cur() else {
                if block == 0 {
                    return Err(malformed(at, "'GIT binary patch' without data"));
                }
                break;
            };
            let (kind, n) = match (l.strip_prefix(b"literal "), l.strip_prefix(b"delta ")) {
                (Some(n), _) => (BinaryKind::Literal, n),
                (_, Some(n)) => (BinaryKind::Delta, n),
                _ if block == 1 => break,
                _ => return Err(malformed(at, "expected 'literal N' or 'delta N'")),
            };
            let size = parse_number(n, at)?;
            if size as u64 > self.lim.max_file_size {
                return Err(malformed(
                    at,
                    format!("a binary section declares {size} bytes, more than {} (VEIL_MAX_OBJECT)", self.lim.max_file_size),
                ));
            }
            if block == 0 {
                self.inflated = self.inflated.saturating_add(size as u64);
                if self.inflated > self.lim.max_inflated {
                    return Err(malformed(
                        at,
                        format!("the binary sections declare more than {} bytes in all", self.lim.max_inflated),
                    ));
                }
            }
            self.bump()?;
            let data_start = self.start;
            let mut lines = 0usize;
            loop {
                let Some(l) = self.cur() else {
                    return Err(malformed(self.line, "the patch ends inside binary data"));
                };
                if l.is_empty() {
                    break;
                }
                if !self.has_nl || binary::check_line(l).is_none() {
                    return Err(malformed(self.line, "not a line of base85 binary data"));
                }
                lines += 1;
                self.bump()?;
            }
            let data = data_start..self.start;
            self.bump()?;
            if lines == 0 && size > 0 {
                return Err(malformed(at, "binary data missing"));
            }
            blocks.push(BinaryBlock { kind, size, data });
        }
        let mut blocks = blocks.into_iter();
        let forward = blocks.next().expect("one block at least");
        Ok(BinaryPatch {
            forward,
            reverse: blocks.next(),
        })
    }
}

/// `---` alone (trailing whitespace allowed): the end of the message body.
fn is_separator(l: &[u8]) -> bool {
    l.strip_prefix(b"---").is_some_and(|r| r.iter().all(|b| *b == b' ' || *b == b'\t'))
}

/// Git's postmark: `From <hex> Mon Sep 17 00:00:00 2001`.
fn is_git_postmark(l: &[u8]) -> bool {
    let Some(rest) = l.strip_prefix(b"From ") else { return false };
    let Some(hex) = rest.strip_suffix(b" Mon Sep 17 00:00:00 2001") else { return false };
    (40..=64).contains(&hex.len()) && hex.iter().all(|b| b.is_ascii_hexdigit())
}

/// `Name: value`, with a name made of printable ASCII other than `:`.
fn is_header_line(l: &[u8]) -> bool {
    match l.iter().position(|b| *b == b':') {
        Some(i) if i > 0 => l[..i].iter().all(|b| b.is_ascii_graphic()),
        _ => false,
    }
}

/// A header only a mail starts with (a plain diff may start with
/// `Index: x` or other `Name: value` text).
fn is_mail_header(l: &[u8]) -> bool {
    if !is_header_line(l) {
        return false;
    }
    let name = l[..l.iter().position(|b| *b == b':').expect("a header")].to_ascii_lowercase();
    name.starts_with(b"x-")
        || [
            &b"from"[..], b"subject", b"date", b"to", b"cc", b"message-id", b"return-path", b"received", b"mime-version",
            b"content-type", b"content-transfer-encoding", b"delivered-to", b"reply-to", b"in-reply-to", b"references", b"sender",
        ]
        .contains(&name.as_slice())
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(s, |i| i + 1);
    &b[s..e]
}

/// One `From:`, `Date:` or `Subject:` header (others are ignored).
fn header_field(h: &mut Headers, full: &[u8], at: usize, lim: &Limits) -> Result<()> {
    if full.len() > lim.max_header {
        return Err(malformed(at, format!("a header longer than {} bytes", lim.max_header)));
    }
    let colon = full.iter().position(|b| *b == b':').ok_or_else(|| malformed(at, "not a header"))?;
    let name = full[..colon].to_ascii_lowercase();
    let raw = trim_ascii(&full[colon + 1..]);
    match name.as_slice() {
        b"from" => {
            let v = decode_header(raw, at)?;
            set_once(&mut h.from, parse_from(&v, at)?, at, "From")
        }
        b"subject" => {
            let v = decode_header(raw, at)?;
            set_once(&mut h.subject, v, at, "Subject")
        }
        b"date" => {
            let v = decode_header(raw, at)?;
            let d = parse_date(&v).ok_or_else(|| malformed(at, format!("cannot read the date '{}'", shown(v.as_bytes()))))?;
            set_once(&mut h.date, d, at, "Date")
        }
        _ => {
            // Not used, but never let a raw control character through.
            if raw.iter().any(|b| *b < 0x20 && *b != b'\t' || *b == 0x7f) {
                return Err(malformed(at, "a header holds a control character"));
            }
            Ok(())
        }
    }
}

/// Is `c` something a decoded header must not hold: a C0 or C1 control
/// (tab aside), DEL, or a bidirectional override or isolate?
fn forbidden_in_header(c: char) -> bool {
    (c.is_control() && c != '\t') || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
}

/// A header value with RFC 2047 encoded words decoded.
fn decode_header(raw: &[u8], at: usize) -> Result<String> {
    let s = std::str::from_utf8(raw).map_err(|_| malformed(at, "a header is neither ASCII nor UTF-8"))?;
    let mut out = String::new();
    let mut rest = s;
    let mut last_was_word = false;
    while !rest.is_empty() {
        match rest.find("=?") {
            None => {
                out.push_str(rest);
                break;
            }
            Some(i) => {
                let (before, from) = rest.split_at(i);
                match encoded_word(from) {
                    Some((text, used)) => {
                        // Whitespace between two encoded words is dropped.
                        if !(last_was_word && before.chars().all(char::is_whitespace)) {
                            out.push_str(before);
                        }
                        out.push_str(&text.map_err(|why| malformed(at, why))?);
                        rest = &from[used..];
                        last_was_word = true;
                        continue;
                    }
                    None => {
                        out.push_str(before);
                        out.push_str("=?");
                        rest = &from[2..];
                    }
                }
            }
        }
        last_was_word = false;
    }
    if out.chars().any(forbidden_in_header) {
        return Err(malformed(at, "a header holds a control character or a direction override"));
    }
    Ok(out)
}

/// `=?charset?B|Q?text?=` at the start of `s`: the decoded text (or why it
/// cannot be decoded) and the bytes used; `None` if `s` does not start
/// with an encoded word.
#[allow(clippy::type_complexity)]
fn encoded_word(s: &str) -> Option<(std::result::Result<String, String>, usize)> {
    let body = s.strip_prefix("=?")?;
    let q1 = body.find('?')?;
    let charset = &body[..q1];
    let after = &body[q1 + 1..];
    let q2 = after.find('?')?;
    let enc = &after[..q2];
    let text_and = &after[q2 + 1..];
    let end = text_and.find("?=")?;
    let text = &text_and[..end];
    if text.contains(char::is_whitespace) {
        return None;
    }
    let used = 2 + q1 + 1 + q2 + 1 + end + 2;
    let bytes = match enc {
        "B" | "b" => base64_decode(text.as_bytes()).ok_or_else(|| "a malformed base64 encoded word".to_string()),
        "Q" | "q" => q_decode(text.as_bytes()).ok_or_else(|| "a malformed quoted-printable encoded word".to_string()),
        _ => Err(format!("unknown encoding '{enc}' in an encoded word")),
    };
    let charset = charset.split('*').next().unwrap_or("").to_ascii_lowercase();
    let decoded = bytes.and_then(|b| match charset.as_str() {
        "utf-8" | "us-ascii" => String::from_utf8(b).map_err(|_| "an encoded word that is not UTF-8".to_string()),
        "iso-8859-1" | "latin1" => Ok(b.iter().map(|c| *c as char).collect()),
        other => Err(format!("unsupported charset '{other}' in an encoded word")),
    });
    Some((decoded, used))
}

fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.strip_suffix(b"==").or_else(|| s.strip_suffix(b"=")).unwrap_or(s);
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn q_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'_' => out.push(b' '),
            b'=' => {
                let h = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(out)
}

/// `Name <email>`, `"Name" <email>` or a bare address, as `Name <email>`.
fn parse_from(v: &str, at: usize) -> Result<String> {
    let v = v.trim();
    let (name, email) = match v.rfind('<') {
        Some(i) => {
            let rest = &v[i + 1..];
            let close = rest.find('>').ok_or_else(|| malformed(at, "'From:' with an unclosed '<'"))?;
            if !rest[close + 1..].trim().is_empty() {
                return Err(malformed(at, "text after the address in 'From:'"));
            }
            (v[..i].trim(), rest[..close].trim())
        }
        None => ("", v),
    };
    let name = name.strip_prefix('"').and_then(|n| n.strip_suffix('"')).unwrap_or(name).trim();
    if name.contains(['<', '>']) || email.contains(['<', '>', ' ']) {
        return Err(malformed(at, "a malformed 'From:' header"));
    }
    Ok(match (name.is_empty(), email.is_empty()) {
        (true, true) => return Err(malformed(at, "an empty 'From:' header")),
        (true, false) => email.to_string(),
        (false, true) => name.to_string(),
        (false, false) => format!("{name} <{email}>"),
    })
}

/// RFC 2822 date (`[Wed, ]4 Nov 2026 18:51:21 +0000`) → milliseconds.
pub(crate) fn parse_date(v: &str) -> Option<i64> {
    let mut t: Vec<&str> = v.split_whitespace().collect();
    if t.first().is_some_and(|d| d.ends_with(',')) {
        t.remove(0);
    }
    if t.len() != 5 {
        return None;
    }
    let num = |s: &str, max_len: usize| -> Option<i64> {
        (!s.is_empty() && s.len() <= max_len && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
    };
    let day = num(t[0], 2)?;
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let month = MONTHS.iter().position(|m| t[1].eq_ignore_ascii_case(m))? as i64 + 1;
    let year = num(t[2], 4)?;
    let hms: Vec<&str> = t[3].split(':').collect();
    if !(2..=3).contains(&hms.len()) {
        return None;
    }
    let (h, m) = (num(hms[0], 2)?, num(hms[1], 2)?);
    let s = if hms.len() == 3 { num(hms[2], 2)? } else { 0 };
    let zone = t[4];
    let offset = match zone {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        z if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let zh = num(&z[1..3], 2)?;
            let zm = num(&z[3..5], 2)?;
            if zm > 59 {
                return None;
            }
            let o = zh * 3600 + zm * 60;
            if z.starts_with('-') {
                -o
            } else {
                o
            }
        }
        _ => return None,
    };
    if !(1970..=9999).contains(&year) || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + h * 3600 + m * 60 + s - offset;
    secs.checked_mul(1000)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: (year, month, day).
#[cfg(feature = "git")]
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `millis` as an RFC 2822 date in UTC (`Wed, 4 Nov 2026 18:51:21 +0000`).
#[cfg(feature = "git")]
pub(crate) fn format_date(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{}, {d} {} {y} {:02}:{:02}:{:02} +0000",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The subject without `Re:` and leading `[…]` tags, and `n/m` from a
/// `[PATCH n/m]` tag.
fn clean_subject(s: &str) -> (String, Option<(u32, u32)>) {
    let mut rest = s.trim();
    let mut number = None;
    loop {
        if rest.len() >= 3 && rest.as_bytes()[..3].eq_ignore_ascii_case(b"re:") {
            rest = rest[3..].trim_start();
        } else if let Some(inner) = rest.strip_prefix('[') {
            let Some(close) = inner.find(']') else { break };
            let tag = &inner[..close];
            if number.is_none() && tag.to_ascii_uppercase().contains("PATCH") {
                number = tag.split_whitespace().find_map(|w| {
                    let (n, m) = w.split_once('/')?;
                    let (n, m) = (n.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
                    (n <= m && m > 0).then_some((n, m))
                });
            }
            rest = inner[close + 1..].trim_start();
        } else {
            break;
        }
    }
    (rest.trim().to_string(), number)
}

fn parse_number(v: &[u8], at: usize) -> Result<usize> {
    if v.is_empty() || v.len() > 18 || !v.iter().all(|b| b.is_ascii_digit()) {
        return Err(malformed(at, format!("not a number: '{}'", shown(v))));
    }
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| malformed(at, "number out of range"))
}

fn parse_percent(v: &[u8], at: usize) -> Result<()> {
    let n = v.strip_suffix(b"%").ok_or_else(|| malformed(at, "a similarity without '%'"))?;
    if parse_number(n, at)? > 100 {
        return Err(malformed(at, "a similarity above 100%"));
    }
    Ok(())
}

fn parse_mode(v: &[u8], at: usize) -> Result<Mode> {
    match v {
        b"100644" | b"100664" => Ok(Mode::Regular),
        b"100755" => Ok(Mode::Executable),
        b"120000" => Ok(Mode::Symlink),
        b"160000" => Ok(Mode::Gitlink),
        _ => Err(malformed(at, format!("unknown file mode '{}'", shown(v)))),
    }
}

/// `index <hex>..<hex>[ <mode>]`.
fn parse_index(v: &[u8], at: usize) -> Result<(String, String, Option<Mode>)> {
    let (ids, mode) = match v.iter().position(|b| *b == b' ') {
        Some(i) => (&v[..i], Some(parse_mode(&v[i + 1..], at)?)),
        None => (v, None),
    };
    let dots = ids.windows(2).position(|w| w == b"..").ok_or_else(|| malformed(at, "an 'index' line without '..'"))?;
    let hex = |h: &[u8]| -> Result<String> {
        if !(4..=64).contains(&h.len()) || !h.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(malformed(at, "an 'index' line with a malformed object id"));
        }
        Ok(String::from_utf8_lossy(h).to_ascii_lowercase())
    };
    Ok((hex(&ids[..dots])?, hex(&ids[dots + 2..])?, mode))
}

/// `@@ -a[,b] +c[,d] @@[ text]`.
fn parse_hunk_header(l: &[u8], at: usize) -> Result<(usize, usize, usize, usize)> {
    let bad = || malformed(at, format!("malformed hunk header '{}'", shown(l)));
    let rest = l.strip_prefix(b"@@ -").ok_or_else(bad)?;
    let end = rest.windows(3).position(|w| w == b" @@").ok_or_else(bad)?;
    let ranges = &rest[..end];
    let space = ranges.iter().position(|b| *b == b' ').ok_or_else(bad)?;
    let old = &ranges[..space];
    let new = ranges[space + 1..].strip_prefix(b"+").ok_or_else(bad)?;
    let range = |r: &[u8]| -> Result<(usize, usize)> {
        match r.iter().position(|b| *b == b',') {
            Some(i) => Ok((parse_number(&r[..i], at)?, parse_number(&r[i + 1..], at)?)),
            None => Ok((parse_number(r, at)?, 1)),
        }
    };
    let (a, b) = range(old)?;
    let (c, d) = range(new)?;
    if (b > 0 && a == 0) || (d > 0 && c == 0) {
        return Err(malformed(at, "a hunk starting at line 0"));
    }
    if b == 0 && d == 0 {
        return Err(malformed(at, "an empty hunk"));
    }
    Ok((a, b, c, d))
}

/// Hunks of one file: in order, not overlapping, and consistent with what
/// the section does.
fn check_hunks(op: FileOp, hunks: &[Hunk], line: usize) -> Result<()> {
    let mut end = 0usize;
    for h in hunks {
        let start = if h.old_len == 0 { h.old_start } else { h.old_start - 1 };
        if start < end {
            return Err(malformed(h.line, "hunks out of order or overlapping"));
        }
        end = start.checked_add(h.old_len).ok_or_else(|| malformed(h.line, "hunk range out of bounds"))?;
    }
    match op {
        FileOp::Create if hunks.len() > 1 || hunks.iter().any(|h| h.old_len != 0 || h.old_start != 0) => {
            Err(malformed(line, "a new file's hunk must add the whole file (@@ -0,0 …)"))
        }
        FileOp::Delete if hunks.len() > 1 || hunks.iter().any(|h| h.new_len != 0 || h.new_start != 0) => {
            Err(malformed(line, "a deleted file's hunk must remove the whole file (… +0,0 @@)"))
        }
        _ => Ok(()),
    }
}

/// The names of a `diff --git a/x b/y` line, without their prefixes, when
/// they can be told apart (`None` for unquoted names with spaces that
/// differ: the rest of the section names them).
fn git_line_names(s: &[u8], at: usize) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let (a, b) = if s.first() == Some(&b'"') {
        let (a, used) = unquote(s, at)?;
        let rest = s[used..].strip_prefix(b" ").ok_or_else(|| malformed(at, "malformed 'diff --git' line"))?;
        let b = if rest.first() == Some(&b'"') {
            let (b, used) = unquote(rest, at)?;
            if used != rest.len() {
                return Err(malformed(at, "text after the names on the 'diff --git' line"));
            }
            b
        } else {
            rest.to_vec()
        };
        (a, b)
    } else if let Some(i) = s.windows(2).position(|w| w == b" \"") {
        let (b, used) = unquote(&s[i + 1..], at)?;
        if i + 1 + used != s.len() {
            return Err(malformed(at, "text after the names on the 'diff --git' line"));
        }
        (s[..i].to_vec(), b)
    } else {
        // `a/X b/X`: the only split where both names agree.
        if s.len() < 5 || s.len().is_multiple_of(2) {
            return Ok(None);
        }
        let x = (s.len() - 5) / 2;
        let (a, b) = (&s[..2 + x], &s[3 + x..]);
        if s[2 + x] != b' ' || !a.starts_with(b"a/") || !b.starts_with(b"b/") || a[2..] != b[2..] {
            return Ok(None);
        }
        (a.to_vec(), b.to_vec())
    };
    let strip = |n: &[u8], p: &[u8]| -> Result<Vec<u8>> {
        n.strip_prefix(p).map(<[u8]>::to_vec).ok_or_else(|| {
            malformed(
                at,
                format!("'{}' lacks the '{}' prefix (patches made with --no-prefix are not supported)", shown(n), shown(p)),
            )
        })
    };
    Ok(Some((strip(&a, b"a/")?, strip(&b, b"b/")?)))
}

/// A path in `rename from`/`copy to`… (quoted or not, no prefix).
fn header_path(v: &[u8], at: usize) -> Result<Vec<u8>> {
    if v.first() == Some(&b'"') {
        let (p, used) = unquote(v, at)?;
        if used != v.len() {
            return Err(malformed(at, "text after a quoted name"));
        }
        return Ok(p);
    }
    Ok(v.to_vec())
}

/// The name on a `---`/`+++` line (`None` for /dev/null). An unquoted
/// name ends at a tab (what follows is a timestamp).
fn file_line_name(v: &[u8], at: usize) -> Result<Option<Vec<u8>>> {
    let name = if v.first() == Some(&b'"') {
        let (p, used) = unquote(v, at)?;
        if !(used == v.len() || v[used] == b'\t') {
            return Err(malformed(at, "text after a quoted name"));
        }
        p
    } else {
        let end = v.iter().position(|b| *b == b'\t').unwrap_or(v.len());
        v[..end].to_vec()
    };
    Ok((name != b"/dev/null").then_some(name))
}

/// Git's C-style quoted name at the start of `s` (which starts with `"`):
/// the bytes and how many input bytes it used.
fn unquote(s: &[u8], at: usize) -> Result<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = 1;
    loop {
        let Some(&c) = s.get(i) else {
            return Err(malformed(at, "an unterminated quoted name"));
        };
        i += 1;
        match c {
            b'"' => return Ok((out, i)),
            b'\\' => {
                let Some(&e) = s.get(i) else {
                    return Err(malformed(at, "an unterminated quoted name"));
                };
                i += 1;
                out.push(match e {
                    b'a' => 7,
                    b'b' => 8,
                    b't' => b'\t',
                    b'n' => b'\n',
                    b'v' => 11,
                    b'f' => 12,
                    b'r' => b'\r',
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'0'..=b'3' => {
                        let d = s.get(i..i + 2).filter(|d| d.iter().all(|b| (b'0'..=b'7').contains(b)));
                        let d = d.ok_or_else(|| malformed(at, "a malformed octal escape in a quoted name"))?;
                        i += 2;
                        (e - b'0') * 64 + (d[0] - b'0') * 8 + (d[1] - b'0')
                    }
                    _ => return Err(malformed(at, "an unknown escape in a quoted name")),
                });
            }
            c => out.push(c),
        }
    }
}

/// Check a path from a patch and make it a [`VPath`] (see the module
/// documentation for the rules).
pub fn check_path(raw: &[u8], at: usize, lim: &Limits) -> Result<VPath> {
    let refuse = |why: &str| VeilError::InvalidPath(format!("patch line {at}: '{}' {why}", shown(raw)));
    let s = std::str::from_utf8(raw).map_err(|_| refuse("is not UTF-8"))?;
    if s.is_empty() {
        return Err(refuse("is empty"));
    }
    if s.len() > lim.max_path {
        return Err(refuse(&format!("is longer than {} bytes", lim.max_path)));
    }
    if s.starts_with('/') {
        return Err(refuse("is an absolute path"));
    }
    for c in s.split('/') {
        if c.is_empty() {
            return Err(refuse("has an empty component ('//' or a trailing '/')"));
        }
        if c == "." || c == ".." {
            return Err(refuse("has a '.' or '..' component"));
        }
        if c.len() > MAX_COMPONENT {
            return Err(refuse(&format!("has a component longer than {MAX_COMPONENT} bytes")));
        }
        if c.chars().any(|ch| ch.is_control()) {
            return Err(refuse("holds a control character"));
        }
        if crate::object::is_reserved_name(c) {
            return Err(refuse("is inside Veil's own metadata (.veil)"));
        }
        if let Some(d) = policy::vcs_metadata_name(c) {
            return Err(refuse(&format!("is inside {d} metadata")));
        }
        if crate::vfs::is_temp_name(c) {
            return Err(refuse("is the name of a Veil temp file"));
        }
    }
    let p = VPath::new(s)?;
    debug_assert_eq!(p.as_str(), s);
    Ok(p)
}

// ---- the applier -----------------------------------------------------------

/// What one patch wrote to its overlay.
#[derive(Debug, Default)]
struct Applied {
    /// Paths written, with their mode (a submodule is written as a file
    /// holding its pin, turned into a gitlink once recorded).
    written: Vec<(VPath, Mode)>,
    removed: Vec<VPath>,
    /// Paths written from a version that is sealed (an edit, a rename or a
    /// copy of a sealed file): never recorded as public.
    from_sealed: Vec<(VPath, VPath)>,
    /// Three-way merges that conflicted (recorded as conflicts).
    conflicts: Vec<Conflicted>,
    /// Paths a three-way merge wrote cleanly.
    merged: Vec<VPath>,
}

/// A three-way merge of `vl am --3way` that conflicted at `path`.
#[derive(Debug)]
struct Conflicted {
    path: VPath,
    base: ConflictTerm,
    ours: ConflictTerm,
    theirs: Vec<u8>,
    executable: bool,
}

/// What a tree holds at a path, as the applier needs to know it.
enum Probe {
    Missing,
    /// A file, a symlink or a gitlink.
    Leaf(TreeEntry),
    /// A directory or a conflict (never traversed, never written through).
    Other(TreeEntry),
    /// An ancestor is not a directory (a file, a symlink, a gitlink).
    Blocked(VPath),
    /// An ancestor is a directory this reader cannot open.
    Sealed(VPath),
}

fn probe(store: &ObjectStore, root: &ObjectId, path: &VPath) -> Result<Probe> {
    let comps: Vec<&str> = path.components().collect();
    let mut tree = store.tree(root)?;
    let mut cur = VPath::root();
    for (i, c) in comps.iter().enumerate() {
        cur = cur.join(c);
        let Some(e) = tree.get(c).cloned() else { return Ok(Probe::Missing) };
        if i + 1 == comps.len() {
            return Ok(if e.kind.holds_blob() { Probe::Leaf(e) } else { Probe::Other(e) });
        }
        if e.kind != EntryKind::Dir {
            return Ok(Probe::Blocked(cur));
        }
        tree = match store.tree(&e.id) {
            Ok(t) => t,
            Err(err) if err.is_unreadable() => return Ok(Probe::Sealed(cur)),
            Err(err) => return Err(err),
        };
    }
    Ok(Probe::Missing)
}

fn refused(why: String) -> VeilError {
    VeilError::Repo(why)
}

/// The version a section changes, read from the snapshot itself.
struct Source {
    /// As the patch shows it: a file's bytes, a link's target, or
    /// `Subproject commit <id>\n` for a submodule.
    data: Vec<u8>,
    mode: Mode,
    entry: TreeEntry,
}

/// The version at `path` a section changes, read from the snapshot itself:
/// never a fallback (which would turn an edit of a sealed file into a
/// public file), never through anything but a directory.
fn read_source(store: &ObjectStore, root: &ObjectId, path: &VPath, mode: Option<Mode>) -> Result<Source> {
    let e = match probe(store, root, path)? {
        Probe::Leaf(e) => e,
        Probe::Other(e) => {
            return Err(refused(match e.kind {
                EntryKind::Dir => format!("{path} is a directory"),
                EntryKind::Conflict => format!("{path} has an unresolved conflict; resolve it first"),
                _ => format!("{path} is not a regular file"),
            }))
        }
        Probe::Missing => return Err(refused(format!("{path} does not exist"))),
        Probe::Blocked(a) => return Err(refused(format!("{path} does not exist ({a} is not a directory)"))),
        Probe::Sealed(d) => return Err(refused(format!("cannot apply to {path}: {d} is sealed and you hold no key for it"))),
    };
    let have = Mode::of_entry(&e).expect("a leaf has a mode");
    if let Some(m) = mode.filter(|m| *m != have) {
        return Err(refused(if m.kind() == have.kind() {
            format!("{path}: the patch expects mode {}, the file has mode {}", m.git(), have.git())
        } else {
            format!("{path}: the patch expects a {}, and it is a {}", m.noun(), have.noun())
        }));
    }
    let raw = match store.read_blob(&e.id) {
        Ok(d) => d,
        Err(err) if err.is_unreadable() => {
            return Err(refused(format!(
                "cannot apply to sealed {} {path}: you hold no key for its content (its public fallback is never patched)",
                if have.kind() == EntryKind::File { "file" } else { have.noun() }
            )))
        }
        Err(err) => return Err(err),
    };
    let data = match have {
        Mode::Gitlink => {
            let pin = parse_pin(&raw).ok_or_else(|| refused(format!("{path}: its submodule pin is malformed")))?;
            format!("Subproject commit {pin}\n").into_bytes()
        }
        _ => raw,
    };
    Ok(Source { data, mode: have, entry: e })
}

/// A path a section creates must be free (or a leaf the same patch
/// deletes: a type change), and every ancestor a directory this reader can
/// open (or a leaf the same patch deletes).
fn check_target(store: &ObjectStore, root: &ObjectId, path: &VPath, deleted: &BTreeSet<VPath>) -> Result<()> {
    match probe(store, root, path)? {
        Probe::Missing => Ok(()),
        Probe::Leaf(_) if deleted.contains(path) => Ok(()),
        Probe::Leaf(e) | Probe::Other(e) => Err(refused(if store.entry_readable(&e) {
            format!("{path} already exists")
        } else {
            format!("{path} already exists (sealed, and you hold no key for it)")
        })),
        Probe::Blocked(a) if deleted.contains(&a) => Ok(()),
        Probe::Blocked(a) => Err(refused(format!("cannot create {path}: {a} is not a directory"))),
        Probe::Sealed(d) => Err(refused(format!("cannot create {path}: {d} is sealed and you hold no key for it"))),
    }
}

/// Names a symlink may not have: Veil's policy file, and the files Git
/// reads from the work tree (Git refuses them as links too).
const NO_LINK_NAMES: &[&str] = &[".veilpolicy", ".gitmodules", ".gitattributes", ".gitignore", ".mailmap"];

/// A symlink target a patch writes: what the recording accepts (not
/// empty, no NUL, UTF-8, at most `PATH_MAX`), and not at a name a link may
/// not have. A target leaving the repository is recorded as it is (Veil
/// never follows links), with a warning.
fn check_link(path: &VPath, target: &[u8]) -> Result<()> {
    crate::vfs::check_link_target(target).map_err(|e| refused(format!("{path}: {e}")))?;
    let name = path.file_name().to_ascii_lowercase();
    if NO_LINK_NAMES.contains(&name.trim_end_matches(['.', ' '])) {
        return Err(refused(format!("{path}: a symlink may not be named {}", path.file_name())));
    }
    Ok(())
}

/// A submodule pin's commit: what a gitlink's content `<hex>\n` names (as
/// `submodule::parse_pin` reads it, available without the Git feature).
fn parse_pin(data: &[u8]) -> Option<String> {
    let hex = data.strip_suffix(b"\n")?;
    let ok = matches!(hex.len(), 40 | 64) && hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    ok.then(|| String::from_utf8_lossy(hex).into_owned())
}

/// The pin (`<id>\n`) a submodule section's content names: exactly
/// `Subproject commit <40 or 64 lowercase hex digits>`, with or without
/// its newline.
fn pin_of(path: &VPath, data: &[u8]) -> Result<Vec<u8>> {
    let bad = || refused(format!("{path}: a submodule's content must be 'Subproject commit <full commit id>'"));
    let hex = data.strip_prefix(b"Subproject commit ").ok_or_else(bad)?;
    let hex = hex.strip_suffix(b"\n").unwrap_or(hex);
    let mut pin = hex.to_vec();
    pin.push(b'\n');
    parse_pin(&pin).ok_or_else(bad)?;
    Ok(pin)
}

/// No two names of one directory may differ only in case or Unicode
/// normalisation (they would be one file on macOS): among the paths a patch
/// creates, and between them and what the directory holds (entries this
/// reader cannot read included).
fn check_collisions(store: &ObjectStore, root: &ObjectId, targets: &[&VPath], deleted: &BTreeSet<VPath>) -> Result<()> {
    let fold = NameFolding::MACOS;
    let mut dirs: BTreeMap<VPath, BTreeMap<String, String>> = BTreeMap::new();
    for t in targets {
        let mut parent = VPath::root();
        for c in t.components() {
            let names = dirs.entry(parent.clone()).or_default();
            let key = fold.key(c).into_owned();
            match names.get(&key) {
                Some(other) if other != c => {
                    return Err(refused(format!(
                        "{} and {} differ only in case or Unicode normalisation (one file on macOS)",
                        parent.join(other),
                        parent.join(c)
                    )))
                }
                _ => {
                    names.insert(key, c.to_string());
                }
            }
            parent = parent.join(c);
        }
    }
    for (dir, names) in &dirs {
        let tree = match probe_dir(store, root, dir)? {
            Some(t) => t,
            None => continue,
        };
        for e in &tree.entries {
            if deleted.contains(&dir.join(&e.name)) {
                continue;
            }
            if let Some(n) = names.get(fold.key(&e.name).as_ref()) {
                if *n != e.name {
                    return Err(refused(format!(
                        "{} differs only in case or Unicode normalisation from the existing {} (one file on macOS)",
                        dir.join(n),
                        dir.join(&e.name)
                    )));
                }
            }
        }
    }
    Ok(())
}

/// The tree of directory `dir` (raw: unreadable entries included), if it
/// exists.
fn probe_dir(store: &ObjectStore, root: &ObjectId, dir: &VPath) -> Result<Option<Arc<crate::object::Tree>>> {
    if dir.is_root() {
        return store.tree(root).map(Some);
    }
    match probe(store, root, dir)? {
        Probe::Other(e) if e.kind == EntryKind::Dir => match store.tree(&e.id) {
            Ok(t) => Ok(Some(t)),
            Err(err) if err.is_unreadable() => Ok(None),
            Err(err) => Err(err),
        },
        _ => Ok(None),
    }
}

/// The Git blob id of `data` (lowercase hex).
#[cfg(feature = "git")]
fn git_blob_id(data: &[u8]) -> String {
    gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, data)
        .map(|o| o.to_string())
        .unwrap_or_else(|_| "0".repeat(40))
}

/// Is `id` a full (40 hex digit) Git object id?
#[cfg(feature = "git")]
fn full_id(id: &str) -> bool {
    id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Most snapshots `vl am --3way` looks through for a pre-image.
const PREIMAGE_SNAPSHOTS: usize = 10_000;
/// Most bytes `vl am --3way` hashes looking for pre-images, per series.
const PREIMAGE_BYTES: u64 = 1 << 30;

/// Where `vl am --3way` looks for a pre-image (the version an `index`
/// line names): the trees of the destination's history, nearest first,
/// then those of every other visible head's history (a patch made on a
/// later version than the destination), read as this reader reads them
/// (its own versions it can open, and the public fallbacks of the
/// others), with the Git ids already computed.
#[cfg_attr(not(feature = "git"), allow(dead_code))]
struct Preimages {
    trees: Vec<ObjectId>,
    hashed: std::collections::HashMap<ObjectId, Option<String>>,
    budget: u64,
}

impl Preimages {
    fn new(repo: &Repo, dest: &ObjectId, heads: impl IntoIterator<Item = ObjectId>) -> Result<Preimages> {
        let mut trees = Vec::new();
        let mut seen_trees = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for start in std::iter::once(*dest).chain(heads) {
            if !seen.insert(start) {
                continue;
            }
            let mut queue = std::collections::VecDeque::from([start]);
            while let Some(id) = queue.pop_front() {
                if seen.len() > PREIMAGE_SNAPSHOTS {
                    break;
                }
                let Ok(s) = repo.snapshot(&id) else { continue };
                if seen_trees.insert(s.tree) {
                    trees.push(s.tree);
                }
                for p in &s.parents {
                    if seen.insert(*p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
        Ok(Preimages {
            trees,
            hashed: Default::default(),
            budget: PREIMAGE_BYTES,
        })
    }

    /// The version of `paths` (in `current`, then in history) whose Git
    /// blob id starts with `want`, and the conflict term it is.
    #[cfg(feature = "git")]
    fn find(&mut self, store: &ObjectStore, current: &ObjectId, paths: &[&VPath], want: &str) -> Result<Option<(Vec<u8>, ConflictTerm)>> {
        if want.len() < 7 || !want.bytes().all(|b| b.is_ascii_hexdigit()) || want.bytes().all(|b| b == b'0') {
            return Ok(None);
        }
        let trees: Vec<ObjectId> = std::iter::once(*current).chain(self.trees.iter().copied()).collect();
        for tree in trees {
            for path in paths {
                let e = match crate::tree::lookup(store, &tree, path) {
                    Ok(Some(e)) if e.kind == EntryKind::File => e,
                    _ => continue,
                };
                let own = ConflictTerm::of(&e);
                let fallback = e.fallback.map(|fb| ConflictTerm {
                    kind: Default::default(),
                    id: fb,
                    size: 0,
                    executable: e.executable,
                    visibility: crate::object::Visibility::Public,
                    fallback: None,
                });
                for term in std::iter::once(own).chain(fallback) {
                    if let Some(Some(oid)) = self.hashed.get(&term.id) {
                        if !oid.starts_with(want) {
                            continue;
                        }
                    } else if self.hashed.contains_key(&term.id) {
                        continue;
                    }
                    let data = match store.read_blob(&term.id) {
                        Ok(d) => d,
                        Err(_) => {
                            self.hashed.insert(term.id, None);
                            continue;
                        }
                    };
                    if !self.hashed.contains_key(&term.id) {
                        if self.budget < data.len() as u64 {
                            return Ok(None);
                        }
                        self.budget -= data.len() as u64;
                        let oid = git_blob_id(&data);
                        let hit = oid.starts_with(want);
                        self.hashed.insert(term.id, Some(oid));
                        if !hit {
                            continue;
                        }
                    }
                    let size = data.len() as u64;
                    return Ok(Some((data, ConflictTerm { size, ..term })));
                }
            }
        }
        Ok(None)
    }
}

/// Mutable state of one series' application.
struct State {
    work: u64,
    inflated: u64,
    /// With `--3way`: where pre-images are looked for.
    preimages: Option<Preimages>,
}

/// The result of a binary section on `base`: `Ok(Err(why))` when `base`
/// is not the version the section was made for.
fn apply_binary(series: &Series, f: &FilePatch, bp: &BinaryPatch, base: &[u8], lim: &Limits, st: &mut State) -> Result<std::result::Result<Vec<u8>, String>> {
    let what = f.path();
    #[cfg(feature = "git")]
    {
        let Some((old_id, new_id)) = &f.index else {
            return Err(refused(format!("{what}: a binary section without an 'index' line (Git writes one)")));
        };
        if !full_id(old_id) || !full_id(new_id) {
            return Err(refused(format!(
                "{what}: a binary section needs full object ids on its 'index' line (`git format-patch --binary` writes them)"
            )));
        }
        if f.old_path.is_some() && git_blob_id(base) != *old_id {
            return Ok(Err(format!("{what}: the binary patch was made for another version of the file")));
        }
    }
    let data = series.binary_data(&bp.forward).map_err(|e| refused(format!("{what}: {e}")))?;
    st.inflated = st.inflated.saturating_add(data.len() as u64);
    let out = match bp.forward.kind {
        BinaryKind::Literal => data,
        BinaryKind::Delta => {
            let r = match binary::apply_delta(base, &data, lim.max_file_size) {
                Ok(r) => r,
                Err(e) if e.contains("is for a file of") => return Ok(Err(format!("{what}: {e}"))),
                Err(e) => return Err(refused(format!("{what}: {e}"))),
            };
            st.inflated = st.inflated.saturating_add(r.len() as u64);
            r
        }
    };
    if st.inflated > lim.max_inflated {
        return Err(refused(format!("the binary sections of the series make more than {} bytes", lim.max_inflated)));
    }
    #[cfg(feature = "git")]
    if let Some((_, new_id)) = &f.index {
        if f.new_path.is_some() && git_blob_id(&out) != *new_id {
            return Err(refused(format!("{what}: the binary patch does not make the file its 'index' line names")));
        }
    }
    Ok(Ok(out))
}

/// The three-way merge of `vl am --3way`: the content the section makes
/// from `base` (`theirs`), merged with `ours` from `base`.
#[cfg_attr(not(feature = "git"), allow(dead_code))]
enum Merged {
    Clean(Vec<u8>),
    /// The content to record for the builder to check (markers, or
    /// `theirs` for binary content) and the conflict.
    Conflict(Vec<u8>, Box<Conflicted>),
}

#[cfg(feature = "git")]
fn merge3(base: &[u8], ours: &Source, theirs: Vec<u8>, conflict: impl FnOnce(Vec<u8>) -> Conflicted) -> Merged {
    if ours.data == base || ours.data == theirs {
        return Merged::Clean(if ours.data == base { theirs } else { ours.data.clone() });
    }
    let binary = [base, &ours.data, &theirs].iter().any(|d| crate::secrets::looks_binary(d));
    if binary {
        return Merged::Conflict(theirs.clone(), Box::new(conflict(theirs)));
    }
    match crate::textmerge::merge(base, &ours.data, &theirs, 7, crate::textmerge::Style::Diff3) {
        Ok(m) => Merged::Clean(m),
        Err(markers) => Merged::Conflict(markers, Box::new(conflict(theirs))),
    }
}

/// `vl am --3way` for section `f` that did not apply to `ours`: the
/// pre-image its `index` line names, from this repository's history, the
/// section applied to it, and the merge (`None`: no pre-image, or the
/// section does not apply to it either).
#[allow(clippy::too_many_arguments)]
fn three_way(
    store: &ObjectStore,
    root: &ObjectId,
    series: &Series,
    f: &FilePatch,
    ours: &Source,
    new_mode: Mode,
    lim: &Limits,
    st: &mut State,
) -> Result<Option<Merged>> {
    #[cfg(not(feature = "git"))]
    {
        let _ = (store, root, series, f, ours, new_mode, lim, st);
        Ok(None)
    }
    #[cfg(feature = "git")]
    {
        if ours.mode.kind() != EntryKind::File {
            return Ok(None);
        }
        let (Some((want, _)), Some(new_path)) = (&f.index, &f.new_path) else { return Ok(None) };
        let Some(pre) = st.preimages.as_mut() else { return Ok(None) };
        let mut paths: Vec<&VPath> = f.old_path.iter().collect();
        if f.new_path != f.old_path {
            paths.push(new_path);
        }
        let Some((base, base_term)) = pre.find(store, root, &paths, want)? else { return Ok(None) };
        let theirs = match &f.binary_patch {
            Some(bp) => match apply_binary(series, f, bp, &base, lim, st)? {
                Ok(t) => t,
                Err(_) => return Ok(None),
            },
            None => match apply_hunks(series, f, &base, lim, &mut st.work) {
                Ok(t) => t,
                Err(_) => return Ok(None),
            },
        };
        let conflict = |theirs: Vec<u8>| Conflicted {
            path: new_path.clone(),
            base: base_term,
            ours: ConflictTerm::of(&ours.entry),
            theirs,
            executable: new_mode == Mode::Executable,
        };
        Ok(Some(merge3(&base, ours, theirs, conflict)))
    }
}

/// Apply one patch to `fs`, an overlay over the tree `root`.
fn apply_patch(store: &ObjectStore, root: &ObjectId, fs: &OverlayBackend, series: &Series, p: &Patch, lim: &Limits, st: &mut State) -> Result<Applied> {
    let deleted: BTreeSet<VPath> = p
        .files
        .iter()
        .filter(|f| matches!(f.op, FileOp::Delete | FileOp::Rename))
        .filter_map(|f| f.old_path.clone())
        .collect();
    let format = store.format();
    let mut out = Applied::default();
    let mut writes: Vec<(VPath, Vec<u8>, Mode)> = Vec::new();
    let mut removals: Vec<(VPath, Mode)> = Vec::new();
    let mut targets: Vec<&VPath> = Vec::new();
    for f in &p.files {
        let what = f.path();
        let at = |e: VeilError| match e {
            VeilError::Repo(m) if !m.contains(what.as_str()) => VeilError::Repo(format!("{what}: {m}")),
            e => e,
        };
        if f.binary && f.binary_patch.is_none() {
            return Err(refused(format!(
                "{what}: the patch says only 'Binary files … differ' and holds no content; ask for one made with \
                 `git format-patch --binary` (or `vl format-patch --binary`)"
            )));
        }
        if format < crate::object::GIT_PARITY_REPO_FORMAT {
            if let Some(m) = [f.old_mode, f.new_mode].into_iter().flatten().find(|m| m.kind() != EntryKind::File) {
                return Err(refused(format!(
                    "{what} is a {}: symlinks and submodules need repository format {}, and this one is at format {format} \
                     (upgrade it with `vl upgrade`)",
                    m.noun(),
                    crate::object::GIT_PARITY_REPO_FORMAT
                )));
            }
        }
        let old = f.old_path.as_ref().map(|o| read_source(store, root, o, f.old_mode)).transpose()?;
        let new_mode = match (f.op, &old) {
            (FileOp::Delete, _) => None,
            (_, Some(o)) => Some(f.new_mode.unwrap_or(o.mode)),
            (_, None) => Some(f.new_mode.unwrap_or(Mode::Regular)),
        };
        if let (Some(o), Some(n)) = (&old, new_mode) {
            if o.mode.kind() != n.kind() {
                return Err(refused(format!(
                    "{what}: the section turns a {} into a {} (Git writes a type change as a deletion and a creation)",
                    o.mode.noun(),
                    n.noun()
                )));
            }
        }
        if f.op != FileOp::Modify {
            if let Some(n) = &f.new_path {
                check_target(store, root, n, &deleted)?;
                targets.push(n);
            }
        }
        if let (Some(o), Some(n)) = (&old, &f.new_path) {
            if !o.entry.visibility.is_public() {
                out.from_sealed.push((n.clone(), f.old_path.clone().expect("a source")));
            }
        }
        let empty = Vec::new();
        let base = old.as_ref().map_or(&empty, |o| &o.data);
        let applied = match &f.binary_patch {
            Some(bp) => apply_binary(series, f, bp, base, lim, st)?.map_err(refused),
            None => apply_hunks(series, f, base, lim, &mut st.work),
        };
        let data = match (applied, &old, new_mode) {
            (Ok(d), _, _) => d,
            (Err(e), Some(o), Some(m)) if st.preimages.is_some() => match three_way(store, root, series, f, o, m, lim, st)? {
                Some(Merged::Clean(d)) => {
                    out.merged.push(f.new_path.clone().expect("a new path"));
                    d
                }
                Some(Merged::Conflict(d, c)) => {
                    if format < crate::object::CONFLICT_REPO_FORMAT && crate::secrets::looks_binary(&d) {
                        return Err(refused(format!(
                            "{what}: the three-way merge of binary content conflicts, and this repository format cannot record \
                             the conflict (upgrade it with `vl upgrade`)"
                        )));
                    }
                    out.conflicts.push(*c);
                    d
                }
                None => return Err(at(e)),
            },
            (Err(e), _, _) => return Err(at(e)),
        };
        if data.len() as u64 > lim.max_file_size {
            return Err(refused(format!(
                "{what}: the patched file would be {} bytes, more than {} (VEIL_MAX_OBJECT)",
                data.len(),
                lim.max_file_size
            )));
        }
        match (&f.new_path, new_mode) {
            (Some(n), Some(m)) => {
                let content = match m {
                    Mode::Symlink => {
                        check_link(n, &data)?;
                        data
                    }
                    Mode::Gitlink => pin_of(n, &data)?,
                    Mode::Regular | Mode::Executable => data,
                };
                if m.kind() != EntryKind::File && n.as_str() == policy::POLICY_FILE {
                    return Err(refused(format!("{n} is always a regular file, never a {}", m.noun())));
                }
                writes.push((n.clone(), content, m));
            }
            _ => {
                if !data.is_empty() {
                    return Err(refused(format!("{what}: the patch deletes the file, but it holds more than the patch removes")));
                }
            }
        }
        if matches!(f.op, FileOp::Delete | FileOp::Rename) {
            let o = old.as_ref().expect("a source");
            removals.push((f.old_path.clone().expect("a source"), o.mode));
        }
    }
    // Nothing is written below another path this patch writes: those are
    // files, symlinks and submodules, never directories (a link is never
    // written through, CVE-2023-23946).
    let leaves: BTreeMap<&VPath, Mode> = writes.iter().map(|(p, _, m)| (p, *m)).collect();
    for (path, _, _) in &writes {
        if let Some((a, m)) = path.ancestors().iter().find_map(|a| leaves.get_key_value(a)) {
            return Err(refused(format!(
                "cannot write {path}: the same patch makes {a} a {} (nothing is ever written through a symlink)",
                m.noun()
            )));
        }
    }
    check_collisions(store, root, &targets, &deleted)?;
    for (r, m) in removals {
        if m == Mode::Gitlink {
            fs.remove_dir_all(&r)?;
        } else {
            fs.remove_file(&r)?;
        }
        out.removed.push(r);
    }
    for (path, data, mode) in writes {
        match mode {
            Mode::Regular | Mode::Executable => {
                fs.write(&path, &data)?;
                fs.set_executable(&path, mode == Mode::Executable)?;
            }
            Mode::Symlink => fs.write_link(&path, &data)?,
            // Recorded as a file holding the pin (classified, scanned and
            // sealed as any content), then made a gitlink.
            Mode::Gitlink => {
                if fs.metadata(&path)?.is_some_and(|m| m.kind == crate::vfs::NodeKind::Dir) {
                    fs.remove_dir_all(&path)?;
                }
                fs.write(&path, &data)?;
            }
        }
        out.written.push((path, mode));
    }
    Ok(out)
}

/// `old` with the hunks of `f` applied. A hunk applies where it says, or
/// up to [`Limits::max_offset`] lines away, only where every line it
/// removes or keeps matches exactly (line endings included: no fuzz, no
/// whitespace or CRLF leniency). A hunk without leading context must match
/// at the start of the file, one without trailing context at its end, one
/// without any only where it says.
fn apply_hunks(series: &Series, f: &FilePatch, old: &[u8], lim: &Limits, work: &mut u64) -> Result<Vec<u8>> {
    let lines: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
    let mut out = Vec::with_capacity(old.len());
    let mut cursor = 0usize;
    let mut offset: isize = 0;
    for (n, h) in f.hunks.iter().enumerate() {
        let mut before: Vec<&[u8]> = Vec::with_capacity(h.old_len);
        let mut after: Vec<&[u8]> = Vec::with_capacity(h.new_len);
        let (mut leading, mut trailing, mut changed) = (0usize, 0usize, false);
        for (kind, text) in series.hunk_lines(h) {
            match kind {
                LineKind::Context => {
                    before.push(text);
                    after.push(text);
                    if changed {
                        trailing += 1;
                    } else {
                        leading += 1;
                    }
                }
                LineKind::Delete => {
                    before.push(text);
                    changed = true;
                    trailing = 0;
                }
                LineKind::Insert => {
                    after.push(text);
                    changed = true;
                    trailing = 0;
                }
            }
        }
        let nominal = if h.old_len == 0 { h.old_start } else { h.old_start - 1 } as isize;
        let want = nominal.saturating_add(offset);
        let k = before.len();
        // What one try may cost: a line, or 64 bytes of it, compared.
        let cost = 1 + k as u64 + before.iter().map(|l| l.len() as u64).sum::<u64>() / 64;
        let fits = |pos: usize| -> bool {
            if pos < cursor || pos + k > lines.len() {
                return false;
            }
            if leading == 0 && trailing > 0 && pos != 0 {
                return false;
            }
            if trailing == 0 && leading > 0 && pos + k != lines.len() {
                return false;
            }
            true
        };
        let reach = if leading == 0 && trailing == 0 { 0 } else { lim.max_offset as isize };
        let mut found = None;
        for d in 0..=reach {
            for pos in if d == 0 { vec![want] } else { vec![want - d, want + d] } {
                if pos < 0 || !fits(pos as usize) {
                    continue;
                }
                let pos = pos as usize;
                *work = work.saturating_add(cost);
                if *work > lim.max_work {
                    return Err(refused("applying the patch takes too long (hunks far from where they say they apply)".into()));
                }
                if lines[pos..pos + k] == before[..] {
                    found = Some(pos);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some(pos) = found else {
            return Err(refused(format!(
                "hunk #{} (@@ -{},{} +{},{} @@, patch line {}) does not apply",
                n + 1,
                h.old_start,
                h.old_len,
                h.new_start,
                h.new_len,
                h.line
            )));
        };
        for l in &lines[cursor..pos] {
            out.extend_from_slice(l);
        }
        for l in &after {
            out.extend_from_slice(l);
        }
        cursor = pos + k;
        offset = pos as isize - nominal;
        if out.len() as u64 > lim.max_file_size {
            return Err(refused(format!("the patched file would be larger than {} bytes (VEIL_MAX_OBJECT)", lim.max_file_size)));
        }
    }
    // A line written without its `\n` (a "no newline" marker) must be last.
    for l in &lines[cursor..] {
        out.extend_from_slice(l);
    }
    if out.split_inclusive(|b| *b == b'\n').rev().skip(1).any(|l| !l.ends_with(b"\n")) {
        return Err(refused("a 'no newline at end of file' line is not at the end of the file".into()));
    }
    Ok(out)
}

// ---- vl am -----------------------------------------------------------------

/// Options of [`apply_series`].
#[derive(Clone, Debug, Default)]
pub struct AmOptions {
    /// Record this repository's user as every change's author (and now as
    /// its time) instead of each patch's `From:` and `Date:`.
    pub author_as_me: bool,
    /// Add a `Signed-off-by:` line with this repository's user.
    pub signoff: bool,
    pub limits: Limits,
    /// Description of a patch with no subject or body (a plain diff).
    pub default_description: String,
    /// When a section does not apply, merge it three ways with the
    /// pre-image its `index` line names, if this repository's history of
    /// the file holds it; a conflict is recorded as a first-class conflict.
    pub three_way: bool,
}

/// What [`apply_series`] recorded.
#[derive(Clone, Debug, Default)]
pub struct AmReport {
    /// The new changes (their snapshots), first patch first.
    pub changes: Vec<ObjectId>,
    /// Cover letters skipped (their position in the input, from 1).
    pub skipped: Vec<usize>,
    /// The working copy's new snapshot, when it was rebased onto the series.
    pub rebased: Option<ObjectId>,
    /// Paths whose protection a patch's `.veilpolicy` would weaken: recorded
    /// with the protection accepted on this device, waiting for
    /// `vl policy accept`.
    pub policy_held_back: Vec<policy::HeldBack>,
    /// Patches that change no file (recorded as empty changes).
    pub empty: Vec<usize>,
    /// With [`AmOptions::three_way`]: files merged cleanly with their
    /// pre-image (patch number from 1, path).
    pub merged: Vec<(usize, VPath)>,
    /// With [`AmOptions::three_way`]: files recorded with a conflict.
    pub conflicts: Vec<(usize, VPath)>,
    /// Symlinks recorded whose target leaves the repository or names an
    /// isolated file (patch number, path, why).
    pub link_warnings: Vec<(usize, VPath, String)>,
}

/// Refuse what the builder would not record as the patch wrote it.
fn check_recorded(store: &ObjectStore, tree: &ObjectId, applied: &Applied, r: &BuildReport) -> Result<()> {
    if let Some((p, f)) = r.quarantined.first() {
        let rule = f.first().map_or("secret", |f| f.rule);
        return Err(VeilError::Policy(format!(
            "{p} quarantined ({rule}): the patch adds what looks like a secret. Nothing was recorded; \
             remove the secret from the patch, or make the path cloaked or isolated first"
        )));
    }
    let first = |v: &[VPath]| v.first().cloned();
    if let Some(p) = first(&r.isolated).or_else(|| first(&r.blocked_exposures)) {
        return Err(VeilError::Policy(format!(
            "{p} is isolated by the policy (local-only): a patch cannot record it. Nothing was recorded"
        )));
    }
    if let Some((p, why)) = r.cloak_failures.first() {
        return Err(VeilError::Policy(format!("{p} cannot be cloaked ({why}). Nothing was recorded")));
    }
    if let Some((p, e)) = r.held_back.first() {
        return Err(VeilError::Policy(format!(
            "{p} is on a line under embargo {e}, which you hold no key for. Nothing was recorded"
        )));
    }
    if let Some((p, why)) = r.unreadable.first() {
        return Err(refused(format!("{p} could not be read ({why}). Nothing was recorded")));
    }
    if let Some(what) = r.unrepresentable.first() {
        return Err(refused(format!("{what} cannot be recorded. Nothing was recorded")));
    }
    for (w, mode) in &applied.written {
        // A submodule is recorded as a file holding its pin first.
        let want = if *mode == Mode::Symlink { EntryKind::Symlink } else { EntryKind::File };
        match crate::tree::lookup(store, tree, w)? {
            Some(e) if e.kind == want => {}
            _ => {
                return Err(VeilError::Policy(format!(
                    "{w} is ignored by the policy (or cannot be recorded): a patch cannot add it. Nothing was recorded"
                )))
            }
        }
    }
    for d in &applied.removed {
        if applied.written.iter().any(|(w, _)| w == d) {
            continue;
        }
        // A directory there is what the patch created below it.
        if crate::tree::lookup(store, tree, d)?.is_some_and(|e| e.kind != EntryKind::Dir) {
            return Err(refused(format!("{d} could not be deleted. Nothing was recorded")));
        }
    }
    Ok(())
}

/// Refuse to record a file a patch wrote with less protection than the
/// `.veilpolicy` of the tree it was applied to gives it. The builder's guard
/// is the policy this device accepted, which may predate a stricter rule
/// that arrived since (by an earlier patch, a pull) and was never accepted:
/// a patch that both drops such a rule and adds a file under it would
/// otherwise record that file as public.
fn check_not_weakened(store: &ObjectStore, tree: &ObjectId, applied: &Applied, before: &Policy) -> Result<()> {
    use crate::{object::Visibility, policy::Tier};
    for (w, mode) in &applied.written {
        let Some(e) = crate::tree::lookup(store, tree, w)? else { continue };
        let wanted = match mode {
            Mode::Symlink => before.classify_link(w),
            _ => before.classify(w, false),
        }
        .tier;
        let weaker = matches!((&wanted, &e.visibility), (Tier::Cloaked(_), Visibility::Public) | (Tier::Isolated | Tier::Ignored, _));
        if weaker {
            return Err(VeilError::Policy(format!(
                "{w}: the policy of the snapshot the patch applies to makes it {}, and the patch would record it {}. \
                 Nothing was recorded; review the policy change with `vl policy show` (and `vl policy accept` it \
                 if you agree) before applying this patch",
                wanted.label(),
                e.visibility.label()
            )));
        }
    }
    Ok(())
}

/// Refuse to record content read from a sealed version as public: an edit,
/// a rename or a copy of a sealed file keeps a sealed audience (the
/// builder keeps an edit's scope; this holds for every other way a patch
/// can carry content along).
fn check_still_sealed(store: &ObjectStore, tree: &ObjectId, applied: &Applied) -> Result<()> {
    for (w, from) in &applied.from_sealed {
        if crate::tree::lookup(store, tree, w)?.is_some_and(|e| e.visibility.is_public()) {
            return Err(VeilError::Policy(format!(
                "{w}: the patch would record content of the sealed {from} as public. Nothing was recorded"
            )));
        }
    }
    Ok(())
}

/// The tree the builder recorded, made what the patch says: written
/// submodules become gitlinks (their pin as recorded: classified, scanned
/// and sealed as content), and the conflicts of `--3way` become
/// conflict entries (repository format 4 and later; before, the file keeps
/// its markers). Returns the tree and the conflicted paths.
fn finish_tree(store: &ObjectStore, mut tree: ObjectId, applied: &Applied) -> Result<(ObjectId, Vec<VPath>)> {
    use crate::{conflict, object::TermKind};
    for (w, mode) in &applied.written {
        if *mode != Mode::Gitlink {
            continue;
        }
        let e = crate::tree::lookup(store, &tree, w)?.ok_or_else(|| refused(format!("{w} was not recorded")))?;
        let link = TreeEntry {
            kind: EntryKind::Gitlink,
            executable: false,
            ..e
        };
        tree = conflict::set_entry(store, &tree, w, Some(link))?;
    }
    let mut paths = Vec::new();
    for c in &applied.conflicts {
        paths.push(c.path.clone());
        if store.format() < crate::object::CONFLICT_REPO_FORMAT {
            continue;
        }
        let e = crate::tree::lookup(store, &tree, &c.path)?.ok_or_else(|| refused(format!("{} was not recorded", c.path)))?;
        // The side the patch brings has the audience the builder gave the
        // merged file (never wider than ours: a sealed file stays sealed).
        let theirs = ConflictTerm {
            kind: TermKind::File,
            id: store.store_file(&c.theirs, &e.visibility)?,
            size: c.theirs.len() as u64,
            executable: c.executable,
            visibility: e.visibility.clone(),
            fallback: None,
        };
        let m = conflict::Merge::three_way(
            conflict::Merge::resolved(Some(c.base.clone())),
            conflict::Merge::resolved(Some(c.ours.clone())),
            conflict::Merge::resolved(Some(theirs)),
        );
        let entry = conflict::entry_for(store, c.path.file_name(), m)?;
        tree = conflict::set_entry(store, &tree, &c.path, entry)?;
    }
    Ok((tree, paths))
}

/// Apply `series` as new changes, one per patch, on top of the snapshot
/// `dest` names (a revision, resolved under the repository lock), in one
/// transaction. See the module documentation. When the working copy of
/// `ws` is a child of `dest` (the default `@-`), it is rebased onto the
/// last new change, so its edits stay on top.
pub fn apply_series(repo: &mut Repo, ws: &str, dest: &str, series: &Series, opts: &AmOptions) -> Result<AmReport> {
    let total = series.patches.len();
    let label = |i: usize, p: &Patch| {
        let s = if p.subject.is_empty() { String::new() } else { format!(" ({})", p.subject) };
        format!("patch {}/{total}{s}", i + 1)
    };
    // Refuse what needs no repository before taking the lock.
    for (i, p) in series.patches.iter().enumerate() {
        if let Some(f) = p.files.iter().find(|f| f.binary && f.binary_patch.is_none()) {
            return Err(refused(format!(
                "{}: {}: the patch says only 'Binary files … differ' and holds no content; ask for one made with \
                 `git format-patch --binary` (or `vl format-patch --binary`). Nothing was recorded",
                label(i, p),
                f.path()
            )));
        }
    }
    if opts.three_way && !cfg!(feature = "git") {
        return Err(VeilError::Unsupported("--3way needs Veil's Git support (the `git` feature)".into()));
    }
    if series.patches.iter().all(Patch::is_cover_letter) {
        return Err(refused("the input holds only a cover letter, no patch".into()));
    }
    let mut report = AmReport::default();
    let mut tx = repo.transaction(format!("am: apply {total} patch(es)"))?;
    let dest = crate::revset::resolve(tx.repo(), dest, ws)?;
    let base = tx.repo().snapshot(&dest)?;
    let store = tx.repo().store.clone();
    let user = tx.repo().user.clone();
    let accepted = policy::load_accepted(&**tx.repo().backend())?;
    let cloak = base.cloak.clone();
    let (mut parent, mut tree, mut conflicts) = (dest, base.tree, base.conflicts.clone());
    let mut st = State {
        work: 0,
        inflated: 0,
        preimages: if opts.three_way {
            let heads: Vec<ObjectId> = tx.view.heads.iter().copied().collect();
            Some(Preimages::new(tx.repo(), &dest, heads)?)
        } else {
            None
        },
    };
    for (i, p) in series.patches.iter().enumerate() {
        if p.is_cover_letter() {
            report.skipped.push(i + 1);
            continue;
        }
        let ctx = |e: VeilError| -> VeilError {
            let l = label(i, p);
            match e {
                VeilError::Repo(m) => VeilError::Repo(format!("{l}: {m}")),
                VeilError::Policy(m) => VeilError::Policy(format!("{l}: {m}")),
                VeilError::InvalidPath(m) => VeilError::InvalidPath(format!("{l}: {m}")),
                e => VeilError::Repo(format!("{l}: {e}")),
            }
        };
        let lower: Arc<dyn StorageBackend> = Arc::new(TreeView::new(store.clone(), tree));
        let fs = OverlayBackend::new(lower.clone());
        let applied = apply_patch(&store, &tree, &fs, series, p, &opts.limits, &mut st).map_err(ctx)?;
        // An incoming change: its `.veilpolicy` is guarded by the policy
        // this device accepted (the destination's, if none was recorded),
        // and nothing here is ever accepted.
        let guard = match &accepted {
            Some(t) => Policy::parse(&String::from_utf8_lossy(t)),
            None => Policy::load(&*lower).map_err(ctx)?,
        };
        let policy = Policy::load(&fs).map_err(ctx)?.guarded_by(guard);
        let line_base = || Ok(tree);
        let (new_tree, built) = build_tree(
            &store,
            &fs,
            &BuildOptions {
                policy: &policy,
                parent_tree: Some(tree),
                cloak: cloak.as_deref(),
                injected: None,
                rescan: false,
                materialised: None,
                line_base: Some(&line_base),
            },
        )
        .map_err(ctx)?;
        check_recorded(&store, &new_tree, &applied, &built).map_err(ctx)?;
        check_not_weakened(&store, &new_tree, &applied, &Policy::load(&*lower).map_err(ctx)?).map_err(ctx)?;
        check_still_sealed(&store, &new_tree, &applied).map_err(ctx)?;
        let (new_tree, conflicted) = finish_tree(&store, new_tree, &applied).map_err(ctx)?;
        report.policy_held_back.extend(built.policy_held_back.iter().cloned());
        report.link_warnings.extend(built.link_warnings.iter().map(|(p, w)| (i + 1, p.clone(), w.clone())));
        report.merged.extend(applied.merged.iter().map(|p| (i + 1, p.clone())));
        report.conflicts.extend(conflicted.iter().map(|p| (i + 1, p.clone())));
        conflicts.extend(conflicted.iter().map(|p| p.to_string()));
        conflicts.sort();
        conflicts.dedup();
        if p.files.is_empty() {
            report.empty.push(i + 1);
        }
        let mut description = p.description();
        if description.is_empty() {
            description = opts.default_description.clone();
        }
        if opts.signoff {
            let line = format!("Signed-off-by: {user}");
            if description.lines().last() != Some(line.as_str()) {
                let sep = if description.lines().last().is_some_and(|l| l.contains(": ")) { "\n" } else { "\n\n" };
                description = if description.is_empty() { line } else { format!("{description}{sep}{line}") };
            }
        }
        let (author, timestamp) = match (opts.author_as_me, &p.author) {
            (false, Some(a)) => (a.clone(), p.date.unwrap_or_else(crate::now_millis)),
            _ => (user.clone(), crate::now_millis()),
        };
        let scope = crate::embargo::description_scope(&store, &new_tree, cloak.as_deref())?;
        conflicts = crate::embargo::recordable_conflicts(&store, &new_tree, conflicts)?;
        let snap = Snapshot {
            parents: vec![parent],
            change_id: ChangeId::random(),
            tree: new_tree,
            description: store.make_text(&description, scope.as_deref())?,
            author,
            timestamp,
            predecessors: vec![],
            conflicts: conflicts.clone(),
            cloak: cloak.clone(),
            embargo: None,
            signature: None, // signed by the transaction
        };
        parent = tx.write_snapshot(&snap)?;
        tree = new_tree;
        report.changes.push(parent);
    }
    // The working copy follows the series when it sat on the destination.
    let wc = tx.view.workspace(ws)?.wc;
    if wc != dest {
        let w = tx.repo().snapshot(&wc)?;
        if w.parents == [dest] {
            let out = tx.repo().rebase_tree(&w.parents, &[parent], w.tree, w.cloak.as_deref())?;
            let mut ns = (*w).clone();
            ns.parents = vec![parent];
            ns.tree = out.tree;
            ns.predecessors = vec![wc];
            ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
            ns.conflicts.sort();
            ns.conflicts.dedup();
            ns.conflicts = crate::embargo::recordable_conflicts(&store, &ns.tree, ns.conflicts)?;
            report.rebased = Some(tx.rewrite(wc, ns)?);
        }
    }
    let n = report.changes.len();
    tx.set_description(format!("am: apply {n} patch(es) onto {}", tx.repo().snapshot(&dest)?.change_id.short()));
    tx.commit()?;
    Ok(report)
}

// ---- vl format-patch -------------------------------------------------------

#[cfg(feature = "git")]
pub use writer::{format_patches, Audience, Export, ExportOptions, ExportedPatch};

#[cfg(feature = "git")]
mod writer {
    use std::collections::BTreeSet;

    use super::{binary, format_date, git_blob_id, Mode, Result, VeilError};
    use crate::{
        git::{public_open, public_text, split_author, GitBridge, Public, Veil},
        id::ObjectId,
        keychain::LOCAL_SCOPE,
        object::{EntryKind, Object, Snapshot, Text, TreeEntry},
        rename::{self, Item, RenameOptions},
        repo::Repo,
        store::ObjectStore,
        tree::{diff_trees, TreeChange},
        vpath::VPath,
    };

    /// Whose view a patch shows.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Audience {
        /// Exactly what the Git export shows (the default).
        #[default]
        Public,
        /// Everything this reader can read.
        Me,
    }

    /// Options of [`format_patches`].
    #[derive(Clone, Debug, Default)]
    pub struct ExportOptions {
        pub audience: Audience,
        /// With [`Audience::Me`]: unreleased embargoes whose content may be
        /// included.
        pub include_embargoed: BTreeSet<String>,
        /// Also write a cover letter (patch 0).
        pub cover_letter: bool,
        /// Detect renames (`-M`), on the audience's sides only.
        pub find_renames: bool,
        /// Detect copies too (`-C`; implies renames): a new file made from
        /// a file changed in the same snapshot.
        pub find_copies: bool,
        /// Similarity a pair needs, in percent (`None`: Git's 50).
        pub rename_threshold: Option<u8>,
        /// Write binary files as `GIT binary patch` data (`--binary`),
        /// which `git am` and `vl am` apply. Never for sealed content: a
        /// sealed binary file is shown as `Binary files … differ`.
        pub binary: bool,
        /// The text after the `-- ` signature line (`vl 0.1.0`).
        pub signature: String,
    }

    /// One mail.
    #[derive(Clone, Debug)]
    pub struct ExportedPatch {
        /// The snapshot (`None` for the cover letter).
        pub snapshot: Option<ObjectId>,
        /// `0001-subject.patch`.
        pub file_name: String,
        pub text: Vec<u8>,
        /// No file changes in this view.
        pub empty: bool,
    }

    /// What [`format_patches`] wrote.
    #[derive(Clone, Debug, Default)]
    pub struct Export {
        pub patches: Vec<ExportedPatch>,
        /// With [`Audience::Me`]: the scopes whose sealed content is included.
        pub scopes: BTreeSet<String>,
        /// With [`Audience::Me`]: the embargoes whose content is included.
        pub embargoes: BTreeSet<String>,
        /// Merges and the root, which have no patch.
        pub skipped: Vec<ObjectId>,
        pub warnings: Vec<String>,
    }

    /// One side of a changed file, as the audience sees it.
    #[derive(Clone)]
    pub(super) struct Side {
        /// A file's bytes, a link's target, a submodule's pin (`<id>\n`).
        pub(super) data: Vec<u8>,
        pub(super) mode: Mode,
        /// Read from a sealed object (audience `me`): never written as
        /// binary data.
        pub(super) sealed: bool,
    }

    impl Side {
        #[cfg(test)]
        pub(super) fn file(data: Vec<u8>, exec: bool) -> Side {
            Side {
                data,
                mode: Mode::of(exec),
                sealed: false,
            }
        }

        /// The content a patch shows (`Subproject commit <id>` for a
        /// submodule) and its Git object id (the commit, for a submodule).
        fn shown(&self) -> (Vec<u8>, String) {
            match self.mode {
                Mode::Gitlink => {
                    let pin = String::from_utf8_lossy(&self.data).trim_end().to_string();
                    (format!("Subproject commit {pin}\n").into_bytes(), pin)
                }
                _ => (self.data.clone(), git_blob_id(&self.data)),
            }
        }
    }

    /// The source of a renamed or copied file.
    #[derive(Clone)]
    pub(super) struct Renamed {
        pub(super) from: VPath,
        pub(super) score: u8,
        pub(super) copy: bool,
    }

    pub(super) struct FileDiff {
        pub(super) path: VPath,
        pub(super) old: Option<Side>,
        pub(super) new: Option<Side>,
        pub(super) from: Option<Renamed>,
    }

    /// Which labels the patch of one snapshot depends on (audience `me`).
    #[derive(Default)]
    struct Labels {
        scopes: BTreeSet<String>,
        embargoes: BTreeSet<String>,
    }

    struct Reader<'a> {
        repo: &'a Repo,
        store: &'a ObjectStore,
        opts: &'a ExportOptions,
    }

    impl Reader<'_> {
        /// Record the label of the sealed object `id` this reader opened,
        /// refusing what may never leave the device.
        /// Returns whether the object is sealed.
        fn note(&self, id: &ObjectId, path: &str, labels: &mut Labels) -> Result<bool> {
            let Ok(raw) = self.store.get_raw(id) else { return Ok(false) };
            let Some(scope) = Object::sealed_scope(&raw) else { return Ok(false) };
            self.note_label(&scope, path, labels)?;
            Ok(true)
        }

        fn note_label(&self, label: &str, what: &str, labels: &mut Labels) -> Result<()> {
            // A key generation's label (`team#<key id>`) names its scope.
            let (scope, _) = crate::keychain::split_label(label);
            if scope == LOCAL_SCOPE {
                return Err(VeilError::Policy(format!(
                    "{what} is sealed for this device only, and never leaves it. Nothing was written"
                )));
            }
            match scope.strip_prefix("embargo/") {
                Some(e) => {
                    if !self.repo.keys().embargo_released(e) {
                        if !self.opts.include_embargoed.contains(e) {
                            return Err(VeilError::Policy(format!(
                                "{what} holds content of unreleased embargo {e}; add --include-embargoed {e} to include it. \
                                 Nothing was written"
                            )));
                        }
                        labels.embargoes.insert(e.to_string());
                    }
                }
                None => {
                    labels.scopes.insert(scope.to_string());
                }
            }
            Ok(())
        }

        /// A file, symlink or submodule entry as this reader reads it
        /// (`None`: no key, and no readable fallback).
        fn me_side(&self, path: &VPath, e: &TreeEntry, labels: &mut Labels) -> Result<Option<Side>> {
            let mode = match e.kind {
                EntryKind::Dir => return Ok(None),
                EntryKind::Conflict => return self.me_conflict(path, e, labels),
                _ => Mode::of_entry(e).expect("a leaf"),
            };
            let (data, sealed) = match self.store.read_blob(&e.id) {
                Ok(data) => (data, self.note(&e.id, path.as_str(), labels)?),
                Err(err) if err.is_unreadable() => match e.fallback.map(|fb| self.store.read_blob(&fb)) {
                    Some(Ok(data)) => (data, self.note(&e.fallback.expect("a fallback"), path.as_str(), labels)?),
                    Some(Err(err)) if !err.is_unreadable() => return Err(err),
                    _ => return Ok(None),
                },
                Err(err) => return Err(err),
            };
            if mode == Mode::Gitlink && super::parse_pin(&data).is_none() {
                return Err(VeilError::Corrupt(e.id.hex(), format!("{path}: a submodule pin that names no commit")));
            }
            Ok(Some(Side { data, mode, sealed }))
        }

        /// A conflict entry: its markers for this reader, or (a conflict
        /// with a symlink or submodule side) that side as it is, as the
        /// working copy holds it.
        fn me_conflict(&self, path: &VPath, e: &TreeEntry, labels: &mut Labels) -> Result<Option<Side>> {
            let c = self.store.conflict(&e.id)?;
            if c.has_special_terms() {
                let Some((_, t)) = crate::conflict::shown_side(&c) else { return Ok(None) };
                return self.me_side(path, &t.entry(&e.name), labels);
            }
            let m = crate::conflict::materialize_entry(self.store, e, crate::conflict::Audience::Reader)?;
            let mut sealed = false;
            for t in c.adds.iter().chain(c.removes.iter()).flatten() {
                if self.store.read_blob(&t.id).is_ok() {
                    sealed |= self.note(&t.id, path.as_str(), labels)?;
                }
            }
            Ok(Some(Side {
                data: m.content,
                mode: Mode::of(m.executable),
                sealed,
            }))
        }
    }

    /// A projected entry's content, read the way a public reader can (no
    /// scope key is ever used).
    fn public_side(store: &ObjectStore, e: &TreeEntry) -> Result<Side> {
        let mode = Mode::of_entry(e);
        match (public_open(store, &Veil::default(), &e.id)?, mode) {
            (Public::Visible { obj: Object::Blob(data), .. }, Some(mode))
                if mode != Mode::Gitlink || super::parse_pin(&data).is_some() =>
            {
                Ok(Side { data, mode, sealed: false })
            }
            _ => Err(VeilError::Corrupt(e.id.hex(), "a public projection holds an unreadable file".into())),
        }
    }

    /// Export `ids` (parents before children) as Git patch mails. Nothing
    /// is written anywhere: the caller writes [`Export::patches`].
    pub fn format_patches(repo: &Repo, bridge: &mut GitBridge, ids: &[ObjectId], opts: &ExportOptions) -> Result<Export> {
        let store = repo.store().clone();
        let reader = Reader {
            repo,
            store: &store,
            opts,
        };
        // Withheld history (the merged-in side of an unreleased embargo) is
        // refused before anything is computed, naming it.
        let withheld = crate::remote::embargo_withheld(repo, true)?;
        for id in ids {
            if let Some(e) = withheld.get(id) {
                let allowed = opts.audience == Audience::Me && opts.include_embargoed.contains(e);
                if !allowed {
                    let change = repo.snapshot(id)?.change_id;
                    return Err(VeilError::Policy(format!(
                        "change {} is the withheld history of unreleased embargo {e}: a patch would publish the fix. \
                         Nothing was written",
                        change.short()
                    )));
                }
            }
        }
        let mut out = Export::default();
        let mut mails: Vec<(Option<ObjectId>, Header, Vec<FileDiff>)> = Vec::new();
        let mut first_parent_tree = None;
        let mut last_tree = None;
        for id in ids {
            let s = repo.snapshot(id)?;
            if s.parents.len() != 1 {
                out.skipped.push(*id);
                continue;
            }
            let parent_tree = repo.snapshot(&s.parents[0])?.tree;
            first_parent_tree.get_or_insert(parent_tree);
            last_tree = Some(s.tree);
            let mut labels = Labels::default();
            let files = changes(&reader, bridge, &parent_tree, &s.tree, &mut labels, &mut out.warnings)?;
            let description = describe(&reader, &s, &mut labels)?;
            let header = Header {
                commit: match opts.audience {
                    Audience::Public => bridge.commit_of(id).map(|c| c.to_string()),
                    Audience::Me => None,
                },
                author: s.author.clone(),
                timestamp: s.timestamp,
                description,
                audience: (opts.audience == Audience::Me).then(|| {
                    let mut l: Vec<String> = labels.scopes.iter().cloned().collect();
                    l.extend(labels.embargoes.iter().map(|e| format!("embargo/{e}")));
                    l
                }),
            };
            out.scopes.extend(labels.scopes);
            out.embargoes.extend(labels.embargoes);
            mails.push((Some(*id), header, files));
        }
        let total = mails.len();
        if opts.cover_letter && total > 0 {
            let mut labels = Labels::default();
            let range = changes(
                &reader,
                bridge,
                &first_parent_tree.expect("a patch"),
                &last_tree.expect("a patch"),
                &mut labels,
                &mut Vec::new(),
            )?;
            out.patches.push(cover_letter(repo, &mails, &range, total, opts));
        }
        for (n, (id, header, files)) in mails.iter().enumerate() {
            let subject = subject_of(&header.description);
            let mut text = Vec::new();
            if render(&mut text, header, files, (n + 1, total), opts) {
                out.warnings.push(format!(
                    "patch {}: lines of its description that look like patch syntax (a diff, '---', a 'From ' line) \
                     were indented by one space, so no reader takes them for a patch",
                    n + 1
                ));
            }
            out.patches.push(ExportedPatch {
                snapshot: *id,
                file_name: file_name(n + 1, &subject),
                text,
                empty: files.is_empty(),
            });
        }
        Ok(out)
    }

    /// The description the audience may read, and its label.
    fn describe(r: &Reader, s: &Snapshot, labels: &mut Labels) -> Result<String> {
        match r.opts.audience {
            Audience::Public => Ok(public_text(r.store, &Veil::default(), &s.description).0),
            Audience::Me => match &s.description {
                Text::Plain(t) => Ok(t.clone()),
                Text::Sealed(env) => match r.store.read_text(&s.description) {
                    Some(t) => {
                        r.note_label(&env.scope, "the description", labels)?;
                        Ok(t)
                    }
                    None => Ok(crate::git::CLOAKED_DESCRIPTION.into()),
                },
            },
        }
    }

    /// The file changes from `old` to `new` as the audience sees them.
    fn changes(
        r: &Reader,
        bridge: &mut GitBridge,
        old: &ObjectId,
        new: &ObjectId,
        labels: &mut Labels,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<FileDiff>> {
        let store = r.store;
        let (from, to) = match r.opts.audience {
            Audience::Public => {
                // The Git export's own projection.
                let po = bridge.project(store, old)?;
                let pn = bridge.project(store, new)?;
                if !(po.complete && pn.complete) {
                    let w = "some content is missing from this replica: the patch shows what it holds".to_string();
                    if !warnings.contains(&w) {
                        warnings.push(w);
                    }
                }
                (po.tree, pn.tree)
            }
            Audience::Me => (Some(*old), Some(*new)),
        };
        let mut out = Vec::new();
        let list = diff_trees(store, from.as_ref(), to.as_ref())?;
        // Renames and copies pair deletions with additions of the
        // audience's own sides: for the public audience the projected
        // trees, read as a public reader (feature 2, point 1), so a pair
        // never involves a path or content the audience cannot see.
        let items: Vec<(TreeChange, Option<Renamed>)> = if r.opts.find_renames || r.opts.find_copies {
            let reader = match r.opts.audience {
                Audience::Public => crate::blame::Reader::Public,
                Audience::Me => crate::blame::Reader::Me,
            };
            let ro = RenameOptions {
                copies: r.opts.find_copies,
                threshold: r.opts.rename_threshold.unwrap_or(rename::DEFAULT_THRESHOLD),
                ..RenameOptions::default()
            };
            let d = rename::detect(store, &list, reader, &ro)?;
            if d.truncated {
                let w = "rename detection stopped at its limits: some renames show as a deletion and an addition".to_string();
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
            special_renames(d.items())
        } else {
            list.into_iter().map(|c| (c, None)).collect()
        };
        for (c, renamed) in items {
            let src = renamed.as_ref().map_or(&c.path, |x| &x.from);
            let side = |path: &VPath, e: &Option<TreeEntry>, labels: &mut Labels| -> Result<Option<Option<Side>>> {
                let Some(e) = e else { return Ok(Some(None)) };
                match r.opts.audience {
                    Audience::Public => Ok(Some(Some(public_side(store, e)?))),
                    Audience::Me => Ok(r.me_side(path, e, labels)?.map(Some)),
                }
            };
            let (Some(old), Some(new)) = (side(src, &c.old, labels)?, side(&c.path, &c.new, labels)?) else {
                warnings.push(format!("{}: you hold no key for one of its versions; left out of the patch", c.path));
                continue;
            };
            let same = match (&old, &new) {
                (Some(a), Some(b)) => a.data == b.data && a.mode == b.mode,
                (None, None) => true,
                _ => false,
            };
            if same && renamed.is_none() {
                continue;
            }
            let sealed = [&old, &new].into_iter().flatten().any(|s| s.sealed);
            let binary = [&old, &new].into_iter().flatten().any(|s| s.mode.kind() == EntryKind::File && is_binary(&s.data));
            if r.opts.binary && sealed && binary && !same {
                warnings.push(format!(
                    "{}: sealed binary content is never written as a binary patch; shown as 'Binary files … differ'",
                    c.path
                ));
            }
            out.push(FileDiff {
                path: c.path,
                old,
                new,
                from: renamed,
            });
        }
        Ok(out)
    }

    /// The changes and pairs `rename::detect` found, plus Git's exact
    /// renames of symlinks and submodules (which `rename.rs` leaves to
    /// files): a deleted and an added entry of the same kind and object,
    /// a same-named one first. Each pair takes the place of its addition.
    fn special_renames(items: Vec<Item>) -> Vec<(TreeChange, Option<Renamed>)> {
        let special = |e: &TreeEntry| matches!(e.kind, EntryKind::Symlink | EntryKind::Gitlink);
        let mut out: Vec<(TreeChange, Option<Renamed>)> = Vec::with_capacity(items.len());
        for it in items {
            match it {
                Item::Change(c) => out.push((c, None)),
                Item::Pair(p) => {
                    let renamed = Renamed {
                        from: p.from,
                        score: p.score,
                        copy: p.copy,
                    };
                    out.push((
                        TreeChange {
                            path: p.to,
                            old: Some(p.old),
                            new: Some(p.new),
                        },
                        Some(renamed),
                    ));
                }
            }
        }
        let deleted: Vec<usize> = (0..out.len())
            .filter(|&i| out[i].1.is_none() && out[i].0.new.is_none() && out[i].0.old.as_ref().is_some_and(special))
            .collect();
        let mut taken = vec![false; out.len()];
        let mut drop = vec![false; out.len()];
        for i in 0..out.len() {
            let (c, r) = &out[i];
            let Some(n) = c.new.as_ref().filter(|n| r.is_none() && c.old.is_none() && special(n)) else { continue };
            let fits = |j: &&usize| !taken[**j] && out[**j].0.old.as_ref().is_some_and(|o| o.kind == n.kind && o.id == n.id);
            let name = c.path.file_name();
            let pick = deleted.iter().filter(fits).find(|j| out[**j].0.path.file_name() == name).or_else(|| deleted.iter().find(fits));
            if let Some(&j) = pick {
                taken[j] = true;
                drop[j] = true;
                let from = out[j].0.path.clone();
                let old = out[j].0.old.clone();
                out[i].0.old = old;
                out[i].1 = Some(Renamed { from, score: 100, copy: false });
            }
        }
        out.into_iter().enumerate().filter(|(i, _)| !drop[*i]).map(|(_, x)| x).collect()
    }

    struct Header {
        commit: Option<String>,
        author: String,
        timestamp: i64,
        description: String,
        /// `Some` (the labels) for the `me` audience.
        audience: Option<Vec<String>>,
    }

    /// First paragraph of a description, on one line, without control
    /// characters.
    fn subject_of(d: &str) -> String {
        let para: Vec<&str> = d.trim().lines().take_while(|l| !l.trim().is_empty()).map(str::trim).collect();
        para.join(" ").chars().map(|c| if c.is_control() { '?' } else { c }).collect()
    }

    fn body_of(d: &str) -> String {
        let d = d.trim();
        let mut lines = d.lines();
        for l in lines.by_ref() {
            if l.trim().is_empty() {
                break;
            }
        }
        lines.collect::<Vec<_>>().join("\n").trim().to_string()
    }

    /// Would a reader of the mail (`git am`, `vl am`) take line `l` of a
    /// body for patch syntax: the end of the message, a file section, a
    /// signature, a new message, or (first in the body) an in-body header?
    fn looks_like_syntax(l: &str, first: bool) -> bool {
        let header = ["From: ", "Date: ", "Subject: "].iter().any(|h| l.len() >= h.len() && l[..h.len()].eq_ignore_ascii_case(h));
        super::is_separator(l.as_bytes())
            || l == "-- "
            || ["diff --git ", "diff -", "--- ", "+++ ", "@@ ", "Index: ", "From "].iter().any(|p| l.starts_with(p))
            || (first && header)
    }

    /// The body, with every line a reader would take for patch syntax
    /// indented by one space (a description is someone's text, never a
    /// patch of its own), and whether any was.
    pub(super) fn escape_body(body: &str) -> (String, bool) {
        let mut changed = false;
        let lines: Vec<String> = body
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if looks_like_syntax(l, i == 0) {
                    changed = true;
                    format!(" {l}")
                } else {
                    l.to_string()
                }
            })
            .collect();
        (lines.join("\n"), changed)
    }

    /// `0001-short-subject.patch`, as Git names it.
    fn file_name(n: usize, subject: &str) -> String {
        let mut slug = String::new();
        for c in subject.chars() {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                slug.push(c);
            } else if !slug.ends_with('-') {
                slug.push('-');
            }
            if slug.len() >= 52 {
                break;
            }
        }
        let slug = slug.trim_matches(|c| c == '-' || c == '.');
        if slug.is_empty() {
            format!("{n:04}.patch")
        } else {
            format!("{n:04}-{slug}.patch")
        }
    }

    /// RFC 2047 Q-encoded words for `s` (split at character boundaries,
    /// each at most 75 characters, folded onto continuation lines).
    fn encode_words(s: &str) -> String {
        let mut words = Vec::new();
        let mut cur = String::from("=?UTF-8?q?");
        for c in s.chars() {
            let mut enc = String::new();
            if c.is_ascii_alphanumeric() || "!*+-/".contains(c) {
                enc.push(c);
            } else if c == ' ' {
                enc.push('_');
            } else {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    enc.push_str(&format!("={b:02X}"));
                }
            }
            if cur.len() + enc.len() + 2 > 75 {
                cur.push_str("?=");
                words.push(std::mem::replace(&mut cur, String::from("=?UTF-8?q?")));
            }
            cur.push_str(&enc);
        }
        cur.push_str("?=");
        words.push(cur);
        words.join("\n ")
    }

    fn header_text(s: &str) -> String {
        let clean: String = s.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
        if clean.is_ascii() && !clean.contains("=?") {
            clean
        } else {
            encode_words(&clean)
        }
    }

    fn from_header(author: &str) -> String {
        let (name, email) = split_author(author);
        let name: String = name.chars().filter(|c| !matches!(c, '"' | '\\')).collect();
        let name = if name.is_empty() { "unknown".to_string() } else { name };
        let shown = if !name.is_ascii() {
            encode_words(&name)
        } else if name.contains(['(', ')', '<', '>', '@', ',', ';', ':', '.', '[', ']']) {
            format!("\"{name}\"")
        } else {
            name.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
        };
        format!("{shown} <{email}>")
    }

    /// Git's C-style quoting of `prefix` + `path`, when the path needs it.
    fn quote(prefix: &str, path: &VPath) -> String {
        let full = format!("{prefix}{path}");
        let needs = full.bytes().any(|b| !(0x20..0x7f).contains(&b) || b == b'"' || b == b'\\');
        if !needs {
            return full;
        }
        let mut out = String::from("\"");
        for b in full.bytes() {
            match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                b'\t' => out.push_str("\\t"),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                7 => out.push_str("\\a"),
                8 => out.push_str("\\b"),
                11 => out.push_str("\\v"),
                12 => out.push_str("\\f"),
                b if !(0x20..0x7f).contains(&b) => out.push_str(&format!("\\{b:03o}")),
                b => out.push(b as char),
            }
        }
        out.push('"');
        out
    }

    const NULL_OID: &str = "0000000000000000000000000000000000000000";

    /// Does Git take `data` for binary (a NUL in its first 8000 bytes)?
    fn is_binary(data: &[u8]) -> bool {
        data[..data.len().min(8000)].contains(&0)
    }

    pub(super) struct Stat {
        name: String,
        ins: usize,
        del: usize,
        binary: Option<(usize, usize)>,
    }

    /// One rendered hunk: header numbers and `(prefix, line)` pairs.
    struct RHunk {
        old: (usize, usize),
        new: (usize, usize),
        lines: Vec<(u8, Vec<u8>)>,
    }

    /// The hunks of a line diff (diffy's, within the bounded work of
    /// `textmerge`; past it, one hunk between the common start and end).
    fn hunks(old: &[u8], new: &[u8]) -> Vec<RHunk> {
        if crate::textmerge::fits(old, new) {
            let p = diffy::create_patch_bytes(old, new);
            return p
                .hunks()
                .iter()
                .map(|h| RHunk {
                    old: (h.old_range().start(), h.old_range().len()),
                    new: (h.new_range().start(), h.new_range().len()),
                    lines: h
                        .lines()
                        .iter()
                        .map(|l| match l {
                            diffy::Line::Context(t) => (b' ', t.to_vec()),
                            diffy::Line::Delete(t) => (b'-', t.to_vec()),
                            diffy::Line::Insert(t) => (b'+', t.to_vec()),
                        })
                        .collect(),
                })
                .collect();
        }
        let a: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
        let b: Vec<&[u8]> = new.split_inclusive(|b| *b == b'\n').collect();
        let p = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
        let s = a[p..].iter().rev().zip(b[p..].iter().rev()).take_while(|(x, y)| x == y).count();
        let from = p.saturating_sub(3);
        let (a_to, b_to) = ((a.len() - s + 3).min(a.len()), (b.len() - s + 3).min(b.len()));
        let mut lines = Vec::new();
        lines.extend(a[from..p].iter().map(|l| (b' ', l.to_vec())));
        lines.extend(a[p..a.len() - s].iter().map(|l| (b'-', l.to_vec())));
        lines.extend(b[p..b.len() - s].iter().map(|l| (b'+', l.to_vec())));
        lines.extend(a[a.len() - s..a_to].iter().map(|l| (b' ', l.to_vec())));
        let start = |from: usize, len: usize| if len == 0 { from } else { from + 1 };
        vec![RHunk {
            old: (start(from, a_to - from), a_to - from),
            new: (start(from, b_to - from), b_to - from),
            lines,
        }]
    }

    /// The text Git writes after a hunk header (its default `funcname`,
    /// xdiff's `def_ff`): the nearest line before the hunk's first line
    /// (`first`, from 0) that starts with an ASCII letter, `_` or `$`, cut
    /// to 80 bytes, without trailing whitespace.
    fn function_line<'a>(lines: &[&'a [u8]], first: usize) -> Option<&'a [u8]> {
        let l = lines[..first.min(lines.len())]
            .iter()
            .rev()
            .find(|l| l.first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_' || *c == b'$'))?;
        let mut l = &l[..l.len().min(80)];
        while let Some((last, rest)) = l.split_last() {
            if !matches!(last, b' ' | b'\t' | b'\n' | b'\r') {
                break;
            }
            l = rest;
        }
        (!l.is_empty()).then_some(l)
    }

    fn range(r: (usize, usize)) -> String {
        if r.1 == 1 {
            format!("{}", r.0)
        } else {
            format!("{},{}", r.0, r.1)
        }
    }

    /// The sections of one changed file; its diffstat entry. A type change
    /// (a file becoming a symlink, …) is a deletion and a creation of the
    /// path, as Git writes it, and one diffstat entry.
    pub(super) fn section(out: &mut Vec<u8>, f: &FileDiff, binary: bool) -> Stat {
        if let (Some(o), Some(n)) = (&f.old, &f.new) {
            if o.mode.kind() != n.mode.kind() {
                let del = FileDiff {
                    path: f.path.clone(),
                    old: Some(o.clone()),
                    new: None,
                    from: None,
                };
                let add = FileDiff {
                    path: f.path.clone(),
                    old: None,
                    new: Some(n.clone()),
                    from: None,
                };
                let a = one_section(out, &del, binary);
                let b = one_section(out, &add, binary);
                return Stat {
                    name: a.name,
                    ins: a.ins + b.ins,
                    del: a.del + b.del,
                    binary: (a.binary.is_some() || b.binary.is_some()).then_some((o.data.len(), n.data.len())),
                };
            }
        }
        one_section(out, f, binary)
    }

    /// Git's name of a rename in a diffstat: the common leading
    /// directories and trailing components written once, `a/{x => y}/z`
    /// (`pprint_rename`).
    fn rename_name(a: &VPath, b: &VPath) -> String {
        let (qa, qb) = (quote("", a), quote("", b));
        if qa != a.as_str() || qb != b.as_str() {
            return format!("{qa} => {qb}");
        }
        let (a, b) = (a.as_str().as_bytes(), b.as_str().as_bytes());
        let mut pfx = 0;
        let mut i = 0;
        while i < a.len() && i < b.len() && a[i] == b[i] {
            if a[i] == b'/' {
                pfx = i + 1;
            }
            i += 1;
        }
        // From the end (the terminating NUL included, as in Git), at most
        // into the slash that ends the prefix.
        let at = |s: &[u8], k: usize| if k == s.len() { 0 } else { s[k] };
        let (mut x, mut y) = (a.len() as isize, b.len() as isize);
        let floor = pfx as isize - if pfx > 0 { 1 } else { 0 };
        let mut sfx = 0;
        while x >= floor && y >= floor && at(a, x as usize) == at(b, y as usize) {
            if at(a, x as usize) == b'/' {
                sfx = a.len() - x as usize;
            }
            x -= 1;
            y -= 1;
        }
        let amid = a.len().saturating_sub(pfx + sfx);
        let bmid = b.len().saturating_sub(pfx + sfx);
        let s = |x: &[u8]| String::from_utf8_lossy(x).into_owned();
        if pfx + sfx > 0 {
            format!(
                "{}{{{} => {}}}{}",
                s(&a[..pfx]),
                s(&a[pfx..pfx + amid]),
                s(&b[pfx..pfx + bmid]),
                s(&a[a.len() - sfx..])
            )
        } else {
            format!("{} => {}", s(&a[pfx..pfx + amid]), s(&b[pfx..pfx + bmid]))
        }
    }

    /// One `GIT binary patch` block making `to` from `from`: a delta when
    /// it deflates smaller than the literal (as Git chooses).
    fn binary_block(out: &mut Vec<u8>, from: &[u8], to: &[u8]) {
        let literal = binary::deflate(to);
        let delta = (!from.is_empty() && !to.is_empty() && from.len().max(to.len()) <= binary::MAX_DELTA_INPUT).then(|| {
            let d = binary::make_delta(from, to);
            (d.len(), binary::deflate(&d))
        });
        let (head, data) = match delta {
            Some((n, z)) if z.len() < literal.len() => (format!("delta {n}\n"), z),
            _ => (format!("literal {}\n", to.len()), literal),
        };
        out.extend_from_slice(head.as_bytes());
        binary::encode_lines(&data, out);
        out.push(b'\n');
    }

    /// One `diff --git` section; its diffstat entry.
    fn one_section(out: &mut Vec<u8>, f: &FileDiff, binary: bool) -> Stat {
        let old_path = f.from.as_ref().map_or(&f.path, |r| &r.from);
        let a = quote("a/", old_path);
        let b = quote("b/", &f.path);
        let w = |out: &mut Vec<u8>, s: &str| out.extend_from_slice(s.as_bytes());
        w(out, &format!("diff --git {a} {b}\n"));
        let (old, old_id) = f.old.as_ref().map_or((Vec::new(), NULL_OID.to_string()), Side::shown);
        let (new, new_id) = f.new.as_ref().map_or((Vec::new(), NULL_OID.to_string()), Side::shown);
        match (&f.old, &f.new) {
            (None, Some(n)) => w(out, &format!("new file mode {}\nindex {NULL_OID}..{new_id}\n", n.mode.git())),
            (Some(o), None) => w(out, &format!("deleted file mode {}\nindex {old_id}..{NULL_OID}\n", o.mode.git())),
            (Some(o), Some(n)) => {
                if o.mode != n.mode {
                    w(out, &format!("old mode {}\nnew mode {}\n", o.mode.git(), n.mode.git()));
                }
                if let Some(r) = &f.from {
                    let verb = if r.copy { "copy" } else { "rename" };
                    w(
                        out,
                        &format!(
                            "similarity index {}%\n{verb} from {}\n{verb} to {}\n",
                            r.score,
                            quote("", &r.from),
                            quote("", &f.path)
                        ),
                    );
                }
                if old_id != new_id {
                    let mode = if o.mode == n.mode { format!(" {}", n.mode.git()) } else { String::new() };
                    w(out, &format!("index {old_id}..{new_id}{mode}\n"));
                }
            }
            (None, None) => {}
        }
        let mut st = Stat {
            name: match &f.from {
                Some(r) => rename_name(&r.from, &f.path),
                None => quote("", &f.path),
            },
            ins: 0,
            del: 0,
            binary: None,
        };
        if old == new {
            return st;
        }
        let (an, bn) = (
            if f.old.is_some() { a.clone() } else { "/dev/null".into() },
            if f.new.is_some() { b.clone() } else { "/dev/null".into() },
        );
        let files = [&f.old, &f.new].into_iter().flatten().all(|s| s.mode.kind() == EntryKind::File);
        if files && (is_binary(&old) || is_binary(&new)) {
            st.binary = Some((old.len(), new.len()));
            if binary && ![&f.old, &f.new].into_iter().flatten().any(|s| s.sealed) {
                w(out, "GIT binary patch\n");
                binary_block(out, &old, &new);
                binary_block(out, &new, &old);
            } else {
                w(out, &format!("Binary files {an} and {bn} differ\n"));
            }
            return st;
        }
        w(out, &format!("--- {an}\n+++ {bn}\n"));
        let old_lines: Vec<&[u8]> = old.split_inclusive(|b| *b == b'\n').collect();
        for h in hunks(&old, &new) {
            out.extend_from_slice(format!("@@ -{} +{} @@", range(h.old), range(h.new)).as_bytes());
            let first = if h.old.1 == 0 { h.old.0 } else { h.old.0 - 1 };
            if let Some(f) = function_line(&old_lines, first) {
                out.push(b' ');
                out.extend_from_slice(f);
            }
            out.push(b'\n');
            for (prefix, text) in h.lines {
                match prefix {
                    b'+' => st.ins += 1,
                    b'-' => st.del += 1,
                    _ => {}
                }
                out.push(prefix);
                out.extend_from_slice(&text);
                if !text.ends_with(b"\n") {
                    out.extend_from_slice(b"\n\\ No newline at end of file\n");
                }
            }
        }
        st
    }

    fn plural(n: usize, one: &str, many: &str) -> String {
        format!("{n} {}", if n == 1 { one } else { many })
    }

    /// Git's diffstat (approximately its layout: names, counts, a `+`/`-`
    /// graph scaled to 72 columns) and summary.
    fn diffstat(stats: &[Stat], files: &[FileDiff]) -> String {
        let mut s = String::new();
        if stats.is_empty() {
            return s;
        }
        let name_w = stats.iter().map(|x| x.name.chars().count()).max().unwrap_or(0);
        let max = stats.iter().filter(|x| x.binary.is_none()).map(|x| x.ins + x.del).max().unwrap_or(0);
        // Counts are aligned with "Bin" when there is a binary file.
        let bin_w = if stats.iter().any(|x| x.binary.is_some()) { 3 } else { 0 };
        let count_w = max.to_string().len().max(bin_w);
        let room = 72usize.saturating_sub(name_w + count_w + 5).max(10);
        for x in stats {
            let pad = " ".repeat(name_w - x.name.chars().count());
            match x.binary {
                Some((a, b)) => s.push_str(&format!(" {}{pad} | {:>count_w$} {a} -> {b} bytes\n", x.name, "Bin")),
                None => {
                    let total = x.ins + x.del;
                    let (i, d) = if max > room && total > 0 {
                        let scale = |n: usize| if n == 0 { 0 } else { (n * room / max).max(1) };
                        (scale(x.ins), scale(x.del))
                    } else {
                        (x.ins, x.del)
                    };
                    let graph = format!("{}{}", "+".repeat(i), "-".repeat(d));
                    let sep = if graph.is_empty() { "" } else { " " };
                    s.push_str(&format!(" {}{pad} | {total:>count_w$}{sep}{graph}\n", x.name));
                }
            }
        }
        let (ins, del): (usize, usize) = stats.iter().fold((0, 0), |(i, d), x| (i + x.ins, d + x.del));
        s.push_str(&format!(" {}", plural(stats.len(), "file changed", "files changed")));
        if ins > 0 {
            s.push_str(&format!(", {}", plural(ins, "insertion(+)", "insertions(+)")));
        }
        if del > 0 {
            s.push_str(&format!(", {}", plural(del, "deletion(-)", "deletions(-)")));
        }
        if ins == 0 && del == 0 {
            s.push_str(", 0 insertions(+), 0 deletions(-)");
        }
        s.push('\n');
        for f in files {
            match (&f.old, &f.new) {
                (None, Some(n)) => s.push_str(&format!(" create mode {} {}\n", n.mode.git(), quote("", &f.path))),
                (Some(o), None) => s.push_str(&format!(" delete mode {} {}\n", o.mode.git(), quote("", &f.path))),
                (Some(o), Some(n)) => {
                    if let Some(r) = &f.from {
                        let verb = if r.copy { "copy" } else { "rename" };
                        s.push_str(&format!(" {verb} {} ({}%)\n", rename_name(&r.from, &f.path), r.score));
                        if o.mode != n.mode {
                            s.push_str(&format!(" mode change {} => {}\n", o.mode.git(), n.mode.git()));
                        }
                    } else if o.mode != n.mode {
                        s.push_str(&format!(" mode change {} => {} {}\n", o.mode.git(), n.mode.git(), quote("", &f.path)));
                    }
                }
                _ => {}
            }
        }
        s
    }

    fn mail_headers(out: &mut Vec<u8>, commit: Option<&str>, author: &str, timestamp: i64, subject: &str, mime: bool, audience: Option<&[String]>) {
        let w = |out: &mut Vec<u8>, s: &str| out.extend_from_slice(s.as_bytes());
        w(out, &format!("From {} Mon Sep 17 00:00:00 2001\n", commit.unwrap_or(NULL_OID)));
        w(out, &format!("From: {}\n", from_header(author)));
        w(out, &format!("Date: {}\n", format_date(timestamp)));
        w(out, &format!("Subject: {subject}\n"));
        if mime {
            w(out, "MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n");
        }
        if let Some(labels) = audience {
            let v = if labels.is_empty() { "public (no sealed content)".to_string() } else { labels.join(",") };
            w(out, &format!("X-Veil-Audience: {v}\n"));
        }
        w(out, "\n");
    }

    fn prefix(n: usize, total: usize) -> String {
        if total == 1 && n == 1 {
            "[PATCH]".into()
        } else {
            format!("[PATCH {n}/{total}]")
        }
    }

    /// Returns whether the body had lines that look like patch syntax
    /// (indented, see [`escape_body`]).
    fn render(out: &mut Vec<u8>, h: &Header, files: &[FileDiff], (n, total): (usize, usize), opts: &ExportOptions) -> bool {
        let subject = subject_of(&h.description);
        let (body, escaped) = escape_body(&body_of(&h.description));
        let mut diff = Vec::new();
        let stats: Vec<Stat> = files.iter().map(|f| section(&mut diff, f, opts.binary)).collect();
        let mime = !body.is_ascii() || !subject.is_ascii() || !h.author.is_ascii() || !diff.is_ascii();
        let subject_line = format!("{} {}", prefix(n, total), header_text(&subject));
        mail_headers(out, h.commit.as_deref(), &h.author, h.timestamp, subject_line.trim_end(), mime, h.audience.as_deref());
        if !body.is_empty() {
            out.extend_from_slice(body.as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(b"---\n");
        out.extend_from_slice(diffstat(&stats, files).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&diff);
        out.extend_from_slice(format!("-- \n{}\n\n", opts.signature).as_bytes());
        escaped
    }

    fn cover_letter(
        repo: &Repo,
        mails: &[(Option<ObjectId>, Header, Vec<FileDiff>)],
        range: &[FileDiff],
        total: usize,
        opts: &ExportOptions,
    ) -> ExportedPatch {
        let mut by_author: Vec<(String, Vec<String>)> = Vec::new();
        for (_, h, _) in mails {
            let (name, _) = split_author(&h.author);
            let subject = subject_of(&h.description);
            match by_author.iter_mut().find(|(a, _)| *a == name) {
                Some((_, s)) => s.push(subject),
                None => by_author.push((name, vec![subject])),
            }
        }
        let mut body = String::from("*** BLURB HERE ***\n\n");
        for (a, subjects) in &by_author {
            body.push_str(&format!("{a} ({}):\n", subjects.len()));
            for s in subjects {
                body.push_str(&format!("  {s}\n"));
            }
            body.push('\n');
        }
        let mut sink = Vec::new();
        let stats: Vec<Stat> = range.iter().map(|f| section(&mut sink, f, false)).collect();
        body.push_str(&diffstat(&stats, range));
        let mut text = Vec::new();
        let me = repo.user().to_string();
        let audience = (opts.audience == Audience::Me).then(Vec::new);
        mail_headers(
            &mut text,
            None,
            &me,
            crate::now_millis(),
            &format!("[PATCH 0/{total}] *** SUBJECT HERE ***"),
            !body.is_ascii() || !me.is_ascii(),
            audience.as_deref(),
        );
        text.extend_from_slice(body.as_bytes());
        text.extend_from_slice(format!("\n-- \n{}\n\n", opts.signature).as_bytes());
        ExportedPatch {
            snapshot: None,
            file_name: "0000-cover-letter.patch".into(),
            text,
            empty: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn lim() -> Limits {
        Limits {
            max_file_size: 1 << 20,
            ..Limits::default()
        }
    }

    fn parse_str(s: &str) -> Result<Series> {
        parse(s.as_bytes().to_vec(), &lim())
    }

    fn err(s: &str) -> String {
        match parse_str(s) {
            Ok(x) => panic!("parsed: {:?}", x.patches),
            Err(e) => e.to_string(),
        }
    }

    /// `old` patched by the only file section of `s`.
    fn applied(s: &str, old: &str) -> Result<String> {
        let series = parse_str(s)?;
        let f = &series.patches[0].files[0];
        let mut work = 0;
        let out = apply_hunks(&series, f, old.as_bytes(), &lim(), &mut work)?;
        Ok(String::from_utf8(out).unwrap())
    }

    const PATCH: &str = "From 3f2a6b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?J=C3=B6rg?= <j@example.com>
Date: Tue, 3 Nov 2026 12:00:00 +0100
Subject: [PATCH 2/3] Fix the
 thing

Body para.

Signed-off-by: J <j@example.com>
---
 a.txt | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/a.txt b/a.txt
index 1234567..89abcde 100644
--- a/a.txt
+++ b/a.txt
@@ -1,2 +1,2 @@
 one
-two
+TWO
-- 
2.43.0

";

    fn wrap(diff: &str) -> String {
        format!(
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@x>\nDate: Wed, 4 Nov 2026 18:51:21 +0000\nSubject: [PATCH] s\n\n---\n{diff}-- \nvl\n\n"
        )
    }

    #[test]
    fn parses_git_format_patch() {
        let s = parse_str(PATCH).unwrap();
        assert_eq!(s.patches.len(), 1);
        let p = &s.patches[0];
        assert_eq!(p.author.as_deref(), Some("Jörg <j@example.com>"));
        assert_eq!(p.date, Some(days_from_civil(2026, 11, 3) * 86_400_000 + 11 * 3_600_000));
        assert_eq!(p.subject, "Fix the thing");
        assert_eq!(p.number, Some((2, 3)));
        assert_eq!(p.body, "Body para.\n\nSigned-off-by: J <j@example.com>");
        assert_eq!(p.description(), "Fix the thing\n\nBody para.\n\nSigned-off-by: J <j@example.com>");
        let f = &p.files[0];
        assert_eq!((f.op, f.path().as_str(), f.old_mode, f.new_mode), (FileOp::Modify, "a.txt", Some(Mode::Regular), Some(Mode::Regular)));
        assert_eq!(applied(PATCH, "one\ntwo\n").unwrap(), "one\nTWO\n");
    }

    #[test]
    fn a_series_splits_on_postmarks_only() {
        let one = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n");
        // A body line starting with `From ` is not a postmark.
        let two = one.replace("Subject: [PATCH] s\n\n", "Subject: [PATCH] s\n\nFrom the start, this is body.\n\n");
        let s = parse_str(&format!("{one}{two}")).unwrap();
        assert_eq!(s.patches.len(), 2);
        assert_eq!(s.patches[1].body, "From the start, this is body.");
    }

    #[test]
    fn in_body_headers_win() {
        let p = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
            .replace("Subject: [PATCH] s\n\n", "Subject: [PATCH] s\n\nFrom: Orig Author <o@x>\nSubject: real subject\n\nbody\n");
        let s = parse_str(&p).unwrap();
        assert_eq!(s.patches[0].author.as_deref(), Some("Orig Author <o@x>"));
        assert_eq!(s.patches[0].subject, "real subject");
        assert_eq!(s.patches[0].body, "body");
    }

    #[test]
    fn deleted_lines_that_look_like_a_signature_are_content() {
        let p = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,3 +1,1 @@\n-- item\n-- \n keep\n");
        assert_eq!(applied(&p, "- item\n- \nkeep\n").unwrap(), "keep\n");
    }

    #[test]
    fn no_newline_markers() {
        let p = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n");
        assert_eq!(applied(&p, "a\nb").unwrap(), "a\nc");
        // The pre-image must lack the newline too.
        assert!(applied(&p, "a\nb\n").is_err());
        let add = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-a\n\\ No newline at end of file\n+a\n+b\n");
        assert_eq!(applied(&add, "a").unwrap(), "a\nb\n");
        // A marker after a context line, then more lines: malformed.
        assert!(err(&wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n\\ x\n-b\n+c\n")).contains("malformed"));
    }

    #[test]
    fn new_deleted_renamed_copied_and_mode_sections() {
        let p = wrap(
            "diff --git a/n.txt b/n.txt\nnew file mode 100755\nindex 0000000..1111111\n--- /dev/null\n+++ b/n.txt\n@@ -0,0 +1 @@\n+hi\n\
             diff --git a/d.txt b/d.txt\ndeleted file mode 100644\nindex 1111111..0000000\n--- a/d.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-bye\n\
             diff --git a/old name b/new name\nsimilarity index 90%\nrename from old name\nrename to new name\n\
             diff --git a/c1 b/c2\ncopy from c1\ncopy to c2\n\
             diff --git a/m b/m\nold mode 100644\nnew mode 100755\n\
             diff --git a/e b/e\nnew file mode 100644\nindex 0000000..e69de29\n",
        );
        let s = parse_str(&p).unwrap();
        let ops: Vec<(FileOp, Option<&str>, Option<&str>)> = s.patches[0]
            .files
            .iter()
            .map(|f| (f.op, f.old_path.as_ref().map(VPath::as_str), f.new_path.as_ref().map(VPath::as_str)))
            .collect();
        assert_eq!(
            ops,
            vec![
                (FileOp::Create, None, Some("n.txt")),
                (FileOp::Delete, Some("d.txt"), None),
                (FileOp::Rename, Some("old name"), Some("new name")),
                (FileOp::Copy, Some("c1"), Some("c2")),
                (FileOp::Modify, Some("m"), Some("m")),
                (FileOp::Create, None, Some("e")),
            ]
        );
        assert_eq!(s.patches[0].files[0].new_mode, Some(Mode::Executable));
        assert_eq!(s.patches[0].files[4].new_mode, Some(Mode::Executable));
    }

    #[test]
    fn quoted_paths_follow_git_c_quoting() {
        let p = wrap("diff --git \"a/\\101 b\\303\\251\" \"b/\\101 b\\303\\251\"\nnew file mode 100644\n");
        assert_eq!(parse_str(&p).unwrap().patches[0].files[0].path().as_str(), "A b\u{e9}");
        // A tab is a control character: refused as a path.
        let p = wrap("diff --git \"a/x\\ty\" \"b/x\\ty\"\nnew file mode 100644\n");
        assert!(err(&p).contains("control character"));
        let p = wrap("diff --git \"a/\\101 b\" \"b/\\101 b\"\nnew file mode 100644\n");
        assert_eq!(parse_str(&p).unwrap().patches[0].files[0].path().as_str(), "A b");
        for bad in ["\"a/x\\q\"", "\"a/x\\4\"", "\"a/x"] {
            let p = wrap(&format!("diff --git {bad} {bad}\nnew file mode 100644\n"));
            assert!(parse_str(&p).is_err(), "{bad}");
        }
    }

    #[test]
    fn hostile_paths_are_refused() {
        let cases = [
            "../../etc/passwd",
            "a/../../x",
            "./x",
            "x/./y",
            "/etc/passwd",
            "x//y",
            "x/",
            ".veil/repo.json",
            "sub/.VEIL/x",
            ".v\u{200c}eil/x",
            ".git/hooks/pre-commit",
            "deep/.Git/config",
            ".g\u{200c}it/hooks/x",
            ".git",
            ".jj/repo",
            ".hg/hgrc",
            "x/.svn/entries",
            "a\u{1b}]2;x",
            "nl\nname",
            "bell\u{7}",
            ".x.vltmp0123abcd",
        ];
        for c in cases {
            let quoted: String = c.bytes().map(|b| format!("\\{b:03o}")).collect();
            let p = wrap(&format!("diff --git \"a/{quoted}\" \"b/{quoted}\"\nnew file mode 100644\n"));
            let e = err(&p);
            assert!(!e.contains('\u{1b}'), "{c:?}: {e}");
        }
        let long = "x".repeat(256);
        assert!(err(&wrap(&format!("diff --git a/{long} b/{long}\nnew file mode 100644\n"))).contains("longer"));
        let deep = vec!["d"; 3000].join("/");
        assert!(err(&wrap(&format!("diff --git a/{deep} b/{deep}\nnew file mode 100644\n"))).contains("longer"));
        // NUL, through quoting.
        assert!(parse_str(&wrap("diff --git \"a/x\\000y\" \"b/x\\000y\"\nnew file mode 100644\n")).is_err());
        // A backslash is an ordinary character (BUG-204).
        let p = wrap("diff --git \"a/back\\\\slash\" \"b/back\\\\slash\"\nnew file mode 100644\n");
        assert_eq!(parse_str(&p).unwrap().patches[0].files[0].path().as_str(), "back\\slash");
        // Names must carry the a/ and b/ prefixes.
        assert!(err(&wrap("diff --git x y\n--- x\n+++ y\n@@ -1 +1 @@\n-a\n+b\n")).contains("prefix"));
        // ---/+++ names disagreeing with diff --git.
        assert!(err(&wrap("diff --git a/x b/x\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n")).contains("disagree"));
    }

    #[test]
    fn hostile_headers_are_refused() {
        // ESC ]2;1 encoded in the subject (a terminal title escape).
        for subject in [
            "=?UTF-8?B?G10yOzE=?=",
            "=?UTF-8?q?a=1Bb?=",
            "=?UTF-8?q?evil=E2=80=AEtxt?=",
            "=?UTF-8?q?nl=0Ahere?=",
            "=?UTF-8?q?c1=C2=9B?=",
        ] {
            let p = PATCH.replace("Subject: [PATCH 2/3] Fix the\n thing", &format!("Subject: {subject}"));
            let e = err(&p);
            assert!(e.contains("control character"), "{subject}: {e}");
        }
        let p = PATCH.replace("From: =?UTF-8?q?J=C3=B6rg?= <j@example.com>", "From: =?UTF-8?B?QWxpY2UbWzMxbQ==?= <a@x>");
        assert!(err(&p).contains("control character"));
        // CRLF mail.
        assert!(err(&PATCH.replace('\n', "\r\n")).contains("CRLF"));
        // Unsupported encodings and multipart.
        let p = PATCH.replace("Subject:", "Content-Transfer-Encoding: base64\nSubject:");
        assert!(err(&p).contains("Content-Transfer-Encoding"));
        let p = PATCH.replace("Subject:", "Content-Type: multipart/mixed; boundary=x\nSubject:");
        assert!(err(&p).contains("Content-Type"));
        let p = PATCH.replace("Subject:", "Subject: again\nSubject:");
        assert!(err(&p).contains("twice"));
        let p = PATCH.replace("Date: Tue, 3 Nov 2026 12:00:00 +0100", "Date: Tue, 31 Feb 2026 12:00:00 +0100");
        assert!(err(&p).contains("date"));
    }

    #[test]
    fn malformed_patches_are_refused() {
        let diff = |d: &str| wrap(d);
        let cases = [
            // counts
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n-b\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n+c\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n a\n x\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n?a\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1\n-a\n+b\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,1 +1 @@\n-a\n+b\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +0,0 @@\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -99999999999999999999 +1 @@\n-a\n+b\n"),
            // order
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -5 +5 @@\n-a\n+b\n@@ -1 +1 @@\n-a\n+b\n"),
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n@@ -2 +2 @@\n-b\n+c\n"),
            // two sections for one path
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -2 +2 @@\n-a\n+b\n"),
            diff("diff --git a/x b/y\nrename from x\nrename to y\ndiff --git a/y b/y\nnew file mode 100644\n"),
            // contradictions
            diff("diff --git a/x b/x\nnew file mode 100644\ndeleted file mode 100644\n"),
            diff("diff --git a/x b/x\nold mode 100644\n"),
            diff("diff --git a/x b/y\nrename from x\n"),
            diff("diff --git a/x b/x\nrename from x\nrename to x\n"),
            diff("diff --git a/x b/x\nnew file mode 100644\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"),
            diff("diff --git a/x b/x\nnew file mode 100644\nnew file mode 100644\n"),
            diff("diff --git a/x b/x\nnew file mode 100777\n"),
            diff("diff --git a/x b/x\nindex zz..yy\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"),
            diff("diff --git a/x b/x\n"),
            // a new file whose hunk does not start at 0
            diff("diff --git a/x b/x\nnew file mode 100644\n--- /dev/null\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"),
            // binary data
            diff("diff --git a/x b/x\nGIT binary patch\nliteral 3\n!!!\n\n"),
            diff("diff --git a/x b/x\nGIT binary patch\nfoo 3\n"),
            // trailing garbage
            diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\ngarbage\n"),
        ];
        for c in &cases {
            let e = err(c);
            assert!(!e.is_empty());
        }
        // Truncated inside a hunk (no final newline, or lines missing).
        let full = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n");
        let cut = &full[..full.find("+c").unwrap() + 2];
        assert!(err(cut).contains("truncated"));
        assert!(err("").contains("empty"));
        assert!(err("hello world\n").contains("not a patch"));
    }

    #[test]
    fn symlinks_submodules_and_type_changes_parse() {
        let s = parse_str(&wrap("diff --git a/link b/link\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+/home/u/.ssh\n\\ No newline at end of file\n")).unwrap();
        assert_eq!(s.patches[0].files[0].new_mode, Some(Mode::Symlink));
        let s = parse_str(&wrap("diff --git a/sub b/sub\nnew file mode 160000\nindex 0000000..1111111\n--- /dev/null\n+++ b/sub\n@@ -0,0 +1 @@\n+Subproject commit 1111111111111111111111111111111111111111\n")).unwrap();
        assert_eq!(s.patches[0].files[0].new_mode, Some(Mode::Gitlink));
        // A type change is a deletion and a creation of one path, as Git
        // writes it; anything else twice is malformed.
        let tc = "diff --git a/l b/l\ndeleted file mode 120000\n--- a/l\n+++ /dev/null\n@@ -1 +0,0 @@\n-t\n\\ No newline at end of file\n\
                  diff --git a/l b/l\nnew file mode 100644\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+now a file\n";
        let s = parse_str(&wrap(tc)).unwrap();
        assert_eq!(s.patches[0].files.len(), 2);
        let same_kind = tc.replace("new file mode 100644", "new file mode 120000");
        assert!(err(&wrap(&same_kind)).contains("two sections"));
        let reversed = "diff --git a/l b/l\nnew file mode 100644\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+x\n\
                        diff --git a/l b/l\ndeleted file mode 120000\n--- a/l\n+++ /dev/null\n@@ -1 +0,0 @@\n-t\n";
        assert!(err(&wrap(reversed)).contains("two sections"));
        // A mode change never changes the type.
        let e = err(&wrap("diff --git a/.veilpolicy b/.veilpolicy\nold mode 100644\nnew mode 120000\n"));
        assert!(e.contains("type"), "{e}");
        // Binary data for a link is malformed.
        let e = err(&wrap("diff --git a/l b/l\nnew file mode 120000\nGIT binary patch\nliteral 0\nHcmV?d00001\n\n"));
        assert!(e.contains("binary data for a symlink"), "{e}");
    }

    #[test]
    fn binary_blocks_are_checked_line_by_line_and_bounded() {
        let ok = wrap("diff --git a/b.bin b/b.bin\nindex 0000000000000000000000000000000000000000..1111111111111111111111111111111111111111 100644\nGIT binary patch\nliteral 6\nNcmZQzWJ=1+0{{Yf0X+Z!\n\nliteral 0\nHcmV?d00001\n\n");
        let s = parse_str(&ok).unwrap();
        let bp = s.patches[0].files[0].binary_patch.clone().unwrap();
        assert_eq!(bp.forward.kind, BinaryKind::Literal);
        assert_eq!(s.binary_data(&bp.forward).unwrap(), b"\x00\x01\x02bin");
        assert!(bp.reverse.is_some());
        // A line whose length character disagrees with its digits.
        assert!(err(&ok.replace("NcmZQzWJ=1+0{{Yf0X+Z!", "NcmZQzWJ=1+0{{Yf0X+Z")).contains("base85"));
        // The declared sizes of the whole series are bounded.
        let small = Limits {
            max_inflated: 10,
            ..lim()
        };
        let two = format!("{ok}{ok}");
        assert!(parse(two.into_bytes(), &small).unwrap_err().to_string().contains("more than 10 bytes in all"));
        // A declared size that is not the data's.
        let s = parse_str(&ok.replace("literal 6", "literal 7")).unwrap();
        let bp = s.patches[0].files[0].binary_patch.clone().unwrap();
        assert!(s.binary_data(&bp.forward).unwrap_err().to_string().contains("not the 7"));
    }

    #[test]
    fn limits_bound_the_input() {
        let small = Limits {
            max_input: 100,
            ..lim()
        };
        assert!(parse(vec![b'x'; 101], &small).unwrap_err().to_string().contains("more than the 100"));
        let small = Limits {
            max_line: 20,
            ..lim()
        };
        assert!(parse(PATCH.as_bytes().to_vec(), &small).unwrap_err().to_string().contains("longer than 20"));
        let small = Limits {
            max_hunks_per_file: 1,
            ..lim()
        };
        let two = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n@@ -5 +5 @@\n-a\n+b\n");
        assert!(parse(two.clone().into_bytes(), &small).unwrap_err().to_string().contains("more than 1 hunks"));
        let small = Limits {
            max_patches: 1,
            ..lim()
        };
        assert!(parse(format!("{two}{two}").into_bytes(), &small).unwrap_err().to_string().contains("more than 1 patches"));
        let small = Limits {
            max_files: 1,
            ..lim()
        };
        let files = wrap("diff --git a/x b/x\nnew file mode 100644\ndiff --git a/y b/y\nnew file mode 100644\n");
        assert!(parse(files.into_bytes(), &small).unwrap_err().to_string().contains("more than 1 file"));
        let small = Limits {
            max_header: 64,
            ..lim()
        };
        let long = PATCH.replace(" thing\n", &" thing\n".repeat(20));
        assert!(parse(long.into_bytes(), &small).unwrap_err().to_string().contains("header longer"));
    }

    #[test]
    fn a_binary_bomb_is_refused_before_anything_is_inflated() {
        let mut p = wrap("diff --git a/x b/x\nGIT binary patch\nliteral 17179869184\n");
        p.push_str(&"zcmV?d00001zcmV?d00001zcmV?d00001\n".repeat(320));
        p.push_str("\nliteral 0\nHcmV?d00001\n\n");
        assert!(p.len() > 10_000);
        let t = std::time::Instant::now();
        let e = parse(p.into_bytes(), &Limits::default()).unwrap_err().to_string();
        assert!(t.elapsed() < std::time::Duration::from_millis(100), "{:?}", t.elapsed());
        assert!(e.contains("declares 17179869184 bytes"), "{e}");
    }

    #[test]
    fn plain_unified_diffs_are_read_with_p1() {
        let s = parse_str("Index: x\n=====\n--- a/src/x.c\t2020-01-01\n+++ b/src/x.c\t2020-01-02\n@@ -1 +1 @@\n-a\n+b\n").unwrap();
        let p = &s.patches[0];
        assert_eq!(p.files[0].path().as_str(), "src/x.c");
        assert!(p.author.is_none() && p.subject.is_empty());
        assert!(parse_str("--- x\n+++ x\n@@ -1 +1 @@\n-a\n+b\n").is_err(), "nothing to strip");
        assert!(parse_str("--- a/x\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n").is_err(), "a rename without git headers");
    }

    #[test]
    fn hunks_apply_exactly_or_within_the_offset() {
        let p = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -2,3 +2,3 @@\n b\n-c\n+C\n d\n");
        assert_eq!(applied(&p, "a\nb\nc\nd\ne\n").unwrap(), "a\nb\nC\nd\ne\n");
        // Five lines later.
        assert_eq!(applied(&p, "1\n2\n3\n4\n5\na\nb\nc\nd\ne\n").unwrap(), "1\n2\n3\n4\n5\na\nb\nC\nd\ne\n");
        // Beyond the offset limit.
        let far = format!("{}a\nb\nc\nd\n", "x\n".repeat(1200));
        assert!(applied(&p, &far).unwrap_err().to_string().contains("does not apply"));
        // A context mismatch, and CRLF context against LF content.
        assert!(applied(&p, "a\nb\nX\nd\n").is_err());
        let crlf = p.replace(" b\n-c\n+C\n d\n", " b\r\n-c\r\n+C\r\n d\r\n");
        assert!(applied(&crlf, "a\nb\nc\nd\n").is_err());
        assert_eq!(applied(&crlf, "a\r\nb\r\nc\r\nd\r\n").unwrap(), "a\r\nb\r\nC\r\nd\r\n");
        // No leading context: only at the start of the file.
        let top = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-a\n+A\n b\n");
        assert_eq!(applied(&top, "a\nb\n").unwrap(), "A\nb\n");
        assert!(applied(&top, "z\na\nb\n").is_err());
        // No context at all (-U0): exactly where it says.
        let zero = wrap("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -2 +2 @@\n-b\n+B\n");
        assert_eq!(applied(&zero, "a\nb\nc\n").unwrap(), "a\nB\nc\n");
        assert!(applied(&zero, "b\na\nc\n").is_err());
        // The work bound.
        let tiny = Limits { max_work: 3, ..lim() };
        let series = parse_str(&p).unwrap();
        let mut work = 0;
        let e = apply_hunks(&series, &series.patches[0].files[0], far.as_bytes(), &tiny, &mut work).unwrap_err();
        assert!(e.to_string().contains("too long"), "{e}");
    }

    #[cfg(feature = "git")]
    #[test]
    fn dates_round_trip() {
        for ms in [0i64, 1_000, 86_399_000, 1_762_282_281_000, 253_402_300_799_000] {
            assert_eq!(parse_date(&format_date(ms)), Some(ms), "{}", format_date(ms));
        }
        assert_eq!(format_date(1_762_282_281_000), "Tue, 4 Nov 2025 18:51:21 +0000");
        assert_eq!(parse_date("4 Nov 2025 19:51:21 +0100"), Some(1_762_282_281_000));
        for bad in ["", "Tue, 4 Nov 2025", "Tue, 4 Foo 2025 18:51:21 +0000", "Tue, 4 Nov 2025 25:00:00 +0000", "4 Nov 1969 00:00:00 +0000", "4 Nov 2025 18:51:21 +0099"] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn subjects_lose_their_tags() {
        assert_eq!(clean_subject("[PATCH v2 3/7] x"), ("x".into(), Some((3, 7))));
        assert_eq!(clean_subject("Re: [RFC PATCH] [net] y"), ("y".into(), None));
        assert_eq!(clean_subject("[PATCH 0/2] cover"), ("cover".into(), Some((0, 2))));
        assert_eq!(clean_subject("[unclosed"), ("[unclosed".into(), None));
    }

    fn checked_paths_only(s: &Series) {
        for p in &s.patches {
            for f in &p.files {
                for path in [&f.old_path, &f.new_path].into_iter().flatten() {
                    assert!(!path.is_root());
                    for c in path.components() {
                        assert!(c != ".." && c != "." && !c.is_empty());
                        assert!(!crate::object::is_reserved_name(c), "{path}");
                        assert!(policy::vcs_metadata_name(c).is_none(), "{path}");
                        assert!(!c.chars().any(char::is_control), "{path:?}");
                    }
                }
            }
        }
    }

    fn text() -> impl Strategy<Value = Vec<u8>> {
        let line = prop_oneof![
            Just("a"), Just("b"), Just("c"), Just(""), Just(" x"), Just("-- "), Just("+y"),
            Just("\\ z"), Just("From x"), Just("diff --git a/q b/q"), Just("@@ -1 +1 @@"), Just("---"), Just("é"),
        ];
        (proptest::collection::vec(line, 0..12), any::<bool>()).prop_map(|(lines, nl)| {
            let mut t = lines.join("\n");
            if nl && !lines.is_empty() {
                t.push('\n');
            }
            t.into_bytes()
        })
    }

    #[cfg(feature = "git")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// What the writer emits for one file, the parser reads back and the
        /// applier turns from the old content into the new one.
        #[test]
        fn writer_sections_parse_and_apply(
            old in text(), new in text(), old_x in any::<bool>(), new_x in any::<bool>(), kind in 0u8..3, nul in any::<bool>(),
        ) {
            use super::writer::{section, FileDiff, Side};
            let mut new = new;
            if nul && kind == 0 {
                new.push(0);
            }
            let f = FileDiff {
                path: VPath::new("dir/f.txt").unwrap(),
                old: (kind != 1).then(|| Side::file(old.clone(), old_x)),
                new: (kind != 2).then(|| Side::file(new.clone(), new_x)),
                from: None,
            };
            prop_assume!(kind != 0 || old != new || old_x != new_x);
            let mut diff = Vec::new();
            section(&mut diff, &f, false);
            let mail = wrap(&String::from_utf8(diff).unwrap());
            let s = parse(mail.into_bytes(), &lim()).unwrap();
            let fp = &s.patches[0].files[0];
            let want_op = [FileOp::Modify, FileOp::Create, FileOp::Delete][kind as usize];
            prop_assert_eq!(fp.op, want_op);
            if nul && kind == 0 && old != new {
                prop_assert!(fp.binary);
                return Ok(());
            }
            let base = if kind == 1 { Vec::new() } else { old.clone() };
            let mut work = 0;
            let out = apply_hunks(&s, fp, &base, &lim(), &mut work).unwrap();
            prop_assert_eq!(out, if kind == 2 { Vec::new() } else { new.clone() });
            if kind != 2 {
                prop_assert_eq!(fp.new_mode.unwrap_or(Mode::of(old_x)), Mode::of(new_x));
            }
        }
    }

    #[cfg(feature = "git")]
    #[test]
    fn descriptions_never_become_patch_syntax() {
        let body = "first line\n\ndiff --git a/evil b/evil\nnew file mode 100644\n---\n-- \nFrom 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: forged <f@x>";
        let (escaped, changed) = super::writer::escape_body(body);
        assert!(changed);
        let mail = format!(
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@x>\nDate: Wed, 4 Nov 2026 18:51:21 +0000\nSubject: [PATCH] s\n\n{escaped}\n---\n-- \nvl\n\n"
        );
        let s = parse_str(&mail).unwrap();
        assert_eq!(s.patches.len(), 1);
        assert!(s.patches[0].files.is_empty());
        assert_eq!(s.patches[0].author.as_deref(), Some("A <a@x>"));
        assert!(s.patches[0].body.contains(" diff --git a/evil b/evil"));
        let (first, _) = super::writer::escape_body("From: forged <f@x>\nok");
        assert!(first.starts_with(' '));
    }

    /// A one-section mail holding the writer's section for `old` → `new`.
    #[cfg(feature = "git")]
    fn binary_mail(old: Option<&[u8]>, new: &[u8]) -> String {
        use super::writer::{section, FileDiff, Side};
        let f = FileDiff {
            path: VPath::new("b.bin").unwrap(),
            old: old.map(|o| Side::file(o.to_vec(), false)),
            new: Some(Side::file(new.to_vec(), false)),
            from: None,
        };
        let mut diff = Vec::new();
        section(&mut diff, &f, true);
        wrap(&String::from_utf8(diff).unwrap())
    }

    #[cfg(feature = "git")]
    fn apply_one(s: &Series, old: &[u8], lim: &Limits) -> Result<Vec<u8>> {
        let f = &s.patches[0].files[0];
        let bp = f.binary_patch.as_ref().expect("a binary patch");
        let mut st = State { work: 0, inflated: 0, preimages: None };
        apply_binary(s, f, bp, old, lim, &mut st)?.map_err(VeilError::Repo)
    }

    /// Point 12: a zlib stream that inflates far beyond what it declares
    /// (64 MiB of zeros in about 64 KB, declared as 1 MiB) is cut off at
    /// the declared size: refused quickly, never inflated in full.
    #[cfg(feature = "git")]
    #[test]
    fn a_zlib_bomb_stops_at_its_declared_size() {
        let mut lines = Vec::new();
        binary::encode_lines(&binary::deflate(&vec![0u8; 64 << 20]), &mut lines);
        let lines = String::from_utf8(lines).unwrap();
        let mail = wrap(&format!(
            "diff --git a/z b/z\nnew file mode 100644\nindex 0000000000000000000000000000000000000000..1111111111111111111111111111111111111111\nGIT binary patch\nliteral {}\n{lines}\nliteral 0\nHcmV?d00001\n\n",
            1 << 20
        ));
        assert!(mail.len() < 200_000, "{}", mail.len());
        let s = parse(mail.into_bytes(), &Limits::default()).unwrap();
        let t = std::time::Instant::now();
        let e = apply_one(&s, b"", &Limits::default()).unwrap_err().to_string();
        assert!(e.contains("more than the 1048576 bytes it declares"), "{e}");
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
        // A delta whose result is declared larger than VEIL_MAX_OBJECT is
        // refused before anything is allocated for it.
        let small = Limits { max_file_size: 1 << 16, ..lim() };
        let delta = [5u8, 0xff, 0xff, 0xff, 0x7f, 5, b'h', b'e', b'l', b'l', b'o'];
        let mut lines = Vec::new();
        binary::encode_lines(&binary::deflate(&delta), &mut lines);
        let mail = wrap(&format!(
            "diff --git a/z b/z\nindex {}..1111111111111111111111111111111111111111 100644\nGIT binary patch\ndelta {}\n{}\n",
            git_blob_id(b"hello"),
            delta.len(),
            String::from_utf8(lines).unwrap()
        ));
        let s = parse(mail.into_bytes(), &small).unwrap();
        let e = apply_one(&s, b"hello", &small).unwrap_err().to_string();
        assert!(e.contains("more than 65536 (VEIL_MAX_OBJECT)"), "{e}");
    }

    #[cfg(feature = "git")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// What the writer emits as `GIT binary patch` (a literal or a
        /// delta, whichever is smaller) parses and applies back exactly.
        #[test]
        fn binary_sections_round_trip(
            old in proptest::collection::vec(any::<u8>(), 0..3000),
            edits in proptest::collection::vec((any::<proptest::sample::Index>(), any::<u8>()), 0..8),
            fresh in any::<bool>(),
        ) {
            let mut new = old.clone();
            for (at, b) in edits {
                if !new.is_empty() {
                    let i = at.index(new.len());
                    new[i] = b;
                }
            }
            new.push(0); // binary for sure
            let old_side = (!fresh).then_some(old.as_slice());
            prop_assume!(old_side != Some(new.as_slice()));
            let mail = binary_mail(old_side, &new);
            let s = parse(mail.into_bytes(), &lim()).unwrap();
            let base = if fresh { &[][..] } else { &old[..] };
            prop_assert_eq!(apply_one(&s, base, &lim()).unwrap(), new);
        }

        /// The binary decoder on hostile input: arbitrary base85 lines,
        /// zlib streams and deltas never panic, never produce more than the
        /// declared or allowed size, and a mutated valid section either
        /// fails cleanly or makes exactly what it declares.
        #[test]
        fn fuzz_the_binary_decoder(
            digits in proptest::collection::vec(proptest::sample::select(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~".to_vec()), 0..300),
            len_char in proptest::sample::select(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".to_vec()),
            size in 0usize..5000,
            delta in proptest::collection::vec(any::<u8>(), 0..200),
            base in proptest::collection::vec(any::<u8>(), 0..300),
            edits in proptest::collection::vec((any::<proptest::sample::Index>(), 0u8..3, any::<u8>()), 1..10),
        ) {
            // Raw lines and streams.
            let mut line = vec![len_char];
            line.extend_from_slice(&digits);
            line.push(b'\n');
            if let Ok(bytes) = binary::decode_lines(&line) {
                if let Ok(out) = binary::inflate(&bytes, size) {
                    prop_assert_eq!(out.len(), size);
                }
            }
            if let Ok(out) = binary::inflate(&delta, size) {
                prop_assert_eq!(out.len(), size);
            }
            if let Ok(out) = binary::apply_delta(&base, &delta, 4096) {
                prop_assert!(out.len() <= 4096);
            }
            // A valid section, mutated.
            let mut data = binary_mail(Some(&base), &[&base[..], b"\x00more"].concat()).into_bytes();
            let start = data.windows(16).position(|w| w == b"GIT binary patch").unwrap();
            for (at, op, b) in edits {
                let i = start + at.index(data.len() - start);
                match op {
                    0 => data[i] = b,
                    1 => data.insert(i, b),
                    _ => { data.remove(i); }
                }
            }
            if let Ok(s) = parse(data, &lim()) {
                for f in s.patches.iter().flat_map(|p| &p.files) {
                    if let Some(bp) = &f.binary_patch {
                        for b in std::iter::once(&bp.forward).chain(&bp.reverse) {
                            if let Ok(out) = s.binary_data(b) {
                                prop_assert_eq!(out.len(), b.size);
                            }
                        }
                        let _ = apply_one(&s, &base, &lim());
                    }
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Arbitrary bytes: never a panic.
        #[test]
        fn fuzz_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Ok(s) = parse(data, &lim()) {
                checked_paths_only(&s);
            }
        }

        /// A valid patch with bytes replaced, inserted or removed: never a
        /// panic, and whatever parses holds only checked paths.
        #[test]
        fn fuzz_mutated_patches(
            edits in proptest::collection::vec((any::<proptest::sample::Index>(), 0u8..3, any::<u8>()), 1..12),
            pick in 0usize..4,
        ) {
            let base = [
                PATCH.to_string(),
                wrap("diff --git \"a/q\\101\" \"b/q\\101\"\nnew file mode 100755\n--- /dev/null\n+++ \"b/q\\101\"\n@@ -0,0 +1,2 @@\n+x\n+y\n\\ No newline at end of file\n"),
                wrap("diff --git a/x y b/z w\nsimilarity index 50%\nrename from x y\nrename to z w\n--- a/x y\n+++ b/z w\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"),
                wrap("diff --git a/b.bin b/b.bin\nGIT binary patch\nliteral 3\nKcmV?d00001\n\nliteral 0\nHcmV?d00001\n\n"),
            ][pick].clone().into_bytes();
            let mut data = base;
            for (at, op, b) in edits {
                let i = at.index(data.len() + 1);
                match op {
                    0 if i < data.len() => data[i] = b,
                    1 => data.insert(i, b),
                    _ if i < data.len() => { data.remove(i); }
                    _ => {}
                }
            }
            if let Ok(s) = parse(data, &lim()) {
                checked_paths_only(&s);
                for p in &s.patches {
                    for f in &p.files {
                        for h in &f.hunks {
                            let n = s.hunk_lines(h).count();
                            prop_assert!(n <= h.old_len + h.new_len);
                        }
                    }
                }
            }
        }

        /// Hostile path headers (quoting, prefixes, traversal pieces): every
        /// path that parses is inside the tree and never VCS metadata.
        #[test]
        fn fuzz_path_headers(parts in proptest::collection::vec(prop_oneof![
            Just("..".to_string()), Just(".".to_string()), Just("".to_string()), Just(".veil".to_string()),
            Just(".git".to_string()), Just(".GIT".to_string()), Just("\\101".to_string()), Just("\\056\\056".to_string()),
            Just("\\000".to_string()), Just("\\033".to_string()), Just("a".to_string()), Just("b c".to_string()),
            Just("\\".to_string()), Just("\\\\".to_string()), Just("\"".to_string()), Just("é".to_string()),
        ], 1..5), quoted in any::<bool>()) {
            let path = parts.join("/");
            let name = |prefix: &str| if quoted { format!("\"{prefix}{path}\"") } else { format!("{prefix}{path}") };
            let p = wrap(&format!(
                "diff --git {} {}\nnew file mode 100644\n--- /dev/null\n+++ {}\n@@ -0,0 +1 @@\n+x\n",
                name("a/"), name("b/"), name("b/")
            ));
            if let Ok(s) = parse(p.into_bytes(), &lim()) {
                checked_paths_only(&s);
            }
        }
    }
}
