//! First-class conflicts (repository format 4).
//!
//! A merge that cannot combine two versions of a file records the conflict
//! as data: a tree entry of kind [`EntryKind::Conflict`] naming a
//! [`Conflict`] object, which lists the versions involved (jj's adds and
//! removes), each with the visibility it had. Nothing is written into the
//! file's content. This module holds:
//!
//! * the **algebra** ([`Merge`]): flattening a merge of conflicts into one
//!   conflict, cancelling equal adds and removes, and jj's trivial
//!   resolution (one add left, or every side made the same change). Rebasing
//!   a conflicted change onto a parent that resolves it therefore resolves
//!   it;
//! * **materialisation** ([`materialize`]): the file checkout writes for a
//!   conflict entry, with markers, rendered for one audience under the rules
//!   of ARCHITECTURE §4 rule 5 (BUG-123/126/127): a side or base is shown
//!   only to its own audience; anything else is replaced by a redaction line;
//! * **parsing back** ([`parse_markers`]): a working-copy file whose markers
//!   were partly edited is turned back into the sides of a conflict, as jj
//!   does.
//!
//! Format-1 to 3 repositories cannot store conflict objects: their merges
//! still write markers into the file and list the path on the snapshot
//! (`Snapshot::conflicts`), as before. So do merges under an unreleased
//! embargo (whose sealed trees never hold conflict entries).

use std::collections::BTreeSet;

use crate::{
    builder::{verify_sealing, Sealing},
    error::{Result, VeilError},
    id::ObjectId,
    object::{Conflict, ConflictTerm, EntryKind, Object, TreeEntry, Visibility},
    secrets::looks_binary,
    store::ObjectStore,
    tree::{diff_trees, walk_files},
    vpath::VPath,
};

/// One term of a merge: a file version, or `None` for "no file".
pub type Term = Option<ConflictTerm>;

fn same_term(a: &Term, b: &Term) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same(y),
        _ => false,
    }
}

/// A possibly resolved merge of file versions: `adds[0] - removes[0] +
/// adds[1] - … + adds[n]`. Resolved when it has a single add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merge {
    pub adds: Vec<Term>,
    pub removes: Vec<Term>,
}

impl Merge {
    /// The resolved merge holding `t`.
    pub fn resolved(t: Term) -> Merge {
        Merge {
            adds: vec![t],
            removes: vec![],
        }
    }

    /// The merge a stored conflict stands for.
    pub fn of_conflict(c: Conflict) -> Merge {
        Merge {
            adds: c.adds,
            removes: c.removes,
        }
    }

    /// The merge an entry stands for: a file is resolved, a conflict entry
    /// is its conflict, and no entry (or a directory, which counts as no
    /// file in a file merge) is resolved to nothing.
    pub fn of_entry(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Merge> {
        Ok(match e {
            // A symlink or gitlink (format 5) is a version like a file.
            Some(e) if e.kind.holds_blob() => Merge::resolved(Some(ConflictTerm::of(e))),
            Some(e) if e.kind == EntryKind::Conflict => Merge::of_conflict(store.conflict(&e.id)?),
            _ => Merge::resolved(None),
        })
    }

    /// The three-way merge of `base`, `ours` and `theirs`, each itself
    /// possibly a conflict, flattened into one merge: `ours - base +
    /// theirs`. With resolved inputs this is `adds = [ours, theirs]`,
    /// `removes = [base]`.
    pub fn three_way(base: Merge, ours: Merge, theirs: Merge) -> Merge {
        let mut adds = ours.adds;
        adds.extend(base.removes);
        adds.extend(theirs.adds);
        let mut removes = ours.removes;
        removes.extend(base.adds);
        removes.extend(theirs.removes);
        Merge { adds, removes }
    }

    /// Cancel every add that equals a remove (jj's `simplify`), keeping the
    /// order of what is left so that `adds[0]` stays "ours".
    pub fn simplify(mut self) -> Merge {
        let mut i = 0;
        while i < self.adds.len() {
            match self.removes.iter().position(|r| same_term(r, &self.adds[i])) {
                Some(j) => {
                    // Move the surviving add of the pair into position `i`.
                    self.adds.swap(j + 1, i);
                    self.removes.remove(j);
                    self.adds.remove(j + 1);
                }
                None => i += 1,
            }
        }
        self
    }

    /// jj's trivial merge: the value when one add is left after cancelling
    /// equal terms, or when every side made the same change.
    pub fn trivial(&self) -> Option<Term> {
        if self.adds.len() == 1 {
            return Some(self.adds[0].clone());
        }
        // Count each distinct term: +1 per add, -1 per remove.
        let mut counts: Vec<(Term, i64)> = Vec::new();
        for (t, n) in self.adds.iter().map(|t| (t, 1)).chain(self.removes.iter().map(|t| (t, -1))) {
            match counts.iter_mut().find(|(c, _)| same_term(c, t)) {
                Some((_, c)) => *c += n,
                None => counts.push((t.clone(), n)),
            }
        }
        counts.retain(|(_, c)| *c != 0);
        match counts.as_slice() {
            [(t, 1)] => Some(t.clone()),
            // Every side made the same change (Git and Mercurial agree).
            [(a, ca), (b, cb)] if ca + cb == 1 => Some(if *ca > 0 { a.clone() } else { b.clone() }),
            _ => None,
        }
    }

    /// The resolved value, if any.
    pub fn as_resolved(&self) -> Option<&Term> {
        (self.adds.len() == 1).then(|| &self.adds[0])
    }

    /// The conflict this merge is, if unresolved (and within the size a
    /// conflict object may have).
    pub fn into_conflict(self) -> Result<Option<Conflict>> {
        if self.adds.len() < 2 {
            return Ok(None);
        }
        let c = Conflict {
            adds: self.adds,
            removes: self.removes,
        };
        c.validate()?;
        Ok(Some(c))
    }
}

/// Merge the executable bits of `m`'s terms on their own: the trivial
/// merge of the bits of the present terms, else the first add's.
pub fn merged_executable(m: &Merge) -> bool {
    let bit = |t: &Term| t.as_ref().map(|t| t.executable);
    let mut counts: Vec<(Option<bool>, i64)> = Vec::new();
    for (b, n) in m.adds.iter().map(|t| (bit(t), 1)).chain(m.removes.iter().map(|t| (bit(t), -1))) {
        match counts.iter_mut().find(|(c, _)| *c == b) {
            Some((_, c)) => *c += n,
            None => counts.push((b, n)),
        }
    }
    counts.retain(|(_, c)| *c != 0);
    let first = m.adds.iter().flatten().next().is_some_and(|t| t.executable);
    match counts.as_slice() {
        [(Some(b), 1)] => *b,
        [(a, ca), (b, cb)] if ca + cb == 1 => (if *ca > 0 { *a } else { *b }).unwrap_or(first),
        _ => first,
    }
}

// ---- materialisation --------------------------------------------------------

/// Who a materialised conflict is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// This reader: whatever its keys open.
    Reader,
    /// Everyone: only plaintext is shown. What the Git export shows.
    Public,
}

/// How a materialised conflict was written, so that a partly edited copy
/// can be parsed back ([`parse_markers`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Style {
    /// One side's content, no markers (modify/delete, binary content, two
    /// sides sealed for different audiences, or a stored conflict that
    /// merges cleanly). Any edit resolves the conflict.
    Whole,
    /// diffy's diff3 markers of a two-sided conflict (`<<<<<<< ours`,
    /// `||||||| original` when the base is shown, `=======`, `>>>>>>>
    /// theirs`), each `marker_len` characters long.
    Diff3 { marker_len: usize, base_shown: bool },
    /// Every side as a whole, one block (more than two sides, or a side
    /// this audience cannot read). Any edit resolves the conflict.
    Blocks { marker_len: usize },
}

/// The file checkout writes for a conflict entry.
#[derive(Clone, Debug)]
pub struct Materialized {
    pub content: Vec<u8>,
    pub executable: bool,
    /// The audience of the rendered file: never wider than any side it
    /// shows (as for a file merged from those sides). What a resolution is
    /// sealed for, unless the policy or the line narrows it.
    pub visibility: Visibility,
    /// The last public version, for a sealed result (as a merged file
    /// would carry it).
    pub fallback: Option<ObjectId>,
    /// The add whose (verified) sealing decided `visibility`, if sealed.
    pub winner: Option<usize>,
    /// Some side or base is not shown (unreadable here, or sealed for
    /// another audience than the result's).
    pub redacted: bool,
    /// Some side cannot be read by this audience at all: it cannot resolve
    /// the conflict (its edits are held back, a deletion is not one).
    pub unreadable_side: bool,
    pub style: Style,
}

/// A term as an audience sees it.
struct Seen {
    /// The visibility its object really has (`None`: unverifiable, the
    /// claimed label is kept in `claimed`).
    verified: Option<Visibility>,
    claimed: Visibility,
    content: Option<Vec<u8>>,
    fallback: Option<ObjectId>,
    id: ObjectId,
}

impl Seen {
    fn vis(&self) -> &Visibility {
        self.verified.as_ref().unwrap_or(&self.claimed)
    }
}

fn released(store: &ObjectStore, v: &Visibility) -> bool {
    matches!(v, Visibility::Embargoed { embargo } if store.keys.embargo_released(embargo))
}

fn see(store: &ObjectStore, t: &ConflictTerm, audience: Audience) -> Result<Seen> {
    let e = t.entry("");
    let verified = match verify_sealing(store, &e)? {
        Sealing::Verified => Some(t.visibility.clone()),
        Sealing::Relabelled(actual) => Some(actual),
        Sealing::Unverifiable => None,
    };
    // Plaintext only: content under an embargo, even a released one, is
    // not shown to the public audience (see `git::project`).
    let shown_to_public = matches!(verified, Some(Visibility::Public));
    // A sealed term's fallback is an older version, never its content.
    let content = match audience {
        Audience::Public if !shown_to_public => None,
        _ => match store.read_blob(&t.id) {
            Ok(b) => Some(b),
            Err(err) if err.is_unreadable() || err.is_not_found() || matches!(err, VeilError::Corrupt(..)) => None,
            Err(err) => return Err(err),
        },
    };
    Ok(Seen {
        verified,
        claimed: t.visibility.clone(),
        content,
        fallback: t.fallback,
        id: t.id,
    })
}

/// Rank of a visibility for picking the result's audience: a scope's
/// sealing beats an embargo's, a released embargo counts as public.
fn rank(store: &ObjectStore, v: &Visibility) -> u8 {
    match v {
        Visibility::Cloaked { .. } => 2,
        Visibility::Embargoed { embargo } if !store.keys.embargo_released(embargo) => 1,
        _ => 0,
    }
}

/// Is a term with (verified) visibility `v` shown in a file sealed as
/// `result`? Public content (and a released embargo's) is shown anywhere;
/// sealed content only in a file sealed exactly as it is (BUG-126).
fn shown_in(store: &ObjectStore, v: Option<&Visibility>, result: &Visibility) -> bool {
    match v {
        Some(Visibility::Public) => true,
        Some(v) if released(store, v) => true,
        Some(v) => v == result,
        None => false,
    }
}

fn redaction_line(store: &ObjectStore, s: &Seen, audience: Audience, other_audience: bool) -> Vec<u8> {
    let why = match (audience, s.vis()) {
        (Audience::Public, _) => "this version is not public".to_string(),
        (_, _) if s.content.is_some() && other_audience => {
            format!("this version is {}, another audience than this file's", s.vis().label())
        }
        (_, v) if !store.has(&s.id) => format!("this version ({}) is not in this repository", v.label()),
        (_, Visibility::Cloaked { scope }) => format!("this version is sealed for scope '{scope}' and you do not hold its key"),
        (_, Visibility::Embargoed { embargo }) => format!("this version is under embargo {embargo}"),
        (_, v) => format!("this version ({}) cannot be read here", v.label()),
    };
    format!("(not shown: {why})\n").into_bytes()
}

/// Longest run of one marker character at the start of a line of `data`.
fn marker_run(data: &[u8]) -> usize {
    data.split(|b| *b == b'\n')
        .filter_map(|l| {
            let c = *l.first()?;
            matches!(c, b'<' | b'|' | b'=' | b'>' | b'+' | b'-').then(|| l.iter().take_while(|x| **x == c).count())
        })
        .max()
        .unwrap_or(0)
}

/// Marker length for content `parts`: Git's 7, longer when a line of the
/// content starts with as many marker characters (so markers stay
/// unambiguous when the copy is parsed back).
fn marker_len<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> usize {
    parts.into_iter().map(marker_run).max().unwrap_or(0).max(6) + 1
}

/// Render conflict `c` for `audience`.
///
/// * Two sides sealed for different scopes (BUG-123): only the side kept by
///   the merge rule (the base's scope, else ours) is written, as it is.
/// * One side absent (modify/delete): the present side, no markers.
/// * Binary content: the first readable side, no markers.
/// * Two readable text sides: diffy's diff3 markers, with the base's
///   section only where its audience is the result's (BUG-126).
/// * More sides, or a side this audience cannot read: every side as a
///   whole in one block, unreadable ones as a redaction line.
///
/// Only what writes or shows the file calls this (checkout, `vl cat`,
/// `vl diff`, `vl show`, the Git export, a snapshot comparing an edited
/// copy); what only describes the conflict uses [`inspect`], which never
/// compares the sides' text (BUG-484).
pub fn materialize(store: &ObjectStore, c: &Conflict, audience: Audience) -> Result<Materialized> {
    render(store, c, audience, true)
}

/// What a reader is told about a materialised conflict, without its text:
/// everything in [`Materialized`] but the content and its layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub executable: bool,
    pub visibility: Visibility,
    pub fallback: Option<ObjectId>,
    pub winner: Option<usize>,
    pub redacted: bool,
    pub unreadable_side: bool,
}

/// [`materialize`]'s description of conflict `c` for `audience`, without
/// merging the sides' text: what `vl status`, `vl ls`, `vl log` and the
/// JSON output need. Each version is still read (whether this reader can
/// read it decides the answers), which is linear in their size.
pub fn inspect(store: &ObjectStore, c: &Conflict, audience: Audience) -> Result<View> {
    let m = render(store, c, audience, false)?;
    Ok(View {
        executable: m.executable,
        visibility: m.visibility,
        fallback: m.fallback,
        winner: m.winner,
        redacted: m.redacted,
        unreadable_side: m.unreadable_side,
    })
}

/// [`inspect`] of conflict entry `e`.
pub fn inspect_entry(store: &ObjectStore, e: &TreeEntry, audience: Audience) -> Result<View> {
    inspect(store, &store.conflict(&e.id)?, audience)
}

/// [`materialize`], or (`text` false) everything but the merge of two
/// text sides, whose content is then left empty.
fn render(store: &ObjectStore, c: &Conflict, audience: Audience, text: bool) -> Result<Materialized> {
    // A link target is never turned into file content (a file of markers a
    // later edit could publish): a conflict with a symlink or gitlink term
    // is materialised as its shown side, as it is ([`shown_side`]; symlinks
    // design, threat 12). It can be described, never rendered as a file.
    if c.has_special_terms() {
        if text {
            return Err(VeilError::Unsupported(
                "a conflict between a symlink or gitlink and another version is never written as a file of markers; \
                 the working copy holds one side as it is (`vl resolve --ours|--theirs` picks one)"
                    .into(),
            ));
        }
        return describe_special(store, c, audience);
    }
    let adds: Vec<Option<Seen>> = c.adds.iter().map(|t| t.as_ref().map(|t| see(store, t, audience)).transpose()).collect::<Result<_>>()?;
    let removes: Vec<Option<Seen>> = c.removes.iter().map(|t| t.as_ref().map(|t| see(store, t, audience)).transpose()).collect::<Result<_>>()?;
    let executable = merged_executable(&Merge {
        adds: c.adds.clone(),
        removes: c.removes.clone(),
    });
    let unreadable_side = adds.iter().flatten().any(|s| s.content.is_none());
    if adds.iter().all(Option::is_none) {
        // Only a hostile object says "no file" on every side.
        return Ok(Materialized {
            content: Vec::new(),
            executable,
            visibility: Visibility::Public,
            fallback: None,
            winner: None,
            redacted: false,
            unreadable_side,
            style: Style::Whole,
        });
    }

    // Two scopes: keep one side as it is (`merge::audience_clash`).
    let mut scopes: Vec<&Visibility> = Vec::new();
    for v in adds.iter().flatten().filter_map(|s| s.verified.as_ref()) {
        if matches!(v, Visibility::Cloaked { .. }) && !scopes.contains(&v) {
            scopes.push(v);
        }
    }
    if scopes.len() > 1 {
        let base_scope = removes.first().and_then(|b| b.as_ref()).and_then(|b| b.verified.clone());
        let kept = adds
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.verified.is_some() && s.verified == base_scope))
            .or_else(|| adds.iter().position(|s| s.as_ref().is_some_and(|s| matches!(s.verified, Some(Visibility::Cloaked { .. })))))
            .expect("a cloaked side exists");
        let s = adds[kept].as_ref().expect("present");
        let content = match &s.content {
            Some(b) => b.clone(),
            None => redaction_line(store, s, audience, false),
        };
        return Ok(Materialized {
            content,
            executable,
            visibility: s.vis().clone(),
            fallback: s.fallback,
            winner: Some(kept),
            redacted: true,
            unreadable_side,
            style: Style::Whole,
        });
    }

    // The result's audience: the highest-ranked side's (ours first), as
    // `merge::merged_visibility` decides for a merged file.
    let mut winner: Option<usize> = None;
    for (i, s) in adds.iter().enumerate() {
        let Some(s) = s else { continue };
        let r = rank(store, s.vis());
        if r > 0 && winner.is_none_or(|w| r > rank(store, adds[w].as_ref().expect("present").vis())) {
            winner = Some(i);
        }
    }
    let (visibility, fallback) = match winner {
        None => (Visibility::Public, None),
        Some(w) => {
            let ws = adds[w].as_ref().expect("present");
            // The newest public version: a public side's, else the sealed
            // side's own fallback.
            let public_side = adds
                .iter()
                .flatten()
                .find(|s| s.vis().is_public() && s.fallback.is_none())
                .map(|s| s.id);
            let fb = match ws.vis() {
                Visibility::Cloaked { .. } => match ws.fallback {
                    Some(_) => public_side.or(ws.fallback),
                    None => None,
                },
                _ => public_side.or(ws.fallback),
            };
            (ws.vis().clone(), fb)
        }
    };
    let shown = |s: &Seen| shown_in(store, s.verified.as_ref(), &visibility) && s.content.is_some();
    let mut out = Materialized {
        content: Vec::new(),
        executable,
        visibility: visibility.clone(),
        fallback,
        winner,
        redacted: false,
        unreadable_side,
        style: Style::Whole,
    };

    // Modify/delete: the present side, as the merge kept it.
    if c.adds.len() == 2 && adds.iter().any(Option::is_none) {
        let s = adds.iter().flatten().next().expect("one side is present");
        out.content = match &s.content {
            Some(b) if shown(s) => b.clone(),
            _ => {
                out.redacted = true;
                redaction_line(store, s, audience, s.content.is_some())
            }
        };
        return Ok(out);
    }

    let all_shown = adds.iter().flatten().all(shown);
    let binary = adds.iter().chain(removes.iter()).flatten().any(|s| s.content.as_deref().is_some_and(looks_binary));
    if binary {
        let first = adds.iter().flatten().find(|s| shown(s));
        out.redacted = !all_shown;
        out.content = match first {
            Some(s) => s.content.clone().expect("shown"),
            None => {
                let s = adds.iter().flatten().next().expect("a side");
                redaction_line(store, s, audience, s.content.is_some())
            }
        };
        return Ok(out);
    }

    if c.adds.len() == 2 && all_shown {
        let (ours, theirs) = (adds[0].as_ref().expect("present"), adds[1].as_ref().expect("present"));
        let base = removes[0].as_ref();
        let base_shown = base.is_none_or(shown);
        let empty = Vec::new();
        let base_text: &[u8] = match base {
            Some(b) if base_shown => b.content.as_deref().expect("shown"),
            // A hidden base keeps nothing in the comparison (as a virtual
            // base does, BUG-127): every difference conflicts, and the
            // base's text is never written.
            _ => &empty,
        };
        let (o, t) = (ours.content.as_deref().expect("shown"), theirs.content.as_deref().expect("shown"));
        let n = marker_len([o, t, base_text]);
        let style = if base_shown {
            crate::textmerge::Style::Diff3
        } else {
            crate::textmerge::Style::Merge
        };
        out.redacted = !base_shown;
        if !text {
            out.style = Style::Diff3 { marker_len: n, base_shown };
            return Ok(out);
        }
        // Bounded (BUG-484): past the work limit, one conflict holds both
        // sides whole, in the same layout.
        match crate::textmerge::merge(base_text, o, t, n, style) {
            Ok(clean) => out.content = clean,
            Err(marked) => {
                out.content = marked;
                out.style = Style::Diff3 {
                    marker_len: n,
                    base_shown,
                };
            }
        }
        return Ok(out);
    }

    // Blocks: every side whole.
    let shown_parts: Vec<&[u8]> = adds.iter().chain(removes.iter()).flatten().filter(|s| shown(s)).map(|s| s.content.as_deref().expect("shown")).collect();
    let n = marker_len(shown_parts);
    let two = c.adds.len() == 2;
    let label = |add: bool, i: usize| -> String {
        match (two, add) {
            (true, true) if i == 0 => "ours".into(),
            (true, true) => "theirs".into(),
            (true, false) => "base".into(),
            (false, true) => format!("side {} of {}", i + 1, c.adds.len()),
            (false, false) => format!("base {}", i + 1),
        }
    };
    let mut body = Vec::new();
    let section = |body: &mut Vec<u8>, marker: u8, title: &str, s: Option<&Seen>, redacted: &mut bool| {
        body.extend(std::iter::repeat_n(marker, n));
        body.push(b' ');
        body.extend_from_slice(title.as_bytes());
        body.push(b'\n');
        match s {
            None => body.extend_from_slice(b"(no file)\n"),
            Some(s) if shown(s) => {
                let b = s.content.as_deref().expect("shown");
                body.extend_from_slice(b);
                if !b.is_empty() && !b.ends_with(b"\n") {
                    body.push(b'\n');
                }
            }
            Some(s) => {
                *redacted = true;
                body.extend(redaction_line(store, s, audience, s.content.is_some()));
            }
        }
    };
    let mut redacted = false;
    for (i, add) in adds.iter().enumerate() {
        let marker = if i == 0 { b'<' } else { b'=' };
        section(&mut body, marker, &label(true, i), add.as_ref(), &mut redacted);
        if let Some(r) = removes.get(i) {
            match r {
                Some(b) if !shown(b) && b.content.is_some() => {
                    // A base for another audience is left out entirely.
                    redacted = true;
                }
                r => section(&mut body, b'|', &label(false, i), r.as_ref(), &mut redacted),
            }
        }
    }
    body.extend(std::iter::repeat_n(b'>', n));
    body.extend_from_slice(b" end of conflict\n");
    out.content = body;
    out.redacted = redacted;
    out.style = Style::Blocks { marker_len: n };
    Ok(out)
}

/// The side of a conflict with a symlink or gitlink term (format 5) that
/// the working copy holds, as it is: the first side present (ours, unless
/// our side deleted it), with its index in `adds`. `None` only for a
/// hostile conflict whose every side is "no file".
pub fn shown_side(c: &Conflict) -> Option<(usize, &crate::object::ConflictTerm)> {
    c.adds.iter().enumerate().find_map(|(i, t)| t.as_ref().map(|t| (i, t)))
}

/// [`inspect`] of a conflict with a symlink or gitlink term: the shown side
/// decides the mode and audience; every other version is not shown.
fn describe_special(store: &ObjectStore, c: &Conflict, audience: Audience) -> Result<Materialized> {
    let mut unreadable_side = false;
    for t in c.adds.iter().flatten() {
        unreadable_side |= see(store, t, audience)?.content.is_none();
    }
    let Some((i, t)) = shown_side(c) else {
        return Ok(Materialized {
            content: Vec::new(),
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
            winner: None,
            redacted: false,
            unreadable_side,
            style: Style::Whole,
        });
    };
    let s = see(store, t, audience)?;
    Ok(Materialized {
        content: Vec::new(),
        executable: t.kind == crate::object::TermKind::File && t.executable,
        visibility: s.vis().clone(),
        fallback: t.fallback,
        winner: Some(i),
        redacted: true,
        unreadable_side,
        style: Style::Whole,
    })
}

/// The materialisation of conflict entry `e` for `audience`.
pub fn materialize_entry(store: &ObjectStore, e: &TreeEntry, audience: Audience) -> Result<Materialized> {
    materialize(store, &store.conflict(&e.id)?, audience)
}

/// Is file entry `file` exactly what a public reader is shown for conflict
/// entry `c`, with every version shown (the Git export of the conflict)?
/// Then a Git commit's edit of that file is an edit of the conflict.
pub fn publicly_renders_as(store: &ObjectStore, c: &TreeEntry, file: &TreeEntry) -> Result<bool> {
    if !file.visibility.is_public() || file.fallback.is_some() {
        return Ok(false);
    }
    let m = match materialize_entry(store, c, Audience::Public) {
        Ok(m) => m,
        Err(e) if e.is_unreadable() || e.is_not_found() || matches!(e, VeilError::Corrupt(..)) => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(!m.redacted && !m.unreadable_side && Object::blob_id(&m.content) == file.id && m.executable == file.executable)
}

/// Conflict entry `c` (at `path`) as the file of markers this reader is
/// shown, sealed as the materialised file is: for trees that cannot hold a
/// conflict entry (under an unreleased embargo). Refused when a version
/// cannot be read here, which writing markers would lose.
pub fn as_marker_file(store: &ObjectStore, c: &TreeEntry, path: &VPath) -> Result<TreeEntry> {
    // A conflict with a symlink or gitlink side: its shown side, as it is
    // (a link target never becomes a file of markers).
    let conflict = store.conflict(&c.id)?;
    if conflict.has_special_terms() {
        return match shown_side(&conflict) {
            Some((_, t)) => Ok(t.entry(&c.name)),
            None => Err(VeilError::Corrupt(path.to_string(), "a conflict with no side".into())),
        };
    }
    let m = materialize(store, &conflict, Audience::Reader)?;
    if m.unreadable_side {
        return Err(VeilError::Policy(format!(
            "cannot merge {path} here: it holds a conflict with a version you cannot read; resolve it first (`vl resolve --list`)"
        )));
    }
    Ok(TreeEntry {
        name: c.name.clone(),
        kind: EntryKind::File,
        id: store.store_file(&m.content, &m.visibility)?,
        size: m.content.len() as u64,
        executable: m.executable,
        visibility: m.visibility,
        fallback: m.fallback,
    })
}

/// The bytes a reader sees for a file-like entry: a file's content (its
/// fallback when this reader cannot read it, as [`ObjectStore::read_entry`])
/// or a conflict's materialisation for this reader.
///
/// A symlink's bytes are its target, a gitlink's its commit id line; a
/// conflict with such a side reads as its shown side ([`shown_side`]).
pub fn read_file_like(store: &ObjectStore, e: &TreeEntry) -> Result<Vec<u8>> {
    match e.kind {
        EntryKind::Conflict => {
            let c = store.conflict(&e.id)?;
            if c.has_special_terms() {
                return match shown_side(&c) {
                    Some((_, t)) => store.read_entry(&t.entry(&e.name)),
                    None => Ok(Vec::new()),
                };
            }
            Ok(materialize(store, &c, Audience::Reader)?.content)
        }
        _ => store.read_entry(e),
    }
}

// ---- parsing a materialised copy back --------------------------------------------

/// The sides of a partly edited diff3 copy: `(ours, base, theirs)`, each
/// the copy's text outside the conflicts plus that side's section of every
/// conflict. `None` when no conflict is left (the copy is a resolution) or
/// the markers no longer parse (the copy is then taken as it is).
///
/// As in jj, text outside the markers belongs to every side, so an edit
/// there is kept whichever side is later chosen. Where the base was not
/// shown (BUG-126), its section is empty: the base's text is never
/// reconstructed for another audience.
pub fn parse_markers(data: &[u8], style: &Style) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let Style::Diff3 { marker_len, base_shown } = style else {
        return None;
    };
    let mk = |c: u8, label: &[u8]| {
        let mut m = vec![c; *marker_len];
        if !label.is_empty() {
            m.push(b' ');
            m.extend_from_slice(label);
        }
        m
    };
    let (start, orig, mid, end) = (mk(b'<', b"ours"), mk(b'|', b"original"), mk(b'=', b""), mk(b'>', b"theirs"));
    #[derive(PartialEq)]
    enum At {
        Out,
        Ours,
        Base,
        Theirs,
    }
    let (mut ours, mut base, mut theirs) = (Vec::new(), Vec::new(), Vec::new());
    let mut at = At::Out;
    let mut hunks = 0;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let bare = line.strip_suffix(b"\n").unwrap_or(line);
        let bare = bare.strip_suffix(b"\r").unwrap_or(bare);
        let next = match at {
            At::Out if bare == start.as_slice() => Some(At::Ours),
            At::Ours if *base_shown && bare == orig.as_slice() => Some(At::Base),
            At::Ours if !*base_shown && bare == mid.as_slice() => Some(At::Theirs),
            At::Base if bare == mid.as_slice() => Some(At::Theirs),
            At::Theirs if bare == end.as_slice() => {
                hunks += 1;
                Some(At::Out)
            }
            _ => None,
        };
        if let Some(n) = next {
            at = n;
            continue;
        }
        // A marker line out of place: the copy no longer parses.
        if [&start, &orig, &mid, &end].iter().any(|m| bare == m.as_slice()) {
            return None;
        }
        match at {
            At::Out => {
                ours.extend_from_slice(line);
                base.extend_from_slice(line);
                theirs.extend_from_slice(line);
            }
            At::Ours => ours.extend_from_slice(line),
            At::Base => base.extend_from_slice(line),
            At::Theirs => theirs.extend_from_slice(line),
        }
    }
    (at == At::Out && hunks > 0).then_some((ours, base, theirs))
}

/// Does `data` still hold a conflict marker line of `style`? (A copy with
/// none left is a resolution.)
pub fn has_markers(data: &[u8], style: &Style) -> bool {
    let n = match style {
        Style::Whole => return false,
        Style::Diff3 { marker_len, .. } | Style::Blocks { marker_len } => *marker_len,
    };
    data.split(|b| *b == b'\n').any(|l| {
        l.len() >= n && matches!(l[0], b'<' | b'>') && l[..n].iter().all(|c| *c == l[0]) && l.get(n).is_none_or(|c| *c == b' ' || *c == b'\r')
    })
}

// ---- the conflict index on snapshots ----------------------------------------------

/// Paths of the conflict entries below `tree`, in order (a full walk).
pub fn conflict_paths(store: &ObjectStore, tree: &ObjectId) -> Result<Vec<VPath>> {
    Ok(walk_files(store, tree)?
        .into_iter()
        .filter(|(_, e)| e.kind == EntryKind::Conflict)
        .map(|(p, _)| p)
        .collect())
}

/// The conflicted paths to record on a snapshot with tree `tree`
/// (repository format 4), given what the operation computed (`listed`: the
/// paths a merge reported, and conflicts carried over from before), and
/// the snapshot it was derived from (`base`: the rewritten snapshot or the
/// first parent, `None` for none).
///
/// `Snapshot::conflicts` is an index: every conflict entry of the tree,
/// plus paths that hold an older kind of conflict (markers written by a
/// format-1 to 3 merge, or a file moved aside by a file/directory conflict)
/// carried by the operation. A listed path that was a conflict entry in
/// `base` and is not one now was resolved and is dropped. Computed from
/// `base` by a tree diff, so unchanged directories cost nothing.
pub fn index_conflicts(store: &ObjectStore, tree: &ObjectId, listed: &[String], base: Option<(&ObjectId, &[String])>) -> Result<Vec<String>> {
    let is_conflict = |t: &ObjectId, p: &str| -> bool {
        VPath::new(p)
            .ok()
            .and_then(|p| crate::tree::lookup(store, t, &p).ok().flatten())
            .is_some_and(|e| e.kind == EntryKind::Conflict)
    };
    let mut now: BTreeSet<String> = BTreeSet::new();
    let mut was: BTreeSet<String> = BTreeSet::new();
    match base {
        Some((bt, blist)) => {
            for p in blist {
                if is_conflict(bt, p) {
                    was.insert(p.clone());
                }
            }
            now = was.clone();
            for c in diff_trees(store, Some(bt), Some(tree))? {
                let p = c.path.to_string();
                if c.old.as_ref().is_some_and(|e| e.kind == EntryKind::Conflict) {
                    was.insert(p.clone());
                }
                match &c.new {
                    Some(e) if e.kind == EntryKind::Conflict => {
                        now.insert(p);
                    }
                    _ => {
                        now.remove(&p);
                    }
                }
            }
        }
        None => now.extend(conflict_paths(store, tree)?.into_iter().map(|p| p.to_string())),
    }
    for p in listed {
        if now.contains(p) {
            continue;
        }
        if is_conflict(tree, p) {
            // A conflict entry the base's index missed is still one.
            now.insert(p.clone());
        } else if !was.contains(p) {
            // An older kind of conflict, carried by the operation.
            now.insert(p.clone());
        }
        // Otherwise it was a conflict entry and is resolved now.
    }
    Ok(now.into_iter().collect())
}

/// Store `m` as a conflict entry named `name` when unresolved, or the file
/// it resolves to (`None`: no file).
pub fn entry_for(store: &ObjectStore, name: &str, m: Merge) -> Result<Option<TreeEntry>> {
    if let Some(t) = m.as_resolved() {
        return Ok(t.as_ref().map(|t| t.entry(name)));
    }
    let c = m.into_conflict()?.expect("unresolved");
    Ok(Some(TreeEntry::conflict(name, store.put_conflict(&c)?)))
}

/// Ids a conflict object references, for walkers over raw objects.
pub fn referenced_ids(raw_obj: &Object) -> Vec<ObjectId> {
    match raw_obj {
        Object::Conflict(c) => c.referenced_ids(),
        _ => Vec::new(),
    }
}

// ---- `vl resolve` --------------------------------------------------------------

/// The version of a conflict `vl resolve` keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// The first side: the version of the change merged into (`@-` for a
    /// `vl merge`, the new parent for a rebase).
    Ours,
    /// The other side of a two-sided conflict.
    Theirs,
    /// The base of a two-sided conflict.
    Base,
    /// Side `n` (1-based) of a conflict of any number of sides.
    Side(usize),
}

impl Pick {
    /// The version of `c` this picks (`None`: no file).
    pub fn term(self, c: &Conflict) -> Result<Term> {
        let sides = c.adds.len();
        match self {
            Pick::Ours => Ok(c.adds[0].clone()),
            Pick::Theirs if sides == 2 => Ok(c.adds[1].clone()),
            Pick::Base if c.removes.len() == 1 => Ok(c.removes[0].clone()),
            Pick::Side(n) if (1..=sides).contains(&n) => Ok(c.adds[n - 1].clone()),
            Pick::Side(n) => Err(VeilError::repo(format!("there is no side {n}: this conflict has {sides} sides"))),
            Pick::Theirs | Pick::Base => Err(VeilError::repo(format!(
                "this conflict has {sides} sides and {} bases; pick one with `--side N`",
                c.removes.len()
            ))),
        }
    }
}

/// `tree` with the entry at `path` replaced by `entry` (removed for
/// `None`; directories left empty disappear, missing ones are created).
/// Plain trees only: a tree under an embargo wrapper is refused.
pub fn set_entry(store: &ObjectStore, tree: &ObjectId, path: &VPath, entry: Option<TreeEntry>) -> Result<ObjectId> {
    let comps: Vec<&str> = path.components().collect();
    let Some((last, dirs)) = comps.split_last() else {
        return Err(VeilError::InvalidPath("the root is not a file".into()));
    };
    // Walk down, keeping each directory, then rebuild upwards.
    let mut chain: Vec<crate::object::Tree> = vec![(*store.tree_object(tree)?).clone()];
    if crate::embargo::wrapper_parts(&chain[0]).is_some() {
        return Err(VeilError::Policy("this change is under an unreleased embargo; edit the file to resolve the conflict".into()));
    }
    for d in dirs {
        let next = match chain.last().expect("non-empty").get(d) {
            Some(e) if e.kind == EntryKind::Dir => (*store.tree_object(&e.id)?).clone(),
            // A directory the tree no longer has (deleted with everything
            // in it, BUG-757): created for an entry put back, and nothing
            // to remove.
            None if entry.is_some() => crate::object::Tree::default(),
            None => return Ok(*tree),
            Some(_) => return Err(VeilError::NotFound(path.to_string())),
        };
        chain.push(next);
    }
    let mut leaf = chain.pop().expect("non-empty");
    match entry {
        Some(e) => leaf.insert(TreeEntry {
            name: last.to_string(),
            ..e
        }),
        None => {
            leaf.remove(last);
        }
    }
    let mut child: Option<ObjectId> = (!leaf.is_empty()).then(|| store.put_tree(&leaf)).transpose()?;
    for (mut t, name) in chain.into_iter().rev().zip(dirs.iter().rev()) {
        match child {
            Some(id) => t.insert(TreeEntry::dir(name, id)),
            None => {
                t.remove(name);
            }
        }
        child = (!t.is_empty()).then(|| store.put_tree(&t)).transpose()?;
    }
    match child {
        Some(id) => Ok(id),
        None => store.empty_tree(),
    }
}

impl crate::repo::Repo {
    /// `vl resolve PATHS --ours|--theirs|--base|--side N`: replace each
    /// conflict entry at or below `paths` in the working copy of `ws` by
    /// the version `pick` names, exactly as that version is recorded (its
    /// sealing, its executable bit; "no file" removes the path). No content
    /// is read or sealed, so a version keeps its audience: choosing a side
    /// sealed for a scope keeps it sealed for that scope. Returns the
    /// resolved paths. The caller checks the result out.
    pub fn resolve_conflicts(&mut self, ws: &str, paths: &[VPath], pick: Pick) -> Result<Vec<VPath>> {
        let mut tx = self.transaction("resolve conflicts")?;
        let wc_id = tx.view.workspace(ws)?.wc;
        let wc = tx.repo().snapshot(&wc_id)?;
        let store = tx.repo().store.clone();
        let under = |p: &VPath| paths.iter().any(|f| f.is_root() || p == f || p.as_str().starts_with(&f.child_prefix()));
        let found: Vec<VPath> = conflict_paths(&store, &wc.tree)?.into_iter().filter(|p| under(p)).collect();
        if found.is_empty() {
            let names: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
            let marked: Vec<&String> = wc.conflicts.iter().filter(|c| VPath::new(c).is_ok_and(|p| under(&p))).collect();
            return Err(VeilError::repo(match marked.is_empty() {
                true => format!("no conflict at {} in the working copy (`vl resolve --list` lists them)", names.join(", ")),
                false => format!(
                    "{} holds a conflict recorded as markers in the file (by a merge in an older repository format, or under an embargo): edit the file to resolve it",
                    marked.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            }));
        }
        let mut tree = wc.tree;
        for p in &found {
            let e = crate::tree::lookup(&store, &tree, p)?.expect("found above");
            let c = store.conflict(&e.id)?;
            let chosen = pick.term(&c).map_err(|err| VeilError::repo(format!("{p}: {err}")))?;
            tree = set_entry(&store, &tree, p, chosen.map(|t| t.entry(&e.name)))?;
        }
        let mut new = (*wc).clone();
        new.tree = tree;
        new.predecessors = vec![wc_id];
        new.timestamp = crate::now_millis();
        tx.rewrite(wc_id, new)?;
        let what = match pick {
            Pick::Ours => "ours".to_string(),
            Pick::Theirs => "theirs".to_string(),
            Pick::Base => "base".to_string(),
            Pick::Side(n) => format!("side {n}"),
        };
        let names: Vec<&str> = found.iter().map(|p| p.as_str()).collect();
        tx.set_description(format!("resolve {} ({what})", names.join(" ")));
        tx.commit()?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u8) -> Term {
        Some(ConflictTerm {
            kind: crate::object::TermKind::File,
            id: ObjectId([n; 32]),
            size: 0,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        })
    }

    fn m3(base: Term, ours: Term, theirs: Term) -> Merge {
        Merge {
            adds: vec![ours, theirs],
            removes: vec![base],
        }
    }

    #[test]
    fn three_way_of_resolved_terms() {
        let m = Merge::three_way(Merge::resolved(t(1)), Merge::resolved(t(2)), Merge::resolved(t(3)));
        assert_eq!(m, m3(t(1), t(2), t(3)));
        assert_eq!(m.clone().simplify(), m);
        assert_eq!(m.trivial(), None);
    }

    #[test]
    fn trivial_cases() {
        assert_eq!(m3(t(1), t(1), t(3)).trivial(), Some(t(3)));
        assert_eq!(m3(t(1), t(2), t(1)).trivial(), Some(t(2)));
        assert_eq!(m3(t(1), t(2), t(2)).trivial(), Some(t(2)), "both sides made the same change");
        assert_eq!(m3(None, t(2), t(2)).trivial(), Some(t(2)));
        assert_eq!(m3(t(1), None, None).trivial(), Some(None), "deleted on both sides");
        assert_eq!(m3(t(1), None, t(1)).trivial(), Some(None));
        assert_eq!(m3(t(1), None, t(3)).trivial(), None, "modify/delete");
    }

    #[test]
    fn simplify_keeps_ours_first() {
        // (2 - 1 + 3) - 2 + 4 → 3 - 1 + 4? No: cancelling the 2s leaves
        // adds [3, 4] and removes [1], with ours' replacement first.
        let m = Merge {
            adds: vec![t(2), t(3), t(4)],
            removes: vec![t(1), t(2)],
        }
        .simplify();
        assert_eq!(m.adds.len(), 2);
        assert_eq!(m.removes, vec![t(1)]);
        assert!(m.adds.contains(&t(3)) && m.adds.contains(&t(4)));
    }

    #[test]
    fn rebasing_a_conflict_onto_its_resolution_resolves_it() {
        // A change C conflicted: ours 2, theirs 3 over base 1, on parent P
        // holding 2. Rebased onto Q holding 3 (theirs' change already in):
        // base P(2), ours Q(3), theirs C.
        let c = m3(t(1), t(2), t(3));
        let m = Merge::three_way(Merge::resolved(t(2)), Merge::resolved(t(3)), c).simplify();
        assert_eq!(m.trivial(), Some(t(3)));
        // Rebased onto R holding 4: still conflicted, with R's version as ours.
        let c = m3(t(1), t(2), t(3));
        let m = Merge::three_way(Merge::resolved(t(2)), Merge::resolved(t(4)), c).simplify();
        assert_eq!(m.trivial(), None);
        assert_eq!(m, m3(t(1), t(4), t(3)));
        // And back onto P: the original conflict.
        let m2 = Merge::three_way(Merge::resolved(t(4)), Merge::resolved(t(2)), Merge::of_conflict(m.into_conflict().unwrap().unwrap())).simplify();
        assert_eq!(m2, m3(t(1), t(2), t(3)));
    }

    #[test]
    fn merging_two_conflicts_flattens() {
        let a = m3(t(1), t(2), t(3));
        let b = m3(t(1), t(2), t(4));
        // Merge a and b against their common version 2.
        let m = Merge::three_way(Merge::resolved(t(2)), a, b).simplify();
        assert_eq!(m.adds.len(), 3, "{m:?}");
        assert_eq!(m.trivial(), None);
        let c = m.clone().into_conflict().unwrap().unwrap();
        assert_eq!(c.removes.len(), 2);
        // Merging a conflict with itself is itself.
        let a = m3(t(1), t(2), t(3));
        let m = Merge::three_way(Merge::resolved(t(2)), a.clone(), a.clone()).simplify();
        assert_eq!(m.trivial(), None);
        assert_eq!(m.adds.len(), 3);
    }

    #[test]
    fn executable_bits_merge_on_their_own() {
        let x = |n: u8, e: bool| {
            Some(ConflictTerm {
                executable: e,
                ..t(n).unwrap()
            })
        };
        assert!(merged_executable(&m3(x(1, false), x(2, false), x(3, true))));
        assert!(!merged_executable(&m3(x(1, true), x(2, false), x(3, true))));
        assert!(merged_executable(&m3(x(1, false), x(2, true), x(3, false))));
    }

    #[test]
    fn markers_parse_back_into_sides() {
        let base = b"a\nb\nc\nd\n";
        let ours = b"a\nB1\nc\nd\n";
        let theirs = b"a\nB2\nc\nD\n";
        let marked = diffy::MergeOptions::new()
            .set_conflict_style(diffy::ConflictStyle::Diff3)
            .merge_bytes(base, ours, theirs)
            .unwrap_err();
        let style = Style::Diff3 {
            marker_len: 7,
            base_shown: true,
        };
        let (o, b, t) = parse_markers(&marked, &style).unwrap();
        assert_eq!(o, b"a\nB1\nc\nD\n");
        assert_eq!(b, b"a\nb\nc\nD\n");
        assert_eq!(t, b"a\nB2\nc\nD\n");
        // An edit outside the markers belongs to every side.
        let edited = [b"top\n".as_slice(), &marked].concat();
        let (o, _, t) = parse_markers(&edited, &style).unwrap();
        assert!(o.starts_with(b"top\n") && t.starts_with(b"top\n"));
        // Markers gone: a resolution.
        assert!(parse_markers(b"a\nB\nc\nD\n", &style).is_none());
        assert!(!has_markers(b"a\nB\nc\nD\n", &style));
        assert!(has_markers(&marked, &style));
        // A marker out of place: not parseable.
        let broken = [marked.as_slice(), b">>>>>>> theirs\n"].concat();
        assert!(parse_markers(&broken, &style).is_none());
    }

    #[test]
    fn hidden_base_parses_with_an_empty_base() {
        let marked = diffy::MergeOptions::new()
            .set_conflict_style(diffy::ConflictStyle::Merge)
            .merge_bytes(b"", b"x\n", b"y\n")
            .unwrap_err();
        let style = Style::Diff3 {
            marker_len: 7,
            base_shown: false,
        };
        let (o, b, t) = parse_markers(&marked, &style).unwrap();
        assert_eq!((o.as_slice(), b.as_slice(), t.as_slice()), (b"x\n".as_slice(), b"".as_slice(), b"y\n".as_slice()));
    }

    #[test]
    fn marker_length_grows_past_marker_like_content() {
        assert_eq!(marker_len([b"a\n".as_slice()]), 7);
        assert_eq!(marker_len([b"=======\n".as_slice()]), 8);
        assert_eq!(marker_len([b"x <<<<<<<<<< y\n".as_slice()]), 7, "only line starts count");
    }
}
