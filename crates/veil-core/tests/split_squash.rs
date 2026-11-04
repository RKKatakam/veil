//! `vl split` and partial `vl squash` (`Repo::split`, `Repo::squash_into`,
//! `selection`): the halves of a change are exactly what was chosen and the
//! rest, put back together they are the original tree, nothing changes
//! audience, conflicts and unreadable files move only whole, and each
//! command is one operation that `undo` takes back exactly.

mod adversarial_support;

use std::collections::BTreeSet;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    commands::ChangeParts,
    hunks::{apply, diff_text},
    object::Visibility,
    selection::{self, Content, HunkRef, Pick, Selection, Spec, Whole},
    tree::walk_files,
    EntryKind, ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn wc(repo: &Repo) -> ObjectId {
    repo.workspace_wc(WS).unwrap()
}

fn tree_of(repo: &Repo, id: &ObjectId) -> ObjectId {
    repo.snapshot(id).unwrap().tree
}

const OLD: &str = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n";
const NEW: &str = "1\nTWO\n3\n4\n5\nSIX\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\nextra\n";

/// `base` commits `a.txt` = OLD and `b.txt`; the working copy edits
/// `a.txt` to NEW (two hunks, the first of two blocks), `b.txt`, and adds
/// `c.txt`.
fn world() -> (Repo, std::sync::Arc<veil_core::MemoryBackend>, ObjectId) {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", OLD), ("b.txt", "b\n")], "base");
    fs.write(&p("a.txt"), NEW.as_bytes()).unwrap();
    fs.write(&p("b.txt"), b"B\n").unwrap();
    fs.write(&p("c.txt"), b"c\n").unwrap();
    snap(&mut repo, &*fs);
    (repo, fs, base)
}

fn spec(path: &str, hunks: &[&str]) -> Spec {
    Spec { path: p(path), hunks: (!hunks.is_empty()).then(|| hunks.iter().map(|h| HunkRef::parse(h).unwrap()).collect()) }
}

fn parts_of(repo: &Repo, id: &ObjectId) -> ChangeParts {
    repo.change_parts(id, true).unwrap()
}

#[test]
fn split_by_hunk_keeps_the_change_id_on_the_rest() {
    let (mut repo, _fs, base) = world();
    let c = wc(&repo);
    let orig = repo.snapshot(&c).unwrap();
    repo.describe(c, "the work").unwrap();
    let c = wc(&repo);
    let parts = parts_of(&repo, &c);
    let sel = selection::select(&parts.units, &[spec("a.txt", &["1.2", "2"]), spec("c.txt", &[])]).unwrap();
    let before_op = repo.op_id();
    let view_before = repo.view().clone();
    let r = repo.split(&parts, &sel, Some("first")).unwrap();

    let first = repo.snapshot(&r.first).unwrap();
    let second = repo.snapshot(&r.second).unwrap();
    assert_eq!(first.parents, vec![base]);
    assert_eq!(second.parents, vec![r.first]);
    assert_eq!(second.change_id, orig.change_id, "the rest keeps the change id");
    assert_ne!(first.change_id, orig.change_id);
    assert_eq!(repo.description(&second), "the work");
    assert_eq!(repo.description(&first), "first");
    assert_eq!(second.tree, tree_of(&repo, &c), "the rest is the original tree");
    assert_eq!(wc(&repo), r.second, "the working copy follows the change");
    assert_eq!(read_at(&repo, &r.first, "a.txt"), format!("{}extra\n", OLD.replacen("\n6\n", "\nSIX\n", 1)).as_bytes());
    assert_eq!(read_at(&repo, &r.first, "b.txt"), b"b\n");
    assert_eq!(read_at(&repo, &r.first, "c.txt"), b"c\n");

    // One operation: undo restores the view exactly.
    assert_ne!(repo.op_id(), before_op);
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view_before);
}

#[test]
fn empty_halves_are_refused() {
    let (mut repo, _fs, _) = world();
    let c = wc(&repo);
    let parts = parts_of(&repo, &c);
    let op = repo.op_id();
    let e = repo.split(&parts, &Selection::new(), None).unwrap_err().to_string();
    assert!(e.contains("nothing chosen"), "{e}");
    let all = selection::select(&parts.units, &[spec("", &[])]).unwrap();
    let e = repo.split(&parts, &all, None).unwrap_err().to_string();
    assert!(e.contains("everything chosen"), "{e}");
    // Every hunk of every file, named one by one, is everything too.
    let each = selection::select(&parts.units, &[spec("a.txt", &["1", "2"]), spec("b.txt", &["1"]), spec("c.txt", &["1"])]).unwrap();
    assert!(repo.split(&parts, &each, None).unwrap_err().to_string().contains("everything chosen"));
    assert_eq!(repo.op_id(), op, "nothing was recorded");
    let e = repo.squash_into(c, None, Some((&parts, &Selection::new()))).unwrap_err().to_string();
    assert!(e.contains("nothing chosen"), "{e}");
}

#[test]
fn specs_that_name_nothing_are_errors() {
    let (repo, _fs, _) = world();
    let parts = parts_of(&repo, &wc(&repo));
    for (s, want) in [
        (spec("nope.txt", &[]), "changes at nope.txt"),
        (spec("a.txt", &["3"]), "has no hunk 3"),
        (spec("a.txt", &["1.3"]), "has no block 3"),
        (spec("a.txt", &["mode"]), "executable bit does not change"),
        (spec("nope.txt", &["1"]), "a changed file nope.txt"),
    ] {
        let e = selection::select(&parts.units, &[s]).unwrap_err().to_string();
        assert!(e.contains(want), "{e}");
    }
}

#[test]
fn a_stale_reading_is_refused() {
    let (mut repo, _fs, _) = world();
    let c = wc(&repo);
    let parts = parts_of(&repo, &c);
    let sel = selection::select(&parts.units, &[spec("b.txt", &[])]).unwrap();
    repo.describe(c, "rewritten meanwhile").unwrap();
    let e = repo.split(&parts, &sel, None).unwrap_err().to_string();
    assert!(e.contains("no longer in the history"), "{e}");
    let e = repo.squash_into(c, None, Some((&parts, &sel))).unwrap_err().to_string();
    assert!(e.contains("no longer in the history"), "{e}");
}

#[test]
fn squash_hunks_into_the_parent_and_back() {
    let (mut repo, _fs, base) = world();
    let c = wc(&repo);
    let t = tree_of(&repo, &c);
    let parts = parts_of(&repo, &c);
    let view_before = repo.view().clone();
    let sel = selection::select(&parts.units, &[spec("a.txt", &["1.1"])]).unwrap();
    let r = repo.squash_into(c, None, Some((&parts, &sel))).unwrap();
    assert!(!r.emptied);
    let src = r.source.unwrap();
    assert_eq!(repo.snapshot(&src).unwrap().parents, vec![r.destination]);
    assert_eq!(tree_of(&repo, &src), t, "the source keeps its whole tree");
    assert_eq!(repo.description(&repo.snapshot(&r.destination).unwrap()), "base", "a partial squash keeps both descriptions");
    assert_eq!(read_at(&repo, &r.destination, "a.txt"), OLD.replacen("2\n", "TWO\n", 1).as_bytes());
    assert_eq!(repo.snapshot(&r.destination).unwrap().change_id, repo.snapshot(&base).unwrap().change_id);
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view_before);

    // Everything, chosen hunk by hunk: the source is emptied and abandoned,
    // its description joined, exactly like a whole squash.
    let c = wc(&repo);
    repo.describe(c, "work").unwrap();
    let c = wc(&repo);
    let parts = parts_of(&repo, &c);
    let all = selection::select(&parts.units, &[spec("a.txt", &["1", "2"]), spec("b.txt", &[]), spec("c.txt", &[])]).unwrap();
    let r = repo.squash_into(c, None, Some((&parts, &all))).unwrap();
    assert!(r.emptied && r.source.is_none());
    assert_eq!(tree_of(&repo, &r.destination), t);
    assert_eq!(repo.description(&repo.snapshot(&r.destination).unwrap()), "base\n\nwork");
}

/// `--into` an ancestor, a descendant and an unrelated change.
#[test]
fn squash_into_other_changes() {
    // root ← base ← mid ← c ← @
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", OLD), ("b.txt", "b\n")], "base");
    let mid = commit_files(&mut repo, &*fs, &[("m.txt", "m\n")], "mid");
    let c = commit_files(&mut repo, &*fs, &[("a.txt", NEW), ("b.txt", "B\n"), ("c.txt", "c\n")], "c");
    let parts = parts_of(&repo, &c);
    let sel = selection::select(&parts.units, &[spec("b.txt", &[]), spec("a.txt", &["2"])]).unwrap();
    let view_before = repo.view().clone();

    // Into the ancestor `base`, two generations up.
    let r = repo.squash_into(c, Some(base), Some((&parts, &sel))).unwrap();
    assert_eq!(read_at(&repo, &r.destination, "b.txt"), b"B\n");
    assert_eq!(read_at(&repo, &r.destination, "a.txt"), format!("{OLD}extra\n").as_bytes());
    let src = r.source.unwrap();
    let mid2 = repo.snapshot(&src).unwrap().parents[0];
    assert_eq!(repo.snapshot(&mid2).unwrap().parents, vec![r.destination], "mid was rebased onto the new base");
    assert_eq!(read_at(&repo, &mid2, "m.txt"), b"m\n");
    assert_eq!(read_at(&repo, &mid2, "b.txt"), b"B\n");
    assert_eq!(read_at(&repo, &src, "b.txt"), b"B\n");
    assert_eq!(read_at(&repo, &src, "a.txt"), NEW.as_bytes());
    assert_eq!(repo.description(&repo.snapshot(&src).unwrap()), "c");
    let at = repo.snapshot(&wc(&repo)).unwrap();
    assert_eq!(at.parents, vec![src], "the working copy followed");
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view_before);

    // From `mid` into its descendant `c`: mid is emptied (it only added
    // m.txt), c keeps its tree.
    let parts_mid = repo.change_parts(&mid, true).unwrap();
    let sel_mid = selection::select(&parts_mid.units, &[spec("m.txt", &[])]).unwrap();
    let c_tree = tree_of(&repo, &c);
    let r = repo.squash_into(mid, Some(c), Some((&parts_mid, &sel_mid))).unwrap();
    assert!(r.emptied && r.source.is_none());
    assert_eq!(tree_of(&repo, &r.destination), c_tree, "the destination keeps its tree");
    let d = repo.snapshot(&r.destination).unwrap();
    assert_eq!(d.parents, vec![base]);
    assert_eq!(repo.description(&d), "c\n\nmid", "emptied: descriptions joined");
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view_before);

    // From `c` into its ancestor... no: from `mid`, partially, into `c`.
    let (mut repo2, fs2, _) = new_repo("alice");
    let base2 = commit_files(&mut repo2, &*fs2, &[("a.txt", OLD)], "base");
    let mid2 = commit_files(&mut repo2, &*fs2, &[("a.txt", NEW)], "mid");
    let top = commit_files(&mut repo2, &*fs2, &[("z.txt", "z\n")], "top");
    let pm = repo2.change_parts(&mid2, true).unwrap();
    let sel = selection::select(&pm.units, &[spec("a.txt", &["1.1"])]).unwrap();
    let top_tree = tree_of(&repo2, &top);
    let r = repo2.squash_into(mid2, Some(top), Some((&pm, &sel))).unwrap();
    let src = r.source.unwrap();
    assert_eq!(read_at(&repo2, &src, "a.txt"), format!("1\n2\n3\n4\n5\nSIX\n{}extra\n", &OLD[12..]).as_bytes());
    assert_eq!(tree_of(&repo2, &r.destination), top_tree);
    assert_eq!(repo2.snapshot(&r.destination).unwrap().parents, vec![src]);
    let _ = base2;

    // Into an unrelated change: a sibling of mid on base.
    let side = repo.new_change(WS, vec![base], "side").unwrap();
    let view_before = repo.view().clone();
    let parts = repo.change_parts(&c, true).unwrap();
    let sel = selection::select(&parts.units, &[spec("c.txt", &[])]).unwrap();
    let r = repo.squash_into(c, Some(side), Some((&parts, &sel))).unwrap();
    assert_eq!(read_at(&repo, &r.destination, "c.txt"), b"c\n");
    let src = r.source.unwrap();
    assert!(file_entry(&repo, &src, "c.txt").is_none(), "the source no longer adds c.txt");
    assert_eq!(read_at(&repo, &src, "b.txt"), b"B\n");
    repo.undo().unwrap();
    assert_eq!(repo.view(), &view_before);
}

/// On a cloaked line, edits of a public file are sealed for the scope with
/// the last public version as fallback: so is every half.
#[test]
fn cloaked_hunks_stay_sealed_with_the_public_fallback() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", OLD)], "base");
    repo.create_workspace("t", vec![base], Some("team".into())).unwrap();
    let o = repo.workspace_overlay("t").unwrap();
    o.write(&p("a.txt"), NEW.as_bytes()).unwrap();
    let c = repo.snapshot_workspace("t", &o).unwrap().snapshot;
    let new_e = file_entry(&repo, &c, "a.txt").unwrap();
    let old_e = file_entry(&repo, &base, "a.txt").unwrap();
    assert_eq!(new_e.visibility, team());
    assert_eq!(new_e.fallback, Some(old_e.id));
    let parts = repo.change_parts(&c, true).unwrap();
    assert!(matches!(parts.units[0].content, Content::Text(_)), "public → sealed for the line: hunks can be chosen");
    let sel = selection::select(&parts.units, &[spec("a.txt", &["1.1"])]).unwrap();
    let r = repo.split(&parts, &sel, Some("part")).unwrap();
    let mid = file_entry(&repo, &r.first, "a.txt").unwrap();
    assert_eq!(mid.visibility, team(), "lines of a sealed version stay sealed for its scope");
    assert_eq!(mid.fallback, Some(old_e.id), "readers without the key still see the last public version");
    let (vis, data) = versions(&repo, &mid).remove(0);
    assert_eq!(vis, team(), "the object itself is sealed");
    assert_eq!(data.unwrap(), OLD.replacen("2\n", "TWO\n", 1).as_bytes());
    assert!(backend_contains(repo.backend().as_ref(), b"TWO").is_empty(), "no plaintext of the edit anywhere");
    assert_eq!(repo.snapshot(&r.first).unwrap().cloak.as_deref(), Some("team"), "the first part is on the same cloaked line");
    assert!(matches!(repo.snapshot(&r.first).unwrap().description, veil_core::object::Text::Sealed(_)), "and its description is sealed");
}

/// A change that moves a file to another audience offers it whole only:
/// the lines of the sealed version never land in a public file.
#[test]
fn exposures_and_rekeys_move_whole() {
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[(".veilpolicy", "s/ cloak team\n"), ("s/a.txt", OLD)], "base");
    assert_eq!(file_entry(&repo, &wc(&repo), "s/a.txt").unwrap().visibility, team());
    fs.write(&p(".veilpolicy"), b"").unwrap();
    fs.write(&p("s/a.txt"), NEW.as_bytes()).unwrap();
    snap(&mut repo, &*fs);
    let c = wc(&repo);
    assert!(file_entry(&repo, &c, "s/a.txt").unwrap().visibility.is_public(), "exposed by the policy edit");
    let parts = repo.change_parts(&c, true).unwrap();
    let u = parts.units.iter().find(|u| u.path == p("s/a.txt")).unwrap();
    assert!(matches!(u.content, Content::Whole(Whole::Audience)), "{:?}", u.content);
    let pol = parts.units.iter().find(|u| u.path == p(".veilpolicy")).unwrap();
    assert!(matches!(pol.content, Content::Whole(Whole::Policy)));
    let e = selection::select(&parts.units, &[spec("s/a.txt", &["1"])]).unwrap_err().to_string();
    assert!(e.contains("cannot be split by hunk"), "{e}");
    // Whole, it moves as recorded.
    let sel = selection::select(&parts.units, &[spec("s/a.txt", &[])]).unwrap();
    let r = repo.split(&parts, &sel, None).unwrap();
    assert!(file_entry(&repo, &r.first, "s/a.txt").unwrap().same_content(&file_entry(&repo, &c, "s/a.txt").unwrap()));
}

/// A reader outside a scope sees a file sealed for it as one opaque unit:
/// it can move it whole (as recorded, never read), not choose its hunks.
#[test]
fn unreadable_files_move_whole() {
    let (alice, _afs, _) = new_repo("alice");
    let sealed_old = alice.store().store_file(OLD.as_bytes(), &team()).unwrap();
    let sealed_new = alice.store().store_file(NEW.as_bytes(), &team()).unwrap();
    let (mut bob, _bfs, _) = new_repo("bob");
    for id in [sealed_old, sealed_new] {
        plant_raw_object(bob.backend().as_ref(), &id, &alice.store().get_raw(&id).unwrap());
    }
    let sealed = |id: ObjectId| TreeEntry { visibility: team(), ..file("s.txt", id) };
    let pub_old = blob(&bob, b"x\n");
    let pub_new = blob(&bob, b"y\n");
    let t0 = raw_tree(&bob, vec![sealed(sealed_old), file("x.txt", pub_old)]);
    let t1 = raw_tree(&bob, vec![sealed(sealed_new), file("x.txt", pub_new)]);
    let root = bob.root_id();
    let s0 = raw_snapshot(&bob, vec![root], t0, "base");
    let s1 = raw_snapshot(&bob, vec![s0], t1, "change");
    bob.edit(WS, s1).unwrap();
    let parts = bob.change_parts(&s1, true).unwrap();
    let u = parts.units.iter().find(|u| u.path == p("s.txt")).unwrap();
    assert_eq!(u.text().map(|_| ()), None);
    assert!(matches!(&u.content, Content::Whole(Whole::Unreadable(s)) if s == "team"), "{:?}", u.content);
    assert!(selection::select(&parts.units, &[spec("s.txt", &["1"])]).is_err());
    let sel = selection::select(&parts.units, &[spec("s.txt", &[])]).unwrap();
    let r = bob.split(&parts, &sel, None).unwrap();
    let e = file_entry(&bob, &r.first, "s.txt").unwrap();
    assert_eq!((e.id, e.visibility.clone()), (sealed_new, team()), "moved exactly as recorded");
    assert_eq!(file_entry(&bob, &r.first, "x.txt").unwrap().id, pub_old);
}

/// A conflicted file moves whole, keeping its conflict; it cannot be split
/// by hunk.
#[test]
fn conflicts_move_whole() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f.txt", "a\nb\nc\n"), ("g.txt", OLD)], "base");
    let ours = commit_files(&mut repo, &*fs, &[("f.txt", "a\nOURS\nc\n")], "ours");
    repo.new_change(WS, vec![base], "").unwrap();
    let o = repo.workspace_overlay(WS).unwrap();
    o.write(&p("f.txt"), b"a\nTHEIRS\nc\n").unwrap();
    o.write(&p("g.txt"), NEW.as_bytes()).unwrap();
    let x = repo.snapshot_workspace(WS, &o).unwrap().snapshot;
    let x = repo.rebase(x, vec![ours]).unwrap();
    assert_eq!(file_entry(&repo, &x, "f.txt").unwrap().kind, EntryKind::Conflict);
    let parts = repo.change_parts(&x, true).unwrap();
    let f = parts.units.iter().find(|u| u.path == p("f.txt")).unwrap();
    assert!(matches!(f.content, Content::Whole(Whole::Conflict)));
    assert!(selection::select(&parts.units, &[spec("f.txt", &["1"])]).unwrap_err().to_string().contains("conflict"));
    let sel = selection::select(&parts.units, &[spec("f.txt", &[]), spec("g.txt", &["1"])]).unwrap();
    let r = repo.split(&parts, &sel, None).unwrap();
    let first = repo.snapshot(&r.first).unwrap();
    assert_eq!(file_entry(&repo, &r.first, "f.txt").unwrap().kind, EntryKind::Conflict);
    assert_eq!(first.conflicts, vec!["f.txt".to_string()], "the conflict moved with the file");
    assert_eq!(tree_of(&repo, &r.second), tree_of(&repo, &x));
}

// ---- the property test ------------------------------------------------------------

/// What one file is in a version.
#[derive(Clone, Debug)]
enum Body {
    Text(Vec<u8>),
    Binary(Vec<u8>),
}

impl Body {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Body::Text(lines) => {
                let mut s = String::new();
                for l in lines {
                    s.push((b'a' + l % 6) as char);
                    s.push('\n');
                }
                // A last line without a line break, sometimes.
                if lines.len() % 5 == 3 {
                    s.pop();
                }
                s.into_bytes()
            }
            Body::Binary(b) => {
                let mut v = vec![0u8];
                v.extend(b);
                v
            }
        }
    }
}

fn body() -> impl Strategy<Value = Body> {
    prop_oneof![
        4 => prop::collection::vec(0u8..6, 0..24).prop_map(Body::Text),
        1 => prop::collection::vec(any::<u8>(), 0..8).prop_map(Body::Binary),
    ]
}

/// A random edit of `b`: lines kept, removed, replaced or inserted.
fn edited(b: &Body, ops: &[u8]) -> Body {
    match b {
        Body::Text(lines) => {
            let mut out = Vec::new();
            for (i, l) in lines.iter().enumerate() {
                match ops.get(i).copied().unwrap_or(0) % 12 {
                    9 => {}
                    10 => out.push((l + 1) % 6),
                    11 => {
                        out.push(*l);
                        out.push((l + 3) % 6);
                    }
                    _ => out.push(*l),
                }
            }
            if ops.first().is_some_and(|o| o % 7 == 6) {
                out.push(5);
            }
            Body::Text(out)
        }
        Body::Binary(v) => {
            let mut v = v.clone();
            v.push(ops.first().copied().unwrap_or(1));
            Body::Binary(v)
        }
    }
}

/// One file of the property test, before and after the change.
#[derive(Clone, Debug)]
struct FileCase {
    old: Option<(Body, bool)>,
    new: Option<(Body, bool)>,
}

fn file_case() -> impl Strategy<Value = FileCase> {
    (body(), any::<bool>(), prop::collection::vec(any::<u8>(), 0..24), 0u8..10, any::<bool>(), body()).prop_map(
        |(b, x, ops, kind, x2, other)| match kind {
            // added
            0 => FileCase { old: None, new: Some((b, x)) },
            // deleted
            1 => FileCase { old: Some((b, x)), new: None },
            // replaced by unrelated content (text ↔ binary too)
            2 => FileCase { old: Some((b, x)), new: Some((other, x2)) },
            // unchanged
            3 => FileCase { old: Some((b.clone(), x)), new: Some((b, x)) },
            // edited, maybe with the executable bit flipped
            _ => {
                let n = edited(&b, &ops);
                FileCase { old: Some((b, x)), new: Some((n, if kind == 4 { !x } else { x })) }
            }
        },
    )
}

const PATHS: [&str; 6] = ["a.txt", "d/b.txt", "d/e/c.txt", "secret/s.txt", "secret/t.bin", "z.txt"];

fn write_version(fs: &dyn StorageBackend, files: &[FileCase], new: bool) {
    for (path, f) in PATHS.iter().zip(files) {
        let v = if new { &f.new } else { &f.old };
        match v {
            Some((b, x)) => {
                fs.write(&p(path), &b.bytes()).unwrap();
                fs.set_executable(&p(path), *x).unwrap();
            }
            None => {
                if fs.exists(&p(path)).unwrap() {
                    fs.remove_file(&p(path)).unwrap();
                }
            }
        }
    }
}

/// A random choice for each unit: nothing, everything, or random blocks
/// (and maybe the executable bit).
fn choose(units: &[selection::Unit], seed: &[u64]) -> Selection {
    let mut sel = Selection::new();
    for (i, u) in units.iter().enumerate() {
        let r = seed.get(i).copied().unwrap_or(0);
        let pick = match r % 3 {
            0 => continue,
            1 => Pick { whole: true, ..Pick::default() },
            _ => match u.text() {
                None => Pick { whole: true, ..Pick::default() },
                Some(t) => {
                    let blocks: BTreeSet<_> = t.diff.all_blocks().into_iter().enumerate().filter(|(k, _)| (r >> (k % 60 + 2)) & 1 == 1).map(|(_, b)| b).collect();
                    Pick { whole: false, mode: t.mode.is_some() && (r >> 62) & 1 == 1, blocks }
                }
            },
        };
        sel.insert(u.path.clone(), pick);
    }
    sel
}

/// The entry the first half must hold at `path` for unit `u` and `pick`.
fn expected(repo: &Repo, u: &selection::Unit, pick: Option<&Pick>, path: &VPath) -> Option<(Vec<u8>, bool, Visibility)> {
    let c = u.changes.iter().find(|c| &c.path == path).unwrap();
    let pick = pick.cloned().unwrap_or_default();
    let read = |e: &TreeEntry| (repo.store().read_blob(&e.id).unwrap(), e.executable, e.visibility.clone());
    if u.is_none(&pick) {
        return c.old.as_ref().map(read);
    }
    if u.is_all(&pick) {
        return c.new.as_ref().map(read);
    }
    let t = u.text().unwrap();
    let data = apply(&t.old, &diff_text(&t.old, &t.new), |id| pick.blocks.contains(&id));
    match (&c.old, &c.new) {
        (None, Some(_)) if pick.blocks.is_empty() => None,
        (Some(_), None) if pick.blocks.len() == t.diff.all_blocks().len() => None,
        (None, Some(n)) => Some((data.into_bytes(), n.executable, n.visibility.clone())),
        (Some(o), None) => Some((data.into_bytes(), o.executable, o.visibility.clone())),
        (Some(o), Some(n)) => Some((data.into_bytes(), if pick.mode { n.executable } else { o.executable }, n.visibility.clone())),
        (None, None) => unreachable!(),
    }
}

fn check(files: Vec<FileCase>, seed: Vec<u64>) -> Result<(), TestCaseError> {
    let (mut repo, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secret/ cloak team\n").unwrap();
    write_version(&*fs, &files, false);
    let base = commit_files(&mut repo, &*fs, &[], "base");
    write_version(&*fs, &files, true);
    snap(&mut repo, &*fs);
    let c = wc(&repo);
    let t = tree_of(&repo, &c);
    let parts = repo.change_parts(&c, true).unwrap();
    let sel = choose(&parts.units, &seed);
    let h = selection::halves(repo.store(), &parts.base, &parts.tree, &parts.units, &sel).unwrap();
    let view0 = repo.view().clone();

    // The chosen half, file by file.
    for u in &parts.units {
        for ch in &u.changes {
            let got = file_entry_in(&repo, &h.chosen, &ch.path);
            let want = expected(&repo, u, sel.get(&u.path), &ch.path);
            let got_v = got.as_ref().map(|e| (repo.store().read_blob(&e.id).unwrap(), e.executable, e.visibility.clone()));
            prop_assert_eq!(&got_v, &want, "{}", ch.path);
            // Nothing changes audience: each entry is sealed as one of
            // its versions, and as the new one when it holds new lines.
            if let Some(e) = &got {
                let real = versions(&repo, e).remove(0).0;
                prop_assert_eq!(&real, &e.visibility);
                let sides: Vec<&Visibility> = [&ch.old, &ch.new].into_iter().flatten().map(|x| &x.visibility).collect();
                prop_assert!(sides.contains(&&e.visibility));
                if ch.path.as_str().starts_with("secret/") {
                    prop_assert_eq!(&e.visibility, &team());
                }
            }
        }
    }
    // The rest is the complement: chosen + rest, from the base, is the
    // change (each file of `rest` is the base with the other blocks).
    let complement: Selection = parts
        .units
        .iter()
        .filter_map(|u| {
            let pick = sel.get(&u.path).cloned().unwrap_or_default();
            if u.is_all(&pick) {
                return None;
            }
            if u.is_none(&pick) {
                return Some((u.path.clone(), Pick { whole: true, ..Pick::default() }));
            }
            let t = u.text().unwrap();
            Some((
                u.path.clone(),
                Pick { whole: false, mode: t.mode.is_some() && !pick.mode, blocks: t.diff.all_blocks().difference(&pick.blocks).copied().collect() },
            ))
        })
        .collect();
    let h2 = selection::halves(repo.store(), &parts.base, &parts.tree, &parts.units, &complement).unwrap();
    prop_assert_eq!(h2.chosen, h.rest, "the rest is exactly the complement");

    if !h.any || h.all {
        prop_assert!(repo.split(&parts, &sel, None).is_err());
        return Ok(());
    }
    // Split, then squash the halves back together: the original tree.
    let r = repo.split(&parts, &sel, Some("first")).unwrap();
    prop_assert_eq!(tree_of(&repo, &r.first), h.chosen);
    prop_assert_eq!(tree_of(&repo, &r.second), t);
    repo.undo().unwrap();
    prop_assert_eq!(repo.view(), &view0, "one undo restores the original exactly");
    let op0 = repo.op_id();
    let r = repo.split(&parts, &sel, None).unwrap();
    let back = repo.squash(r.second).unwrap();
    prop_assert_eq!(tree_of(&repo, &back), t, "the halves squashed together are the original");
    prop_assert_eq!(repo.snapshot(&back).unwrap().parents.clone(), vec![base]);
    repo.restore_operation(op0).unwrap();
    prop_assert_eq!(repo.view(), &view0);

    // The same choice squashed into the parent: the parent gets the
    // chosen half, the change keeps its tree.
    let r = repo.squash_into(c, None, Some((&parts, &sel))).unwrap();
    prop_assert_eq!(tree_of(&repo, &r.destination), h.chosen);
    prop_assert_eq!(tree_of(&repo, &r.source.unwrap()), t);
    repo.undo().unwrap();
    prop_assert_eq!(repo.view(), &view0);
    Ok(())
}

fn file_entry_in(repo: &Repo, tree: &ObjectId, path: &VPath) -> Option<TreeEntry> {
    walk_files(repo.store(), tree).unwrap().into_iter().find(|(q, _)| q == path).map(|(_, e)| e)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn halves_are_the_choice_and_the_rest(files in prop::collection::vec(file_case(), 6), seed in prop::collection::vec(any::<u64>(), 8)) {
        check(files, seed)?;
    }
}

/// Pure: applying a random set of blocks, then the complement on top of
/// that, is the new text; all and none are the two versions.
#[test]
fn applying_blocks_is_exact() {
    proptest!(ProptestConfig::with_cases(256), |(a in body(), ops in prop::collection::vec(any::<u8>(), 0..24), mask in any::<u64>())| {
        let Body::Text(_) = &a else { return Ok(()) };
        let b = edited(&a, &ops);
        let (old, new) = (String::from_utf8(a.bytes()).unwrap(), String::from_utf8(b.bytes()).unwrap());
        let d = diff_text(&old, &new);
        let all = d.all_blocks();
        prop_assert_eq!(apply(&old, &d, |id| all.contains(&id)), new.clone());
        prop_assert_eq!(apply(&old, &d, |_| false), old.clone());
        let chosen: BTreeSet<_> = all.iter().enumerate().filter(|(k, _)| (mask >> (k % 64)) & 1 == 1).map(|(_, b)| *b).collect();
        let mid = apply(&old, &d, |id| chosen.contains(&id));
        // From the half way point, the remaining blocks give the new text.
        let d2 = diff_text(&mid, &new);
        let all2 = d2.all_blocks();
        prop_assert_eq!(apply(&mid, &d2, |id| all2.contains(&id)), new);
    });
}

/// A file replaced by a directory of the same name is one unit: naming a
/// file inside it is refused, naming the swap moves both halves.
#[test]
fn file_directory_swaps_move_as_one() {
    let (mut repo, fs, _) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("x", "file\n"), ("keep.txt", "k\n"), ("bin", "\0a")], "base");
    fs.remove_file(&p("x")).unwrap();
    fs.write(&p("x/inner.txt"), b"inner\n").unwrap();
    fs.write(&p("bin"), b"\0b").unwrap();
    fs.write(&p("keep.txt"), b"K\n").unwrap();
    snap(&mut repo, &*fs);
    let c = wc(&repo);
    let parts = repo.change_parts(&c, true).unwrap();
    let x = parts.units.iter().find(|u| u.path == p("x")).unwrap();
    assert_eq!(x.changes.len(), 2);
    assert!(matches!(x.content, Content::Whole(Whole::TypeChange)));
    let bin = parts.units.iter().find(|u| u.path == p("bin")).unwrap();
    assert!(matches!(bin.content, Content::Whole(Whole::Binary)));
    let e = selection::select(&parts.units, &[spec("x/inner.txt", &[])]).unwrap_err().to_string();
    assert!(e.contains("file/directory swap at x"), "{e}");
    let sel = selection::select(&parts.units, &[spec("x", &[]), spec("bin", &[])]).unwrap();
    let r = repo.split(&parts, &sel, None).unwrap();
    assert_eq!(read_at(&repo, &r.first, "x/inner.txt"), b"inner\n");
    assert_eq!(read_at(&repo, &r.first, "bin"), b"\0b");
    assert_eq!(read_at(&repo, &r.first, "keep.txt"), b"k\n");
    assert_eq!(tree_of(&repo, &r.second), tree_of(&repo, &c));
    // The reverse: the directory comes back as a file, left in the rest.
    let parts = repo.change_parts(&r.second, true).unwrap();
    assert_eq!(parts.units.iter().map(|u| u.path.as_str()).collect::<Vec<_>>(), ["keep.txt"]);
}
