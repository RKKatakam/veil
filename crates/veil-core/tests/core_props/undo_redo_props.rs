//! Property tests for `vl undo` / `vl redo` (BUG-247, BUG-206): random
//! sequences of commands, undos and redos land on the view a simple model
//! predicts. The model is jj's: commands push onto a history, undo moves the
//! newest state onto a redo stack (repeated undos go further back), redo
//! moves it back, and any new command clears the redo stack.

use std::sync::Arc;

use proptest::prelude::*;
use veil_core::{oplog::View, tree::lookup, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath};

const WS: &str = "default";

#[derive(Clone, Debug)]
enum Step {
    Describe(u8),
    Commit(u8),
    NewChange,
    SetTag(u8),
    Undo,
    Redo,
    /// An unrecorded edit, picked up by an automatic snapshot (not a
    /// command: undo skips it and keeps it).
    Edit,
}

fn step(edits: bool) -> impl Strategy<Value = Step> {
    prop_oneof![
        2 => (0..4u8).prop_map(Step::Describe),
        2 => (0..4u8).prop_map(Step::Commit),
        1 => Just(Step::NewChange),
        2 => (0..3u8).prop_map(Step::SetTag),
        4 => Just(Step::Undo),
        3 => Just(Step::Redo),
        (if edits { 3 } else { 0 }) => Just(Step::Edit),
    ]
}

fn wc(repo: &Repo) -> ObjectId {
    repo.workspace_wc(WS).unwrap()
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&wc(repo)).unwrap().tree
}

/// Run one command; `true` if it recorded an operation.
fn command(repo: &mut Repo, s: &Step, i: usize) -> bool {
    let before = repo.op_id();
    match s {
        Step::Describe(m) => {
            repo.describe(wc(repo), &format!("message {m}")).unwrap();
        }
        Step::Commit(m) => {
            repo.commit_working_copy(WS, &format!("commit {m} at {i}")).unwrap();
        }
        Step::NewChange => {
            repo.new_change(WS, vec![wc(repo)], "").unwrap();
        }
        Step::SetTag(t) => {
            let target = repo.snapshot(&wc(repo)).unwrap().parents[0];
            repo.set_tag(&format!("t{t}"), target, None, true).unwrap();
        }
        _ => unreachable!(),
    }
    repo.op_id() != before
}

/// Bring `fs` (the "disk") to the working copy after an undo or redo, as
/// the CLI does.
fn materialise(repo: &Repo, fs: &MemoryBackend, from: &ObjectId) {
    repo.checkout_tree(fs, Some(from), &wc_tree(repo)).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, failure_persistence: None, ..ProptestConfig::default() })]

    /// Without unrecorded edits, every undo and redo restores exactly the
    /// view the model predicts, and refuses exactly when it has nothing to
    /// undo or redo.
    #[test]
    fn undo_and_redo_follow_the_jj_model(steps in prop::collection::vec(step(false), 1..24)) {
        let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap();
        let mut history: Vec<View> = vec![repo.view().clone()];
        let mut redo: Vec<View> = Vec::new();
        for (i, s) in steps.iter().enumerate() {
            match s {
                Step::Undo => {
                    let r = repo.undo_keeping_edits(WS);
                    if history.len() > 1 {
                        prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                        redo.push(history.pop().unwrap());
                    } else {
                        prop_assert!(r.is_err(), "step {i}: undid past the start");
                    }
                }
                Step::Redo => {
                    let r = repo.redo_keeping_edits(WS);
                    match redo.pop() {
                        Some(v) => {
                            prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                            history.push(v);
                        }
                        None => prop_assert!(r.is_err(), "step {i}: redid with nothing to redo"),
                    }
                }
                _ => {
                    if command(&mut repo, s, i) {
                        history.push(repo.view().clone());
                        redo.clear();
                    }
                }
            }
            prop_assert_eq!(repo.view(), history.last().unwrap(), "after step {} ({:?}) of {:?}", i, s, steps);
        }
    }

    /// With unrecorded edits in between, undo and redo still succeed and
    /// refuse as the model says, tags follow it, and no edit is lost.
    #[test]
    fn undo_and_redo_keep_every_unrecorded_edit(steps in prop::collection::vec(step(true), 1..24)) {
        let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap();
        let fs = MemoryBackend::new();
        let mut history = vec![repo.view().tags.clone()];
        let mut redo = Vec::new();
        let mut edits = Vec::new();
        for (i, s) in steps.iter().enumerate() {
            match s {
                Step::Edit => {
                    let (path, content) = (format!("e{i}.txt"), format!("edit {i}\n"));
                    fs.write(&VPath::new(&path).unwrap(), content.as_bytes()).unwrap();
                    repo.snapshot_workspace(WS, &fs).unwrap();
                    edits.push((path, content));
                }
                Step::Undo => {
                    let disk = wc_tree(&repo);
                    let r = repo.undo_keeping_edits(WS);
                    if history.len() > 1 {
                        prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                        redo.push(history.pop().unwrap());
                        materialise(&repo, &fs, &disk);
                    } else {
                        prop_assert!(r.is_err(), "step {i}: undid past the start");
                    }
                }
                Step::Redo => {
                    let disk = wc_tree(&repo);
                    let r = repo.redo_keeping_edits(WS);
                    match redo.pop() {
                        Some(v) => {
                            prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                            history.push(v);
                            materialise(&repo, &fs, &disk);
                        }
                        None => prop_assert!(r.is_err(), "step {i}: redid with nothing to redo"),
                    }
                }
                _ => {
                    if command(&mut repo, s, i) {
                        history.push(repo.view().tags.clone());
                        redo.clear();
                    }
                }
            }
            // Tags point at committed changes, which carrying edits never
            // rewrites: their names follow the model exactly.
            let names = |t: &std::collections::BTreeMap<String, _>| t.keys().cloned().collect::<Vec<_>>();
            prop_assert_eq!(names(&repo.view().tags), names(history.last().unwrap()), "after step {} of {:?}", i, steps);
        }
        let tree = wc_tree(&repo);
        for (path, content) in &edits {
            let e = lookup(repo.store(), &tree, &VPath::new(path).unwrap()).unwrap();
            prop_assert!(e.is_some(), "{} was lost after {:?}", path, steps);
            prop_assert_eq!(fs.read(&VPath::new(path).unwrap()).unwrap(), content.as_bytes().to_vec());
        }
    }
}

/// What actor 1 (the `default` workspace) sees: its working copy and the
/// tags (only actor 1 sets tags).
fn actor1_state(repo: &Repo) -> (ObjectId, std::collections::BTreeMap<String, ObjectId>) {
    (wc(repo), repo.view().tags.iter().map(|(n, t)| (n.clone(), t.target)).collect())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, ..ProptestConfig::default() })]

    /// The lock-free op log (format 6, threat 11): a second actor commits in
    /// its own workspace between actor 1's commands. Undo and redo in
    /// `default` follow the jj model for actor 1 (its working copy and the
    /// tags), and never take back one of actor 2's commits.
    #[test]
    fn two_actor_undo_keeps_other_work(steps in prop::collection::vec((step(false), any::<bool>()), 1..20)) {
        let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("alice")), "alice").unwrap();
        let root = repo.root_id();
        // Actor 2's workspace is its own (`vl ws new agent`, run there).
        repo.set_command_workspace(Some("agent".into()));
        repo.create_workspace("agent", vec![root], None).unwrap();
        repo.set_command_workspace(Some(WS.into()));
        let mut history = vec![actor1_state(&repo)];
        let mut redo = Vec::new();
        let mut agent_files: Vec<String> = Vec::new();
        for (i, (s, agent_works)) in steps.iter().enumerate() {
            if *agent_works {
                // Actor 2, in its own workspace (its own `vl ws exec`).
                repo.set_command_workspace(Some("agent".into()));
                let ov = repo.workspace_overlay("agent").unwrap();
                let name = format!("agent-{i}.txt");
                ov.write(&VPath::new(&name).unwrap(), b"agent\n").unwrap();
                // Recorded, not committed: a commit would advance a tag of
                // actor 1's on the same parent, which is not this property.
                repo.snapshot_workspace("agent", &ov).unwrap();
                agent_files.push(name);
                repo.set_command_workspace(Some(WS.into()));
            }
            match s {
                Step::Undo => {
                    let r = repo.undo_keeping_edits(WS);
                    if history.len() > 1 {
                        prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                        redo.push(history.pop().unwrap());
                    } else {
                        prop_assert!(r.is_err(), "step {i}: undid past the start ({:?})", r.ok());
                    }
                }
                Step::Redo => {
                    let r = repo.redo_keeping_edits(WS);
                    match redo.pop() {
                        Some(v) => {
                            prop_assert!(r.is_ok(), "step {i} {s:?}: {:?}", r.err());
                            history.push(v);
                        }
                        None => prop_assert!(r.is_err(), "step {i}: redid with nothing to redo"),
                    }
                }
                _ => {
                    if command(&mut repo, s, i) {
                        history.push(actor1_state(&repo));
                        redo.clear();
                    }
                }
            }
            prop_assert_eq!(&actor1_state(&repo), history.last().unwrap(), "actor 1 after step {} ({:?}) of {:?}", i, s, steps);
            let agent_tree = repo.snapshot(&repo.workspace_wc("agent").unwrap()).unwrap().tree;
            for f in &agent_files {
                prop_assert!(lookup(repo.store(), &agent_tree, &VPath::new(f).unwrap()).unwrap().is_some(), "actor 2's {} was undone at step {} of {:?}", f, i, steps);
            }
        }
    }
}
