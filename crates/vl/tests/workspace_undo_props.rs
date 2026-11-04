//! Property test (BUG-100): random sequences of `vl ws switch`, edits,
//! `vl commit`, `vl undo` and `vl redo` through the real binary never lose
//! an edit the user had not recorded yet. The guide: undo and `op restore`
//! "keep the files on disk that you had not recorded yet".
//!
//! Every edit is a new file with unique content, written into the project
//! directory while it is attached to some workspace. Whatever `vl undo`
//! undoes (a commit, a switch, going further back past earlier undos) or
//! `vl redo` re-applies, or either refuses, at the end each
//! edit must still be in the working copy of the workspace it was made in.

mod adversarial_support;

use adversarial_support::{text, write, Env};
use proptest::prelude::*;

const U: &str = "alice";
const WORKSPACES: [&str; 3] = ["default", "a", "b"];

#[derive(Clone, Debug)]
enum Step {
    Edit,
    Switch(usize),
    Commit,
    Undo,
    Redo,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        3 => Just(Step::Edit),
        3 => (0..WORKSPACES.len()).prop_map(Step::Switch),
        1 => Just(Step::Commit),
        3 => Just(Step::Undo),
        2 => Just(Step::Redo),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn undo_and_switch_never_lose_an_unrecorded_edit(steps in prop::collection::vec(step(), 1..9)) {
        let env = Env::new();
        let proj = env.project(U, "proj", &[("a.txt", "a\n")]);
        for ws in &WORKSPACES[1..] {
            env.ok(U, &proj, &["ws", "new", ws]);
        }
        let mut attached = "default".to_string();
        // (path, content, workspace it was made in)
        let mut edits: Vec<(String, String, String)> = Vec::new();
        let mut log = Vec::new();
        for (i, s) in steps.iter().enumerate() {
            match s {
                Step::Edit => {
                    let (path, content) = (format!("e{i}.txt"), format!("edit {i} in {attached}\n"));
                    write(&proj, &path, &content);
                    edits.push((path, content, attached.clone()));
                    log.push(format!("edit e{i}.txt in {attached}"));
                }
                Step::Switch(w) => {
                    let out = env.vl(U, &proj, &["ws", "switch", WORKSPACES[*w]]);
                    // An undo may have undone the creation of the workspace.
                    prop_assert!(out.status.success() || text(&out).contains("no workspace named"), "{}", text(&out));
                    log.push(format!("switch {} → {}", WORKSPACES[*w], text(&out).trim().replace('\n', " | ")));
                }
                Step::Commit => {
                    let out = env.vl(U, &proj, &["commit", "-m", &format!("commit {i}")]);
                    prop_assert!(out.status.success(), "{}", text(&out));
                    log.push("commit".into());
                }
                Step::Undo => {
                    let out = env.vl(U, &proj, &["undo"]);
                    // Refusing is allowed (nothing to undo, a grant…); a
                    // crash or lost work is not.
                    log.push(format!("undo → {}", text(&out).trim().replace('\n', " | ")));
                }
                Step::Redo => {
                    let out = env.vl(U, &proj, &["redo"]);
                    log.push(format!("redo → {}", text(&out).trim().replace('\n', " | ")));
                }
            }
            // Where the directory is attached now (an undone switch moves it).
            let list = env.stdout(U, &proj, &["ws", "list"]);
            attached = list
                .lines()
                .find_map(|l| l.strip_prefix("* "))
                .and_then(|l| l.split(':').next())
                .unwrap_or_else(|| panic!("no attached workspace in:\n{list}"))
                .trim()
                .to_string();
        }
        for (path, content, ws) in &edits {
            let out = env.vl(U, &proj, &["ws", "cat", ws, path]);
            prop_assert!(
                out.status.success() && String::from_utf8_lossy(&out.stdout) == *content,
                "{path} (made in '{ws}') is gone from that workspace after:\n  {}\n{}",
                log.join("\n  "),
                text(&out)
            );
            if *ws == attached {
                let on_disk = std::fs::read_to_string(proj.join(path)).ok();
                prop_assert_eq!(on_disk.as_deref(), Some(content.as_str()), "{} is gone from the directory", path);
            }
        }
    }
}
