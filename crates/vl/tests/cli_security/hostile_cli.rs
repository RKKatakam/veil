//! CLI checks for hostile objects and metadata (complements
//! `adversarial_cli_remote.rs`; see BUG-030, BUG-036 in `docs/BUGS.md`).

use crate::adversarial_support;

use adversarial_support::*;
use veil_core::object::Object;

#[test]
fn tag_set_refuses_a_blob_id() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let blob = Object::blob_id(b"a\n").hex();
    let out = env.vl("alice", &proj, &["tag", "set", "bad", "-r", &blob]);
    assert!(exited_cleanly(&out) && !out.status.success(), "{}", text(&out));
    env.ok("alice", &proj, &["log"]);
}

#[test]
fn hostile_file_names_and_authors_are_escaped() {
    let env = Env::new();
    let remote = env.dir("remote");
    evil_remote_on_disk(&remote, "line one\n\x1b[31mred", &["main"], |r| {
        raw_tree(r, vec![file("evil\x1b]0;title\x07.txt", blob(r, b"hi\n"))])
    });
    let work = env.dir("work");
    let clone = env.vl("victim", &work, &["clone", remote.to_str().unwrap(), "dest"]);
    assert!(clone.status.success(), "{}", text(&clone));
    let dest = work.join("dest");
    for args in [&["files", "-r", "main"][..], &["show", "main"], &["status"], &["log"]] {
        let out = env.vl("victim", &dest, args);
        assert!(!text(&out).contains('\x1b'), "{args:?}: {:?}", text(&out));
        assert!(!text(&out).contains('\x07'), "{args:?}: {:?}", text(&out));
        if args[0] == "files" {
            assert!(text(&out).contains("evil\\x1b]0;title\\x07.txt"), "{:?}", text(&out));
        }
    }
}
