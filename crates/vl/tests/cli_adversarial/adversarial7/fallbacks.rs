//! BUG-682 / BUG-707: a sealed version's fallback (what readers without
//! the key are shown, and what a public push sends) is only ever a version
//! the line's base already shows them, never a draft no remote has seen.
//!
//! Each route that takes a public change into a cloaked line (squash,
//! rebase then squash, duplicate, cherry-pick, and a split of what the
//! cloaked change took in) gets a committed but never pushed draft that
//! edits `a.txt`, a file the cloaked change already seals an edit of (the
//! merge of the two is where the draft became the fallback), and `b.txt`.
//! Everything on the cloaked line is then pushed to a public mirror, whose
//! bytes (packed objects decoded) must hold neither draft marker.

use std::path::PathBuf;

use super::{
    adversarial_support::{write, Env},
    rewrites::mirror_contains,
    ws_write, U,
};

const DRAFTS: [&str; 2] = ["DRAFT-A-0001", "DRAFT-B-0001"];

struct World {
    env: Env,
    proj: PathBuf,
    mirror: PathBuf,
    /// The draft's change id.
    draft: String,
}

fn world() -> World {
    let env = Env::new();
    let proj = env.project(U, "proj", &[("a.txt", "1\n2\n3\n4\n5\n6\n7\n8\n9\n"), ("b.txt", "b\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    ws_write(&env, &proj, "sec", "a.txt", "1\n2\n3\n4\n5\n6\n7\n8\nSEALED-9\n");
    let mirror = env.root.join("pub");
    env.ok(U, &proj, &["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["tag", "set", "s", "-r", "sec@"]);
    env.ok(U, &proj, &["push", "pub"]);
    // A public draft on `main`, committed but never pushed.
    write(&proj, "a.txt", &format!("{}\n2\n3\n4\n5\n6\n7\n8\n9\n", DRAFTS[0]));
    write(&proj, "b.txt", &format!("{}\n", DRAFTS[1]));
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "draft"]);
    let log: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["log", "--json", "-r", "@-"])).unwrap();
    let draft = log["entries"][0]["change_id"].as_str().unwrap().to_string();
    World { env, proj, mirror, draft }
}

impl World {
    /// `rev` holds `path` sealed for `team`.
    fn sealed(&self, rev: &str, path: &str) -> bool {
        let files = self.env.stdout(U, &self.proj, &["files", "-r", rev]);
        files.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with(path))
    }

    /// Tag each of `revs` and push them all; neither draft is on the
    /// mirror.
    fn publish_and_check(&self, revs: &[&str]) {
        for (i, r) in revs.iter().enumerate() {
            self.env.ok(U, &self.proj, &["tag", "set", &format!("line-{i}"), "-r", r, "--allow-backwards"]);
        }
        self.env.ok(U, &self.proj, &["push", "pub", "--force"]);
        for d in DRAFTS {
            let hits = mirror_contains(&self.mirror, d.as_bytes());
            assert!(hits.is_empty(), "{d}, taken in by the cloaked line, is on the public mirror: {hits:?}");
        }
    }
}

/// The change `vl duplicate` / `vl cherry-pick` reports it made
/// ("    as <change> <snapshot> …").
fn duplicate_in(out: &str) -> String {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("as ").and_then(|r| r.split_whitespace().next()).map(str::to_string))
        .unwrap_or_else(|| panic!("no duplicate in: {out}"))
}

fn both_sealed(w: &World, rev: &str) {
    for f in ["a.txt", "b.txt"] {
        assert!(w.sealed(rev, f), "{rev}:{f} is not sealed for the line");
    }
}

#[test]
fn a_draft_squashed_into_a_cloaked_change_stays_off_the_mirror() {
    let w = world();
    w.env.ok(U, &w.proj, &["squash", "-r", &w.draft, "--into", "sec@"]);
    let text = w.env.stdout(U, &w.proj, &["cat", "-r", "sec@", "a.txt"]);
    assert!(text.contains(DRAFTS[0]) && text.contains("SEALED-9"), "{text}");
    both_sealed(&w, "sec@");
    w.publish_and_check(&["sec@"]);
}

/// The draft rebased onto the cloaked change (its `a.txt` merges with the
/// sealed edit there), then squashed into it, its parent now.
#[test]
fn a_draft_rebased_onto_a_cloaked_change_and_squashed_in_stays_off_the_mirror() {
    let w = world();
    w.env.ok(U, &w.proj, &["rebase", "-s", &w.draft, "-d", "sec@"]);
    w.env.ok(U, &w.proj, &["squash", "-r", &w.draft]);
    let text = w.env.stdout(U, &w.proj, &["cat", "-r", "sec@", "a.txt"]);
    assert!(text.contains(DRAFTS[0]) && text.contains("SEALED-9"), "{text}");
    both_sealed(&w, "sec@");
    w.publish_and_check(&["sec@"]);
}

/// BUG-707.
#[test]
fn a_draft_duplicated_onto_a_cloaked_line_stays_off_the_mirror() {
    let w = world();
    let out = w.env.ok(U, &w.proj, &["duplicate", &w.draft, "-d", "sec@"]);
    let dup = duplicate_in(&out);
    both_sealed(&w, &dup);
    w.publish_and_check(&["sec@", &dup]);
}

/// `vl cherry-pick` onto the working copy's parent, the cloaked change.
#[test]
fn a_draft_cherry_picked_onto_a_cloaked_line_stays_off_the_mirror() {
    let w = world();
    w.env.ok(U, &w.proj, &["new", "sec@"]);
    let out = w.env.ok(U, &w.proj, &["cherry-pick", &w.draft]);
    let dup = duplicate_in(&out);
    both_sealed(&w, &dup);
    w.publish_and_check(&["sec@", &dup]);
}

/// What the cloaked change took in, split in two: both halves stay on the
/// line, and neither shows the draft.
#[test]
fn a_cloaked_change_split_after_taking_a_draft_in_stays_off_the_mirror() {
    let w = world();
    w.env.ok(U, &w.proj, &["squash", "-r", &w.draft, "--into", "sec@"]);
    w.env.ok(U, &w.proj, &["split", "a.txt", "-r", "sec@", "-m", "first"]);
    assert!(w.sealed("sec@-", "a.txt") && w.sealed("sec@", "b.txt"), "the halves left the line");
    w.publish_and_check(&["sec@", "sec@-"]);
}

