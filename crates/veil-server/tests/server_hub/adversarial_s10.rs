//! Adversarial pass on S10, commits through the API (`docs/HUB.md`
//! §13.13): what an API commit answers, what it lands, and what the push
//! code it now shares still does. The attacker is a member reaching beyond
//! their folders, or a hostile API client.

use serde_json::{json, Value};
use veil_core::{object::Object as O, ObjectId};

use crate::support::*;

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn change(hub: &TestHub, token: &str, project: &str, body: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), body)
}

fn put(path: &str, text: &str) -> Value {
    json!({"path": path, "put": {"text": text}})
}

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).to_string()
}

/// The real (admin's) id at `path` on main.
fn real_id(p: &Project, path: &str) -> ObjectId {
    real_paths(&p.dir).into_iter().find(|(q, _)| q == path).unwrap_or_else(|| panic!("no {path}")).1
}

/// A member names, at a path they cannot see, the object they guess is
/// there (its id is the hash of the content they guess: "is the invoice
/// 5,000?"). A right guess and a wrong one must get the same answer, as a
/// push's do (BUG-824's rule).
#[test]
#[ignore = "BUG-1050: put.object at a hidden path confirms a guess of the hidden file's content (closure is judged on the real base before the graft)"]
fn bug_1050_a_put_at_a_hidden_path_never_confirms_a_guess_of_its_content() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    for path in [format!("{BILL_DIR}/acme/invoice.txt"), format!("src/{NESTED_DIR}/key.txt")] {
        let right = real_id(&p, &path);
        let wrong = ObjectId::hash(&O::Blob(b"a wrong guess".to_vec()).encode());
        let answer = |id: ObjectId| {
            let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [{"path": path, "put": {"object": id.hex()}}]}));
            (r.status, body(&r).replace(&id.hex(), "ID").replace(&id.short(), "ID"))
        };
        // A push naming the same objects there, not uploaded: one answer.
        let pushed = |id: ObjectId| {
            let api = hub.api();
            let mut c = Craft::new(&api, &p.dev, &p.name, "main");
            c.refer(&path, id, 10);
            let r = c.push("main", "guess");
            (r.status, body(&r).replace(&id.hex(), "ID").replace(&id.short(), "ID"))
        };
        assert_eq!(pushed(right), pushed(wrong), "{path}: control: a push answers both guesses alike");
        let (a, b) = (answer(right), answer(wrong));
        assert_eq!(a, b, "{path}: the answer tells a right guess of the hidden content from a wrong one");
    }
}

/// A member's change on a base from before an admin changed the access
/// lines, with `onto` refused (a stale `expected`, or a rebase that cannot
/// apply): the branch did not move, so the answer is "rejected" and the
/// change is kept, as for any other base.
#[test]
#[ignore = "BUG-1051: an API commit whose move is refused, on a base older than the accepted policy, fails with 'only admins may change who has access'"]
fn bug_1051_a_refused_move_on_an_older_base_is_rejected_not_an_access_change() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    // An admin adds an access line on main (through the API, as in S10's
    // own test), with a file the dev sees.
    let atok = p.admin.token();
    let abase = tip(&hub, &atok, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let r = change(&hub, &atok, &p.name, &json!({"base": abase.hex(), "edits": [put(".veilpolicy", &format!("{policy}docs/ public\n")), put("src/admin.txt", "a")],
        "onto": {"branch": "main", "expected": abase.hex()}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    // The dev's change on its old base, with the old tip expected.
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/late.txt", "late")],
        "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "rejected", "{}", body(&r));
    // The same with a rebase that cannot apply (the edited file changed).
    let now = tip(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": now.hex(), "edits": [put("src/lib.rs", "theirs")],
        "onto": {"branch": "main", "expected": now.hex()}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/lib.rs", "mine again")],
        "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "rejected", "{}", body(&r));
}

/// Rebasing over a change the caller cannot see (a hidden file in a folder
/// they edit, a hidden folder emptied of their files) keeps it: the change
/// is exactly its edits on the full tip.
#[test]
fn s10_rebase_keeps_hidden_changes_in_edited_folders() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    // The admin changes the nested hidden file, then the dev rebases an
    // edit of src/ (and deletes the only visible file there) onto it.
    write_files(&p.dir, &[(&format!("src/{NESTED_DIR}/key.txt"), "NESTED-SECOND-VERSION-6b0e")]);
    p.admin.commit_main(&p.dir, "nested edit");
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(tip(&hub, &token, &p.name), base, "a hidden-only change is not in the dev's history");
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [{"path": "src/lib.rs", "delete": true}, put("src/new.txt", "n")],
        "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert_eq!(std::fs::read_to_string(p.dir.join(format!("src/{NESTED_DIR}/key.txt"))).unwrap(), "NESTED-SECOND-VERSION-6b0e");
    assert!(p.dir.join("src/new.txt").exists() && !p.dir.join("src/lib.rs").exists());
    assert!(p.dir.join(format!("{BILL_DIR}/acme/invoice.txt")).exists());
}

/// Kind changes across an access boundary, and hidden names, get the
/// answers a push gives: a file over a hidden folder, a folder under a
/// hidden file's name, a delete of a hidden folder's file.
#[test]
fn s10_kind_changes_across_a_boundary_answer_alike_for_hidden_and_missing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    let ask = |edit: Value| {
        let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [edit]}));
        (r.status, body(&r))
    };
    // A file over the hidden billing folder, and over a name that is not there.
    let (s1, b1) = ask(put(BILL_DIR, "x"));
    let (s2, b2) = ask(put("bill-00000000", "x"));
    assert_eq!((s1, b1.replace(BILL_DIR, "N")), (s2, b2.replace("bill-00000000", "N")));
    // Deletes of a hidden file and of a missing one.
    let (s1, b1) = ask(json!({"path": format!("{BILL_DIR}/.env"), "delete": true}));
    let (s2, b2) = ask(json!({"path": "bill-00000000/.env", "delete": true}));
    assert_eq!((s1, b1.replace(BILL_DIR, "N")), (s2, b2.replace("bill-00000000", "N")));
    // Below a hidden file's name, in the private root.
    let (s1, b1) = ask(put(&format!("{ROOT_FILE}/x"), "x"));
    let (s2, b2) = ask(put("README-root-00000000.md/x", "x"));
    assert_eq!((s1, b1.replace(ROOT_FILE, "N")), (s2, b2.replace("README-root-00000000.md", "N")));
    assert_eq!(tip(&hub, &token, &p.name), base);
}

/// The server answers a commit 600 folders deep, inside the documented
/// limit of 1,024 levels, and stays up. Run in a child process: today the
/// whole server (and this test binary with it) aborts on a stack overflow.
#[test]
#[ignore = "BUG-1052: a path 500-1,024 levels deep (an API edit or a pushed tree) overflows a server worker's stack and aborts the whole server"]
fn bug_1052_a_deep_edit_never_takes_the_server_down() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["adversarial_s10::deep_edit_in_a_child", "--exact", "--include-ignored", "--nocapture"])
        .env("VEIL_S10_CHILD", "1")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("deep edits answered"), "the server went down: {:?}\n{}", out.status, &text[text.len().saturating_sub(600)..]);
}

#[test]
#[ignore = "helper of bug_1052 (run in a child process)"]
fn deep_edit_in_a_child() {
    if std::env::var_os("VEIL_S10_CHILD").is_none() {
        return;
    }
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // A read-only member (finance reads src/), then a writer.
    for who in [&p.fin, &p.dev] {
        let token = who.token();
        let base = tip(&hub, &token, &p.name);
        let chain = vec!["d"; 600].join("/");
        let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put(&format!("src/{chain}"), "x")]}));
        assert!(r.status < 500, "{} {}", r.status, body(&r));
    }
    // The same depth through a push (the graft recurses too); crafted on a
    // thread with a large stack (the crafting recurses as well).
    let r = std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(512 << 20)
            .spawn_scoped(s, || {
                let api = hub.api();
                let mut c = Craft::new(&api, &p.dev, &p.name, "main");
                c.file(&format!("src/x/{}", vec!["d"; 600].join("/")), "deep");
                c.push("main", "deep").status
            })
            .unwrap()
            .join()
            .unwrap()
    });
    assert!(r < 500, "{r}");
    eprintln!("deep edits answered");
}

/// Changes within the documented limits (10,000 edits; here 1,000 files
/// 100 folders deep, 100,000 objects from a 236 KB request) land on an S3
/// store (MinIO here): the server does not send every object at once.
#[test]
#[ignore = "BUG-1053: an API commit stores all its objects at once (one task each, unbounded); on S3 a 10,000-file change gets HTTP 429s and fails with a 500"]
fn bug_1053_a_change_of_ten_thousand_files_lands_on_s3() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    let chain = vec!["d"; 98].join("/");
    let deep: Vec<Value> = (0..1_000).map(|i| put(&format!("src/deep/{i}/{chain}"), &format!("file {i}\n"))).collect();
    let flat: Vec<Value> = (0..10_000).map(|i| put(&format!("src/many/{i}.txt"), &format!("file {i}\n"))).collect();
    for edits in [deep, flat] {
        let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": edits}));
        assert_eq!(r.status, 200, "{}", body(&r));
    }
}

/// A member stacks a change on their own unlanded one (as §13.13 says to:
/// "to stack on an unlanded change ... use `expected`"), expecting main
/// where they see it. A change on main they cannot see must not change the
/// answer: it is not in their history, and must not show (S1, §13.4).
#[test]
#[ignore = "BUG-1054: an expected tip is refused as 'not a fast-forward' when a change the caller cannot see landed on main, revealing it"]
fn bug_1054_a_hidden_change_on_main_does_not_refuse_an_expected_move() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let answer = |hidden_change: bool| {
        let main = tip(&hub, &token, &p.name);
        // An unlanded change of the dev's, kept on its ref.
        let r = change(&hub, &token, &p.name, &json!({"base": main.hex(), "edits": [put(&format!("src/{}.txt", unique("x")), "x")]}));
        assert_eq!(r.status, 200, "{}", body(&r));
        let x: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
        if hidden_change {
            p.admin.ok(&p.dir, &["pull"]);
            p.admin.ok(&p.dir, &["new", "main"]);
            write_files(&p.dir, &[(&format!("{BILL_DIR}/acme/invoice.txt"), &unique("hidden edit "))]);
            p.admin.commit_main(&p.dir, "billing only");
            p.admin.ok(&p.dir, &["push"]);
            assert_eq!(tip(&hub, &token, &p.name), main, "the dev's main did not move");
        }
        let r = change(&hub, &token, &p.name, &json!({"base": x.hex(), "edits": [put(&format!("src/{}.txt", unique("y")), "y")],
            "onto": {"branch": "main", "expected": main.hex()}}));
        assert_eq!(r.status, 200, "{}", body(&r));
        let v = r.json();
        (v["branch"]["status"].as_str().unwrap().to_string(), v["branch"]["message"].clone())
    };
    let without = answer(false);
    let with = answer(true);
    assert_eq!(without.0, "ok", "{without:?}");
    assert_eq!(with, without, "a change the dev cannot see changed the answer");
}

