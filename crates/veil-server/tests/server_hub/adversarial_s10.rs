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
    let push = |path: String| {
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(512 << 20)
                .spawn_scoped(s, || {
                    let api = hub.api();
                    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
                    c.file(&path, "deep");
                    let r = c.push("main", "deep");
                    (r.status, body(&r))
                })
                .unwrap()
                .join()
                .unwrap()
        })
    };
    let (r, _) = push(format!("src/x/{}", vec!["d"; 600].join("/")));
    assert!(r < 500, "{r}");
    // Exactly at the limit (`MAX_TREE_DEPTH` folders above the file), both
    // routes land; one folder more is refused by both (BUG-1052).
    let limit = veil_core::tree::MAX_TREE_DEPTH;
    let token = p.dev.token();
    // `folders` folders above the file, the first of them `top`.
    let at = |top: &str, folders: usize| format!("{top}/{}f", "d/".repeat(folders - 1));
    assert_eq!(at("src", limit).split('/').count(), limit + 1);
    let base = tip(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put(&at("src", limit), "x")], "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let r = change(&hub, &token, &p.name, &json!({"base": tip(&hub, &token, &p.name).hex(), "edits": [put(&at("src", limit + 1), "x")]}));
    assert_eq!(r.status, 400, "{}", body(&r));
    let (r, b) = push(at("src", limit).replacen("src/d/", "src/p/", 1));
    assert_eq!(r, 200, "a push at the limit: {b}");
    let (r, b) = push(at("src", limit + 1).replacen("src/d/", "src/q/", 1));
    assert!((400..500).contains(&r), "a push past the limit: {r} {b}");
    eprintln!("deep edits answered");
}

/// Changes within the documented limits (10,000 edits; here 1,000 files
/// 100 folders deep, 100,000 objects from a 236 KB request) land on an S3
/// store (MinIO here): the server does not send every object at once.
/// The deep change is ten times the objects of the flat one and took about
/// 22 times as long; under load both stretch alike, so the deep change may
/// take 60 times the flat one's duration, measured first in the same run,
/// before it counts as hung (with the 120 s of every other request at the
/// least): a fixed limit failed on a loaded machine.
#[test]
fn bug_1053_a_change_of_ten_thousand_files_lands_on_s3() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    let path = format!("/v1/projects/{}/changes", p.name);
    let flat: Vec<Value> = (0..10_000).map(|i| put(&format!("src/many/{i}.txt"), &format!("file {i}\n"))).collect();
    let t = std::time::Instant::now();
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": flat}));
    let baseline = t.elapsed();
    assert_eq!(r.status, 200, "{}", body(&r));
    let chain = vec!["d"; 98].join("/");
    let deep: Vec<Value> = (0..1_000).map(|i| put(&format!("src/deep/{i}/{chain}"), &format!("file {i}\n"))).collect();
    let limit = (baseline * 60).max(std::time::Duration::from_secs(120));
    let r = hub.api().post_json_within(&token, &path, &json!({"base": base.hex(), "edits": deep}), limit);
    assert_eq!(r.status, 200, "{}", body(&r));
}

/// A member stacks a change on their own unlanded one (as §13.13 says to:
/// "to stack on an unlanded change ... use `expected`"), expecting main
/// where they see it. A change on main they cannot see must not change the
/// answer: it is not in their history, and must not show (S1, §13.4).
#[test]
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


// ---- S10 cycle 2 (BUG-1055..) ----

/// Format 8 keeps a secret sealed when its member renames it to an
/// ordinary name ("protection follows a secret across a rename",
/// `veil-core` `builder.rs`; `upgrade.rs` accepts it as what format 8
/// writes). The server must take what `vl` itself writes: the member's
/// push of the rename lands, still sealed.
#[test]
fn bug_1055_a_renamed_secret_that_vl_keeps_sealed_is_accepted() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // To a path no rule of the policy names (the private root): the case
    // `vl` protects (`builder.rs` `protect_moves`).
    std::fs::rename(p.dir.join(format!("{BILL_DIR}/.env")), p.dir.join("settings-from-env.txt")).unwrap();
    p.admin.commit_main(&p.dir, "rename the env file");
    // Control: the member's own vl keeps it sealed at the new path.
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let tree = repo.store().snapshot(&repo.view().tags["main"].target).unwrap().tree;
    let e = veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new("settings-from-env.txt").unwrap()).unwrap().expect("renamed");
    assert!(!e.visibility.is_public(), "control: vl keeps the renamed secret sealed");
    drop(repo);
    let out = p.admin.run(&p.dir, &["push"]);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "the push of vl's own renamed secret was refused: {text}");
}

/// A stack over a hidden change (BUG-1054's fix makes the caller's own
/// changes again on the real tip) fails with 400 "missing object" when a
/// change of the stack holds a folder its maker sees whole: `restack`
/// counts as known only the files it changed and the trees the projector
/// made, never a real tree of the caller's (a new folder of theirs, or
/// every folder for a member who sees all of the fork), so the push's
/// closure check refuses it. Without the hidden change the same request
/// lands, so the answer also tells the caller that a change they cannot
/// see landed (BUG-1054's class, through the fix).
#[test]
fn bug_1056_a_stack_over_a_hidden_change_lands_when_it_adds_a_folder() {
    let hub = TestHub::start();
    let mut failures = Vec::new();
    // A: the usual project; the dev's first change adds a new folder.
    {
        let p = setup_project(&hub);
        let token = p.dev.token();
        let main = tip(&hub, &token, &p.name);
        let r = change(&hub, &token, &p.name, &json!({"base": main.hex(), "edits": [put("src/newdir/first.txt", "1")]}));
        assert_eq!(r.status, 200, "{}", body(&r));
        let x: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
        write_files(&p.dir, &[(&format!("{BILL_DIR}/acme/invoice.txt"), "MARKER-HIDDEN-UNDER-NEWDIR-0c4e19")]);
        p.admin.commit_main(&p.dir, "billing only");
        p.admin.ok(&p.dir, &["push"]);
        assert_eq!(tip(&hub, &token, &p.name), main, "control: a hidden-only change is not in the dev's history");
        let r = change(&hub, &token, &p.name, &json!({"base": x.hex(), "edits": [put("src/second.txt", "2")],
            "onto": {"branch": "main", "expected": main.hex()}}));
        if r.status != 200 || r.json()["branch"]["status"] != "ok" {
            failures.push(format!("a new folder: {} {}", r.status, body(&r)));
        }
    }
    // B: a member who sees all of the fork (src/ and .veilpolicy).
    {
        let admin = hub.person("admin");
        let dev = hub.person("dev");
        let name = unique("full");
        let dir = admin.dir("proj");
        std::fs::create_dir_all(&dir).unwrap();
        admin.ok(&dir, &["init"]);
        write_files(&dir, &[("src/lib.rs", "pub fn f() {}\n")]);
        admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
        admin.commit_main(&dir, "initial import");
        admin.ok(&dir, &["push"]);
        admin.ok(&dir, &["group", "create", "devs"]);
        admin.ok(&dir, &["group", "add", "devs", &dev.name, "--confirm", &dev.fingerprint()]);
        admin.ok(&dir, &["access", "src/", "devs"]);
        admin.ok(&dir, &["access", ".veilpolicy", "devs"]);
        admin.commit_main(&dir, "access rules");
        admin.ok(&dir, &["push"]);
        dev.trust_project(&hub, &name, &admin.project_fingerprint(&dir));
        let (token, atok) = (dev.token(), admin.token());
        let main = tip(&hub, &token, &name);
        assert_eq!(main, tip(&hub, &atok, &name), "control: the dev sees all of main");
        let r = change(&hub, &token, &name, &json!({"base": main.hex(), "edits": [put("src/first.txt", "1")]}));
        assert_eq!(r.status, 200, "{}", body(&r));
        let x: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
        // The admin adds a file in the private root: hidden from the dev.
        write_files(&dir, &[("notes-admin-only.txt", "MARKER-ADMIN-ONLY-NOTE-5e21c0")]);
        admin.commit_main(&dir, "admin only");
        admin.ok(&dir, &["push"]);
        assert_eq!(tip(&hub, &token, &name), main, "control: a hidden-only change is not in the dev's history");
        assert_ne!(tip(&hub, &atok, &name), main);
        let r = change(&hub, &token, &name, &json!({"base": x.hex(), "edits": [put("src/second.txt", "2")],
            "onto": {"branch": "main", "expected": main.hex()}}));
        if r.status != 200 || r.json()["branch"]["status"] != "ok" {
            failures.push(format!("a member who sees the whole fork: {} {}", r.status, body(&r)));
        }
    }
    assert!(failures.is_empty(), "a stack over a hidden change did not land: {failures:#?}");
}
