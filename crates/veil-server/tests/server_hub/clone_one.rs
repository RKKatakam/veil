//! Clone one folder (BUG-1945): `GET /v1/projects/{p}/subtree`, the trees
//! of a folder, every level, in one answer, with `fetch`'s access at every
//! level (a folder or snapshot the caller may not see is refused as a fetch
//! of it is, an answer names nothing the caller may not see, a narrowed
//! agent session gets its paths only, `docs/HUB.md` §13.27); and `vl clone
//! --only`, thin by default, which records as deleted, changed or present
//! nothing it did not write, thin or `--full`.

use serde_json::{json, Value};
use veil_core::{object::Object, ObjectId};

use crate::support::*;

fn subtree(hub: &TestHub, token: Option<&str>, project: &str, snap: &ObjectId, path: &str) -> Reply {
    hub.api().get(token, &format!("/v1/projects/{project}/subtree?snapshot={}&path={path}", snap.hex()))
}

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// The trees of an answer: (id, tree), each checked against its id.
fn trees(r: &Reply) -> Vec<(ObjectId, veil_core::object::Tree)> {
    r.frames()
        .into_iter()
        .map(|(id, raw)| {
            assert_eq!(ObjectId::hash(&raw), id, "an object that is not its id");
            match Object::decode(&raw).unwrap() {
                Object::Tree(t) => (id, t),
                o => panic!("not a tree: {o:?}"),
            }
        })
        .collect()
}

/// The id of the tree at `path` as `token`'s person sees it (the query API).
fn tree_id(hub: &TestHub, token: &str, project: &str, path: &str) -> String {
    let r = hub.api().get(Some(token), &format!("/v1/projects/{project}/q/tree?path={path}"));
    assert_eq!(r.status, 200, "{path}: {}", body(&r));
    r.json()["id"].as_str().unwrap().to_string()
}

/// Every tree of `path` and below as `token`'s person sees it, by the
/// query API (one level at a time): (path, id).
fn trees_by_query(hub: &TestHub, token: &str, project: &str, path: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![path.to_string()];
    while let Some(p) = stack.pop() {
        let r = hub.api().get(Some(token), &format!("/v1/projects/{project}/q/tree?path={p}"));
        assert_eq!(r.status, 200, "{p}: {}", body(&r));
        let v: Value = r.json();
        out.push((p.clone(), v["id"].as_str().unwrap().to_string()));
        for e in v["entries"].as_array().unwrap() {
            if e["kind"] == "dir" {
                let name = e["name"].as_str().unwrap();
                stack.push(if p.is_empty() { name.to_string() } else { format!("{p}/{name}") });
            }
        }
    }
    out
}

/// Deeper folders than the standard project has: three levels under
/// `src/deep`, and a sibling folder.
fn with_deep_folders(hub: &TestHub, p: &Project) {
    let token = p.dev.token();
    let base = tip(hub, &token, &p.name);
    let r = hub.api().post_json(
        Some(&token),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": base.hex(), "description": "deep folders", "onto": {"branch": "main", "expected": base.hex()},
                "edits": [{"path": "src/deep/a/b/c.rs", "put": {"text": "fn c() {} // MARKER-DEEP-1"}},
                          {"path": "src/deep/a/d.rs", "put": {"text": "fn d() {}"}},
                          {"path": "src/deep/e/f.rs", "put": {"text": "fn f() {}"}},
                          {"path": "src/side/g.rs", "put": {"text": "fn g() {} // MARKER-SIDE-2"}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
}

/// The answer is the trees on the way and every tree below, each the one
/// the caller's projection has at its path, in one request; nothing of a
/// folder the caller may not see is in any tree of the answer.
#[test]
fn the_subtree_route_answers_every_level_as_the_caller_sees_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_deep_folders(&hub, &p);
    let dev = p.dev.token();
    let snap = tip(&hub, &dev, &p.name);
    let r = subtree(&hub, Some(&dev), &p.name, &snap, "src/deep");
    assert_eq!(r.status, 200, "{}", body(&r));
    let got: Vec<String> = trees(&r).iter().map(|(id, _)| id.hex()).collect();
    let on_the_way: Vec<String> = ["", "src"].iter().map(|d| tree_id(&hub, &dev, &p.name, d)).collect();
    assert_eq!(got[..2], on_the_way[..], "the root and src come first");
    let mut want: Vec<String> = trees_by_query(&hub, &dev, &p.name, "src/deep").into_iter().map(|(_, id)| id).collect();
    want.extend(on_the_way);
    let (mut g, mut w) = (got, want);
    g.sort();
    w.sort();
    assert_eq!(g, w, "the trees of src/deep and the way there, as the query API shows them");
    // The whole tree, from the root: every folder the dev sees, no other,
    // and no tree names anything the dev may not see.
    let r = subtree(&hub, Some(&dev), &p.name, &snap, "");
    assert_eq!(r.status, 200, "{}", body(&r));
    let all = trees(&r);
    let mut got: Vec<String> = all.iter().map(|(id, _)| id.hex()).collect();
    let mut want: Vec<String> = trees_by_query(&hub, &dev, &p.name, "").into_iter().map(|(_, id)| id).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "every tree the dev sees, as the query API shows them");
    let frames: Vec<(String, Vec<u8>)> = r.frames().into_iter().map(|(i, b)| (i.hex(), b)).collect();
    for m in restricted_markers() {
        assert!(!has_marker(&frames, m), "the answer holds {m}");
    }
    assert!(all.iter().all(|(_, t)| t.entries.iter().all(|e| !restricted_markers().contains(&e.name.as_str()))));
}

/// A folder the caller may not see, or a path through it, is refused
/// exactly as a fetch of its tree is (the same status and body, naming
/// nothing), and so is a snapshot it may not see; someone with no session
/// gets the public folder only; a person who may see the folder gets it.
#[test]
fn a_folder_or_snapshot_the_caller_may_not_see_is_refused_as_fetch_refuses_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (dev, fin, admin) = (p.dev.token(), p.fin.token(), p.admin.token());
    let snap = tip(&hub, &dev, &p.name);
    let bill_tree = tree_id(&hub, &fin, &p.name, BILL_DIR);
    let fetch = hub.api().post_json(Some(&dev), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": snap.hex(), "objects": [{"path": BILL_DIR, "id": bill_tree}]}));
    assert_eq!(fetch.status, 404, "control: fetch refuses the dev the billing folder: {}", body(&fetch));
    for (who, path) in [
        (&dev, BILL_DIR.to_string()),
        (&dev, format!("{BILL_DIR}/acme")),
        (&dev, PERSON_DIR.to_string()),
        (&dev, format!("src/{NESTED_DIR}")),
        (&dev, "no-such-folder".to_string()),
        (&fin, PERSON_DIR.to_string()),
        (&fin, format!("src/{NESTED_DIR}")),
    ] {
        let r = subtree(&hub, Some(who), &p.name, &snap, &path);
        assert_eq!((r.status, body(&r)), (fetch.status, body(&fetch)), "{path}: not refused as fetch refuses it");
        for m in restricted_markers() {
            assert!(!body(&r).contains(m), "{path}: the refusal names {m}");
        }
    }
    // Someone with no session: the public folder only.
    let r = subtree(&hub, None, &p.name, &snap, BILL_DIR);
    assert_eq!(r.status, 404, "{}", body(&r));
    assert!(!body(&r).contains(BILL_MARK));
    let r = subtree(&hub, None, &p.name, &snap, "src");
    assert_eq!(r.status, 200, "src is public: {}", body(&r));
    let frames: Vec<(String, Vec<u8>)> = r.frames().into_iter().map(|(i, b)| (i.hex(), b)).collect();
    for m in restricted_markers() {
        assert!(!has_marker(&frames, m), "anyone's answer holds {m}");
    }
    // A snapshot nobody has: refused as fetch refuses it.
    let none = ObjectId::hash(b"no such snapshot");
    let r = subtree(&hub, Some(&admin), &p.name, &none, "");
    let f = hub.api().post_json(Some(&admin), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": none.hex(), "objects": [{"path": "", "id": none.hex()}]}));
    assert_eq!(f.status, 404, "control: {}", body(&f));
    assert_eq!((r.status, body(&r)), (f.status, body(&f)), "a snapshot nobody has");
    // Control: finance reads the billing folder, every level.
    let r = subtree(&hub, Some(&fin), &p.name, &snap, BILL_DIR);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(trees(&r).len(), 3, "the root, the billing folder and acme");
}

/// A narrowed agent session (`docs/HUB.md` §13.27): a path outside its
/// paths, the root and the folders on the way included, is refused as
/// every file route refuses it; inside, it gets the folders on the way and
/// what is below its path, as a fetch would give it, nothing else.
#[test]
fn a_narrowed_agent_session_gets_only_its_paths_from_the_subtree_route() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_deep_folders(&hub, &p);
    let token = p.dev.token();
    let r = hub.api().post_json(
        Some(&token),
        "/v1/sessions/agent",
        &json!({"project": p.name, "attribution": {"agent": "claude-code/2.3", "task": "T", "run": "r"}, "only": ["src/deep/a"]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    let agent = r.json()["token"].as_str().unwrap().to_string();
    let snap = tip(&hub, &agent, &p.name);
    for path in ["", "src", "src/deep", "src/side", "src/deep/e", BILL_DIR] {
        let r = subtree(&hub, Some(&agent), &p.name, &snap, path);
        assert_eq!((r.status, r.json()["code"].clone()), (403, json!("agent_session")), "{path}: {}", body(&r));
        assert!(!body(&r).contains("MARKER"), "{path}");
        // Control: the person reads it (but billing, not theirs).
        if path != BILL_DIR {
            assert_eq!(subtree(&hub, Some(&token), &p.name, &snap, path).status, 200, "control {path}");
        }
    }
    let r = subtree(&hub, Some(&agent), &p.name, &snap, "src/deep/a");
    assert_eq!(r.status, 200, "{}", body(&r));
    let got: Vec<String> = trees(&r).iter().map(|(id, _)| id.hex()).collect();
    let mut want: Vec<String> = ["", "src", "src/deep"].iter().map(|d| tree_id(&hub, &token, &p.name, d)).collect();
    want.extend(trees_by_query(&hub, &token, &p.name, "src/deep/a").into_iter().map(|(_, id)| id));
    let (mut g, mut w) = (got, want);
    g.sort();
    w.sort();
    assert_eq!(g, w, "the folders on the way and src/deep/a's trees, nothing of src/deep/e or src/side");
}

/// No line of `vl status` says a path was added, changed or deleted.
fn assert_clean(status: &str, what: &str) {
    for l in status.lines() {
        let t = l.trim_start();
        for k in ["A ", "M ", "D ", "R "] {
            assert!(!t.starts_with(k), "{what}: recorded {l:?}:\n{status}");
        }
    }
}

/// `vl clone --only` records as deleted, changed or present nothing it did
/// not write (BUG-1945), thin (the default) and `--full`: after the clone,
/// after a pull that brings changes inside and outside the folder and a
/// move to them, with a file of the person's own in a folder it never
/// wrote, and after an edit inside pushed: the project outside the folder
/// is exactly as others left it, and nothing outside the folder was
/// fetched.
#[test]
fn a_one_folder_clone_records_only_what_it_wrote() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let url = hub.url(&p.name);
    for full in [false, true] {
        let d = p.fin.dir(if full { "only-full" } else { "only-thin" });
        let mut args = vec!["clone", &url as &str, d.to_str().unwrap(), "--only", BILL_DIR];
        if full {
            args.push("--full");
        }
        let out = p.fin.ok(p.fin.home.path(), &args);
        assert!(out.contains("Cloned"), "{out}");
        assert_eq!(out.contains("thin"), !full, "{out}");
        // What the project holds now (the thin round pushed an edit).
        let invoice = std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap();
        assert_eq!(std::fs::read_to_string(d.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), invoice);
        assert!(!d.join("src").exists(), "a folder outside --only was written");
        assert_clean(&p.fin.ok(&d, &["status"]), "after the clone");
        assert!(!has_marker(&everything_in(&d), PUBLIC_MARK), "full {full}: an object outside --only was fetched");
        // Others change the project inside and outside the folder.
        write_files(
            &p.dir,
            &[
                ("src/lib.rs", &format!("{PUBLIC_MARK} v2 full {full}")),
                ("src/added.rs", &format!("{PUBLIC_MARK} added full {full}")),
                (&format!("{BILL_DIR}/acme/new.txt"), &format!("new full {full}")),
            ],
        );
        p.admin.commit_main(&p.dir, "inside and outside");
        p.admin.ok(&p.dir, &["push"]);
        p.fin.ok(&d, &["pull"]);
        p.fin.ok(&d, &["new", "main"]);
        assert_eq!(std::fs::read_to_string(d.join(BILL_DIR).join("acme/new.txt")).unwrap(), format!("new full {full}"));
        assert!(!d.join("src").exists(), "a folder outside --only was written by the move");
        assert_clean(&p.fin.ok(&d, &["status"]), "after the pull and the move");
        assert!(!has_marker(&everything_in(&d), PUBLIC_MARK), "full {full}: an object outside --only was fetched by the pull");
        // A file of the person's own in a folder the clone never wrote: listed,
        // never recorded.
        write_files(&d, &[("src/mine.txt", "MARKER-MINE-not-recorded")]);
        let status = p.fin.ok(&d, &["status"]);
        assert_clean(&status, "with a file in a folder never written");
        assert!(status.contains("src/mine.txt"), "the file is not listed:\n{status}");
        // An edit inside, committed and pushed: the only change the project gets.
        let before = real_paths(&p.dir);
        write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt"), &format!("edited full {full}"))]);
        p.fin.commit_main(&d, "edit inside");
        p.fin.ok(&d, &["push"]);
        p.admin.ok(&p.dir, &["pull"]);
        p.admin.ok(&p.dir, &["new", "main"]);
        assert_eq!(std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), format!("edited full {full}"));
        assert!(!p.dir.join("src/mine.txt").exists(), "a file never recorded reached the project");
        assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), format!("{PUBLIC_MARK} v2 full {full}"));
        let after = real_paths(&p.dir);
        let invoice = format!("{BILL_DIR}/acme/invoice.txt");
        let changed: Vec<&String> = after
            .iter()
            .filter(|(path, id)| !before.iter().any(|(bp, bid)| bp == path && bid == id))
            .map(|(path, _)| path)
            .collect();
        for path in &changed {
            assert!(path.is_empty() || invoice.starts_with(path.as_str()), "full {full}: the push changed {path}: {changed:?}");
        }
        assert!(before.iter().all(|(bp, _)| after.iter().any(|(ap, _)| ap == bp)), "full {full}: the push deleted something");
        assert!(changed.contains(&&invoice), "the edit landed");
        assert!(after.iter().any(|(path, _)| path == &format!("src/{NESTED_DIR}")));
    }
}

/// Run `vl clone` with a power cut simulated before its one barrier
/// (`VEIL_TEST_CLONE_POWER_CUT`, debug builds): the process ends there.
fn clone_cut(who: &Person, url: &str, dest: &std::path::Path, seed: u64, only: Option<&str>) {
    let mut args = vec!["clone", url, dest.to_str().unwrap()];
    if let Some(o) = only {
        args.extend(["--only", o]);
    }
    let out = who.command(who.home.path(), &args).env("VEIL_TEST_CLONE_POWER_CUT", seed.to_string()).output().unwrap();
    assert_eq!(out.status.code(), Some(86), "the clone did not stop at the cut: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// BUG-1945: a fresh clone defers its set-up's flushes (the repository,
/// the pull, the new change) to one barrier before its checkout's journal.
/// A power cut before that barrier, whatever it did to what was deferred
/// (lost, emptied, cut short, kept), leaves a directory that every command
/// refuses with the clone's refusal, never one that looks usable: in the
/// directory, in a folder of it, and inside another repository, where a
/// lost `repo.json` must not make it a folder of that one (which records
/// none of it). Removed and cloned again, it works.
#[test]
fn a_fresh_clone_cut_before_its_one_barrier_is_refused_never_usable() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let outer = p.fin.dir("outer");
    std::fs::create_dir_all(&outer).unwrap();
    p.fin.ok(&outer, &["init"]);
    write_files(&outer, &[("mine.txt", "outer")]);
    p.fin.ok(&outer, &["commit", "-m", "outer"]);
    let url = hub.url(&p.name);
    for seed in 0..6u64 {
        for (inside, only) in [(false, None), (true, None), (true, Some(BILL_DIR)), (false, Some(BILL_DIR))] {
            let what = format!("seed {seed}, inside {inside}, only {only:?}");
            let d = match inside {
                true => outer.join(format!("cut{seed}-{}", only.is_some())),
                false => p.fin.dir(&format!("cut{seed}-{}", only.is_some())),
            };
            clone_cut(&p.fin, &url, &d, seed, only);
            assert!(d.join(".veil/local/clone-incomplete").is_file(), "{what}: the marker is durable before the deferral");
            std::fs::create_dir_all(d.join("sub")).unwrap();
            for at in [d.clone(), d.join("sub")] {
                for args in [&["status"][..], &["log", "-n", "3"], &["commit", "-m", "x"], &["pull"], &["push"]] {
                    let out = p.fin.fails(&at, args);
                    assert!(out.contains("interrupted before it fetched the project"), "{what}, {args:?} in {}: {out}", at.display());
                }
            }
            if inside {
                // The repository around it records nothing of it.
                let status = p.fin.ok(&outer, &["status"]);
                assert!(
                    !status.lines().any(|l| l.contains(&format!("cut{seed}")) && ["A ", "M ", "D "].iter().any(|k| l.trim_start().starts_with(k))),
                    "{what}: the outer repository recorded the cut clone:\n{status}"
                );
            }
            std::fs::remove_dir_all(&d).unwrap();
            let mut args = vec!["clone", &url as &str, d.to_str().unwrap()];
            if let Some(o) = only {
                args.extend(["--only", o]);
            }
            p.fin.ok(p.fin.home.path(), &args);
            assert_clean(&p.fin.ok(&d, &["status"]), &what);
            assert!(d.join(BILL_DIR).join("acme/invoice.txt").is_file(), "{what}");
        }
    }
}

/// BUG-1945: only a clone into a directory it makes defers anything: into
/// an empty directory that was there, every write is durable as it is
/// made (the cut that removes everything deferred removes nothing there),
/// and the clone is refused all the same until its checkout's journal.
#[test]
fn a_clone_into_a_directory_that_was_there_defers_nothing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("there");
    std::fs::create_dir_all(&d).unwrap();
    // Seed 1: every deferred file removed.
    clone_cut(&p.fin, &hub.url(&p.name), &d, 1, None);
    let repo_json = std::fs::read_to_string(d.join(".veil/repo.json")).unwrap();
    assert!(repo_json.contains("format"), "repo.json was deferred: {repo_json:?}");
    assert!(d.join(".veil/local/clone-incomplete").is_file());
    let out = p.fin.fails(&d, &["status"]);
    assert!(out.contains("interrupted before it fetched the project"), "{out}");
    // Control: a new directory's cut removes what it deferred.
    let fresh = p.fin.dir("fresh");
    clone_cut(&p.fin, &hub.url(&p.name), &fresh, 1, None);
    assert!(!fresh.join(".veil/repo.json").exists(), "control: the new directory's repo.json was not deferred");
}
