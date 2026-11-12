//! `GET /v1/projects/{p}/subtree` (client speed round 5, BUG-1945): the
//! trees of a folder, every level, in one answer. Access is `fetch`'s at
//! every level: a folder the caller may not see is refused as a fetch of it
//! is, an answer names nothing the caller may not see, and a narrowed agent
//! session gets its paths only (`docs/HUB.md` §13.27). A thin clone's
//! first fetch uses it (covered by the `thin::` clones).

use serde_json::{json, Value};
use veil_core::{
    object::{EntryKind, Object},
    ObjectId,
};

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

/// The trees of an answer: (id, tree), checked against their ids.
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
                stack.push(if p.is_empty() { e["name"].as_str().unwrap().to_string() } else { format!("{p}/{}", e["name"].as_str().unwrap()) });
            }
        }
    }
    out
}

/// A deeper folder than the standard project has: three levels under
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
/// the caller's projection has at its path, in one request; a person
/// outside a folder sees no trace of it in any tree of the answer.
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
    // The root, `src`, then `src/deep` and everything below it.
    let mut want: Vec<String> = trees_by_query(&hub, &dev, &p.name, "src/deep").into_iter().map(|(_, id)| id).collect();
    let on_the_way: Vec<String> = ["", "src"].iter().map(|p2| hub.api().get(Some(&dev), &format!("/v1/projects/{}/q/tree?path={p2}", p.name)).json()["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(got[..2], on_the_way[..], "the root and src come first");
    want.extend(on_the_way);
    let (mut g, mut w) = (got.clone(), want.clone());
    g.sort();
    w.sort();
    assert_eq!(g, w, "the trees of src/deep and the way there, as the query API shows them");
    // The dev's root and src trees name nothing they may not see.
    for (_, t) in trees(&r) {
        for e in &t.entries {
            for m in restricted_markers() {
                assert!(!e.name.contains(m), "a tree of the answer names {}", e.name);
            }
        }
    }
    // The whole tree, from the root: every folder the dev sees, no other.
    let r = subtree(&hub, Some(&dev), &p.name, &snap, "");
    assert_eq!(r.status, 200, "{}", body(&r));
    let all = trees(&r);
    let by_query = trees_by_query(&hub, &dev, &p.name, "");
    assert_eq!(all.len(), by_query.len(), "{by_query:?}");
    assert!(!has_marker(&r.frames().into_iter().map(|(i, b)| (i.hex(), b)).collect::<Vec<_>>(), NESTED_DIR), "the security folder");
    assert!(all.iter().all(|(_, t)| t.entries.iter().all(|e| e.kind != EntryKind::Dir || !restricted_markers().contains(&e.name.as_str()))));
}

/// A folder the caller may not see is refused exactly as a fetch of its
/// tree is (404, nothing named), and so is a snapshot it may not see; a
/// person who may see the folder gets it (control).
#[test]
fn a_folder_or_snapshot_the_caller_may_not_see_is_refused_as_fetch_refuses_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (dev, fin, admin) = (p.dev.token(), p.fin.token(), p.admin.token());
    let snap = tip(&hub, &dev, &p.name);
    let bill_tree = hub.api().get(Some(&fin), &format!("/v1/projects/{}/q/tree?path={BILL_DIR}", p.name)).json()["id"].as_str().unwrap().to_string();
    let fetch = hub.api().post_json(Some(&dev), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": snap.hex(), "objects": [{"path": BILL_DIR, "id": bill_tree}]}));
    assert_eq!(fetch.status, 404, "control: fetch refuses the dev the billing folder: {}", body(&fetch));
    for (who, path) in [(&dev, BILL_DIR.to_string()), (&dev, format!("{BILL_DIR}/acme")), (&dev, PERSON_DIR.to_string()), (&dev, format!("src/{NESTED_DIR}")), (&fin, PERSON_DIR.to_string())] {
        let r = subtree(&hub, Some(who), &p.name, &snap, &path);
        assert_eq!(r.status, 404, "{path}: {}", body(&r));
        assert_eq!(r.json()["code"], fetch.json()["code"], "{path}: {}", body(&r));
        for m in restricted_markers() {
            assert!(!body(&r).contains(m), "{path}: the refusal names {m}");
        }
    }
    // Someone with no session: the public folder only.
    let r = subtree(&hub, None, &p.name, &snap, BILL_DIR);
    assert_eq!(r.status, 404, "{}", body(&r));
    let r = subtree(&hub, None, &p.name, &snap, "src");
    assert_eq!(r.status, 200, "src is public: {}", body(&r));
    // A snapshot nobody has: as fetch.
    let none = ObjectId::hash(b"no such snapshot");
    let r = subtree(&hub, Some(&admin), &p.name, &none, "");
    let f = hub.api().post_json(Some(&admin), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": none.hex(), "objects": [{"path": "", "id": none.hex()}]}));
    assert_eq!((r.status, r.json()["code"].clone()), (f.status, f.json()["code"].clone()), "{} / {}", body(&r), body(&f));
    assert_eq!(r.status, 404);
    // Control: finance reads the billing folder, every level.
    let r = subtree(&hub, Some(&fin), &p.name, &snap, BILL_DIR);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(trees(&r).len(), 3, "the root, the billing folder and acme");
}

/// A narrowed agent session (`docs/HUB.md` §13.27): a path outside its
/// paths, the root and the folders on the way included, is refused as
/// every file route refuses it; inside, it gets the folders on the way and
/// what is below its path, as a fetch would give it.
#[test]
fn a_narrowed_agent_session_gets_only_its_paths_from_the_subtree_route() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_deep_folders(&hub, &p);
    let token = p.dev.token();
    let r = hub.api().post_json(Some(&token), "/v1/sessions/agent", &json!({"project": p.name, "attribution": {"agent": "claude-code/2.3", "task": "T", "run": "r"}, "only": ["src/deep/a"]}));
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
    let mut want: Vec<String> = ["", "src", "src/deep"].iter().map(|p2| hub.api().get(Some(&token), &format!("/v1/projects/{}/q/tree?path={p2}", p.name)).json()["id"].as_str().unwrap().to_string()).collect();
    want.extend(trees_by_query(&hub, &token, &p.name, "src/deep/a").into_iter().map(|(_, id)| id));
    let (mut g, mut w) = (got, want);
    g.sort();
    w.sort();
    assert_eq!(g, w, "the folders on the way and src/deep/a's trees, nothing of src/deep/e or src/side");
}
