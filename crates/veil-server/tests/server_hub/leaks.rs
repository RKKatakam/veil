//! Confidentiality: nobody receives a file, or a name, from a folder they
//! have no access to, by any route (`docs/VISIBILITY.md`; brief S1 §5).
//!
//! The project has one folder per rule kind, each with a unique marker in
//! its content and in a name: the private root (no rule), a group's folder,
//! a person's folder, a restricted folder nested inside a public one, and a
//! sealed `.env`. Each viewer clones, logs and lists, and then crawls the
//! API with their session, including with the real ids an admin sees; every
//! byte they obtain is searched for every marker they may not see (whole
//! markers only). Safety is checked before liveness.

use serde_json::json;
use veil_core::{hub::wire::read_frames, ObjectId};

use crate::support::*;

/// Everything `who` (with `token`, or anyone on Earth) gets from the API
/// for `project`, given the real paths and snapshot ids an admin sees.
fn crawl(api: &Api, token: Option<&str>, project: &str, real: &[(String, ObjectId)], snaps: &[ObjectId]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut keep = |what: String, r: Reply| {
        out.push((what, r.body));
    };
    let tips = api.get(token, &format!("/v1/projects/{project}/tips"));
    let tips_json = tips.json();
    keep("tips".into(), tips);
    let tip_ids: Vec<String> = tips_json["branches"]
        .as_object()
        .map(|m| m.values().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // History from the tips the viewer was given, and from every real id.
    let h = api.post_json(token, &format!("/v1/projects/{project}/history"), &json!({"tips": tip_ids, "stop": []}));
    let mut viewer_snaps: Vec<ObjectId> = Vec::new();
    if h.status == 200 {
        for (id, raw) in read_frames(&h.body).unwrap() {
            viewer_snaps.push(id);
            if let Ok(veil_core::object::Object::Snapshot(s)) = veil_core::object::Object::decode(raw) {
                viewer_snaps.push(s.tree);
            }
        }
    }
    keep("history of my tips".into(), h);
    for s in snaps {
        let r = api.post_json(token, &format!("/v1/projects/{project}/history"), &json!({"tips": [s.hex()], "stop": []}));
        keep(format!("history of real {}", s.short()), r);
    }
    // Fetch: every real object at its real path, under every snapshot
    // the viewer knows and every real one, and at the root path.
    let mut under: Vec<ObjectId> = snaps.to_vec();
    under.extend(viewer_snaps.iter().copied());
    for snap in &under {
        for (path, id) in real {
            for p in [path.as_str(), ""] {
                let r = api.post_json(
                    token,
                    &format!("/v1/projects/{project}/fetch"),
                    &json!({"snapshot": snap.hex(), "objects": [{"path": p, "id": id.hex()}]}),
                );
                keep(format!("fetch {p:?} {} under {}", id.short(), snap.short()), r);
            }
        }
    }
    for (path, _) in real {
        let r = api.get(token, &format!("/v1/projects/{project}/access?path={path}"));
        keep(format!("access {path}"), r);
    }
    keep("groups".into(), api.get(token, &format!("/v1/projects/{project}/groups")));
    keep("rings".into(), api.get(token, &format!("/v1/projects/{project}/rings")));
    out
}

/// What `who` gets by cloning (all of it, and each restricted folder with
/// `--only`), logging and listing.
fn through_vl(hub: &TestHub, who: &Person, project: &str, only: &[&str]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let dir = who.dir("clone");
    who.ok(who.home.path(), &["clone", &hub.url(project), dir.to_str().unwrap()]);
    for args in [&["log"][..], &["files", "-r", "main"], &["show", "main"], &["status"], &["ls", "-r", "main"]] {
        let o = who.run(&dir, args);
        out.push((format!("vl {args:?}"), [o.stdout, o.stderr].concat()));
    }
    out.extend(everything_in(&dir));
    for (i, o) in only.iter().enumerate() {
        let d = who.dir(&format!("only{i}"));
        let r = who.run(who.home.path(), &["clone", &hub.url(project), d.to_str().unwrap(), "--only", o]);
        // The clone's own message repeats the name the caller typed: only
        // what the server sent counts.
        let said = String::from_utf8_lossy(&[r.stdout, r.stderr].concat()).replace(o, "<asked>");
        out.push((format!("clone --only {o}"), said.into_bytes()));
        if d.exists() {
            out.extend(everything_in(&d));
        }
    }
    out
}

#[test]
fn no_viewer_receives_bytes_or_names_of_a_folder_they_cannot_see() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let real = real_paths(&p.dir);
    let snaps = real_snapshots(&p.dir);
    let api = hub.api();
    let only = [BILL_DIR, PERSON_DIR, &format!("src/{NESTED_DIR}") as &str, ""];
    let only: Vec<&str> = only.into_iter().filter(|o| !o.is_empty()).collect();

    // (viewer, the markers they may see)
    let anyone = hub.anyone();
    let cases: Vec<(&Person, Option<String>, Vec<&str>)> = vec![
        (&anyone, None, vec![]),
        (&p.dev, Some(p.dev.token()), vec![]),
        (&p.fin, Some(p.fin.token()), vec![BILL_DIR, BILL_MARK, ENV_MARK, DESC_MARK]),
        (&p.carol, Some(p.carol.token()), vec![PERSON_DIR, PERSON_MARK]),
        (&p.sec, Some(p.sec.token()), vec![NESTED_DIR, NESTED_MARK]),
    ];
    for (who, token, allowed) in &cases {
        let forbidden: Vec<&str> = restricted_markers().into_iter().filter(|m| !allowed.contains(m)).collect();
        // Safety first: every route.
        let mut got = through_vl(&hub, who, &p.name, &only);
        got.extend(crawl(&api, token.as_deref(), &p.name, &real, &snaps));
        assert_no_marker(&got, &forbidden, &who.name);
        // Then liveness: what they may see, they have.
        let clone = everything_in(&who.dir("clone"));
        assert!(has_marker(&clone, PUBLIC_MARK), "{} lacks the public folder", who.name);
        for m in allowed.iter().filter(|m| **m != ENV_MARK && **m != DESC_MARK) {
            assert!(has_marker(&clone, m), "{} lacks {m}", who.name);
        }
    }
    // The finance member holds the secret key (granted by the admin's
    // `vl group add`): the .env opens on their device only.
    let env = std::fs::read_to_string(p.fin.dir("clone").join(BILL_DIR).join(".env")).unwrap();
    assert!(env.contains(ENV_MARK), "{env}");
    // The server never holds the secret in plain text.
    let hubref = hub.hub();
    let project_id: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hubref.db))
        .unwrap();
    let admin_objects = everything_in(&p.dir);
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let mut on_server = Vec::new();
    for id in repo.store().list_objects().unwrap() {
        if let Some(b) = hub.rt.block_on(hubref.objects.get(project_id, &id)).unwrap() {
            on_server.push((format!("server object {}", id.short()), b.to_vec()));
        }
    }
    assert!(on_server.len() > 5, "the server holds the project's objects");
    assert_no_marker(&on_server, &[ENV_MARK], "the server");
    assert!(has_marker(&admin_objects, BILL_MARK), "the admin's own store is complete");
}

#[test]
fn anyone_on_earth_sees_public_folders_only_and_private_projects_not_at_all() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let anyone = hub.anyone();
    let dir = anyone.dir("c");
    anyone.ok(anyone.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    let mut files: Vec<String> = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.file_name() == ".veil" {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                files.push(e.path().strip_prefix(&dir).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    assert_eq!(files, ["src/lib.rs"]);
    // Anyone cannot upload, push, create groups or read rings.
    let api = hub.api();
    assert_eq!(api.upload_anon(&p.name).status, 401);
    let r = api.post_json(None, &format!("/v1/projects/{}/push", p.name), &json!({"updates": []}));
    assert_eq!(r.status, 401);
    assert_eq!(api.get(None, &format!("/v1/projects/{}/rings", p.name)).status, 401);
    assert_eq!(api.post_json(None, &format!("/v1/projects/{}/groups/x", p.name), &json!({})).status, 401);
    // A project with nothing public does not exist for anyone on Earth,
    // nor for a signed-in stranger.
    let admin = hub.person("solo");
    let d = admin.dir("solo");
    std::fs::create_dir_all(&d).unwrap();
    admin.ok(&d, &["init"]);
    write_files(&d, &[("plan.txt", ROOT_MARK)]);
    let name = unique("private");
    admin.ok(&d, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&d, "x");
    admin.ok(&d, &["push"]);
    assert!(api.tips(None, &name).is_none());
    let stranger = hub.person("stranger");
    assert!(api.tips(Some(&stranger.token()), &name).is_none());
    let out = anyone.fails(anyone.home.path(), &["clone", &hub.url(&name), anyone.dir("p").to_str().unwrap()]);
    assert!(!out.contains(ROOT_MARK), "{out}");
}

#[test]
fn removing_someone_from_a_group_stops_serving_at_once() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.fin.token();
    let real = real_paths(&p.dir);
    let (path, id) = real.iter().find(|(p, _)| p.ends_with("invoice.txt")).unwrap().clone();
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let fetch = |t: &str| {
        api.post_json(
            Some(t),
            &format!("/v1/projects/{}/fetch", p.name),
            &json!({"snapshot": tip.hex(), "objects": [{"path": path, "id": id.hex()}]}),
        )
    };
    assert_eq!(fetch(&token).status, 200, "a member reads the file");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let r = fetch(&token);
    assert_eq!(r.status, 404, "the next request is refused");
    assert_no_marker(&[("after removal".into(), r.body)], &[BILL_MARK], &p.fin.name);
}

/// Revision 1: one fetch names objects of several snapshots
/// (`Want::snapshot`). Each want is checked in its own snapshot, as its
/// viewer sees it: what another snapshot holds is not served through it,
/// and nothing restricted is served through any.
#[test]
fn fetch_across_snapshots_checks_each_want_in_its_own_snapshot() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let tips = api.tips(Some(&token), &p.name).unwrap();
    assert_eq!(tips.revision, veil_core::hub::wire::REVISION);
    let before = tips.branches["main"];
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/across.txt", "across snapshots");
    let r = c.push("main", "a new file");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let after = veil_core::ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
    let id = veil_core::ObjectId::hash(&veil_core::object::Object::Blob(b"across snapshots".to_vec()).encode());
    let fetch = |wants: serde_json::Value| api.post_json(Some(&token), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": before.hex(), "objects": wants}));
    // In the snapshot it names: served.
    let got = fetch(json!([{"path": "src/across.txt", "id": id.hex(), "snapshot": after.hex()}]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(got.frames()[0].0, id);
    // In the request's snapshot, where it is not: refused.
    assert_eq!(fetch(json!([{"path": "src/across.txt", "id": id.hex()}])).status, 404);
    // Restricted objects, named in any snapshot the viewer was shown, or
    // in a real one: never.
    let real = real_paths(&p.dir);
    let admin_tip = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    for (path, oid) in real.iter().filter(|(q, _)| q.starts_with(BILL_DIR) || q.starts_with(ROOT_FILE)) {
        for snap in [before, after, admin_tip] {
            let r = fetch(json!([{"path": "src/across.txt", "id": id.hex(), "snapshot": after.hex()}, {"path": path, "id": oid.hex(), "snapshot": snap.hex()}]));
            assert_eq!(r.status, 404, "{path} in {}", snap.short());
            assert_no_marker(&[("fetch".into(), r.body)], &restricted_markers(), &p.dev.name);
        }
    }
}

/// BUG-839: `vl tag set NAME --cloak` makes a tag whose name is sealed for
/// its scope, and before the Veil server no public remote ever received
/// it. `vl push` to the server sends every local tag as a branch, cloaked
/// ones too, and the server shows branch names to everyone who may read
/// anything in the project: anyone on Earth, once a folder is public.
#[test]
#[ignore = "BUG-839: a cloaked tag's name is pushed to the server as a branch everyone sees"]
fn bug_839_a_cloaked_tag_name_never_reaches_anyone_on_earth() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    const TAG: &str = "plan-acquire-initech-6d1f";
    p.admin.ok(&p.dir, &["tag", "set", TAG, "-r", "main", "--cloak"]);
    let _ = p.admin.run(&p.dir, &["push"]);
    let api = hub.api();
    let tips = api.tips(None, &p.name);
    assert!(
        tips.as_ref().is_none_or(|t| !t.branches.contains_key(TAG)),
        "anyone on Earth sees the cloaked tag's name: {tips:?}"
    );
    assert!(api.tips(None, &p.name).is_some(), "control: the project has public folders");
}
