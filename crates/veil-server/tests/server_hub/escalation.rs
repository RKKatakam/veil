//! Privilege escalation is refused (brief S1 §5): `.veilpolicy` access
//! edits by non-admins, group self-adds and managers' overreach, writes
//! into folders without access, forced or deleting branch moves, and
//! labels inside pushed snapshots used as authority.

use serde_json::json;
use veil_core::object::{Object, Visibility};

use crate::support::*;

fn tip(hub: &TestHub, p: &Project) -> veil_core::ObjectId {
    hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"]
}

#[test]
fn only_admins_change_access_lines() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // devs may read and write .veilpolicy itself, but not change access.
    p.admin.ok(&p.dir, &["access", ".veilpolicy", "devs"]);
    p.admin.commit_main(&p.dir, "devs edit the policy file");
    p.admin.ok(&p.dir, &["push"]);
    let before = tip(&hub, &p);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    let policy = std::fs::read_to_string(d.join(".veilpolicy")).unwrap();
    for (what, edited) in [
        ("grant themselves the nested folder", policy.replace(&format!("src/{NESTED_DIR}/       security"), &format!("src/{NESTED_DIR}/       devs"))),
        ("add a rule", format!("{policy}{BILL_DIR}/ devs\n")),
        ("make the root public", format!("{policy}{ROOT_FILE} public\n")),
        ("drop every rule", "# nothing\n".to_string()),
    ] {
        assert_ne!(edited, policy, "{what}: the edit changed nothing");
        std::fs::write(d.join(".veilpolicy"), &edited).unwrap();
        p.dev.commit_main(&d, what);
        let out = p.dev.fails(&d, &["push"]);
        assert!(out.contains("only admins"), "{what}: {out}");
        // Not on a side branch either.
        p.dev.ok(&d, &["tag", "set", "side", "-r", "main", "--force"]);
        let out = p.dev.fails(&d, &["push", "-t", "side"]);
        assert!(out.contains("only admins"), "{what} on a side branch: {out}");
        p.dev.ok(&d, &["tag", "delete", "side"]);
        p.dev.ok(&d, &["tag", "set", "main", "-r", "origin/main", "--force"]);
        p.dev.ok(&d, &["new", "main"]);
        std::fs::write(d.join(".veilpolicy"), &policy).unwrap();
    }
    assert_eq!(tip(&hub, &p), before, "nothing landed");
    // A line that is not an access line is theirs to edit.
    std::fs::write(d.join(".veilpolicy"), format!("{policy}*.log ignore\n")).unwrap();
    p.dev.commit_main(&d, "ignore logs");
    p.dev.ok(&d, &["push"]);
    // And the access they tried to take is still not theirs.
    let api = hub.api();
    let got = api.post_json(Some(&p.dev.token()), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip(&hub, &p).hex()]}));
    assert_no_marker(&[("history".into(), got.body)], &restricted_markers(), &p.dev.name);
}

#[test]
fn group_self_adds_and_manager_overreach_are_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let home = p.dev.home.path();
    let d = p.dev.dir("c");
    p.dev.ok(home, &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    for args in [
        vec!["group", "add", "finance", p.dev.name.as_str()],
        vec!["group", "add", "devs", p.carol.name.as_str()],
        vec!["group", "remove", "finance", p.fin.name.as_str()],
        vec!["group", "manager", "finance", p.dev.name.as_str()],
        vec!["group", "create", "newgroup"],
    ] {
        let out = p.dev.fails(&d, &args);
        assert!(out.contains("only an admin") || out.contains("forbidden"), "{args:?}: {out}");
    }
    // A manager adds and removes other people, never themselves, and
    // cannot choose managers or create groups.
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    let c = p.carol.dir("c");
    p.carol.ok(p.carol.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let out = p.carol.fails(&c, &["group", "add", "finance", &p.carol.name]);
    assert!(out.contains("ask an admin"), "{out}");
    p.carol.fails(&c, &["group", "manager", "finance", &p.dev.name]);
    p.carol.fails(&c, &["group", "create", "x"]);
    p.carol.fails(&c, &["group", "add", "security", &p.dev.name]);
    p.carol.ok(&c, &["group", "add", "finance", &p.dev.name]);
    p.carol.ok(&c, &["group", "remove", "finance", &p.dev.name]);
    // Groups are listed only to their members, managers and admins.
    let list = p.dev.ok(&d, &["group", "list"]);
    assert!(list.contains("devs") && !list.contains("finance") && !list.contains("security"), "{list}");
    // A name binds to the project's group before any person: someone who
    // signs up under a group's name before the group exists gains nothing.
    let api = hub.api();
    let gname = unique("grp");
    let squat = veil_core::Identity::generate("squat");
    let token = api.login(&squat, Some(&gname)).unwrap();
    p.admin.ok(&p.dir, &["group", "create", &gname]);
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("squatted/plan.txt", "MARKER-SQUAT-CONTENT-77d1e0a2")]);
    p.admin.ok(&p.dir, &["access", "squatted/", &gname]);
    p.admin.commit_main(&p.dir, "new folder");
    let out = p.admin.ok(&p.dir, &["push"]);
    assert!(out.contains(&format!("squatted/ → group {gname}")), "{out}");
    let got = api.post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip(&hub, &p).hex()]}));
    assert_no_marker(&[("squatter".into(), got.body)], &["MARKER-SQUAT-CONTENT-77d1e0a2", "squatted"], "a squatter");
}

#[test]
fn writes_into_folders_without_access_are_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let before = tip(&hub, &p);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    for (path, who) in [
        (format!("{BILL_DIR}/new.txt"), &p.dev),
        (format!("src/{NESTED_DIR}/x.txt"), &p.dev),
        ("NEW-AT-ROOT.txt".to_string(), &p.dev),
        (format!("{PERSON_DIR}/x.txt"), &p.dev),
    ] {
        write_files(&d, &[(&path, "x")]);
        who.commit_main(&d, "try");
        let out = who.fails(&d, &["push"]);
        assert!(out.contains("you do not have access") || out.contains("may not write"), "{path}: {out}");
        who.ok(&d, &["tag", "set", "main", "-r", "origin/main", "--force"]);
        who.ok(&d, &["new", "main"]);
        let _ = std::fs::remove_file(d.join(&path));
    }
    // Read-only: finance reads the public src/ but may not write it.
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    write_files(&f, &[("src/lib.rs", "changed")]);
    p.fin.commit_main(&f, "try");
    let out = p.fin.fails(&f, &["push"]);
    assert!(out.contains("may not write 'src/lib.rs'"), "{out}");
    assert_eq!(tip(&hub, &p), before, "nothing landed");
    // What they may write lands, and keeps what they cannot see.
    p.dev.ok(&d, &["new", "main"]);
    write_files(&d, &[("src/ok.rs", "fn ok() {}")]);
    p.dev.commit_main(&d, "dev writes src");
    p.dev.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    let real = real_paths(&p.dir);
    for want in ["src/ok.rs", ROOT_FILE, &format!("{BILL_DIR}/acme/invoice.txt") as &str, &format!("src/{NESTED_DIR}/key.txt")] {
        p.admin.ok(&p.dir, &["new", "main"]);
        assert!(real.iter().any(|(path, _)| path == want), "{want} missing after the graft: {real:?}");
    }
}

#[test]
fn forced_and_deleting_branch_moves_need_an_admin() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    // Back to the first snapshot (before any access line existed).
    p.dev.ok(&d, &["tag", "set", "main", "-r", "main-", "--force"]);
    let out = p.dev.fails(&d, &["push", "--force"]);
    assert!(out.contains("only admins may force"), "{out}");
    let out = p.dev.fails(&d, &["push"]);
    assert!(out.contains("fast-forward") || out.contains("moved"), "{out}");
    let api = hub.api();
    let t = tip(&hub, &p);
    let r = api.post_json(
        Some(&p.dev.token()),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "main", "expected": api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"].hex(), "new": null}]}),
    );
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(tip(&hub, &p), t);
}

#[test]
fn labels_in_pushed_snapshots_are_never_authority() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // An admin's side branch with a permissive policy grants nothing: only
    // the accepted policy (the default branch's) decides.
    p.admin.ok(&p.dir, &["new", "main"]);
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), "devs"]);
    p.admin.ok(&p.dir, &["commit", "-m", "experiment"]);
    p.admin.ok(&p.dir, &["tag", "set", "exp", "-r", "@-"]);
    p.admin.ok(&p.dir, &["push", "-t", "exp"]);
    let api = hub.api();
    let token = p.dev.token();
    let tips = api.tips(Some(&token), &p.name).unwrap();
    let mut got = Vec::new();
    for t in tips.branches.values() {
        let h = api.post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [t.hex()]}));
        got.push(("history".into(), h.body));
    }
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    got.extend(everything_in(&d));
    assert_no_marker(&got, &[BILL_DIR, BILL_MARK], &p.dev.name);
    // A crafted snapshot labelling a hidden folder's file as public, or as
    // sealed for a scope the crafter holds, is still a write to a folder
    // they cannot see.
    for vis in [Visibility::Public, Visibility::Cloaked { scope: "team".into() }] {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.set(&format!("{BILL_DIR}/acme/invoice.txt"), Object::Blob(b"overwritten".to_vec()), vis);
        let r = c.push("main", "label trick");
        assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    }
}

#[test]
fn secrets_arrive_sealed_and_personal_keys_never() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    for (path, obj, vis, why) in [
        (format!("{BILL_DIR}/.env"), Object::Blob(b"PLAIN=1".to_vec()), Visibility::Public, "encrypted"),
        (format!("{BILL_DIR}/prod.env.local"), Object::Blob(b"x".to_vec()), Visibility::Public, ""),
        (format!("{BILL_DIR}/.netrc"), Object::Blob(b"machine x".to_vec()), Visibility::Public, "stays on the device"),
        (format!("{BILL_DIR}/id_ed25519"), Object::Blob(b"KEY".to_vec()), Visibility::Public, "personal private key"),
    ] {
        let mut c = Craft::new(&api, &p.fin, &p.name, "main");
        c.set(&path, obj, vis);
        let r = c.push("main", "secret");
        if why.is_empty() {
            // Not a secret name: an ordinary file of finance's folder.
            assert_eq!(r.status, 200, "{path}: {}", String::from_utf8_lossy(&r.body));
            continue;
        }
        assert_eq!(r.status, 403, "{path}: {}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains(why), "{path}: {}", String::from_utf8_lossy(&r.body));
    }
}
