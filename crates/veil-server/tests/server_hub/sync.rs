//! Sync through the server: clone one directory, pull what others push,
//! secrets keys granted and rotated by group changes, and signatures that
//! verify in every viewer's history.

use std::sync::Arc;

use crate::support::*;

#[test]
fn clone_one_directory_fetches_only_that_subtree() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("only");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap(), "--only", BILL_DIR]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists());
    assert!(!d.join("src/lib.rs").exists(), "a file outside --only was written");
    let objects = everything_in(&d);
    assert!(!has_marker(&objects, PUBLIC_MARK), "an object outside --only was fetched");
    // Edit and push from the one-directory clone; the rest is kept.
    write_files(&d, &[(&format!("{BILL_DIR}/acme/invoice.txt") as &str, "from a partial clone")]);
    p.fin.commit_main(&d, "partial edit");
    p.fin.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert_eq!(std::fs::read_to_string(p.dir.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    assert_eq!(std::fs::read_to_string(p.dir.join(BILL_DIR).join("acme/invoice.txt")).unwrap(), "from a partial clone");
}

#[test]
fn people_see_each_others_pushes_and_every_signature_verifies() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/dev.rs", "fn dev() {}")]);
    p.dev.commit_main(&d, "dev change");
    p.dev.ok(&d, &["push"]);
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(f.join("src/dev.rs").exists());
    write_files(&f, &[(&format!("{BILL_DIR}/q.txt") as &str, "q")]);
    p.fin.commit_main(&f, "finance change");
    p.fin.ok(&f, &["push"]);
    p.dev.ok(&d, &["pull"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert!(p.dir.join(BILL_DIR).join("q.txt").exists() && p.dir.join("src/dev.rs").exists());
    // Every snapshot each viewer holds carries a valid signature: the
    // author's, or the server's on a projection.
    for dir in [&d, &f, &p.dir] {
        let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
        let mut stack = vec![repo.view().tags["main"].target];
        let mut seen = 0;
        while let Some(id) = stack.pop() {
            if id == repo.root_id() {
                continue;
            }
            let s = repo.store().snapshot(&id).unwrap();
            assert_eq!(s.signature_valid(), Some(true), "{} in {}", id.short(), dir.display());
            stack.extend(s.parents.iter().copied());
            seen += 1;
        }
        assert!(seen >= 2, "{seen} snapshots in {}", dir.display());
    }
    // The dev's own snapshot comes back to them with their own signature.
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&d)), None, "test").unwrap();
    let mine = (|| {
        let mut stack = vec![repo.view().tags["main"].target];
        while let Some(id) = stack.pop() {
            let s = repo.store().snapshot(&id).unwrap();
            if matches!(&s.description, veil_core::object::Text::Plain(t) if t.contains("dev change")) {
                return s;
            }
            stack.extend(s.parents.iter().copied());
        }
        panic!("the dev's change is missing")
    })();
    assert_eq!(mine.signature.as_ref().unwrap().key, p.dev.identity().verifying_hex());
}

#[test]
fn group_changes_grant_and_rotate_secret_keys() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // fin was added by the admin: their device holds the team key.
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    // A manager's addition reaches the server's group, but the key needs a
    // ring admin's signature: until then the secret stays closed.
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    let c = p.carol.dir("c");
    p.carol.ok(p.carol.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    // Someone in no group yet, so no admin's device ever granted them a key.
    let newbie = hub.person("newbie");
    let out = p.carol.ok(&c, &["group", "add", "finance", &newbie.name]);
    assert!(out.contains("key-ring admin"), "{out}");
    let d = newbie.dir("c");
    newbie.ok(newbie.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists(), "folder access is the server's record");
    assert!(!d.join(BILL_DIR).join(".env").exists(), "no key without an admin's signature");
    assert_no_marker(&everything_in(&d), &[ENV_MARK], &newbie.name);
    // Removing fin from every group rotates the key away from them.
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("rotated away"), "{out}");
}
