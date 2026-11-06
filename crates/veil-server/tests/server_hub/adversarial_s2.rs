//! Adversarial pass on S2's secrets (`docs/HUB.md` §13.12): invites, keys
//! per access rule, background sharing, device removal. The attacker is a
//! compromised server (it writes its own rows, rings included), a removed
//! person, an outsider, or a member reaching beyond their rules.

use std::sync::Arc;

use veil_core::{
    keychain::{Keychain, KeyRing, Role},
    policy::rule_scope_of,
    Identity, MemoryBackend, StorageBackend,
};

use crate::{secrets2::*, support::*};

/// A key ring the server makes on its own: genesis signed by its own key,
/// with `members` (public identity, name, role) granted.
fn server_ring(scope: &str, srv: &Identity, members: &[(&str, &str, Role)]) -> KeyRing {
    let kc = Keychain::new(Arc::new(MemoryBackend::new()) as Arc<dyn StorageBackend>, Some(srv.clone()), "server".into());
    kc.set_format(7);
    kc.create_scope(scope).unwrap();
    for (id, name, role) in members {
        kc.grant_role(scope, id, name, *role).unwrap();
    }
    kc.load_ring(scope).unwrap().unwrap()
}

/// The server stores `ring` as the project's ring of its scope.
fn plant_ring(hub: &TestHub, p: &Project, ring: &KeyRing) {
    let body = serde_json::to_string(ring).unwrap();
    sql(
        hub,
        "INSERT INTO rings (project_id, scope, body) SELECT id, $1, $2 FROM projects WHERE name = $3 \
         ON CONFLICT (project_id, scope) DO UPDATE SET body = EXCLUDED.body",
        &[&ring.scope, &body, &p.name],
    );
}

/// The server lists `dev` as an active device of `person`.
fn list_device(hub: &TestHub, person: &str, dev: &Identity) {
    let fp = veil_core::hub::wire::device_fingerprint(&pid(dev)).unwrap();
    sql(
        hub,
        "INSERT INTO devices (person_id, signing_key, public_identity, created_at, fingerprint) SELECT id, $1, $2, 0, $3 FROM people WHERE name = $4",
        &[&dev.verifying_hex(), &dev.public_id(), &fp, &person.to_string()],
    );
}

/// BUG-840. A compromised server makes a key ring of its own (any scope
/// name) that records its device under the name of someone an admin is
/// about to add, and lists that device for them. The admin's ordinary
/// `vl pull` stores the ring; `vl group add finance newbie` (no
/// `--confirm`) then takes "a verified ring holds it under newbie's name" as
/// a confirmation and wraps `billing/`'s key for the server's device.
#[test]
fn bug_840_a_ring_the_server_made_never_confirms_a_device() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let newbie = hub.person("newbie");
    let srv = Identity::generate("srv");
    let mal = Identity::generate(&newbie.name);
    list_device(&hub, &newbie.name, &mal);
    plant_ring(&hub, &p, &server_ring("decoy", &srv, &[(&mal.public_id(), &newbie.name, Role::Member)]));
    p.admin.ok(&p.dir, &["pull"]);
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &newbie.name]);
    let (_, st) = ring(&hub, &p, &bill_scope());
    assert!(!member_of(&st, &mal), "billing/'s key was wrapped for the server's device:\n{out}");
}

/// BUG-841. A compromised server puts up a key ring for a folder rule
/// before the admin creates it (`rule-<infra>`: the scope name is public),
/// with a key it made, wrapped for the admin's device. `vl access infra/
/// ops` fetches the server's ring first and keeps it; the admin's next
/// commit seals `infra/.env` under the server's key.
#[test]
fn bug_841_a_ring_the_server_made_never_seals_a_secret() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // Its device under the admin's own name: a target of every ring.
    let srv = Identity::generate(&p.admin.name);
    let scope = rule_scope_of("infra");
    let admin = p.admin.identity();
    plant_ring(&hub, &p, &server_ring(&scope, &srv, &[(&admin.public_id(), &p.admin.name, Role::Admin)]));
    p.admin.ok(&p.dir, &["group", "create", "ops"]);
    let _ = p.admin.run(&p.dir, &["access", "infra/", "ops"]);
    write_files(&p.dir, &[("infra/.env", "TOKEN=MARKER-INFRA-SECRET-5d1e0c77\n")]);
    p.admin.commit_main(&p.dir, "infra secrets");
    let _ = p.admin.run(&p.dir, &["push"]);
    // What the server holds: the sealed object (if it was recorded at all)
    // and its own identity.
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), Some(srv), "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let tree = repo.store().snapshot(&tip).unwrap().tree;
    if let Some(e) = veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new("infra/.env").unwrap()).unwrap() {
        assert!(repo.store().read_blob(&e.id).is_err(), "the server's own key opens the admin's new infra/.env");
    }
}

/// BUG-842. An admin invites someone, changes their mind and removes them
/// from the group before they join (there is no other way to take an
/// invite back). The removed person's `vl join` still works within the 7
/// days, and the server adds them to the group: they read `billing/`.
#[test]
fn bug_842_removing_an_invited_person_cancels_their_invite() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let alice = hub.person("alice");
    let out = p.admin.ok(&p.dir, &["invite", &alice.name, "--to", "finance"]);
    let link = link_in(&out);
    let _ = p.admin.run(&p.dir, &["group", "remove", "finance", &alice.name]);
    let _ = alice.run(alice.home.path(), &["join", &link]);
    let groups = p.admin.ok(&p.dir, &["group", "list"]);
    let finance = groups.lines().find(|l| l.starts_with("finance")).unwrap_or_default().to_string();
    assert!(!finance.contains(&alice.name), "the removed person joined finance anyway: {finance}");
    // A newcomer (no account yet) can be taken back the same way.
    let newbie = hub.newcomer("newbie");
    let link = link_in(&p.admin.ok(&p.dir, &["invite", &newbie.name, "--to", "finance"]));
    let out = p.admin.run(&p.dir, &["group", "remove", "finance", &newbie.name]);
    assert!(out.status.success(), "an invite to someone who has not joined cannot be taken back: {}", String::from_utf8_lossy(&out.stderr));
    newbie.fails(newbie.home.path(), &["join", &link]);
}

/// BUG-843. Anyone can make a project, add any person to one of its groups
/// (no consent is asked) and, as its admin, `vl identity remove` that
/// person's device: the server removes it everywhere. The person's laptop
/// can no longer sign in to their own company's project, and that
/// project's rings revoke it in the background.
#[test]
#[ignore = "BUG-843: an admin of any project removes a person's device in every project"]
fn bug_843_an_admin_removes_a_device_only_for_their_own_project() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    // An outsider's own project; fin is added to a group of it.
    let evil = hub.person("evil");
    let name = unique("evil");
    let dir = evil.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    evil.ok(&dir, &["init"]);
    write_files(&dir, &[("a.txt", "a")]);
    evil.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    evil.commit_main(&dir, "x");
    evil.ok(&dir, &["push"]);
    evil.ok(&dir, &["group", "create", "g"]);
    evil.ok(&dir, &["group", "add", "g", &p.fin.name]);
    // Its own client: the device is any of fin's the server lists.
    let r = hub.api().post_json(
        Some(&evil.token()),
        "/v1/devices/remove",
        &serde_json::json!({"device": p.fin.identity().public_id(), "project": name}),
    );
    println!("remove: {} {}", r.status, String::from_utf8_lossy(&r.body));
    let out = p.fin.run(&f, &["pull"]);
    assert!(out.status.success(), "an outsider's project removed fin's device from fin's own project: {}", String::from_utf8_lossy(&out.stderr));
}

/// BUG-844. `vl upgrade --rule-keys` rewrites `.veilpolicy` first, then
/// creates the rule rings and makes `team` the admins' only. If it stops in
/// between (the server is unreachable, a 409 storm, ^C), running it again
/// says "already" and does nothing: `team` keeps every S1 member, and it
/// now seals the admins' secrets (paths no line names anyone for), so they
/// open the admins' new `.env`.
#[test]
fn bug_844_an_interrupted_rule_keys_move_is_finished_by_a_rerun() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let dev = hub.person("dev");
    let name = unique("old");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    let s2 = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    std::fs::write(dir.join(".veilpolicy"), s2.replace("cloak rule", "cloak team")).unwrap();
    write_files(&dir, &[("src/lib.rs", "fn main() {}")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "s1");
    admin.ok(&dir, &["push"]);
    admin.ok(&dir, &["group", "create", "devs"]);
    admin.ok(&dir, &["group", "add", "devs", &dev.name, "--confirm", &dev.fingerprint()]);
    admin.ok(&dir, &["access", "src/", "devs"]);
    admin.commit_main(&dir, "access");
    admin.ok(&dir, &["push"]);
    // The first run stopped right after rewriting the policy.
    let text = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    let rewritten: Vec<String> = text
        .lines()
        .map(|l| {
            let f = veil_core::policy::split_fields(l);
            if f.len() == 3 && f[1] == "cloak" && f[2] == "team" { format!("{:<25}cloak rule", f[0]) } else { l.to_string() }
        })
        .collect();
    std::fs::write(dir.join(".veilpolicy"), rewritten.join("\n") + "\n").unwrap();
    let out = admin.ok(&dir, &["upgrade", "--rule-keys"]);
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&dir)), None, "test").unwrap();
    let team = repo.keys().ring_state(veil_core::policy::DEFAULT_SCOPE).unwrap().unwrap().unwrap();
    assert!(!member_of(&team, &dev.identity()), "the move was reported done and team still holds a non-admin:\n{out}");
}

/// BUG-845. Rule scope names depend on the path only (`rule-<billing>` is
/// the same in every project), and a ring does not say which project it
/// belongs to. An admin runs two projects with a `billing/` line. Their
/// new laptop clones project B; the compromised server hands it project A's
/// `billing/` ring (started by the same admin, so it passes BUG-840's
/// check), and the laptop seals B's `billing/.env` under A's key: A's
/// finance, who have nothing in B, open it.
#[test]
#[ignore = "BUG-845: a ring of another project with the same rule path seals this project's secrets"]
fn bug_845_a_ring_of_another_project_never_seals_a_secret() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // The admin's second project, with its own billing/ line and ring.
    let b = unique("bee");
    let bdir = p.admin.dir("b");
    std::fs::create_dir_all(&bdir).unwrap();
    p.admin.ok(&bdir, &["init"]);
    write_files(&bdir, &[("README.md", "b")]);
    p.admin.ok(&bdir, &["remote", "add", "origin", &hub.url(&b)]);
    p.admin.commit_main(&bdir, "b");
    p.admin.ok(&bdir, &["push"]);
    p.admin.ok(&bdir, &["group", "create", "finance"]);
    p.admin.ok(&bdir, &["group", "add", "finance", &p.sec.name, "--confirm", &p.sec.fingerprint()]);
    p.admin.ok(&bdir, &["access", &format!("{BILL_DIR}/"), "finance"]);
    p.admin.commit_main(&bdir, "access");
    p.admin.ok(&bdir, &["push"]);
    // The admin's new laptop, confirmed from their first device (and given
    // project A's keys by it).
    let laptop = hub.new_device_of(&p.admin);
    p.admin.ok(&p.dir, &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--name", &p.admin.name, "--ca", hub.ca.to_str().unwrap()]);
    assert!(member_of(&ring(&hub, &p, &bill_scope()).1, &laptop.identity()), "the laptop holds project A's billing/ key");
    // The server serves A's billing/ ring as B's.
    let (a_ring, _) = ring(&hub, &p, &bill_scope());
    let body = serde_json::to_string(&a_ring).unwrap();
    sql(&hub, "UPDATE rings SET body = $1 WHERE scope = $2 AND project_id = (SELECT id FROM projects WHERE name = $3)", &[&body, &bill_scope(), &b]);
    let bl = laptop.dir("b");
    laptop.ok(laptop.home.path(), &["clone", &hub.url(&b), bl.to_str().unwrap()]);
    write_files(&bl, &[(&format!("{BILL_DIR}/.env") as &str, "B=MARKER-PROJECT-B-SECRET-2b9c\n")]);
    laptop.commit_main(&bl, "b secrets");
    // What A's finance member opens, if the server hands it to them.
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&bl)), None, "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let tree = repo.store().snapshot(&tip).unwrap().tree;
    let Some(e) = veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(&format!("{BILL_DIR}/.env")).unwrap()).unwrap() else { panic!("not recorded") };
    let raw = (e.id, repo.store().get_raw(&e.id).unwrap());
    let f = clone(&hub, &p, &p.fin, "f");
    assert!(!opens(&p.fin, &f, &raw), "project A's finance member opens project B's billing/.env");
}

/// BUG-846. `vl access billing/ finance` while finance has nobody else in
/// it builds the line's key ring, finds nobody to grant and drops it: the
/// ring is never created, so the admin's own `billing/.env` is "kept
/// local-only" (no key for its scope) until someone joins finance.
#[test]
fn bug_846_an_access_line_gets_its_ring_with_nobody_else_in_it() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("solo");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, &[("README.md", "x")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "x");
    admin.ok(&dir, &["push"]);
    admin.ok(&dir, &["group", "create", "finance"]);
    admin.ok(&dir, &["access", "billing/", "finance"]);
    write_files(&dir, &[("billing/.env", "K=v\n")]);
    let out = admin.ok(&dir, &["commit", "-m", "secret"]);
    assert!(!out.contains("kept local-only"), "{out}");
}
