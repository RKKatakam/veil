//! Crossing projects (BUG-843, BUG-845): a compromised server tries every
//! route to make one project's key ring seal or confirm another's secrets,
//! and a project's admin tries to reach a person's other projects. Each key
//! ring names its project in its signed genesis, and a device trusts a
//! project's rings only once it confirmed the project's fingerprint (an
//! invite link carries it); an admin removes a device from their project
//! only (`docs/HUB.md` §13.12).

use std::path::Path;

use veil_core::{keychain::RingChange, policy::rule_scope_of, Repo};

use crate::{adversarial_s2::*, secrets2::*, support::*};

fn repo(dir: &Path) -> Repo {
    Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap()
}

/// The server's `team` ring of `project`.
fn team_of(hub: &TestHub, p: &Project, project: &str) -> veil_core::keychain::KeyRing {
    let r = hub.api().get(Some(&p.admin.token()), &format!("/v1/projects/{project}/rings/team"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    serde_json::from_slice(&r.body).unwrap()
}

/// A ring served under another scope name, or with a change of another
/// project's ring replayed onto it, never verifies; and the server itself
/// refuses a ring whose genesis names another project.
#[test]
fn renamed_or_replayed_rings_never_cross_projects() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (b, bdir) = second_project(&hub, &p);
    let (a_bill, _) = ring(&hub, &p, &bill_scope());
    // Renamed: A's billing/ ring served as B's ring of another path.
    let money = rule_scope_of("money");
    let mut renamed = a_bill.clone();
    renamed.scope = money.clone();
    plant_in(&hub, &b, &renamed);
    let out = p.admin.ok(&bdir, &["pull"]);
    assert!(repo(&bdir).keys().load_ring(&money).unwrap().is_none(), "a renamed ring was taken:\n{out}");
    // Replayed: the last change of A's billing/ ring appended to B's.
    let r = hub.api().get(Some(&p.admin.token()), &format!("/v1/projects/{b}/rings/{}", bill_scope()));
    let b_bill: veil_core::keychain::KeyRing = serde_json::from_slice(&r.body).unwrap();
    let mut replayed = b_bill.clone();
    let mut c: RingChange = a_bill.log.last().unwrap().clone();
    c.seq = replayed.log.len() as u64;
    c.prev = replayed.log.last().unwrap().hash(&replayed.scope);
    replayed.log.push(c);
    assert!(replayed.verify().is_err(), "a change of A's ring verifies on B's");
    plant_in(&hub, &b, &replayed);
    p.admin.ok(&bdir, &["pull"]);
    assert_eq!(repo(&bdir).keys().load_ring(&bill_scope()).unwrap().unwrap(), b_bill, "B's clone took the replayed change");
    // The server refuses a ring that names another project, as a new ring
    // of a project that has none for its scope.
    let c_name = unique("cee");
    let cdir = p.admin.dir("c");
    std::fs::create_dir_all(&cdir).unwrap();
    p.admin.ok(&cdir, &["init"]);
    write_files(&cdir, &[("c.txt", "c")]);
    p.admin.ok(&cdir, &["remote", "add", "origin", &hub.url(&c_name)]);
    p.admin.commit_main(&cdir, "c");
    p.admin.ok(&cdir, &["push"]);
    let r = hub.api().post_json(
        Some(&p.admin.token()),
        &format!("/v1/projects/{c_name}/rings/{}", bill_scope()),
        &serde_json::to_value(&a_bill).unwrap(),
    );
    assert_eq!(r.status, 400, "the server stored another project's ring: {}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("does not belong to this project"));
}

/// A device's first clone of a project takes no key ring until the device
/// confirmed the project's fingerprint; then only the `team` ring with
/// that fingerprint. A server that serves another project's `team` gets
/// nothing trusted: the confirmation fails, and a device that confirmed
/// the real one refuses it.
#[test]
fn a_first_clone_trusts_only_the_confirmed_team_ring() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (b, bdir) = second_project(&hub, &p);
    let b_fp = p.admin.project_fingerprint(&bdir);
    assert_ne!(b_fp, p.fp, "two projects with one fingerprint");
    write_files(&bdir, &[(&format!("{BILL_DIR}/.env") as &str, "B=MARKER-B-ENV-61d0e2aa\n")]);
    p.admin.commit_main(&bdir, "b secret");
    p.admin.ok(&bdir, &["push"]);
    // sec was granted B's billing/ key, but their device trusts only A yet.
    let s = p.sec.dir("b");
    let out = p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&b), s.to_str().unwrap()]);
    assert!(out.contains(&b_fp) && out.contains("vl identity confirm"), "{out}");
    assert!(!s.join(BILL_DIR).join(".env").exists(), "a clone opened a secret before trusting the project");
    assert!(repo(&s).keys().load_ring("team").unwrap().is_none(), "an unconfirmed clone stored a key ring");
    // Another project's fingerprint confirms nothing here.
    p.sec.fails(&s, &["identity", "confirm", &p.fp]);
    p.sec.ok(&s, &["identity", "confirm", &b_fp]);
    assert!(std::fs::read_to_string(s.join(BILL_DIR).join(".env")).unwrap().contains("MARKER-B-ENV-61d0e2aa"));
    // The server now serves A's `team` as B's.
    let a_team = team_of(&hub, &p, &p.name);
    plant_in(&hub, &b, &a_team);
    // A device that confirmed B before refuses it on a new clone...
    let s2 = p.sec.dir("b2");
    let out = p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&b), s2.to_str().unwrap()]);
    assert!(out.contains("not the project's key ring this device confirmed"), "{out}");
    assert!(!s2.join(BILL_DIR).join(".env").exists());
    // ...and a new device cannot confirm B's real fingerprint against it.
    let laptop = hub.new_device_of(&p.admin);
    p.admin.ok(&p.dir, &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let l = laptop.dir("b");
    laptop.ok(laptop.home.path(), &["clone", &hub.url(&b), l.to_str().unwrap()]);
    laptop.fails(&l, &["identity", "confirm", &b_fp]);
    assert!(repo(&l).keys().load_ring("team").unwrap().is_none());
    // Nothing the laptop commits there is sealed under A's keys.
    write_files(&l, &[(&format!("{BILL_DIR}/.env") as &str, "B=MARKER-B-LAPTOP-0c93\n")]);
    laptop.commit_main(&l, "laptop secret");
    assert!(!a_finance_opens(&hub, &p, &l, &format!("{BILL_DIR}/.env")));
}

/// An admin's new laptop, confirmed by their first device (which shares
/// project A's keys with it), trusts each project only once its fingerprint
/// is confirmed there: before that it seals nothing, and another project's
/// fingerprint does not do.
#[test]
fn an_admins_new_laptop_confirms_each_project() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (_, bdir) = second_project(&hub, &p);
    let laptop = hub.new_device_of(&p.admin);
    p.admin.ok(&p.dir, &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let l = laptop.dir("a");
    laptop.ok(laptop.home.path(), &["clone", &hub.url(&p.name), l.to_str().unwrap()]);
    assert!(!l.join(BILL_DIR).join(".env").exists(), "the laptop opened A's secret before confirming A");
    let show = laptop.ok(&l, &["identity", "show"]);
    assert!(show.contains("not confirmed"), "{show}");
    write_files(&l, &[("root/.env", "R=MARKER-LAPTOP-ROOT-9a1e\n")]);
    let out = laptop.ok(&l, &["commit", "-m", "x"]);
    assert!(out.contains("local-only") || out.contains("no key"), "an unconfirmed clone sealed a secret:\n{out}");
    laptop.fails(&l, &["identity", "confirm", &p.admin.project_fingerprint(&bdir)]);
    laptop.ok(&l, &["identity", "confirm", &p.fp]);
    assert!(std::fs::read_to_string(l.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    assert_eq!(laptop.project_fingerprint(&l), p.fp);
}

/// The invite link names the project's fingerprint: `vl join` checks it
/// against the server's `team` ring and records it, so the invitee's clone
/// trusts that ring only. A server that serves another project's `team`
/// (or a link whose fingerprint was changed) gets a loud failure and no
/// trusted ring. The link may come on standard input.
#[test]
fn an_invite_names_the_projects_fingerprint() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // On standard input.
    let alice = hub.newcomer("alice");
    let link = link_in(&p.admin.ok(&p.dir, &["invite", &alice.name, "--to", "finance"]));
    assert!(link.ends_with(&p.fp.replace('-', "")), "{link}");
    let mut child = alice
        .command(alice.home.path(), &["join", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), format!("{link}\n").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("matches your invite"), "{text}{}", String::from_utf8_lossy(&out.stderr));
    p.admin.ok(&p.dir, &["share-keys"]);
    let a = alice.dir("c");
    alice.ok(alice.home.path(), &["clone", &hub.url(&p.name), a.to_str().unwrap()]);
    assert!(std::fs::read_to_string(a.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    assert_eq!(alice.project_fingerprint(&a), p.fp);
    // A link whose fingerprint is not the project's.
    let bob = hub.newcomer("bob");
    let link = link_in(&p.admin.ok(&p.dir, &["invite", &bob.name, "--to", "finance"]));
    let wrong = format!("{}{}", &link[..link.len() - 20], "0".repeat(20));
    let out = bob.fails(bob.home.path(), &["join", &wrong]);
    assert!(out.contains("not the one your invite names"), "{out}");
    let b = bob.dir("c");
    let out = bob.ok(bob.home.path(), &["clone", &hub.url(&p.name), b.to_str().unwrap()]);
    assert!(out.contains("vl identity confirm"), "{out}");
    assert!(repo(&b).keys().load_ring("team").unwrap().is_none(), "a mismatched invite left a trusted ring");
    // A server that serves another project's `team` before the join.
    let (other, _) = second_project(&hub, &p);
    let carl = hub.newcomer("carl");
    let link = link_in(&p.admin.ok(&p.dir, &["invite", &carl.name, "--to", "finance"]));
    plant_in(&hub, &p.name, &team_of(&hub, &p, &other));
    let out = carl.fails(carl.home.path(), &["join", &link]);
    assert!(out.contains("not the one your invite names"), "{out}");
}

/// Removal scope (BUG-843): an admin's `vl identity remove` bars a device
/// from their project only (and rotates that project's keys away from it);
/// the person removes their own device everywhere; nobody else can.
#[test]
fn an_admin_bars_a_device_from_their_project_only() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // fin also works in sec's project.
    let theirs = unique("theirs");
    let tdir = p.sec.dir("t");
    std::fs::create_dir_all(&tdir).unwrap();
    p.sec.ok(&tdir, &["init"]);
    write_files(&tdir, &[("t.txt", "t")]);
    p.sec.ok(&tdir, &["remote", "add", "origin", &hub.url(&theirs)]);
    p.sec.commit_main(&tdir, "t");
    p.sec.ok(&tdir, &["push"]);
    p.sec.ok(&tdir, &["group", "create", "g"]);
    p.sec.ok(&tdir, &["group", "add", "g", &p.fin.name, "--confirm", &p.fin.fingerprint()]);
    let ft = p.fin.dir("t");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&theirs), ft.to_str().unwrap()]);
    let fa = clone(&hub, &p, &p.fin, "a");
    // Nobody but the person removes a device everywhere, even with a valid
    // session of their own.
    let r = hub.api().post_json(Some(&p.admin.token()), "/v1/devices/remove", &serde_json::json!({"device": p.fin.identity().public_id()}));
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
    // A's admin removes it from A.
    let out = p.admin.ok(&p.dir, &["identity", "remove", &p.fin.fingerprint()]);
    assert!(out.contains("from project") && out.contains("rotated away"), "{out}");
    assert!(!member_of(&ring(&hub, &p, &bill_scope()).1, &p.fin.identity()));
    let out = p.fin.fails(&fa, &["pull"]);
    assert!(out.contains("removed this device from this project"), "{out}");
    // fin's other project, and signing in, are untouched.
    p.fin.ok(&ft, &["pull"]);
    p.fin.ok(p.fin.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    // The person removes their own laptop everywhere.
    let laptop = hub.new_device_of(&p.fin);
    p.fin.ok(&ft, &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let out = p.fin.ok(&ft, &["identity", "remove", &laptop.fingerprint()]);
    assert!(out.contains("can no longer sign in"), "{out}");
    laptop.fails(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
}
