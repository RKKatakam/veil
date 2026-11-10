//! Packs (S28, `docs/HUB.md` §13.18): a push's objects in one storage
//! write, read by range; uploads staged until a push lists them, refused
//! ones deleted (BUG-930); receipts bound to their person and pack; the
//! push's checks of a long history several at once (BUG-865), with the
//! answers of one at a time.

use std::sync::atomic::Ordering::Relaxed;

use serde_json::json;
use veil_core::{hub::wire::put_frame, object::Object as O, ObjectId};

use crate::{secrets2::clone, support::*};

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// `(listed, discarded)` pack rows of the project.
fn pack_rows(hub: &TestHub, project: i64) -> (i64, i64) {
    hub.rt
        .block_on(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT count(*) FILTER (WHERE state = 1), count(*) FILTER (WHERE state = 2) FROM packs WHERE project_id = $1",
            )
            .bind(project)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

/// Storage writes of requests: the deriver's in the background aside.
fn writes(hub: &TestHub) -> u64 {
    let o = &hub.hub().objects;
    o.own_writes.load(Relaxed)
}

fn blob(text: &str) -> (ObjectId, Vec<u8>) {
    let raw = O::Blob(text.as_bytes().to_vec()).encode();
    (ObjectId::hash(&raw), raw)
}

/// A `vl push` of a change costs one storage write: its upload's staged
/// pack, listed as it is. A push the server completes (a member who cannot
/// see every folder: the graft's trees, the real snapshot, the member's
/// projection) costs one more, its own pack. Everyone reads what they read
/// before, through a second server too (which learns of the packs from the
/// database).
#[test]
fn a_push_is_one_storage_write_and_reads_come_from_its_pack() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let (listed0, _) = pack_rows(&hub, pid);
    assert!(listed0 >= 1, "the initial import is in packs");
    // The admin: the upload's pack, listed as it is.
    write_files(&p.dir, &[("src/one.rs", "MARKER-PACK-ADMIN-0d9e")]);
    p.admin.commit_main(&p.dir, "one file");
    let w = writes(&hub);
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(writes(&hub) - w, 1, "an admin's push: one storage write");
    assert_eq!(pack_rows(&hub, pid), (listed0 + 1, 0));
    // A developer, who cannot see billing: the server completes the
    // snapshot, and stores what it made in one pack of the push's own.
    let d = clone(&hub, &p, &p.dev, "dev");
    write_files(&d, &[("src/two.rs", "MARKER-PACK-DEV-77ab")]);
    p.dev.commit_main(&d, "dev's file");
    let w = writes(&hub);
    p.dev.ok(&d, &["push"]);
    let n = writes(&hub) - w;
    assert!(n <= 2, "a completed push: {n} storage writes");
    // Every viewer reads it, from a fresh server on the same database and
    // store (nothing cached: the packs read from the listing).
    let other = TestHub::beside(&hub);
    let api = other.api();
    for (who, sees_billing) in [(&p.admin, true), (&p.fin, true), (&p.dev, false)] {
        let token = who.token();
        assert_eq!(read_file(&api, &token, &p.name, "src/one.rs").as_deref(), Some(&b"MARKER-PACK-ADMIN-0d9e"[..]));
        assert_eq!(read_file(&api, &token, &p.name, "src/two.rs").as_deref(), Some(&b"MARKER-PACK-DEV-77ab"[..]));
        let bill = read_file(&api, &token, &p.name, &format!("{BILL_DIR}/acme/invoice.txt"));
        assert_eq!(bill.is_some(), sees_billing, "{}", who.name);
    }
}

/// The content of the file at `path` on `main` as `token`'s person sees it,
/// read through `api`'s server: its tips, history and fetch routes.
fn read_file(api: &Api, token: &str, project: &str, path: &str) -> Option<Vec<u8>> {
    let tip = api.tips(Some(token), project).unwrap().branches["main"];
    let h = api.history(token, project, &[tip]);
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!() };
    let mut id = s.tree;
    let mut at = String::new();
    for part in path.split('/') {
        let r = api.post_json(Some(token), &format!("/v1/projects/{project}/fetch"), &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let O::Tree(t) = O::decode(&r.frames()[0].1).unwrap() else { panic!("not a tree") };
        id = t.get(part)?.id;
        at = if at.is_empty() { part.to_string() } else { format!("{at}/{part}") };
    }
    let r = api.post_json(Some(token), &format!("/v1/projects/{project}/fetch"), &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    match O::decode(&r.frames()[0].1).unwrap() {
        O::Blob(b) => Some(b),
        _ => panic!("not a file"),
    }
}

/// BUG-930 with S28: an upload is staged; a push that refuses it deletes its
/// pack, so the refused plain-text secret is in no object of the store,
/// and the upload's receipt is of no use after.
#[test]
fn a_refused_push_deletes_its_staged_upload() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let secret = "aws_access_key_id = AKIAR4T6EXAMPLEW8Y2Q\n";
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/creds.txt", secret);
    let tip = c.tip;
    // As `Craft::push`, with the receipts kept.
    let mut s = veil_core::object::Snapshot {
        parents: vec![tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("a secret".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    s.sign(&c.identity);
    let snap = c.put(O::Snapshot(s));
    let up = api.upload(&c.token, &p.name, &c.objects);
    assert_eq!(up.status, 200);
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let pack = receipts[0].split_once('.').unwrap().1.to_string();
    assert!(receipts.iter().all(|r| r.ends_with(&pack)), "one upload, one pack");
    let h = hub.hub();
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &pack)).unwrap().is_some(), "staged");
    let map: serde_json::Map<String, serde_json::Value> = c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect();
    let body = json!({"updates": [{"branch": "main", "expected": tip.hex(), "new": snap.hex()}], "receipts": map});
    let r = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &body);
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    // Gone from the store (a fresh server reads only the store), never the
    // project's, and refused as never uploaded when shown again.
    let other = TestHub::beside(&hub);
    assert!(other.rt.block_on(other.hub().objects.staged_index(pid, &pack)).unwrap().is_none(), "the refused upload is deleted");
    assert!(hub.rt.block_on(h.objects.get(pid, &blob(secret).0)).unwrap().is_none());
    assert_eq!(pack_rows(&hub, pid).1, 1, "the discarded pack's row");
    let again = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &body);
    assert!(again.status == 400 || again.status == 404, "{}: {}", again.status, String::from_utf8_lossy(&again.body));
    assert_eq!(hub.api().tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"], tip);
}

/// A receipt holds for the person it was given to and the pack it names
/// only: another member showing it, or a receipt moved to another pack (of
/// theirs or anyone's), is an object never uploaded; malformed ones too.
#[test]
fn receipts_hold_only_for_their_person_and_pack() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let mark = "MARKER-RECEIPT-PERSON-5a1c";
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/receipt.rs", mark);
    let tip = c.tip;
    let mut s = veil_core::object::Snapshot {
        parents: vec![tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("receipts".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    s.sign(&c.identity);
    let snap = c.put(O::Snapshot(s));
    let up = api.upload(&c.token, &p.name, &c.objects);
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    // Carol (who may write src/) uploads something of her own: another pack.
    let (oid, oraw) = blob("carol's");
    let mut body = Vec::new();
    put_frame(&mut body, &oid, &oraw);
    let theirs: Vec<String> = serde_json::from_value(api.upload_body(&p.carol.token(), &p.name, &body).json()["receipts"].clone()).unwrap();
    let carol_pack = theirs[0].split_once('.').unwrap().1.to_string();
    let push = |token: &str, f: &dyn Fn(&str) -> String| {
        let map: serde_json::Map<String, serde_json::Value> = c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(f(r)))).collect();
        let body = json!({"updates": [{"branch": "main", "expected": tip.hex(), "new": snap.hex()}], "receipts": map});
        api.post_json(Some(token), &format!("/v1/projects/{}/push", p.name), &body)
    };
    let refused = |r: Reply, what: &str| {
        assert!(r.status == 400 || r.status == 404, "{what}: {} {}", r.status, String::from_utf8_lossy(&r.body));
    };
    let mac = |r: &str| r.split_once('.').unwrap().0.to_string();
    refused(push(&p.carol.token(), &|r| r.to_string()), "dev's receipts shown by carol");
    refused(push(&c.token, &|r| format!("{}.{carol_pack}", mac(r))), "moved to carol's pack");
    refused(push(&c.token, &|r| format!("{}.{}", mac(r), "0".repeat(32))), "moved to a pack nobody has");
    refused(push(&c.token, &|r| mac(r)), "without its pack");
    for bad in ["", ".", "x.y", &format!("{}.{}", "f".repeat(32), "A".repeat(32)), &format!("{}.../../x", "f".repeat(32))] {
        refused(push(&c.token, &|_| bad.to_string()), bad);
    }
    // The receipts as given, by the dev: landed.
    let r = push(&c.token, &|r| r.to_string());
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let d = clone(&hub, &p, &p.sec, "sec");
    assert_eq!(std::fs::read_to_string(d.join("src/receipt.rs")).unwrap(), mark);
}

/// BUG-865: a long history in one push, checked several snapshots at once.
/// The admin's (every guess right) and a developer's, who cannot see
/// billing (the server completes every snapshot: every guess wrong, so one
/// at a time), both land with the answers of one at a time: the same tips,
/// each snapshot's files, and billing intact for those who see it.
#[test]
fn bug_865_a_long_history_is_checked_several_at_once_with_the_same_answers() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    for i in 0..70 {
        write_files(&p.dir, &[(&format!("src/a/f{i}.rs"), &format!("admin {i}"))]);
        p.admin.commit_main(&p.dir, &format!("admin {i}"));
    }
    p.admin.ok(&p.dir, &["push"]);
    let d = clone(&hub, &p, &p.dev, "dev");
    for i in 0..70 {
        write_files(&d, &[(&format!("src/d/f{i}.rs"), &format!("dev {i}"))]);
        p.dev.commit_main(&d, &format!("dev {i}"));
    }
    p.dev.ok(&d, &["push"]);
    let f = clone(&hub, &p, &p.fin, "fin");
    for i in 0..70 {
        assert_eq!(std::fs::read_to_string(f.join(format!("src/a/f{i}.rs"))).unwrap(), format!("admin {i}"));
        assert_eq!(std::fs::read_to_string(f.join(format!("src/d/f{i}.rs"))).unwrap(), format!("dev {i}"));
    }
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join("acme/invoice.txt")).unwrap().contains(BILL_MARK));
    // The developer's own history: every one of their 70 snapshots, under
    // the ids they made.
    let log = p.dev.ok(&d, &["log", "-n", "200"]);
    for i in 0..70 {
        assert!(log.contains(&format!("dev {i}")), "dev {i} missing from\n{log}");
    }
}

// ---------------------------------------------------------------------------
// S28 cycle 1 review (`docs/BUGS.md` "S28 cycle 1").

/// A snapshot of `c`'s tree on `parents`, signed by `by` (the crafter's
/// device unless another identity is given), put among `c`'s objects.
fn snap(c: &mut Craft, parents: Vec<ObjectId>, msg: &str, by: Option<&veil_core::Identity>) -> ObjectId {
    let mut s = veil_core::object::Snapshot {
        parents,
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain(msg.into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    s.sign(by.unwrap_or(&c.identity));
    c.put(O::Snapshot(s))
}

/// Upload `c`'s objects (one request: one staged pack) as `c`'s person;
/// the receipts by id, and the pack's name.
fn upload_all(api: &Api, c: &Craft) -> (serde_json::Map<String, serde_json::Value>, String) {
    let up = api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let pack = receipts[0].split_once('.').unwrap().1.to_string();
    (c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect(), pack)
}

fn push_body(api: &Api, token: &str, project: &str, expected: ObjectId, new: ObjectId, receipts: &serde_json::Map<String, serde_json::Value>) -> Reply {
    let body = json!({"updates": [{"branch": "main", "expected": expected.hex(), "new": new.hex()}], "receipts": receipts});
    api.post_json(Some(token), &format!("/v1/projects/{project}/push"), &body)
}

/// BUG-1155 (S28 cycle 1; BUG-824's class): a receipt still counts as an
/// upload after its staged pack was discarded, and the object is then read
/// from the project's store. So a member can confirm a guess of content in
/// a folder they cannot see: upload the guess, have a push refused (which
/// discards the upload), then push a file naming the guess with its old
/// receipt. A right guess lands (the hidden object is read from the
/// project); a wrong one is refused as missing. Both must get the same
/// answer, as before S28 (an upload was stored, so a guess always read).
#[test]
fn bug_1155_a_receipt_of_a_discarded_upload_confirms_no_guess() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // The dev guesses the hidden invoice exactly (asserted: the real id).
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(path, _)| *path == hidden_path).unwrap().1;
    let right = format!("{BILL_MARK}\nsecond").into_bytes();
    let wrong = b"MARKER-A-WRONG-GUESS-OF-THE-INVOICE-71c0".to_vec();
    let (rid, rraw) = (ObjectId::hash(&O::Blob(right.clone()).encode()), O::Blob(right.clone()).encode());
    let (wid, wraw) = (ObjectId::hash(&O::Blob(wrong.clone()).encode()), O::Blob(wrong.clone()).encode());
    assert_eq!(rid, real, "the guess is the hidden object");
    let up = api.upload(&token, &p.name, &[(rid, rraw), (wid, wraw)]);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let pack = receipts[0].split_once('.').unwrap().1.to_string();
    // A push its checks refuse, naming those receipts: the upload is
    // discarded (BUG-930).
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let shown: serde_json::Map<String, serde_json::Value> = [(rid.hex(), json!(receipts[0])), (wid.hex(), json!(receipts[1]))].into_iter().collect();
    let refused = push_body(&api, &token, &p.name, tip, ObjectId::hash(b"never uploaded"), &shown);
    assert_eq!(refused.status, 400, "{}", String::from_utf8_lossy(&refused.body));
    assert!(hub.rt.block_on(hub.hub().objects.staged_index(pid, &pack)).unwrap().is_none(), "the upload is discarded");
    // Now a file naming each guess, shown with its old receipt (the file's
    // object is not uploaded again).
    let mut answers = Vec::new();
    for (id, content, receipt) in [(wid, &wrong, &receipts[1]), (rid, &right, &receipts[0])] {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.set("src/guess.txt", O::Blob(content.clone()), veil_core::object::Visibility::Public);
        c.objects.retain(|(o, _)| *o != id);
        let s = { let t = c.tip; snap(&mut c, vec![t], "a guess", None) };
        let (mut map, _) = upload_all(&api, &c);
        map.insert(id.hex(), json!(receipt));
        let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
        answers.push((r.status, String::from_utf8_lossy(&r.body).to_string()));
    }
    let (wrong_answer, right_answer) = (&answers[0], &answers[1]);
    assert!(wrong_answer.0 == 400 || wrong_answer.0 == 404, "a wrong guess, its upload discarded: {wrong_answer:?}");
    assert_eq!(
        right_answer.0, wrong_answer.0,
        "a right guess of hidden content got another answer than a wrong one: right {right_answer:?}, wrong {wrong_answer:?}"
    );
}

/// BUG-1155 through `POST …/changes` (fixed): an API commit putting a
/// guessed object, shown with the receipt of an upload an earlier, refused
/// API commit discarded, gets the same answer whether the guess is the
/// hidden file or not.
#[test]
fn bug_1155_an_api_commit_with_a_discarded_upload_confirms_no_guess() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(path, _)| *path == hidden_path).unwrap().1;
    let right = format!("{BILL_MARK}\nsecond").into_bytes();
    let wrong = b"MARKER-A-WRONG-GUESS-THROUGH-THE-API-9e2d".to_vec();
    let (rid, rraw) = (ObjectId::hash(&O::Blob(right.clone()).encode()), O::Blob(right.clone()).encode());
    let (wid, wraw) = (ObjectId::hash(&O::Blob(wrong.clone()).encode()), O::Blob(wrong.clone()).encode());
    assert_eq!(rid, real, "the guess is the hidden object");
    let up = api.upload(&token, &p.name, &[(rid, rraw), (wid, wraw)]);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let base = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let change = |body: serde_json::Value| api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &body);
    // Refused on purpose (a path the dev may not write): its uploads are
    // discarded.
    let both: serde_json::Map<String, serde_json::Value> = [(rid.hex(), json!(receipts[0])), (wid.hex(), json!(receipts[1]))].into_iter().collect();
    let refused = change(json!({"base": base.hex(), "edits": [{"path": format!("{BILL_DIR}/x.txt"), "put": {"object": rid.hex()}}], "receipts": both}));
    assert!(refused.status == 403 || refused.status == 400, "{}: {}", refused.status, String::from_utf8_lossy(&refused.body));
    let mut answers = Vec::new();
    for (id, receipt) in [(wid, &receipts[1]), (rid, &receipts[0])] {
        let r = change(json!({"base": base.hex(), "edits": [{"path": "src/guess.txt", "put": {"object": id.hex()}}],
            "receipts": {id.hex(): receipt}}));
        // The body names the object's id, which differs: compare the rest.
        answers.push((r.status, String::from_utf8_lossy(&r.body).replace(&id.hex(), "ID").replace(&id.short(), "ID")));
    }
    assert!(answers[0].0 == 400 || answers[0].0 == 404, "a wrong guess: {:?}", answers[0]);
    assert_eq!(answers[1], answers[0], "a right guess of hidden content got another answer than a wrong one");
}

/// The refusal (status and message) of pushing `n` new snapshots on
/// `main`, as `who`, each changing one file; `bad` makes snapshot `i`
/// refused: a plain-text `.env` (`Some(path)`), or signed by a key no
/// device is registered with (`None`).
fn refused_history(hub: &TestHub, p: &Project, who: &Person, n: usize, bad: &[(usize, Option<String>)]) -> (u16, String) {
    let api = hub.api();
    let mut c = Craft::new(&api, who, &p.name, "main");
    let tip = c.tip;
    let stranger = veil_core::Identity::generate("stranger");
    let mut prev = tip;
    for i in 0..n {
        c.file(&format!("src/chain/f{}.rs", i % 7), &format!("step {i} of {n}"));
        let mut by = None;
        for (at, what) in bad.iter().filter(|(at, _)| *at == i) {
            match what {
                Some(path) => c.file(path, &format!("KEY=MARKER-PLAIN-ENV-{at}-3d1f\n")),
                None => by = Some(&stranger),
            }
        }
        prev = snap(&mut c, vec![prev], &format!("step {i}"), by);
    }
    let (map, _) = upload_all(&api, &c);
    let r = push_body(&api, &c.token, &p.name, tip, prev, &map);
    (r.status, String::from_utf8_lossy(&r.body).to_string())
}

/// Guarantee 4 (BUG-865's fix): checks run several at once answer as one
/// at a time, the first error included, whether the guesses are right
/// (the admin's history: each snapshot is its own real one) or wrong (a
/// developer's, whom the server completes every snapshot for), within the
/// first window or past it, and whatever kind each error is.
#[test]
fn guessed_checks_refuse_with_the_first_error_in_order() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let tip = hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let env = |i: usize| Some(format!("src/chain/e{i}/.env"));
    for who in [&p.admin, &p.dev] {
        // Two secrets: the first in order is the answer.
        let (status, body) = refused_history(&hub, &p, who, 30, &[(20, env(20)), (6, env(6))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e6/.env' is a secret and must arrive encrypted") && !body.contains("e20"), "{}: {body}", who.name);
        // A precheck refusal (an unknown key) after a secret, and before one.
        let (status, body) = refused_history(&hub, &p, who, 30, &[(2, env(2)), (5, None)]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e2/.env'"), "{}: {body}", who.name);
        let (status, body) = refused_history(&hub, &p, who, 30, &[(3, None), (10, env(10))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("signed by a key no device here is registered with") && !body.contains("e10"), "{}: {body}", who.name);
        // Past the first window of guesses.
        let (status, body) = refused_history(&hub, &p, who, 75, &[(70, env(70)), (66, env(66))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e66/.env'") && !body.contains("e70"), "{}: {body}", who.name);
    }
    assert_eq!(hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"], tip, "nothing landed");
}

/// BUG-1157 (S28 cycle 1, fixed): a push that lands nothing because every
/// update lost a race (here: not on the branch's current tip) keeps its
/// staged upload, recorded in the database, for the next try; `vl` then
/// uploads the same objects again (up to five tries per `vl push`), and
/// they get the receipts of that same pack, so the tries leave one copy,
/// not one each. Every pack in storage has a row.
#[test]
fn bug_1157_a_push_that_lost_a_race_leaves_no_copy_of_its_upload() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/raced.rs", "MARKER-RACED-UPLOAD-61aa");
    let s = { let t = c.tip; snap(&mut c, vec![t], "raced", None) };
    // Someone else lands first.
    write_files(&p.dir, &[("src/first.rs", "first")]);
    p.admin.commit_main(&p.dir, "first");
    p.admin.ok(&p.dir, &["push"]);
    let w = writes(&hub);
    let mut packs = Vec::new();
    for _ in 0..3 {
        let (map, pack) = upload_all(&api, &c);
        let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], json!(false), "{}", String::from_utf8_lossy(&r.body));
        packs.push(pack);
    }
    assert!(packs.iter().all(|n| *n == packs[0]), "the tries got the receipts of one pack: {packs:?}");
    assert_eq!(writes(&hub) - w, 1, "one storage write for three tries");
    let state: Option<i16> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT state FROM packs WHERE project_id = $1 AND name = $2").bind(pid).bind(&packs[0]).fetch_optional(&hub.hub().db))
        .unwrap();
    assert_eq!(state, Some(0), "the upload is recorded, staged");
    // Every pack in storage has a row (whatever the storage: S3 or a
    // directory).
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "packs in storage with no row");
    // The same objects, landed on the tip: one more try, which lands.
    let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
    c2.file("src/raced.rs", "MARKER-RACED-UPLOAD-61aa");
    let s2 = { let t = c2.tip; snap(&mut c2, vec![t], "raced, again", None) };
    let (map, _) = upload_all(&api, &c2);
    let r = push_body(&api, &c2.token, &p.name, c2.tip, s2, &map);
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));
}

/// BUG-1153 (S28 × S15 merge): a push's storage writes are its own pack
/// and upload; the background indexers' are counted apart. S15's search
/// indexer stores its segments with `Objects::put` on a blocking thread,
/// outside `store::in_background`, so they count as the push's: S28's
/// `a_push_is_one_storage_write…` fails whenever the indexer runs before
/// it counts, and `veil-bench load`'s writes-per-push gate counts them.
#[test]
fn bug_1153_background_indexing_is_not_counted_as_a_pushs_writes() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let settle = || {
        // Until the background work is done: no write for 3 s.
        let mut last = (u64::MAX, std::time::Instant::now());
        let start = std::time::Instant::now();
        loop {
            let w = hub.hub().objects.writes.load(Relaxed);
            if w != last.0 {
                last = (w, std::time::Instant::now());
            } else if last.1.elapsed() > std::time::Duration::from_secs(3) {
                return;
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(120), "the background never settled");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    };
    settle();
    write_files(&p.dir, &[("src/indexed.rs", "fn MARKER_SEARCHED_WORD_b71d() {}")]);
    p.admin.commit_main(&p.dir, "indexed");
    let w = writes(&hub);
    p.admin.ok(&p.dir, &["push"]);
    settle();
    assert_eq!(writes(&hub) - w, 1, "an admin's push, its background work done: one storage write of its own");
}

/// Guarantee 3: a staged pack that one push of a person lists while
/// another push of theirs, on another server, refuses and discards it: the
/// listing push lands with its content readable, or is refused and nothing
/// moves; never a listed pack missing from the store.
#[test]
fn a_pack_discarded_while_another_server_lists_it_is_listed_or_gone() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let other = TestHub::beside(&hub);
    let (a, b) = (hub.api(), other.api());
    let stranger = veil_core::Identity::generate("stranger");
    let mut landed = 0;
    for round in 0..8 {
        let mut c = Craft::new(&a, &p.dev, &p.name, "main");
        let mark = format!("MARKER-RACED-LISTING-{round}-8e2c");
        c.file(&format!("src/race{round}.rs"), &mark);
        let good = { let t = c.tip; snap(&mut c, vec![t], "good", None) };
        let (map, _) = upload_all(&a, &c);
        // The refused push: a snapshot of an unknown key, with the same
        // receipts (and its own upload).
        let mut bad = Craft::new(&a, &p.dev, &p.name, "main");
        bad.objects.clear();
        let unknown = snap(&mut bad, vec![c.tip], "unknown key", Some(&stranger));
        let (mut bad_map, _) = upload_all(&a, &bad);
        bad_map.extend(map.clone());
        let (token, project, tip) = (c.token.clone(), p.name.clone(), c.tip);
        let (ra, rb) = std::thread::scope(|s| {
            let x = s.spawn(|| push_body(&a, &token, &project, tip, good, &map));
            let y = s.spawn(|| push_body(&b, &token, &project, tip, unknown, &bad_map));
            (x.join().unwrap(), y.join().unwrap())
        });
        assert_eq!(rb.status, 403, "{}", String::from_utf8_lossy(&rb.body));
        let now = a.tips(Some(&token), &p.name).unwrap().branches["main"];
        match ra.status {
            200 => {
                assert_eq!(ra.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&ra.body));
                landed += 1;
                // Read back through a third server: nothing cached.
                let third = TestHub::beside(&hub);
                assert_eq!(read_file(&third.api(), &token, &p.name, &format!("src/race{round}.rs")).as_deref(), Some(mark.as_bytes()));
            }
            400 | 409 => assert_eq!(now, tip, "refused, yet main moved: {}", String::from_utf8_lossy(&ra.body)),
            s => panic!("the listing push: {s} {}", String::from_utf8_lossy(&ra.body)),
        }
    }
    eprintln!("{landed} of 8 listing pushes landed");
}

/// BUG-1156 (S28 cycle 1): an API commit reads every upload its receipts
/// name into memory (up to 1 GiB each) before its checks, outside the
/// server's bound on decoded bytes in flight (`store::DECODED_IN_FLIGHT`,
/// 256 MiB, BUG-1009/BUG-1087). Uploads are stored compressed, so a member
/// sends a few MiB per upload, then several API commits at once: each
/// holds its 256 MiB decoded. Before S28 a commit read uploads from the
/// store as its checks needed them. Hostile size: run alone.
#[test]
fn hostile_bug_1156_api_commits_hold_their_uploads_within_the_servers_bound() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    // 16 objects of 16 MiB, about 12 times compressible (within the 64
    // times an upload may expand).
    let mut frames = Vec::new();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for k in 0..16u8 {
        let mut b = vec![0u8; 16 << 20];
        for i in (0..b.len()).step_by(16) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b[i] = x as u8;
        }
        b[0] = k;
        let raw = O::Blob(b).encode();
        let id = ObjectId::hash(&raw);
        frames.push((id, encoding::encode(&raw).into_owned()));
    }
    let base = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let commits: Vec<serde_json::Value> = (0..6)
        .map(|n| {
            let mut body = Vec::new();
            for (id, enc) in &frames {
                put_frame(&mut body, id, enc);
            }
            let up = api.upload_encoded_body(&token, &p.name, &body);
            assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
            let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
            let edits: Vec<serde_json::Value> =
                frames.iter().enumerate().map(|(i, (id, _))| json!({"path": format!("src/big{n}/b{i}.bin"), "put": {"object": id.hex()}})).collect();
            let receipts: serde_json::Map<String, serde_json::Value> = frames.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect();
            json!({"base": base.hex(), "description": "large", "edits": edits, "receipts": receipts})
        })
        .collect();
    let vm = |field: &str| -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let l = s.lines().find(|l| l.starts_with(field)).unwrap();
        l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() << 10
    };
    // Peak memory from now on.
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = vm("VmRSS:");
    let replies: Vec<Reply> = std::thread::scope(|s| {
        let hs: Vec<_> = commits.iter().map(|c| s.spawn(|| api.post_json_within(&token, &format!("/v1/projects/{}/changes", p.name), c, std::time::Duration::from_secs(1200)))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &replies {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    let grew = vm("VmHWM:").saturating_sub(before);
    assert!(grew < 1 << 30, "six API commits at once took the server {} MiB past where it was", grew >> 20);
}

/// BUG-1158 (S28 cycle 1): a rolling upgrade runs servers before S28
/// beside S28 servers, on one database and one object store (the
/// migrations are built for it: BUG-838). A server before S28 reads an
/// object only under its own key (`p/<project>/<id>`; `integration` @
/// `6fa552c4`, `store.rs` `Objects::get`), which is exactly what
/// `Objects` without a database and without listed packs reads. Whatever
/// an S28 server took in a push is in packs only, so every older server
/// answers "missing object" for it (and refuses S28's receipts) until the
/// last one is stopped; `HUB.md` §13.20 says how to revert, not that the
/// upgrade cannot be rolling.
#[test]
#[ignore = "BUG-1158 (closed by decision: the upgrade to S28 is not rolling, HUB.md §13.20): a server before S28 cannot find what an S28 server stored"]
fn bug_1158_a_server_before_s28_finds_what_an_s28_server_stored() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    write_files(&p.dir, &[("src/rolling.rs", "MARKER-ROLLING-UPGRADE-0f4b")]);
    p.admin.commit_main(&p.dir, "during the upgrade");
    p.admin.ok(&p.dir, &["push"]);
    let id = blob("MARKER-ROLLING-UPGRADE-0f4b").0;
    let api = hub.api();
    assert_eq!(read_file(&api, &p.admin.token(), &p.name, "src/rolling.rs").as_deref(), Some(&b"MARKER-ROLLING-UPGRADE-0f4b"[..]), "the S28 server reads it");
    // What a server before S28 reads, on the same store.
    let before_s28 = veil_server::store::Objects::new(hub.blob_store(), 1 << 20);
    let got = hub.rt.block_on(before_s28.get(pid, &id)).unwrap();
    assert_eq!(got.as_deref(), Some(&O::Blob(b"MARKER-ROLLING-UPGRADE-0f4b".to_vec()).encode()[..]), "a server before S28 finds no object an S28 server stored");
}

/// Guarantee 2: a plain-text secret uploaded with a push's objects but
/// named by none of its snapshots (its checks never read it) is in no
/// listed pack once the push lands, and its staged upload is deleted: the
/// push copies what its checks read into a pack of its own.
#[test]
fn an_unread_plain_text_secret_beside_a_landing_push_is_not_kept() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/landed.rs", "MARKER-LANDED-BESIDE-A-SECRET-2b7e");
    let s = { let t = c.tip; snap(&mut c, vec![t], "beside a secret", None) };
    let secret = "AWS_SECRET_ACCESS_KEY=MARKER-UNREAD-PLAIN-SECRET-c4d9e1\n";
    let (sid, sraw) = blob(secret);
    c.objects.push((sid, sraw));
    let (map, pack) = upload_all(&api, &c);
    let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));
    let h = hub.hub();
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &pack)).unwrap().is_none(), "the upload it did not list is deleted");
    let fresh = TestHub::beside(&hub);
    assert!(fresh.rt.block_on(fresh.hub().objects.get(pid, &sid)).unwrap().is_none(), "the unread secret is not the project's");
    // In no listed pack's index.
    let names: Vec<String> =
        hub.rt.block_on(sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = 1").bind(pid).fetch_all(&h.db)).unwrap();
    let store = hub.blob_store();
    for n in &names {
        let bound = veil_server::pack::Bound::new(veil_server::pack::INDEXES_HELD);
        let held = hub.rt.block_on(veil_server::pack::read_index(&*store, &veil_server::pack::key(pid, n), &bound)).unwrap().unwrap();
        assert!(held.index.get(&sid).is_none(), "the unread secret is in listed pack {n}");
    }
    assert_eq!(read_file(&fresh.api(), &c.token, &p.name, "src/landed.rs").as_deref(), Some(&b"MARKER-LANDED-BESIDE-A-SECRET-2b7e"[..]));
}

// ---------------------------------------------------------------------------
// S28 cycle 2 review (`docs/BUGS.md` "S28 cycle 2").

/// Until the background work is done: no storage write for 3 s.
fn settle(hub: &TestHub) {
    let mut last = (u64::MAX, std::time::Instant::now());
    let start = std::time::Instant::now();
    loop {
        let w = hub.hub().objects.writes.load(Relaxed);
        if w != last.0 {
            last = (w, std::time::Instant::now());
        } else if last.1.elapsed() > std::time::Duration::from_secs(3) {
            return;
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(120), "the background never settled");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The packs in `project`'s storage (listed from the store itself, S3 or a
/// directory).
fn packs_in_store(hub: &TestHub, project: i64) -> Vec<String> {
    let prefix = format!("p/{project}/pack/");
    let keys = hub.rt.block_on(hub.blob_store().list(&prefix)).unwrap();
    keys.iter().filter_map(|k| k.strip_prefix(&prefix)).filter(|n| veil_server::pack::valid_name(n)).map(str::to_string).collect()
}

/// The packs in `project`'s storage that have no row in `packs`.
fn packs_without_rows(hub: &TestHub, project: i64) -> Vec<String> {
    let rows: Vec<String> =
        hub.rt.block_on(sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1").bind(project).fetch_all(&hub.hub().db)).unwrap();
    let in_store = packs_in_store(hub, project);
    assert!(!in_store.is_empty(), "the project has packs in storage");
    in_store.into_iter().filter(|n| !rows.contains(n)).collect()
}

/// Property 1 (S28 cycle 2): a member who cannot see billing names the
/// hidden invoice (a right guess) or other bytes (a wrong one) in a push and
/// in an API commit, showing each kind of receipt that is not theirs for
/// that object in an upload of theirs: another person's, one of theirs for
/// another object, the form before S28 (no pack), one moved to another of
/// their packs, none. Every kind gets one answer for both guesses.
#[test]
fn a_guess_gets_one_answer_whatever_receipt_it_shows() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(path, _)| *path == hidden_path).unwrap().1;
    let right = format!("{BILL_MARK}\nsecond").into_bytes();
    let wrong = b"MARKER-A-WRONG-GUESS-OF-EVERY-RECEIPT-4d27".to_vec();
    let rid = ObjectId::hash(&O::Blob(right.clone()).encode());
    let wid = ObjectId::hash(&O::Blob(wrong.clone()).encode());
    assert_eq!(rid, real, "the guess is the hidden object");
    let receipts_of = |who: &str, objects: &[(ObjectId, Vec<u8>)]| -> Vec<String> {
        let up = api.upload(who, &p.name, objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        serde_json::from_value(up.json()["receipts"].clone()).unwrap()
    };
    // Carol's receipts for both guesses; two uploads of the dev's own of
    // something else (two packs).
    let carols = receipts_of(&p.carol.token(), &[(rid, O::Blob(right.clone()).encode()), (wid, O::Blob(wrong.clone()).encode())]);
    let (oid, oraw) = blob("MARKER-SOMETHING-ELSE-OF-THE-DEV-1b90");
    let mine = receipts_of(&token, &[(oid, oraw.clone())]).remove(0);
    let (o2, o2raw) = blob("MARKER-SOMETHING-ELSE-AGAIN-6e11");
    let mine2 = receipts_of(&token, &[(o2, o2raw)]).remove(0);
    let (mac, other_pack) = (mine.split_once('.').unwrap().0.to_string(), mine2.split_once('.').unwrap().1.to_string());
    type Receipt<'a> = Box<dyn Fn(usize) -> Option<String> + 'a>;
    let kinds: Vec<(&str, Receipt)> = vec![
        ("another person's", Box::new(|g| Some(carols[g].clone()))),
        ("one for another object", Box::new(|_| Some(mine.clone()))),
        ("before S28 (no pack)", Box::new(|_| Some(mac.clone()))),
        ("moved to another pack of theirs", Box::new(|_| Some(format!("{mac}.{other_pack}")))),
        ("none", Box::new(|_| None)),
    ];
    let norm = |r: &Reply, ids: &[ObjectId]| {
        let mut b = String::from_utf8_lossy(&r.body).into_owned();
        for id in ids {
            b = b.replace(&id.hex(), "ID").replace(&id.short(), "ID");
        }
        (r.status, b)
    };
    for (kind, receipt) in &kinds {
        // A push of a file naming the guess.
        let mut answers = Vec::new();
        for (g, (id, content)) in [(wid, &wrong), (rid, &right)].into_iter().enumerate() {
            let mut c = Craft::new(&api, &p.dev, &p.name, "main");
            c.set("src/guess.txt", O::Blob(content.clone()), veil_core::object::Visibility::Public);
            c.objects.retain(|(o, _)| *o != id);
            let s = { let t = c.tip; snap(&mut c, vec![t], "a guess", None) };
            let (mut map, _) = upload_all(&api, &c);
            if let Some(r) = receipt(1 - g) {
                map.insert(id.hex(), json!(r));
            }
            let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
            let trees: Vec<ObjectId> = c.objects.iter().map(|(o, _)| *o).collect();
            answers.push(norm(&r, &[[id, s].as_slice(), &trees].concat()));
        }
        assert!(answers[0].0 == 400 || answers[0].0 == 404, "push, {kind}: a wrong guess is refused: {:?}", answers[0]);
        assert_eq!(answers[1], answers[0], "push, {kind}: a right guess of hidden content got another answer than a wrong one");
        // An API commit putting the guess.
        let base = api.tips(Some(&token), &p.name).unwrap().branches["main"];
        let mut answers = Vec::new();
        for (g, id) in [wid, rid].into_iter().enumerate() {
            let mut receipts = serde_json::Map::new();
            if let Some(r) = receipt(1 - g) {
                receipts.insert(id.hex(), json!(r));
            }
            let r = api.post_json(
                Some(&token),
                &format!("/v1/projects/{}/changes", p.name),
                &json!({"base": base.hex(), "edits": [{"path": "src/guess.txt", "put": {"object": id.hex()}}], "receipts": receipts}),
            );
            answers.push(norm(&r, &[id]));
        }
        assert!(answers[0].0 == 400 || answers[0].0 == 404, "API commit, {kind}: a wrong guess is refused: {:?}", answers[0]);
        assert_eq!(answers[1], answers[0], "API commit, {kind}: a right guess of hidden content got another answer than a wrong one");
    }
}

/// Property 4 (S28 cycle 2): after a push its checks refuse, a push that
/// lost a race, its retry that lands, an API commit that lands and one
/// that is refused, every pack in storage has a row.
#[test]
fn every_pack_in_storage_has_a_row_after_refusals_races_and_api_commits() {
    // Whatever the storage (S3 or a directory: listed from the store).
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // Refused by its checks (a snapshot signed by a key nobody knows): the
    // upload and the push's own pack go.
    let stranger = veil_core::Identity::generate("stranger");
    let mut bad = Craft::new(&api, &p.dev, &p.name, "main");
    bad.file("src/refused.rs", "MARKER-REFUSED-PUSH-2c8d");
    let unknown = { let t = bad.tip; snap(&mut bad, vec![t], "unknown key", Some(&stranger)) };
    let (map, _) = upload_all(&api, &bad);
    let r = push_body(&api, &bad.token, &p.name, bad.tip, unknown, &map);
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "after a refused push");
    // Lost a race, then landed.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/raced.rs", "MARKER-RACED-THEN-LANDED-5f0e");
    let s = { let t = c.tip; snap(&mut c, vec![t], "raced", None) };
    write_files(&p.dir, &[("src/first.rs", "first")]);
    p.admin.commit_main(&p.dir, "first");
    p.admin.ok(&p.dir, &["push"]);
    let (map, _) = upload_all(&api, &c);
    let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
    assert_eq!(r.json()["results"][0]["ok"], json!(false), "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "after a lost race");
    let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
    c2.file("src/raced.rs", "MARKER-RACED-THEN-LANDED-5f0e");
    let s2 = { let t = c2.tip; snap(&mut c2, vec![t], "raced, again", None) };
    let (map, _) = upload_all(&api, &c2);
    let r = push_body(&api, &c2.token, &p.name, c2.tip, s2, &map);
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "after the retry landed");
    // API commits: one landed, one refused.
    let base = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    for (path, ok) in [("src/api.txt".to_string(), true), (format!("{BILL_DIR}/api.txt"), false)] {
        let (id, raw) = blob(&format!("MARKER-API-COMMIT-{ok}-77d1"));
        let up = api.upload(&token, &p.name, &[(id, raw)]);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
        let r = api.post_json(
            Some(&token),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": path, "put": {"object": id.hex()}}], "receipts": {id.hex(): receipts[0]}}),
        );
        match ok {
            true => assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body)),
            false => assert!(r.status == 403 || r.status == 400, "{}: {}", r.status, String::from_utf8_lossy(&r.body)),
        }
        assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "after an API commit (landed: {ok})");
    }
}

/// BUG-1399 (S28 cycle 2; BUG-1157's class): a push whose client goes away
/// while its transaction runs (a `vl push` stopped, a network that drops) is
/// cancelled by the HTTP server where it stands: the code after
/// `push_staged` that deletes the push's own pack when its transaction did
/// not list it (`sync::push`) never runs. The own pack was written before
/// the transaction and gets its row only in it, so it stays in storage
/// with no row: nothing (not S29's job, which reads the rows) knows it is
/// there. Here the push waits on the upload's row, held by another
/// transaction, so the client's 3 s run out within it.
#[test]
fn bug_1399_a_push_whose_client_goes_away_leaves_no_pack_without_a_row() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "before");
    // A developer's push: the server completes it, in a pack of its own.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/gone.rs", "MARKER-CLIENT-GONE-3b7e");
    let s = { let t = c.tip; snap(&mut c, vec![t], "the client goes", None) };
    let before = packs_in_store(&hub, pid);
    let (map, pack) = upload_all(&api, &c);
    let mut lock = hub.rt.block_on(hub.hub().db.begin()).unwrap();
    hub.rt
        .block_on(sqlx::query("SELECT 1 FROM packs WHERE project_id = $1 AND name = $2 FOR UPDATE").bind(pid).bind(&pack).execute(&mut *lock))
        .unwrap();
    let body = json!({"updates": [{"branch": "main", "expected": c.tip.hex(), "new": s.hex()}], "receipts": map});
    let gave_up = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        api.post_json_within(&c.token, &format!("/v1/projects/{}/push", p.name), &body, std::time::Duration::from_secs(3))
    }));
    assert!(gave_up.is_err(), "the client gave up before the push was answered: {:?}", gave_up.map(|r| r.status));
    // The push's own pack is in storage by now (written before its
    // transaction, which waits on the row), and has a row (BUG-1399's fix).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !packs_in_store(&hub, pid).iter().any(|n| *n != pack && !before.contains(n)) {
        assert!(std::time::Instant::now() < deadline, "the push never wrote its own pack");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "the push's own pack has its row before it is written");
    hub.rt.block_on(lock.rollback()).unwrap();
    // Whatever the push does now, it has had time to do it.
    std::thread::sleep(std::time::Duration::from_secs(10));
    let tip = api.tips(Some(&c.token), &p.name).unwrap().branches["main"];
    let orphans = packs_without_rows(&hub, pid);
    assert!(orphans.is_empty(), "packs in storage with no row: {orphans:?} (the push landed: {})", tip != c.tip);
}

/// BUG-1398 (S28 cycle 2; BUG-1153's class): a pull is no push, yet the
/// projections it stores count as a push's storage writes. `tips` and
/// `history` project each tip for the viewer (`sync::projected`), and a
/// projection made then is stored with `Objects::put` (`sync.rs`
/// `projected_inner`), outside `in_background`; grants' trees were moved
/// there in cycle 2 (`grant.rs`), these were not. The deriver projects
/// every view in the background after a landing (`derive::memo_tips`), but
/// a view can appear without one: here carol joins a group (a new way to
/// read the project), and her first pull projects the history for it.
/// `veil-bench load` takes `storage_writes - storage_background_writes` as
/// the pushes' writes; so does `writes` here.
#[test]
fn bug_1398_a_pulls_projections_are_not_counted_as_a_pushs_writes() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "security", &p.carol.name, "--confirm", &p.carol.fingerprint()]);
    settle(&hub);
    let w = writes(&hub);
    let all = hub.hub().objects.writes.load(Relaxed);
    let tips = hub.api().tips(Some(&p.carol.token()), &p.name).unwrap();
    assert!(tips.branches.contains_key("main"), "the tips were read");
    settle(&hub);
    assert!(hub.hub().objects.writes.load(Relaxed) > all, "the pull stored its projections");
    assert_eq!(writes(&hub) - w, 0, "a pull's storage writes were counted as a push's");
}

/// BUG-1397 (S28 cycle 2; BUG-1156's class): an API commit reads every
/// upload's encoding into memory **before** it takes its share of the
/// server-wide bound on decoded bytes (`sync::take_uploads`: the
/// `staged_encoding` loop, then `ReadAhead::wait`). Uploads that do not
/// compress are stored plain, so an encoding is as large as the object:
/// every API commit waiting for its share holds what it names (up to
/// 1 GiB, `MAX_API_UPLOADS`), outside the bound. Eight commits of 192 MiB
/// at once: the bound lets one decode at a time, while all of them hold
/// their encodings. Hostile size: run alone.
#[test]
fn hostile_bug_1397_api_commits_read_their_uploads_within_the_servers_bound() {
    use veil_core::hub::{encoding, wire::put_frame};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let base = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let commits: Vec<serde_json::Value> = (0..8)
        .map(|n| {
            let mut edits = Vec::new();
            let mut receipts = serde_json::Map::new();
            for i in 0..4 {
                // 48 MiB that does not compress: stored plain.
                let mut b = vec![0u8; 48 << 20];
                for w in b.as_chunks_mut::<8>().0 {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    w.copy_from_slice(&x.to_le_bytes());
                }
                let raw = O::Blob(b).encode();
                let id = ObjectId::hash(&raw);
                let enc = encoding::encode(&raw).into_owned();
                assert!(!encoding::is_compressed(&enc), "stored plain");
                let mut body = Vec::new();
                put_frame(&mut body, &id, &enc);
                drop((raw, enc));
                let up = api.upload_encoded_body(&token, &p.name, &body);
                assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
                let r: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
                receipts.insert(id.hex(), json!(r[0]));
                edits.push(json!({"path": format!("src/plain{n}/b{i}.bin"), "put": {"object": id.hex()}}));
            }
            json!({"base": base.hex(), "description": "large, plain", "edits": edits, "receipts": receipts})
        })
        .collect();
    let vm = |field: &str| -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let l = s.lines().find(|l| l.starts_with(field)).unwrap();
        l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() << 10
    };
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = vm("VmRSS:");
    let replies: Vec<Reply> = std::thread::scope(|s| {
        let hs: Vec<_> = commits.iter().map(|c| s.spawn(|| api.post_json_within(&token, &format!("/v1/projects/{}/changes", p.name), c, std::time::Duration::from_secs(1200)))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &replies {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    let grew = vm("VmHWM:").saturating_sub(before);
    assert!(grew < 1 << 30, "eight API commits at once took the server {} MiB past where it was", grew >> 20);
}


/// BUG-1496 (S28 cycle 3 review; BUG-1087's class): pack indexes read into
/// memory are held outside every bound. A push reads the index of every
/// staged pack its receipts name (`sync::staging`) and holds them all until
/// it is answered: an index is 48 bytes a slot in memory, a staged pack may
/// hold 2^21 objects (an upload request may be 2 GiB), and the staged-index
/// cache (32 MiB) keeps none larger than itself, so each push reads and
/// holds copies of its own. A participant uploads two packs of a million
/// tiny objects once, then sends pushes that name one receipt of each and
/// lose their race (the expected tip is wrong): the uploads stay staged,
/// and each push holds about 96 MiB of indexes (and their 88 MB of encoding
/// while it reads them). The same class: `Packs::refresh` holds every index
/// of a project it has not read before it adds any (the first lookup of a
/// large project on a server), `Packs::find_paged` one per lookup, with any
/// number at once. Fixed (cycle 4): every index held outside the lookup
/// maps holds a share of one server-wide bound (`pack::INDEXES_HELD`, 96
/// MiB), taken before it is read; a push keeps only the slots its receipts
/// name; `refresh` loads each index as it is read. Hostile size: run alone.
#[test]
fn hostile_bug_1496_pushes_hold_the_staged_indexes_they_name_within_a_bound() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let mut receipts = serde_json::Map::new();
    for k in 0..2 {
        let mut body = Vec::with_capacity(60 << 20);
        let mut first = None;
        for i in 0..1_000_000u32 {
            let raw = O::Blob(format!("{k}.{i}").into_bytes()).encode();
            let id = ObjectId::hash(&raw);
            first.get_or_insert(id);
            put_frame(&mut body, &id, &raw);
        }
        let up = api.upload_encoded_body(&token, &p.name, &body);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body[..up.body.len().min(400)]));
        // The first receipt (the answer holds a million).
        let text = std::str::from_utf8(&up.body).unwrap();
        let at = text.find("[\"").expect("receipts") + 2;
        let r = &text[at..at + text[at..].find('"').unwrap()];
        receipts.insert(first.unwrap().hex(), json!(r));
    }
    let wrong = ObjectId::hash(b"not the tip");
    let body = json!({"updates": [{"branch": "main", "expected": wrong.hex(), "new": tip.hex()}], "receipts": receipts});
    let path = format!("/v1/projects/{}/push", p.name);
    let vm = |field: &str| -> u64 {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let l = s.lines().find(|l| l.starts_with(field)).unwrap();
        l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() << 10
    };
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = vm("VmRSS:");
    let replies: Vec<Reply> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8).map(|_| s.spawn(|| api.post_json(Some(&token), &path, &body))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for r in &replies {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], json!(false), "the push lost its race: {}", String::from_utf8_lossy(&r.body));
    }
    let grew = vm("VmHWM:").saturating_sub(before);
    assert!(
        grew < 256 << 20,
        "eight pushes naming two staged uploads each took the server {} MiB past where it was (the staged-index cache is 32 MiB, the lookup budget 128 MiB)",
        grew >> 20
    );
}

/// BUG-1624 (review s28r5; BUG-1153's and BUG-1398's class, and the root cause
/// of `packs::bug_1157_a_push_that_lost_a_race_leaves_no_copy_of_its_upload`
/// failing 7 of 10 runs on YugabyteDB): `sync::push` runs `push_to_its_end`
/// inside `store::own(...)` (`sync.rs:1445`), where every `Objects::put`
/// increments `Objects::own_writes` (`storage_push_writes`). Inside
/// `push_staged` (`sync.rs:1543`, `1707`), the push projects the branch's
/// already-committed current tip for the viewer via `projected(hub, project,
/// viewer, *t)` (`deferred = None`), which stores any un-memoized projected
/// snapshot loose via `hub.objects.put` (`sync.rs:521`). When a non-admin push
/// runs before an earlier push's background deriver (`derive::memo_tips`) has
/// memoized that viewer's projection of the committed tip (as happens 7/10
/// times on YugabyteDB right after `p.admin`'s push in `bug_1157_…`, or
/// deterministically after a group change before any pull), that lazy
/// projection of already-committed history is counted as the push's own
/// storage write—even when the push loses its race and lands nothing.
#[test]
fn bug_1624_a_push_projecting_a_committed_tip_does_not_count_it_as_its_own_storage_write() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let settle = || {
        let mut last = (u64::MAX, std::time::Instant::now());
        let start = std::time::Instant::now();
        loop {
            let w = hub.hub().objects.writes.load(Relaxed);
            if w != last.0 {
                last = (w, std::time::Instant::now());
            } else if last.1.elapsed() > std::time::Duration::from_secs(1) {
                return;
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(60), "the background never settled");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };
    // Success first: when the viewer's tip projection is already memoized, a raced push adds 0 writes after its 1 upload write.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/dev_raced.rs", "MARKER-DEV-RACED-1624");
    let s = {
        let t = c.tip;
        snap(&mut c, vec![t], "dev raced", None)
    };
    write_files(&p.dir, &[("src/admin_first.rs", "admin landed first")]);
    p.admin.commit_main(&p.dir, "admin first");
    p.admin.ok(&p.dir, &["push"]);
    settle();

    let (map, _) = upload_all(&api, &c);
    let w_memoized = writes(&hub);
    let r = push_body(&api, &c.token, &p.name, c.tip, s, &map);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(false));
    assert_eq!(writes(&hub) - w_memoized, 0, "with the tip projection already memoized, a push that lost a race writes nothing");

    // When a push runs before `derive::memo_tips` has memoized the viewer's projection of the
    // committed tip in `projections` (as happens 7/10 times on YugabyteDB right after `p.admin`'s
    // push in `bug_1157_…`, or on another server replica before the memo row lands), `push_staged`
    // projects the committed tip with `deferred = None` inside `store::own`:
    let pid = project_id(&hub, &p.name);
    let other = TestHub::beside(&hub);
    let other_api = other.api();
    let (map2, _) = upload_all(&other_api, &c);
    hub.rt
        .block_on(sqlx::query("DELETE FROM projections WHERE project_id = $1").bind(pid).execute(&hub.hub().db))
        .unwrap();
    let w_before = writes(&other);
    let r2 = push_body(&other_api, &c.token, &p.name, c.tip, s, &map2);
    assert_eq!(r2.status, 200, "{}", String::from_utf8_lossy(&r2.body));
    assert_eq!(r2.json()["results"][0]["ok"], json!(false));
    assert_eq!(
        writes(&other) - w_before,
        0,
        "a push that lost a race must not count projecting an already-committed tip as its own storage write"
    );
}

/// S28 cycle 7 review (Guarantee 1): a push of more than `MAX_OBJECTS` small
/// objects (where `sync::packs_to_list` splits `own` across multiple packs)
/// lands without waiting on its own earlier pack's share, and releases all its
/// index shares when it ends, whether the push succeeds or fails.
#[test]
fn a_push_of_more_than_max_objects_lands_and_releases_every_share() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    let count = veil_server::pack::MAX_OBJECTS + 48_000;
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let tip = c.tip;

    let mut frames = Vec::with_capacity((count + 16) * 56);
    let mut obj_ids = Vec::with_capacity(count + 16);

    // Put an unread object at the very start of the first `MAX_OBJECTS` chunk so neither staged pack is
    // listed as-is (`sp.slots.len() < sp.objects` on both), forcing `packs_to_list` to copy all `count`
    // touched objects into `own` and split `own` across two `put_pack` calls.
    let (unread0_id, unread0_raw) = blob("MARKER-UNREAD-FIRST-PACK");
    put_frame(&mut frames, &unread0_id, &unread0_raw);
    obj_ids.push(unread0_id);

    let mut dir_entries = Vec::with_capacity(count);
    for i in 0..count {
        let mut raw = [0u8; 18];
        raw[..10].copy_from_slice(b"veil:blob\n");
        raw[10..18].copy_from_slice(&(i as u64).to_le_bytes());
        let id = ObjectId::hash(&raw);
        put_frame(&mut frames, &id, &raw);
        obj_ids.push(id);
        dir_entries.push(veil_core::TreeEntry {
            name: format!("b{i:06}"),
            id,
            kind: veil_core::object::EntryKind::File,
            executable: false,
            size: 8,
            visibility: veil_core::object::Visibility::Public,
        });
    }
    let (unread1_id, unread1_raw) = blob("MARKER-UNREAD-SECOND-PACK");
    put_frame(&mut frames, &unread1_id, &unread1_raw);
    obj_ids.push(unread1_id);

    let sub_tree = O::Tree(veil_core::Tree { entries: dir_entries }).encode_with(veil_core::object::TreeEncoding::Binary);
    let sub_tree_id = ObjectId::hash(&sub_tree);
    put_frame(&mut frames, &sub_tree_id, &sub_tree);
    obj_ids.push(sub_tree_id);

    c.refer_dir("src/many", sub_tree_id);
    for (id, raw) in &c.objects {
        put_frame(&mut frames, id, raw);
        obj_ids.push(*id);
    }

    let snap_id = snap(&mut c, vec![tip], "more than MAX_OBJECTS", None);
    let snap_raw = c.objects.iter().find(|(id, _)| *id == snap_id).unwrap().1.clone();
    put_frame(&mut frames, &snap_id, &snap_raw);
    obj_ids.push(snap_id);

    // Clear any staged-index cache entries from setup_project so `available()` reflects this push's shares only.
    let initial_staged: Vec<std::sync::Arc<str>> = hub
        .rt
        .block_on(sqlx::query_scalar::<_, String>("SELECT name FROM packs WHERE project_id = $1").bind(pid).fetch_all(&hub.hub().db))
        .unwrap()
        .into_iter()
        .map(std::sync::Arc::from)
        .collect();
    let _ = hub.rt.block_on(hub.hub().objects.discard(pid, &initial_staged));
    assert_eq!(hub.hub().objects.index_bound().available(), veil_server::pack::INDEXES_HELD, "idle bound before push");

    // 1. Success first: upload and push > MAX_OBJECTS small objects; it splits `own` into 2 packs,
    //    lands without waiting on its own earlier pack's share, and releases every share when done.
    let (listed_before, _) = pack_rows(&hub, pid);
    let up = api.upload_encoded_body(&c.token, &p.name, &frames);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body[..up.body.len().min(400)]));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    assert_eq!(receipts.len(), obj_ids.len());
    let mut map = serde_json::Map::new();
    for (id, r) in obj_ids.iter().zip(&receipts) {
        if *id != unread0_id && *id != unread1_id {
            map.insert(id.hex(), json!(r));
        }
    }
    let r = push_body(&api, &c.token, &p.name, tip, snap_id, &map);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));
    let (listed_after, _) = pack_rows(&hub, pid);
    assert!(listed_after - listed_before >= 2, "push of > MAX_OBJECTS listed {} packs", listed_after - listed_before);
    assert_eq!(
        hub.hub().objects.index_bound().available(),
        veil_server::pack::INDEXES_HELD,
        "all index shares released after a landing push of > MAX_OBJECTS (discarded staged uploads evicted from staged cache, listed own packs moved to lookup maps)"
    );

    // 2. Failure path: a refused push (unsigned/unknown-signer snapshot) with > MAX_OBJECTS receipts
    //    also releases all its shares when it ends.
    let new_tip = api.tips(Some(&c.token), &p.name).unwrap().branches["main"];
    let stranger = veil_core::Identity::generate("stranger");
    let bad_snap_id = snap(&mut c, vec![new_tip], "bad signer", Some(&stranger));
    let bad_snap_raw = c.objects.iter().find(|(id, _)| *id == bad_snap_id).unwrap().1.clone();
    let mut bad_frames = Vec::new();
    let (bad_b_id, bad_b_raw) = blob("MARKER-BAD-PUSH-UPLOAD");
    put_frame(&mut bad_frames, &bad_b_id, &bad_b_raw);
    put_frame(&mut bad_frames, &bad_snap_id, &bad_snap_raw);
    let up_bad = api.upload_encoded_body(&c.token, &p.name, &bad_frames);
    assert_eq!(up_bad.status, 200);
    let bad_receipts: Vec<String> = serde_json::from_value(up_bad.json()["receipts"].clone()).unwrap();
    let mut bad_map = serde_json::Map::new();
    bad_map.insert(bad_b_id.hex(), json!(bad_receipts[0]));
    bad_map.insert(bad_snap_id.hex(), json!(bad_receipts[1]));
    let r_bad = push_body(&api, &c.token, &p.name, new_tip, bad_snap_id, &bad_map);
    assert_eq!(r_bad.status, 403, "refused push: {}", String::from_utf8_lossy(&r_bad.body));
    assert_eq!(
        hub.hub().objects.index_bound().available(),
        veil_server::pack::INDEXES_HELD,
        "all index shares released after a failed push"
    );
}

/// S28 + S11 + S17: a push of a stack with attempts across parallel windows
/// (more snapshots than one `GUESS_WINDOW` of 64) keeps every attempt on its
/// version and lands none of them — both when every guess in `GUESS_WINDOW`
/// hits (`admin`) and when the server completes every attempt and version so
/// the initial guesses miss (`dev`, who cannot see `billing/`), as well as
/// through the landing service on a protected branch.
#[test]
fn a_push_of_a_stack_with_attempts_across_windows_keeps_every_attempt_and_lands_none() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    let push_stack_with_attempts = |person: &Person, prefix: &str, count: usize, branch: &str, land: Option<&str>| -> (Vec<veil_core::ChangeId>, Vec<ObjectId>, Vec<ObjectId>, Reply) {
        let mut c = Craft::new(&api, person, &p.name, branch);
        let expected = c.tip;
        let mut cur = c.tip;
        let mut cids = Vec::with_capacity(count);
        let mut attempts = Vec::with_capacity(count);
        let mut versions = Vec::with_capacity(count);
        for i in 0..count {
            let cid = veil_core::ChangeId::random();
            cids.push(cid);
            c.file(&format!("src/{prefix}/try_{i}.rs"), &format!("attempt {prefix} {i}"));
            let mut att = veil_core::object::Snapshot {
                parents: vec![cur],
                change_id: cid,
                tree: c.root,
                description: veil_core::object::Text::Plain(format!("try {prefix} {i}")),
                author: person.name.clone(),
                timestamp: veil_core::now_millis(),
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                signature: None,
                agent: Some(veil_core::object::Attribution {
                    agent: "claude-code".into(),
                    task: Some(format!("TASK-{prefix}-{i}")),
                    prompt: None,
                    run: None,
                }),
                attempts: vec![],
                abandoned: Some(format!("REASON-{prefix}-{i}: dead end")),
            };
            att.sign(&c.identity);
            let att_id = c.put(O::Snapshot(att));
            attempts.push(att_id);

            // Reset root tree back to `cur`'s tree so the attempt's `try_{i}.rs` is not in the version's tree.
            let cur_raw = if cur == expected {
                api.history(&c.token, &p.name, &[cur]).frames().into_iter().find(|(id, _)| *id == cur).unwrap().1
            } else {
                c.objects.iter().find(|(id, _)| *id == cur).unwrap().1.clone()
            };
            let O::Snapshot(cur_s) = O::decode(&cur_raw).unwrap() else { panic!() };
            c.root = cur_s.tree;
            c.file(&format!("src/{prefix}/ok_{i}.rs"), &format!("version {prefix} {i}"));
            let mut ver = veil_core::object::Snapshot {
                parents: vec![cur],
                change_id: cid,
                tree: c.root,
                description: veil_core::object::Text::Plain(format!("ok {prefix} {i}")),
                author: person.name.clone(),
                timestamp: veil_core::now_millis(),
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                signature: None,
                agent: Some(veil_core::object::Attribution {
                    agent: "claude-code".into(),
                    task: Some(format!("TASK-{prefix}-{i}")),
                    prompt: None,
                    run: None,
                }),
                attempts: vec![att_id],
                abandoned: None,
            };
            ver.sign(&c.identity);
            let ver_id = c.put(O::Snapshot(ver));
            versions.push(ver_id);
            cur = ver_id;
        }
        let up = api.upload(&c.token, &p.name, &c.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let map: serde_json::Map<String, serde_json::Value> =
            c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        let update = json!({"branch": branch, "expected": expected.hex(), "new": cur.hex()});
        let mut body = json!({"updates": [update], "receipts": map});
        if land.is_some() {
            body["wait"] = json!(true);
        }
        let r = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &body);
        (cids, attempts, versions, r)
    };

    // 1. Admin pushes 40 changes each with an attempt (80 snapshots > GUESS_WINDOW = 64):
    //    every guess in `GUESS_WINDOW` hits (`rp == real_parents && ra == real_attempts`).
    let (admin_cids, admin_attempts, admin_versions, r_admin) = push_stack_with_attempts(&p.admin, "adm", 40, "main", None);
    assert_eq!(r_admin.status, 200, "{}", String::from_utf8_lossy(&r_admin.body));
    assert_eq!(r_admin.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r_admin.body));

    // 2. Dev (who cannot see billing/) pushes 40 changes each with an attempt (80 snapshots > GUESS_WINDOW = 64):
    //    the server completes every attempt and every version, so `complete_one` and `guesses`
    //    substitute both `real_parents` and `real_attempts` across windows.
    let (dev_cids, dev_attempts, dev_versions, r_dev) = push_stack_with_attempts(&p.dev, "dev", 40, "main", None);
    assert_eq!(r_dev.status, 200, "{}", String::from_utf8_lossy(&r_dev.body));
    assert_eq!(r_dev.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r_dev.body));

    // 3. Protected branch (S17 landing service): protect `guarded` and push 40 changes
    //    with attempts (80 snapshots > GUESS_WINDOW = 64) with `wait: true`.
    let mut rules_c = Craft::new(&api, &p.admin, &p.name, "main");
    rules_c.file(".veilrules", "[branches.guarded]\nprotected = true\n");
    let r_rules = rules_c.push("main", "protect guarded");
    assert_eq!(r_rules.status, 200, "{}", String::from_utf8_lossy(&r_rules.body));
    let main_tip = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let r_branch = api.post_json(
        Some(&p.admin.token()),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "guarded", "expected": null, "new": main_tip.hex()}]}),
    );
    assert_eq!(r_branch.status, 200, "{}", String::from_utf8_lossy(&r_branch.body));
    let (guarded_cids, guarded_attempts, guarded_versions, r_guarded) =
        push_stack_with_attempts(&p.dev, "grd", 40, "guarded", Some("wait"));
    assert_eq!(r_guarded.status, 200, "{}", String::from_utf8_lossy(&r_guarded.body));
    assert_eq!(r_guarded.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r_guarded.body));
    assert!(r_guarded.json()["results"][0]["ticket"].is_string(), "{}", String::from_utf8_lossy(&r_guarded.body));

    // Verify in the database that NO attempt is ever recorded in `landed_changes`, `landings`, or `landed_from`,
    // while all 120 changes are recorded in `landed_changes`.
    let all_attempts: Vec<String> = admin_attempts
        .iter()
        .chain(&dev_attempts)
        .chain(&guarded_attempts)
        .map(ObjectId::hex)
        .collect();
    let landed_attempt_rows: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar(
                "SELECT (SELECT count(*) FROM landed_changes lc \
                         LEFT JOIN projections p ON p.project_id = lc.project_id AND p.real_id = lc.landed \
                         WHERE lc.project_id = $1 AND (lc.landed = ANY($2) OR p.projected_id = ANY($2))) \
                      + (SELECT count(*) FROM landings l \
                         LEFT JOIN projections p ON p.project_id = l.project_id AND (p.real_id = l.submitted OR p.real_id = l.landed) \
                         WHERE l.project_id = $1 AND (l.submitted = ANY($2) OR l.landed = ANY($2) OR p.projected_id = ANY($2))) \
                      + (SELECT count(*) FROM landed_from lf \
                         LEFT JOIN projections p ON p.project_id = lf.project_id AND (p.real_id = lf.source OR p.real_id = lf.landed) \
                         WHERE lf.project_id = $1 AND (lf.source = ANY($2) OR lf.landed = ANY($2) OR p.projected_id = ANY($2)))",
            )
            .bind(pid)
            .bind(&all_attempts)
            .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert_eq!(landed_attempt_rows, 0, "an attempt was recorded as landed");

    let all_cids: Vec<String> = admin_cids
        .iter()
        .chain(&dev_cids)
        .chain(&guarded_cids)
        .map(veil_core::ChangeId::to_string)
        .collect();
    let landed_change_rows: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar(
                "SELECT count(DISTINCT lc.change_id) FROM landed_changes lc \
                 WHERE lc.project_id = $1 AND lc.change_id = ANY($2)",
            )
            .bind(pid)
            .bind(&all_cids)
            .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert_eq!(landed_change_rows, 120, "every version of the 3 stacks landed");
    let _ = (&admin_versions, &dev_versions, &guarded_versions);

    // Verify history and trees for both `admin` (real snapshots) and `dev` (projected snapshots):
    // every version keeps its attempt with its reason, and no attempt file lands on the branch tree.
    for (who, sees_billing) in [(&p.admin, true), (&p.dev, false)] {
        let tok = who.token();
        let tips = api.tips(Some(&tok), &p.name).unwrap().branches;
        let h = api.history(&tok, &p.name, &[tips["main"], tips["guarded"]]);
        assert_eq!(h.status, 200);
        let frames = h.frames();
        let snaps: std::collections::HashMap<ObjectId, veil_core::object::Snapshot> = frames
            .into_iter()
            .filter_map(|(id, raw)| match O::decode(&raw) {
                Ok(O::Snapshot(s)) => Some((id, s)),
                _ => None,
            })
            .collect();
        for (prefix, cids) in [("adm", &admin_cids), ("dev", &dev_cids), ("grd", &guarded_cids)] {
            for (i, cid) in cids.iter().enumerate() {
                let ver = snaps
                    .values()
                    .find(|s| s.change_id == *cid && s.abandoned.is_none())
                    .unwrap_or_else(|| panic!("{} missing version {prefix} {i}", who.name));
                assert_eq!(ver.attempts.len(), 1, "{} version {prefix} {i} attempts", who.name);
                let att = snaps
                    .get(&ver.attempts[0])
                    .unwrap_or_else(|| panic!("{} missing attempt snapshot for {prefix} {i}", who.name));
                assert_eq!(
                    att.abandoned.as_deref(),
                    Some(format!("REASON-{prefix}-{i}: dead end").as_str()),
                    "{} attempt reason for {prefix} {i}",
                    who.name
                );
                assert_eq!(att.change_id, *cid);
            }
        }
        assert_eq!(
            read_file(&api, &tok, &p.name, "src/adm/ok_39.rs").as_deref(),
            Some(&b"version adm 39"[..])
        );
        assert_eq!(
            read_file(&api, &tok, &p.name, "src/dev/ok_39.rs").as_deref(),
            Some(&b"version dev 39"[..])
        );
        assert!(
            read_file(&api, &tok, &p.name, "src/adm/try_0.rs").is_none()
                && read_file(&api, &tok, &p.name, "src/adm/try_39.rs").is_none()
                && read_file(&api, &tok, &p.name, "src/dev/try_0.rs").is_none()
                && read_file(&api, &tok, &p.name, "src/dev/try_39.rs").is_none(),
            "attempt file landed on main for {}",
            who.name
        );
        let bill = read_file(&api, &tok, &p.name, &format!("{BILL_DIR}/acme/invoice.txt"));
        assert_eq!(bill.is_some(), sees_billing, "billing visibility for {}", who.name);
    }
}
