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
    // A path not named is checked as a path (`/e20/`): a refusal also names
    // a snapshot by its hex id, which may hold `e20` (BUG-2471's class).
    for who in [&p.admin, &p.dev] {
        // Two secrets: the first in order is the answer.
        let (status, body) = refused_history(&hub, &p, who, 30, &[(20, env(20)), (6, env(6))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e6/.env' is a secret and must arrive encrypted") && !body.contains("/e20/"), "{}: {body}", who.name);
        // A precheck refusal (an unknown key) after a secret, and before one.
        let (status, body) = refused_history(&hub, &p, who, 30, &[(2, env(2)), (5, None)]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e2/.env'"), "{}: {body}", who.name);
        let (status, body) = refused_history(&hub, &p, who, 30, &[(3, None), (10, env(10))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("signed by a key no device here is registered with") && !body.contains("/e10/"), "{}: {body}", who.name);
        // Past the first window of guesses.
        let (status, body) = refused_history(&hub, &p, who, 75, &[(70, env(70)), (66, env(66))]);
        assert_eq!(status, 403, "{}: {body}", who.name);
        assert!(body.contains("'src/chain/e66/.env'") && !body.contains("/e70/"), "{}: {body}", who.name);
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
    let kept0 = hub.hub().objects.objects_kept.load(Relaxed);
    p.admin.ok(&p.dir, &["push"]);
    settle();
    let kept = hub.hub().objects.objects_kept.load(Relaxed) - kept0;
    assert_eq!(writes(&hub) - w, 1 + kept, "an admin's push, its background work done: only its upload + kept objects");
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
    rules_c.file(
        ".veilrules",
        "[branches.guarded]\nprotected = true\n[review]\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n",
    );
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

/// S28 × S22: a push of an embargoed stack with more snapshots than one
/// `GUESS_WINDOW` (64) keeps every snapshot on its hidden `embargo/<id>` line
/// and none on `main` until release, and its objects are in the push's pack.
#[test]
fn embargoed_stack_across_guess_windows_stays_on_hidden_line_until_release_and_packs_its_objects() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    let initial_main = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];
    let initial_dev_main = api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"];

    // `p.sec` (in `security` and `devs`, cannot see `billing/`) crafts a stack of
    // 40 embargoed changes each with an abandoned attempt (80 snapshots > GUESS_WINDOW = 64)
    // on `main`: first an embargoed merge introducing `eid`, then 38 follow-up changes
    // (each with an abandoned attempt) on top of it.
    let eid = "a1b2c3d4e5";
    let mut c = Craft::new(&api, &p.sec, &p.name, "main");
    let expected = c.tip;

    // 1. The fix commit (parent = expected).
    c.file("src/emb_win/f_0.rs", "EMBARGO-WIN-FILE-0\n");
    let mut fix = veil_core::object::Snapshot {
        parents: vec![expected],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("embargoed win 0".into()),
        author: p.sec.name.clone(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    fix.sign(&c.identity);
    let fix_id = c.put(O::Snapshot(fix));

    // 2. The embargoed merge commit (parents = [expected, fix_id], embargo = Some(eid)).
    c.file("src/emb_win/f_1.rs", "EMBARGO-WIN-FILE-1\n");
    let mut mrg = veil_core::object::Snapshot {
        parents: vec![expected, fix_id],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("embargoed merge 1".into()),
        author: p.sec.name.clone(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: Some(eid.to_string()),
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    mrg.sign(&c.identity);
    let mut cur = c.put(O::Snapshot(mrg));

    let mut pushed_snaps = vec![fix_id, cur];
    let mut active_snaps = vec![fix_id, cur];
    let mut file_blobs = vec![blob("EMBARGO-WIN-FILE-0\n").0, blob("EMBARGO-WIN-FILE-1\n").0];

    // 3. 38 more changes on top, each with 1 abandoned attempt (2 + 38 * 2 = 78 new snapshots > GUESS_WINDOW = 64,
    //    and 40 changes on the line <= MAX_STACK = 64 so release landing succeeds).
    for i in 2..40 {
        let cid = veil_core::ChangeId::random();
        let cur_tree = c.root;
        c.file(&format!("src/emb_win/try_{i}.rs"), &format!("EMBARGO-WIN-TRY-{i}\n"));
        let mut att = veil_core::object::Snapshot {
            parents: vec![cur],
            change_id: cid,
            tree: c.root,
            description: veil_core::object::Text::Plain(format!("embargoed try {i}")),
            author: p.sec.name.clone(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
            agent: None,
            attempts: vec![],
            abandoned: Some(format!("abandoned try {i}")),
        };
        att.sign(&c.identity);
        let att_id = c.put(O::Snapshot(att));
        pushed_snaps.push(att_id);

        c.root = cur_tree;
        let content = format!("EMBARGO-WIN-FILE-{i}\n");
        file_blobs.push(blob(&content).0);
        c.file(&format!("src/emb_win/f_{i}.rs"), &content);
        let mut s = veil_core::object::Snapshot {
            parents: vec![cur],
            change_id: cid,
            tree: c.root,
            description: veil_core::object::Text::Plain(format!("embargoed win {i}")),
            author: p.sec.name.clone(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
            agent: None,
            attempts: vec![att_id],
            abandoned: None,
        };
        s.sign(&c.identity);
        cur = c.put(O::Snapshot(s));
        pushed_snaps.push(cur);
        active_snaps.push(cur);
    }
    assert_eq!(pushed_snaps.len(), 78);

    let rec = veil_core::keychain::EmbargoRecord {
        format: veil_core::keychain::EMBARGO_FORMAT,
        id: eid.to_string(),
        scope: "security".to_string(),
        until: Some(veil_core::now_millis() + 3_600_000),
        created: veil_core::now_millis(),
        released_at: None,
        state: None,
        reason: None,
    };

    let (listed_before, discarded_before) = pack_rows(&hub, pid);
    let w_before = writes(&hub);
    let kept_before = hub.hub().objects.objects_kept.load(Relaxed);

    let up = api.upload(&c.token, &p.name, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let upload_pack = receipts[0].split_once('.').unwrap().1.to_string();
    let map: serde_json::Map<String, serde_json::Value> =
        c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect();

    let push_body = json!({
        "updates": [{"branch": "main", "expected": expected.hex(), "new": cur.hex()}],
        "receipts": map,
        "embargoes": [rec],
    });
    let r = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &push_body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["branch"], json!("main"));

    // Objects layout: `p.sec` cannot see `billing/`, so the server completes every snapshot
    // across both GUESS_WINDOW chunks, stores every kept object loose (1 upload container + kept),
    // and lists no new pack.
    let w_used = writes(&hub) - w_before;
    let kept = hub.hub().objects.objects_kept.load(Relaxed) - kept_before;
    assert_eq!(w_used, 1 + kept, "expected 1 upload + {kept} kept objects, got {w_used}");
    let (listed_after, discarded_after) = pack_rows(&hub, pid);
    assert_eq!(listed_after, listed_before, "push in objects layout lists no pack ({listed_before} -> {listed_after})");
    assert_eq!(discarded_after, discarded_before, "upload container purged after commit");

    // Verify all uploaded blobs and completed snapshots are readable from a fresh server `other`.
    let other = TestHub::beside(&hub);
    let h_other = other.hub();
    for bid in &file_blobs {
        assert!(
            other.rt.block_on(h_other.objects.get(pid, bid)).unwrap().is_some(),
            "blob {bid} must be readable on a fresh server"
        );
    }
    let _ = upload_pack;

    // Every one of the active snapshots is on the hidden `embargo/<id>` line and recorded in `embargo_snapshots`,
    // and NONE of them is on `main` before release!
    let ebranch = format!("embargo/{eid}");
    let sec_tips = api.tips(Some(&c.token), &p.name).unwrap();
    assert_eq!(sec_tips.branches["main"], expected, "main must not move before embargo release");
    assert_eq!(sec_tips.branches[&ebranch], cur, "hidden line {ebranch} must point to the top snapshot");
    let admin_tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    assert_eq!(admin_tips.branches["main"], initial_main, "admin main must not move before embargo release");

    let dev_tips = api.tips(Some(&p.dev.token()), &p.name).unwrap();
    assert_eq!(dev_tips.branches["main"], initial_dev_main, "outsider main must not move before release");
    assert!(!dev_tips.branches.contains_key(&ebranch), "outsider must not see {ebranch}");

    // Check `embargo_snapshots` in DB: all 78 real and origin snapshots (both active versions and attempts) are recorded under `eid`.
    for snap_id in &pushed_snaps {
        let on_embargo: bool = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM embargo_snapshots WHERE project_id = $1 AND embargo_id = $2 AND snapshot = $3)")
                    .bind(pid)
                    .bind(eid)
                    .bind(snap_id.hex())
                    .fetch_one(&hub.hub().db),
            )
            .unwrap();
        assert!(on_embargo, "pushed snapshot {snap_id} must be recorded on hidden embargo line");
        let h_dev = api.post_json(
            Some(&p.dev.token()),
            &format!("/v1/projects/{}/history", p.name),
            &json!({"tips": [snap_id.hex()], "stop": []}),
        );
        assert_eq!(h_dev.status, 404, "outsider must not read embargoed snapshot {snap_id} before release");
    }

    // Release the embargo via `POST /v1/projects/{p}/embargoes/{eid}/release` and verify all 40 files land on `main`.
    let rel = api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/embargoes/{eid}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel.status, 200, "{}", String::from_utf8_lossy(&rel.body));
    assert_eq!(rel.json()["released"], json!(true));

    let after_tips = api.tips(Some(&p.dev.token()), &p.name).unwrap();
    assert_ne!(after_tips.branches["main"], initial_dev_main, "main must advance on release");
    assert!(!after_tips.branches.contains_key(&ebranch), "hidden branch must be removed on release");

    let other_api = other.api();
    let dev_tok = p.dev.token();
    for i in [0, 1, 20, 38, 39] {
        assert_eq!(
            read_file(&other_api, &dev_tok, &p.name, &format!("src/emb_win/f_{i}.rs")).as_deref(),
            Some(format!("EMBARGO-WIN-FILE-{i}\n").as_bytes()),
            "file f_{i}.rs must be on main after release"
        );
    }
}

/// BUG-2370: a push that loses its race in its transaction discards the
/// pack of its own that it wrote (what the server made for it). Eight
/// pushes race onto one tip, five rounds: each round exactly one lands and the others
/// are told to pull and push again; afterwards the only packs still staged
/// are uploads (kept for the next try, BUG-1157), no discarded pack is
/// still stored, every pack in storage has a row, and the tip holds
/// exactly the winners' files.
#[test]
fn bug_2370_racing_pushes_leave_no_pack_of_their_own_behind() {
    use std::collections::HashSet;
    const RACERS: usize = 8;
    const ROUNDS: usize = 5;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mut uploads: HashSet<String> = HashSet::new();
    let mut winners = Vec::new();
    for round in 0..ROUNDS {
        // Every racer's push is made on the same tip, then all are sent at once.
        let crafted: Vec<_> = (0..RACERS)
            .map(|i| {
                let mut c = Craft::new(&api, &p.dev, &p.name, "main");
                c.file(&format!("src/race/r{round}_{i}.rs"), &format!("round {round}, racer {i}\n"));
                let s = { let t = c.tip; snap(&mut c, vec![t], &format!("round {round}, racer {i}"), None) };
                let (map, pack) = upload_all(&api, &c);
                (c.token.clone(), c.tip, s, map, pack)
            })
            .collect();
        uploads.extend(crafted.iter().map(|c| c.4.clone()));
        let answers: Vec<(u16, bool, String)> = std::thread::scope(|sc| {
            let handles: Vec<_> = crafted
                .iter()
                .map(|(token, tip, s, map, _)| {
                    let (hub, name) = (&hub, &p.name);
                    sc.spawn(move || {
                        let r = push_body(&hub.api(), token, name, *tip, *s, map);
                        let body = String::from_utf8_lossy(&r.body).to_string();
                        (r.status, r.status == 200 && r.json()["results"][0]["ok"] == json!(true), body)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let won: Vec<usize> = answers.iter().enumerate().filter(|(_, a)| a.1).map(|(i, _)| i).collect();
        assert_eq!(won.len(), 1, "round {round}: exactly one push lands: {answers:?}");
        for (i, (status, ok, body)) in answers.iter().enumerate() {
            if !ok {
                assert!(*status == 409 || (*status == 200 && body.contains("moved")), "round {round}, racer {i}: a lost race is told so: {status} {body}");
            }
        }
        winners.push((round, won[0]));
    }
    settle(&hub);
    let h = hub.hub();
    let rows: Vec<(String, i16)> = hub.rt.block_on(sqlx::query_as("SELECT name, state FROM packs WHERE project_id = $1").bind(pid).fetch_all(&h.db)).unwrap();
    let staged_own: Vec<&String> = rows.iter().filter(|(n, st)| *st == 0 && !uploads.contains(n)).map(|(n, _)| n).collect();
    assert!(staged_own.is_empty(), "a push's own pack was left staged: {staged_own:?}");
    for (n, _) in rows.iter().filter(|(_, st)| *st == 2) {
        assert!(!hub.rt.block_on(h.objects.blob_store().exists(&veil_server::pack::key(pid, n))).unwrap(), "discarded pack {n} is still stored");
    }
    assert_eq!(packs_without_rows(&hub, pid), Vec::<String>::new(), "packs in storage with no row");
    let token = p.dev.token();
    for round in 0..ROUNDS {
        for i in 0..RACERS {
            let there = read_file(&api, &token, &p.name, &format!("src/race/r{round}_{i}.rs"));
            match winners.contains(&(round, i)) {
                true => assert_eq!(there.as_deref(), Some(format!("round {round}, racer {i}\n").as_bytes()), "round {round}: the winner's file"),
                false => assert_eq!(there, None, "round {round}, racer {i}: a push that lost left its file on the branch"),
            }
        }
    }
}
/// BUG-1150: a push introducing enough objects (~500,500 tiny blobs + trees)
/// that per-object receipts exceed the 64 MiB JSON body limit is refused with
/// 413 before the fix and lands cleanly once a push names its staged packs.
#[test]
fn bug_1150_push_past_64_mib_of_per_object_receipts_lands() {
    use std::sync::Arc;
    use veil_core::{
        object::{Snapshot, Text, Tree, TreeEntry, Visibility},
        oplog::Tag,
        pack::PackBuilder,
        vfs::{DiskBackend, StorageBackend},
        Repo,
    };

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let dir = clone(&hub, &p, &p.admin, "admin-1150");

    let backend: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(&dir));
    let mut repo = Repo::open(backend, Some(p.admin.identity()), &p.admin.name).unwrap();
    let tip = repo.view().tags["main"].target;
    let tip_snap = repo.store().get(&tip).unwrap();
    let base_root_id = match tip_snap {
        O::Snapshot(s) => s.tree,
        _ => panic!("expected snapshot"),
    };
    let base_root = repo.store().tree(&base_root_id).unwrap();
    let base_src_id = base_root.entries.iter().find(|e| e.name == "src").expect("src dir").id;
    let base_src = repo.store().tree(&base_src_id).unwrap();

    // 500 dirs * 1,000 tiny 7-byte blobs = 500,000 blobs + 504 trees/snapshot.
    // At 135 bytes per receipt entry in JSON, 500,504 receipts ≈ 67.57 MB > 64 MiB.
    const DIRS: usize = 500;
    const FILES_PER_DIR: usize = 1_000;
    let mut pb = PackBuilder::new(1).unwrap();
    let mut put = |obj: O| -> ObjectId {
        let raw = obj.encode();
        let id = ObjectId::hash(&raw);
        pb.add(id, &raw, None).unwrap();
        id
    };

    let mut bulk_entries = Vec::with_capacity(DIRS);
    let mut sample_id = ObjectId([0; 32]);
    let mut sample_text = String::new();
    for d in 0..DIRS {
        let mut entries = Vec::with_capacity(FILES_PER_DIR);
        for f in 0..FILES_PER_DIR {
            let content = format!("{d:03}/{f:03}");
            let id = put(O::Blob(content.as_bytes().to_vec()));
            if d == DIRS - 1 && f == FILES_PER_DIR - 1 {
                sample_id = id;
                sample_text = content.clone();
            }
            entries.push(TreeEntry {
                name: format!("f{f:03}"),
                kind: veil_core::object::EntryKind::File,
                id,
                size: content.len() as u64,
                visibility: Visibility::Public,
                executable: false,
            });
        }
        let dir_tree_id = put(O::Tree(Tree { entries }));
        bulk_entries.push(TreeEntry::dir(&format!("d{d:03}"), dir_tree_id));
    }
    let bulk_tree_id = put(O::Tree(Tree { entries: bulk_entries }));

    let mut src_entries = base_src.entries.clone();
    src_entries.push(TreeEntry::dir("bulk", bulk_tree_id));
    src_entries.sort_by(|a, b| a.name.cmp(&b.name));
    let new_src_id = put(O::Tree(Tree { entries: src_entries }));

    let mut root_entries = base_root.entries.clone();
    for e in &mut root_entries {
        if e.name == "src" {
            e.id = new_src_id;
        }
    }
    root_entries.sort_by(|a, b| a.name.cmp(&b.name));
    let new_root_id = put(O::Tree(Tree { entries: root_entries }));

    let mut snap = Snapshot {
        parents: vec![tip],
        change_id: veil_core::ChangeId::random(),
        tree: new_root_id,
        description: Text::Plain("BUG-1150 bulk 500k tiny objects".into()),
        author: p.admin.name.clone(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    snap.sign(&p.admin.identity());
    let snap_id = put(O::Snapshot(snap));

    pb.finish(repo.backend().as_ref(), &repo.store().pack_dir()).unwrap();
    repo.store().reload_packs().unwrap();

    let mut tx = repo.transaction("bulk 500k").unwrap();
    tx.repository_wide();
    tx.view.heads.insert(snap_id);
    tx.view.tags.insert("main".into(), Tag { target: snap_id, annotation: None });
    tx.commit().unwrap();
    drop(repo);

    let out = p.admin.run(&dir, &["push"]);
    assert!(
        out.status.success(),
        "vl push with >500k objects failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let api = hub.api();
    let tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    assert_eq!(tips.branches["main"], snap_id, "main must advance to pushed snapshot");

    let fetched = api.post_json(
        Some(&p.admin.token()),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({
            "snapshot": snap_id.hex(),
            "objects": [{"path": format!("src/bulk/d{:03}/f{:03}", DIRS - 1, FILES_PER_DIR - 1), "id": sample_id.hex()}],
        }),
    );
    assert_eq!(fetched.status, 200, "{}", String::from_utf8_lossy(&fetched.body));
    let frames = fetched.frames();
    assert_eq!(frames.len(), 1);
    assert_eq!(O::decode(&frames[0].1).unwrap(), O::Blob(sample_text.into_bytes()));
}

/// Proof-of-upload test for BUG-1150 (`PushRequest::packs` and
/// `LandRequest::packs`) in `objects` layout.
fn bug_1150_push_packs_proof_of_upload(hub: TestHub) {
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let h = hub.hub();
    let dev_tok = p.dev.token();
    let carol_tok = p.carol.token();

    let assert_bad_request = |r: &Reply, what: &str| {
        assert_eq!(r.status, 400, "{what}: status {} body {}", r.status, String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["code"], "bad_request", "{what}: body {}", String::from_utf8_lossy(&r.body));
    };

    // 1. Naming another person's staged pack is refused (400 bad_request) and
    //    never discards the other person's staged pack.
    let mut c1 = Craft::new(&api, &p.dev, &p.name, "main");
    c1.file("src/owned_1150.rs", "MARKER-OWNED-1150\n");
    let tip1 = c1.tip;
    let snap1 = snap(&mut c1, vec![tip1], "dev owned", None);
    let up_dev1 = api.upload(&dev_tok, &p.name, &c1.objects);
    assert_eq!(up_dev1.status, 200, "{}", String::from_utf8_lossy(&up_dev1.body));
    let dev_packs1: Vec<String> = serde_json::from_value(up_dev1.json()["packs"].clone()).unwrap();
    assert_eq!(dev_packs1.len(), 1);
    let dev_pack1 = dev_packs1[0].clone();

    let carol_text = "MARKER-CAROL-1150\n";
    let (carol_blob_id, carol_blob_raw) = blob(carol_text);
    let mut carol_frames = Vec::new();
    put_frame(&mut carol_frames, &carol_blob_id, &carol_blob_raw);
    let up_carol = api.upload_body(&carol_tok, &p.name, &carol_frames);
    assert_eq!(up_carol.status, 200, "{}", String::from_utf8_lossy(&up_carol.body));
    let carol_packs: Vec<String> = serde_json::from_value(up_carol.json()["packs"].clone()).unwrap();
    assert_eq!(carol_packs.len(), 1);
    let carol_pack = carol_packs[0].clone();

    let push_packs = |client: &Api, tok: &str, expected: ObjectId, new: ObjectId, packs: &[&str]| {
        client.post_json(
            Some(tok),
            &format!("/v1/projects/{}/push", p.name),
            &json!({
                "updates": [{"branch": "main", "expected": expected.hex(), "new": new.hex()}],
                "packs": packs,
            }),
        )
    };

    let r_carol_using_dev = push_packs(&api, &carol_tok, tip1, snap1, &[&dev_pack1]);
    assert_bad_request(&r_carol_using_dev, "carol naming dev's pack");
    assert!(
        hub.rt.block_on(h.objects.staged_index(pid, &dev_pack1)).unwrap().is_some(),
        "another person naming dev's pack must not discard dev's pack"
    );

    let r_dev_using_carol = push_packs(&api, &dev_tok, tip1, snap1, &[&carol_pack]);
    assert_bad_request(&r_dev_using_carol, "dev naming carol's pack");
    let r_dev_mixed = push_packs(&api, &dev_tok, tip1, snap1, &[&dev_pack1, &carol_pack]);
    assert_bad_request(&r_dev_mixed, "dev naming own pack + carol's pack");
    assert_eq!(
        r_dev_using_carol.body, r_dev_mixed.body,
        "naming another person's pack alone or beside own pack gives the same answer"
    );
    assert!(
        hub.rt.block_on(h.objects.staged_index(pid, &carol_pack)).unwrap().is_some(),
        "dev naming carol's pack must never discard carol's staged pack"
    );
    assert!(
        hub.rt.block_on(h.objects.staged_index(pid, &dev_pack1)).unwrap().is_none(),
        "dev's own staged pack in a refused push is discarded"
    );

    // 2. Duplicate pack name, forged/malformed pack names, mixing `packs` and
    //    `receipts`, then a clean push with `packs`.
    let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
    c2.file("src/valid_1150.rs", "MARKER-VALID-1150\n");
    let tip2 = c2.tip;
    let snap2 = snap(&mut c2, vec![tip2], "dev valid", None);
    let up_dev2 = api.upload(&dev_tok, &p.name, &c2.objects);
    assert_eq!(up_dev2.status, 200, "{}", String::from_utf8_lossy(&up_dev2.body));
    let up_dev2_json = up_dev2.json();
    let dev_pack2 = up_dev2_json["packs"][0].as_str().unwrap().to_string();
    let dev_receipt0 = up_dev2_json["receipts"][0].as_str().unwrap().to_string();

    let r_dup = push_packs(&api, &dev_tok, tip2, snap2, &[&dev_pack2, &dev_pack2]);
    assert_bad_request(&r_dup, "same pack named twice");

    for bad in ["", ".", "../x", &"A".repeat(32), &"0".repeat(31)] {
        let r_bad = push_packs(&api, &dev_tok, tip2, snap2, &[bad]);
        assert_bad_request(&r_bad, &format!("malformed pack name {bad:?}"));
    }

    let r_both = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "main", "expected": tip2.hex(), "new": snap2.hex()}],
            "packs": [&dev_pack2],
            "receipts": {c2.objects[0].0.hex(): dev_receipt0},
        }),
    );
    assert_bad_request(&r_both, "push sending both packs and receipts");

    let r_forged = push_packs(&api, &dev_tok, tip2, snap2, &[&"0".repeat(32)]);
    assert_bad_request(&r_forged, "forged 32-hex pack name");
    assert_eq!(
        r_forged.body, r_dev_using_carol.body,
        "forged 32-hex pack name must give the exact same answer as another person's pack (no oracle)"
    );

    let r_ok = push_packs(&api, &dev_tok, tip2, snap2, &[&dev_pack2]);
    assert_eq!(r_ok.status, 200, "{}", String::from_utf8_lossy(&r_ok.body));
    assert_eq!(r_ok.json()["results"][0]["ok"], true);
    assert_eq!(read_file(&api, &dev_tok, &p.name, "src/valid_1150.rs"), Some(b"MARKER-VALID-1150\n".to_vec()));

    // 3. Introducing an object not in the named packs (hidden billing blob vs
    //    random nonexistent id): refused with identical 400 bad_request answers.
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let real_hidden_id = real_paths(&p.dir)
        .into_iter()
        .find(|(path, _)| *path == hidden_path)
        .expect("billing invoice")
        .1;
    let right_bytes = format!("{BILL_MARK}\nsecond").into_bytes();
    let wrong_bytes = b"MARKER-WRONG-1150-NOT-STORED".to_vec();
    let (rid, rraw) = (ObjectId::hash(&O::Blob(right_bytes.clone()).encode()), O::Blob(right_bytes.clone()).encode());
    let (wid, wraw) = (ObjectId::hash(&O::Blob(wrong_bytes.clone()).encode()), O::Blob(wrong_bytes.clone()).encode());
    assert_eq!(rid, real_hidden_id, "right guess matches hidden billing blob");

    let mut unuploaded_answers = Vec::new();
    for (id, bytes, label) in [(wid, &wrong_bytes, "random missing"), (rid, &right_bytes, "hidden billing")] {
        let mut cg = Craft::new(&api, &p.dev, &p.name, "main");
        cg.set("src/claim_1150.txt", O::Blob(bytes.clone()), veil_core::object::Visibility::Public);
        cg.objects.retain(|(o, _)| *o != id);
        let tip = cg.tip;
        let sg = snap(&mut cg, vec![tip], "claim unuploaded", None);
        let up = api.upload(&dev_tok, &p.name, &cg.objects);
        assert_eq!(up.status, 200, "{label}: {}", String::from_utf8_lossy(&up.body));
        let pack = up.json()["packs"][0].as_str().unwrap().to_string();
        let r = push_packs(&api, &dev_tok, tip, sg, &[&pack]);
        assert_bad_request(&r, &format!("object not in named pack ({label})"));
        assert!(
            hub.rt.block_on(h.objects.staged_index(pid, &pack)).unwrap().is_none(),
            "refused push's staged pack is discarded ({label})"
        );
        let mut norm = String::from_utf8_lossy(&r.body).into_owned();
        for oid in cg.objects.iter().map(|(o, _)| *o).chain([id, sg]) {
            norm = norm.replace(&oid.hex(), "ID").replace(&oid.short(), "ID");
        }
        unuploaded_answers.push((r.status, norm));
    }
    assert_eq!(
        unuploaded_answers[1], unuploaded_answers[0],
        "naming an unuploaded hidden object must match a random missing id (no oracle)"
    );

    // 4. Discarded pack from an earlier refused push (BUG-1155 with `packs`):
    //    refused with identical 400 bad_request answers for right vs wrong guess.
    let up_guess = api.upload(&dev_tok, &p.name, &[(rid, rraw), (wid, wraw)]);
    assert_eq!(up_guess.status, 200, "{}", String::from_utf8_lossy(&up_guess.body));
    let g_pack = up_guess.json()["packs"][0].as_str().unwrap().to_string();
    let tip_now = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let refused_discard = push_packs(&api, &dev_tok, tip_now, ObjectId::hash(b"missing-snap-1150"), &[&g_pack]);
    assert_bad_request(&refused_discard, "push discarding g_pack");
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &g_pack)).unwrap().is_none(), "g_pack discarded");

    let mut discarded_answers = Vec::new();
    for (id, bytes, label) in [(wid, &wrong_bytes, "wrong guess"), (rid, &right_bytes, "right guess")] {
        let mut cg = Craft::new(&api, &p.dev, &p.name, "main");
        cg.set("src/guess_1150.txt", O::Blob(bytes.clone()), veil_core::object::Visibility::Public);
        cg.objects.retain(|(o, _)| *o != id);
        let tip = cg.tip;
        let sg = snap(&mut cg, vec![tip], "discarded pack guess", None);
        let up = api.upload(&dev_tok, &p.name, &cg.objects);
        assert_eq!(up.status, 200, "{label}: {}", String::from_utf8_lossy(&up.body));
        let cg_pack = up.json()["packs"][0].as_str().unwrap().to_string();
        let r = push_packs(&api, &dev_tok, tip, sg, &[&cg_pack, &g_pack]);
        assert_bad_request(&r, &format!("discarded pack ({label})"));
        assert_eq!(r.body, r_forged.body, "discarded pack must match forged pack (no oracle)");
        assert!(hub.rt.block_on(h.objects.staged_index(pid, &cg_pack)).unwrap().is_none(), "sibling pack discarded");
        discarded_answers.push((r.status, r.body));
    }
    assert_eq!(discarded_answers[1], discarded_answers[0]);

    // 5. Carol's untouched pack from step 1 still works through a cold second
    //    server (`TestHub::beside`), and an unread extra blob in a named pack
    //    is not kept in the project's store.
    let carol_path = format!("{PERSON_DIR}/carol_1150.txt");
    let mut cc = Craft::new(&api, &p.carol, &p.name, "main");
    cc.set(&carol_path, O::Blob(carol_text.as_bytes().to_vec()), veil_core::object::Visibility::Public);
    cc.objects.retain(|(o, _)| *o != carol_blob_id);
    let c_tip = cc.tip;
    let c_snap = snap(&mut cc, vec![c_tip], "carol uses her earlier pack", None);
    let (unread_id, unread_raw) = blob("MARKER-UNREAD-EXTRA-1150\n");
    cc.objects.push((unread_id, unread_raw));
    let up_c2 = api.upload(&carol_tok, &p.name, &cc.objects);
    assert_eq!(up_c2.status, 200, "{}", String::from_utf8_lossy(&up_c2.body));
    let carol_pack2 = up_c2.json()["packs"][0].as_str().unwrap().to_string();

    let cold = TestHub::beside(&hub);
    let cold_api = cold.api();
    let r_carol_ok = push_packs(&cold_api, &carol_tok, c_tip, c_snap, &[&carol_pack, &carol_pack2]);
    assert_eq!(r_carol_ok.status, 200, "{}", String::from_utf8_lossy(&r_carol_ok.body));
    assert_eq!(r_carol_ok.json()["results"][0]["ok"], true);
    assert_eq!(read_file(&api, &carol_tok, &p.name, &carol_path), Some(carol_text.as_bytes().to_vec()));
    assert!(
        hub.rt.block_on(h.objects.get(pid, &unread_id)).unwrap().is_none(),
        "unread extra object in a named staged pack must not be kept in the project"
    );

    // 6. Snapshot landing (`POST …/land`) accepts `packs`, refuses `packs` +
    //    `receipts`, and refuses `packs` with `edits`.
    let mut cl = Craft::new(&api, &p.dev, &p.name, "main");
    cl.file("src/land_1150.rs", "MARKER-LAND-1150\n");
    let l_tip = cl.tip;
    let l_snap = snap(&mut cl, vec![l_tip], "land with packs", None);
    let up_l = api.upload(&dev_tok, &p.name, &cl.objects);
    assert_eq!(up_l.status, 200, "{}", String::from_utf8_lossy(&up_l.body));
    let l_pack = up_l.json()["packs"][0].as_str().unwrap().to_string();
    let l_rec0 = up_l.json()["receipts"][0].as_str().unwrap().to_string();

    let r_land_both = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "onto": "main",
            "snapshot": l_snap.hex(),
            "packs": [&l_pack],
            "receipts": {cl.objects[0].0.hex(): l_rec0},
            "wait": true,
        }),
    );
    assert_bad_request(&r_land_both, "land with both packs and receipts");

    let r_land_edits = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "onto": "main",
            "base": l_tip.hex(),
            "edits": [{"path": "src/e.txt", "put": {"text": "hi"}}],
            "packs": [&l_pack],
            "wait": true,
        }),
    );
    assert_bad_request(&r_land_edits, "land with packs and edits");

    let r_land_ok = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "onto": "main",
            "snapshot": l_snap.hex(),
            "packs": [&l_pack],
            "wait": true,
        }),
    );
    assert_eq!(r_land_ok.status, 200, "{}", String::from_utf8_lossy(&r_land_ok.body));
    assert_eq!(r_land_ok.json()["state"], "landed", "{}", String::from_utf8_lossy(&r_land_ok.body));
    assert_eq!(read_file(&api, &dev_tok, &p.name, "src/land_1150.rs"), Some(b"MARKER-LAND-1150\n".to_vec()));
}

#[test]
fn bug_1150_push_packs_proof_of_upload_in_objects_layout() {
    bug_1150_push_packs_proof_of_upload(TestHub::start_objects());
}

/// BUG-2851 (review b1a; `t3/bug-1150-push-packs` × `t3/object-layout`):
/// In `objects` layout, a committing push marks its consumed staged pack `P1`
/// `DISCARDED (objects = -1)` and synchronously runs `purge_discarded`
/// (`pack.rs:1691-1725`), deleting `P1`'s blob and `packs` row before returning
/// `200`. A concurrent or retrying push naming `[P1, P2]` (where `P2` is an
/// unrelated live sibling upload by the same person) finds no row for `P1` in
/// `usable_for_packs` (`pack.rs:1476-1518`), classifies `P1` as `invalid`
/// instead of `consumed`, calls `discard_refused` on live sibling `P2`
/// (`sync.rs:4663`), and returns non-retryable `400 bad_request` instead of
/// retryable `409 conflict` (`DISCARDED_UPLOAD`), destroying `P2`.
#[test]
fn bug_2851_push_packs_consumed_in_objects_layout_answers_409_and_keeps_sibling_uploads() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let h = hub.hub();
    let dev_tok = p.dev.token();

    let mut c1 = Craft::new(&api, &p.dev, &p.name, "main");
    c1.file("src/first_2851.rs", "MARKER-FIRST-2851\n");
    let tip1 = c1.tip;
    let snap1 = snap(&mut c1, vec![tip1], "first commit", None);
    let up1 = api.upload(&dev_tok, &p.name, &c1.objects);
    assert_eq!(up1.status, 200, "{}", String::from_utf8_lossy(&up1.body));
    let p1 = up1.json()["packs"][0].as_str().unwrap().to_string();

    let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
    c2.file("src/sibling_2851.rs", "MARKER-SIBLING-2851\n");
    let snap2 = snap(&mut c2, vec![tip1], "sibling commit", None);
    let up2 = api.upload(&dev_tok, &p.name, &c2.objects);
    assert_eq!(up2.status, 200, "{}", String::from_utf8_lossy(&up2.body));
    let p2 = up2.json()["packs"][0].as_str().unwrap().to_string();

    assert!(hub.rt.block_on(h.objects.staged_index(pid, &p1)).unwrap().is_some(), "p1 staged");
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &p2)).unwrap().is_some(), "p2 staged");

    // Push 1 consumes `p1` (marking `objects = -1` and purging its `packs` row in `objects` layout).
    let r1 = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "main", "expected": tip1.hex(), "new": snap1.hex()}],
            "packs": [&p1],
        }),
    );
    assert_eq!(r1.status, 200, "push 1 committing p1: {}", String::from_utf8_lossy(&r1.body));
    assert_eq!(r1.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r1.body));
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &p2)).unwrap().is_some(), "sibling p2 still staged after push 1");

    // Push 2 names already-consumed `p1` alongside live sibling `p2`: must
    // answer retryable `409 conflict` (`DISCARDED_UPLOAD`) and keep `p2` live.
    let r2 = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "side-2851", "expected": null, "new": snap2.hex()}],
            "packs": [&p1, &p2],
        }),
    );
    assert_eq!(
        r2.status,
        409,
        "push naming consumed pack in objects layout must answer 409 conflict (not 400): {}",
        String::from_utf8_lossy(&r2.body)
    );
    assert_eq!(r2.json()["code"], "conflict", "{}", String::from_utf8_lossy(&r2.body));
    assert!(
        hub.rt.block_on(h.objects.staged_index(pid, &p2)).unwrap().is_some(),
        "live sibling staged upload p2 must not be discarded when p1 was already consumed"
    );

    // Retry naming only live sibling `p2` succeeds.
    let r3 = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "side-2851", "expected": null, "new": snap2.hex()}],
            "packs": [&p2],
        }),
    );
    assert_eq!(r3.status, 200, "retry with surviving sibling p2: {}", String::from_utf8_lossy(&r3.body));
    assert_eq!(r3.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r3.body));
}

/// BUG-2852 (review b1a; regression of BUG-1496 in `t3/bug-1150-push-packs`):
/// `sync::staging_packs` (`sync.rs:4679-4750`) loads each named staged pack's
/// full index under `Packs::bound` (`pack::INDEXES_HELD`, 96 MiB), immediately
/// copies every `(ObjectId, Slot)` into an unbudgeted `Vec` (`StagedSlots`),
/// drops the `Held` permit (`sync.rs:4686`), duplicates every entry into
/// `at: HashMap<ObjectId, (Arc<str>, Slot)>` (`sync.rs:4737-4740`), and copies
/// every key a third time into `uploaded: HashSet<ObjectId>` (`sync.rs:3124`).
/// Concurrent losing pushes naming two large staged packs therefore bypass
/// `INDEXES_HELD` and grow server RSS by hundreds of MiB. Hostile size: run alone.
#[test]
fn hostile_bug_2852_push_packs_holds_staged_indexes_within_indexes_held_bound() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let mut packs = Vec::new();
    for k in 0..2 {
        let mut body = Vec::with_capacity(16 << 20);
        for i in 0..250_000u32 {
            let raw = O::Blob(format!("{k}.{i}").into_bytes()).encode();
            let id = ObjectId::hash(&raw);
            put_frame(&mut body, &id, &raw);
        }
        let up = api.upload_encoded_body(&token, &p.name, &body);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body[..up.body.len().min(400)]));
        let text = std::str::from_utf8(&up.body).unwrap();
        let marker = "\"packs\":[\"";
        let at = text.find(marker).expect("packs in upload reply") + marker.len();
        let pack = text[at..at + text[at..].find('"').unwrap()].to_string();
        assert_eq!(pack.len(), 32, "valid 32-hex pack name");
        packs.push(pack);
    }
    let wrong = ObjectId::hash(b"not the tip 2852");
    let body = json!({"updates": [{"branch": "main", "expected": wrong.hex(), "new": tip.hex()}], "packs": packs});
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
        "eight pushes naming two 250k-object staged packs took the server {} MiB past where it was (INDEXES_HELD is 96 MiB)",
        grew >> 20
    );
}
