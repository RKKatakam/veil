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
    o.writes.load(Relaxed) - o.background_writes.load(Relaxed)
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
    let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [tip.hex()]}));
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
    // Every pack in storage has a row (a directory store: walk it).
    if let Some(dir) = hub.objects_dir() {
        let dir = dir.join(format!("p/{pid}/pack"));
        let rows: Vec<String> =
            hub.rt.block_on(sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1").bind(pid).fetch_all(&hub.hub().db)).unwrap();
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(rows.contains(&n), "pack {n} in storage has no row");
        }
    }
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
fn bug_1156_api_commits_hold_their_uploads_within_the_servers_bound() {
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
        let (index, _) = hub.rt.block_on(veil_server::pack::read_index(&*store, &veil_server::pack::key(pid, n))).unwrap().unwrap();
        assert!(index.get(&sid).is_none(), "the unread secret is in listed pack {n}");
    }
    assert_eq!(read_file(&fresh.api(), &c.token, &p.name, "src/landed.rs").as_deref(), Some(&b"MARKER-LANDED-BESIDE-A-SECRET-2b7e"[..]));
}
