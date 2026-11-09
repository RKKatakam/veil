//! The Veil daemon (S6, `docs/HUB.md` §13.29), its guarantees as tests:
//!
//! 1. it never serves an object the server would not serve that person's
//!    device now, whatever id, chain, grant or signature is sent, cold or
//!    warm, with everyone's objects in its store;
//! 2. a removed person, a changed policy and a removed device are refused
//!    within the owner's bound (5 s); without the server it serves nothing
//!    from its store after 5 s, public objects included (fail closed);
//! 3. a thin clone answers the same with and without it;
//! 4. its store keeps to its bound, and its memory to its budget, with
//!    every object it holds counted;
//! 5. a `vl` without it (off, killed, or lying) works and answers as the
//!    server does;
//! 6. its socket and store are its user's alone.

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use veil_core::{
    hub::grant::{sign_request, BatchRequest, ChainWant, Grant},
    object::Object,
    Identity, ObjectId,
};

use crate::support::*;

/// The daemon's bound, and how long the tests allow beyond it for an
/// answer to arrive.
const STALE: Duration = Duration::from_secs(5);

// ---- a raw client of a daemon's socket --------------------------------------------

/// One request to the daemon at `socket`: the objects that arrived, and the
/// answer's end (`None`: unfinished).
fn ask(socket: &Path, req: &serde_json::Value) -> (Vec<(ObjectId, Vec<u8>)>, Option<serde_json::Value>) {
    let mut s = UnixStream::connect(socket).unwrap_or_else(|e| panic!("connecting to {}: {e}", socket.display()));
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    ask_as(&mut s, PROTOCOL, req)
}

/// The daemon's socket protocol version (`proto::PROTOCOL`).
const PROTOCOL: u8 = 1;

/// [`ask`] on stream `s`, the request sent as protocol version `version`.
/// The daemon acknowledges every request with its version (`A`) first.
fn ask_as(s: &mut UnixStream, version: u8, req: &serde_json::Value) -> (Vec<(ObjectId, Vec<u8>)>, Option<serde_json::Value>) {
    let mut body = vec![version];
    body.extend_from_slice(&serde_json::to_vec(req).unwrap());
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    s.write_all(&msg).unwrap();
    let mut got = Vec::new();
    let mut acked = false;
    loop {
        let mut head = [0u8; 5];
        if s.read_exact(&mut head).is_err() {
            return (got, None);
        }
        let len = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        if s.read_exact(&mut payload).is_err() {
            return (got, None);
        }
        match head[0] {
            b'A' => {
                assert!(!acked && got.is_empty(), "the acknowledgement comes first, once");
                assert_eq!(payload, [PROTOCOL], "the daemon's version");
                acked = true;
            }
            // Progress, while the daemon works (every 0.1 s).
            b'P' => assert!(acked, "progress before the acknowledgement"),
            b'O' => {
                assert!(acked, "an object before the acknowledgement");
                let id = ObjectId(payload[..32].try_into().unwrap());
                let raw = payload[32..].to_vec();
                assert_eq!(ObjectId::hash(&raw), id, "the daemon sent bytes that are not the object's");
                got.push((id, raw));
            }
            b'E' => return (got, Some(serde_json::from_slice(&payload).unwrap())),
            k => panic!("an unknown message {k}"),
        }
    }
}

/// A person's daemon, in their Veil home.
struct Daemon {
    socket: PathBuf,
    dir: PathBuf,
}

impl Daemon {
    fn of(who: &Person) -> Daemon {
        let dir = who.home.path().join("veil/daemon");
        Daemon { socket: dir.join("sock"), dir }
    }

    /// `vl daemon start` as `who` (with `--cache-size` when given).
    fn start(who: &Person, size: Option<&str>) -> Daemon {
        let mut args = vec!["daemon", "start"];
        if let Some(s) = size {
            args.extend(["--cache-size", s]);
        }
        let out = who.ok(who.home.path(), &args);
        assert!(out.contains("the Veil daemon runs"), "{out}");
        Daemon::of(who)
    }

    fn status(&self) -> serde_json::Value {
        let (_, end) = ask(&self.socket, &serde_json::json!({"op": "status"}));
        end.expect("the daemon answers its status")["body"].clone()
    }

    fn stat(&self, name: &str) -> u64 {
        self.status()[name].as_u64().unwrap_or_else(|| panic!("no counter {name}"))
    }

    fn pid(&self) -> i32 {
        self.status()["pid"].as_i64().unwrap() as i32
    }

    /// Every file of its store.
    fn store_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![self.dir.join("store")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                } else {
                    out.push((e.path().display().to_string(), std::fs::read(e.path()).unwrap_or_default()));
                }
            }
        }
        out
    }
}

/// Someone who gets grants from the server and reads objects through a
/// daemon's socket (theirs or another's), naming the server `upstream`.
struct Reader {
    socket: PathBuf,
    upstream: String,
    project: String,
    id: Option<Identity>,
    grant: String,
    key: String,
}

impl Reader {
    fn new(server: &Api, socket: &Path, upstream: &str, who: Option<&Person>, project: &str) -> Reader {
        let tips = server.tips(who.map(|p| p.token()).as_deref(), project).expect("tips");
        Reader {
            socket: socket.to_path_buf(),
            upstream: upstream.to_string(),
            project: project.to_string(),
            id: who.map(|p| p.identity()),
            grant: tips.grants.get("main").expect("a grant for main").clone(),
            key: tips.grant_key.unwrap(),
        }
    }

    fn root(&self) -> ObjectId {
        Grant::read_unverified(&self.grant).unwrap().root
    }

    /// A batch under `grant`, signed by `signer` (`None`: unsigned).
    fn batch_as(&self, grant: &str, signer: Option<&Identity>, wants: &[(Vec<ObjectId>, ObjectId)]) -> (Vec<(ObjectId, Vec<u8>)>, Option<serde_json::Value>) {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
        let ts = veil_core::now_millis();
        let signature = Grant::verify(grant, &self.key).and_then(|g| signer.map(|i| sign_request(i, &g, ts, &ids)));
        let req = BatchRequest {
            grant: grant.to_string(),
            ts,
            signature,
            wants: wants.iter().map(|(chain, id)| ChainWant { chain: chain.clone(), id: *id }).collect(),
            skip: Vec::new(),
        };
        ask(&self.socket, &serde_json::json!({"op": "batch", "upstream": self.upstream, "project": self.project, "batch": req}))
    }

    fn batch(&self, wants: &[(Vec<ObjectId>, ObjectId)]) -> Vec<(ObjectId, Vec<u8>)> {
        let (got, end) = self.batch_as(&self.grant, self.id.as_ref(), wants);
        assert!(end.is_some(), "the daemon's answer is unfinished");
        got
    }

    /// Everything reachable from the grant's root, level by level, with
    /// the chain each object was met at; asked again for what did not
    /// arrive (as a client does).
    fn walk(&self) -> Vec<(Vec<ObjectId>, ObjectId, Vec<u8>)> {
        let mut out = Vec::new();
        let mut wants = vec![(Vec::new(), self.root())];
        let mut seen = HashSet::new();
        while !wants.is_empty() {
            let mut got: HashMap<ObjectId, Vec<u8>> = HashMap::new();
            for _ in 0..5 {
                let left: Vec<_> = wants.iter().filter(|w| !got.contains_key(&w.1)).cloned().collect();
                if left.is_empty() {
                    break;
                }
                got.extend(self.batch(&left));
            }
            let mut next = Vec::new();
            for (chain, id) in wants {
                let raw = got.get(&id).unwrap_or_else(|| panic!("{} never arrived", id.short())).clone();
                if !seen.insert((chain.clone(), id)) {
                    continue;
                }
                let c = [chain.clone(), vec![id]].concat();
                match Object::decode(&raw) {
                    Ok(Object::Tree(t)) => next.extend(t.entries.iter().map(|e| (c.clone(), e.id))),
                    Ok(Object::Conflict(k)) => next.extend(k.referenced_ids().into_iter().map(|t| (c.clone(), t))),
                    _ => {}
                }
                out.push((chain, id, raw));
            }
            wants = next;
        }
        out
    }
}

/// The same walk straight from the server's batch route.
fn server_walk(server: &Api, who: Option<&Person>, project: &str) -> Vec<(Vec<ObjectId>, ObjectId, Vec<u8>)> {
    let tips = server.tips(who.map(|p| p.token()).as_deref(), project).unwrap();
    let grant = tips.grants["main"].clone();
    let g = Grant::verify(&grant, tips.grant_key.as_ref().unwrap()).unwrap();
    let id = who.map(|p| p.identity());
    let mut out = Vec::new();
    let mut wants = vec![(Vec::new(), g.body.root)];
    while !wants.is_empty() {
        let ids: Vec<ObjectId> = wants.iter().map(|w: &(Vec<ObjectId>, ObjectId)| w.1).collect();
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: grant.clone(),
            ts,
            signature: id.as_ref().map(|i| sign_request(i, &g, ts, &ids)),
            wants: wants.iter().map(|(c, i)| ChainWant { chain: c.clone(), id: *i }).collect(),
            skip: Vec::new(),
        };
        let got: HashMap<ObjectId, Vec<u8>> = server.post(None, &format!("/v1/objects/{project}:batch"), &serde_json::to_vec(&req).unwrap(), true).frames().into_iter().collect();
        let mut next = Vec::new();
        let mut seen = HashSet::new();
        for (chain, id) in wants {
            let Some(raw) = got.get(&id).cloned() else { continue };
            if !seen.insert((chain.clone(), id)) {
                continue;
            }
            let c = [chain.clone(), vec![id]].concat();
            match Object::decode(&raw) {
                Ok(Object::Tree(t)) => next.extend(t.entries.iter().map(|e| (c.clone(), e.id))),
                Ok(Object::Conflict(k)) => next.extend(k.referenced_ids().into_iter().map(|t| (c.clone(), t))),
                _ => {}
            }
            out.push((chain, id, raw));
        }
        wants = next;
    }
    out
}

fn items(walked: &[(Vec<ObjectId>, ObjectId, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = walked.iter().map(|(_, id, raw)| (format!("object {}", id.short()), raw.clone())).collect();
    v.sort();
    v
}

fn random_id() -> ObjectId {
    ObjectId(veil_core::crypto::random_bytes::<32>())
}

/// Ask until `f()` holds, for at most `limit`; how long it took.
fn until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Duration {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < limit, "{what}: not within {limit:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    t.elapsed()
}

/// Read `(chain, id)` through the daemon until it serves it from its store
/// (its epochs confirmed, the object kept).
fn warm(_d: &Daemon, r: &Reader, chain: &[ObjectId], id: &ObjectId) {
    until(Duration::from_secs(10), "served from the daemon's store", || {
        let (got, end) = r.batch_as(&r.grant, r.id.as_ref(), &[(chain.to_vec(), *id)]);
        assert_eq!(got.len(), 1, "the object is served");
        end.expect("a whole answer")["from_store"] == 1
    });
}

/// The admin's real tree of `main`: every object with its path and the
/// chain of real tree ids above it.
fn real_chains(dir: &Path) -> Vec<(String, Vec<ObjectId>, ObjectId)> {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let root = repo.snapshot(&tip).unwrap().tree;
    let mut out = vec![(String::new(), Vec::new(), root)];
    let mut stack = vec![(String::new(), vec![root])];
    while let Some((p, chain)) = stack.pop() {
        let t = repo.store().tree(chain.last().unwrap()).unwrap();
        for e in &t.entries {
            let path = if p.is_empty() { e.name.clone() } else { format!("{p}/{}", e.name) };
            out.push((path.clone(), chain.clone(), e.id));
            if e.kind == veil_core::object::EntryKind::Dir {
                stack.push((path, [chain.clone(), vec![e.id]].concat()));
            }
        }
    }
    out
}

// ---- 1. only what a grant reaches ---------------------------------------------------

/// A refusal asserted exactly: a whole answer, nothing from the store, and
/// the server's own `401` passed on (a closed connection would also send
/// no object).
fn refused(end: Option<serde_json::Value>, what: &str) {
    let end = end.unwrap_or_else(|| panic!("{what}: the daemon's answer is unfinished"));
    assert!(end.get("from_store").is_none(), "{what}: answered from the store: {end}");
    assert_eq!(end["status"], 401, "{what}: not the server's refusal: {end}");
}

/// Guarantee 1: the admin's daemon holds every object of the project; each
/// viewer asking it with their own grant (and every chain they can build,
/// the admin's real ones included) receives exactly what the server sends
/// them, and nothing hidden is served from the store.
#[test]
fn the_daemon_serves_only_what_the_server_would() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let d = Daemon::start(&p.admin, None);
    let real = real_chains(&p.dir);
    let admin_root = real[0].2;
    let env_id = real.iter().find(|(path, _, _)| *path == format!("{BILL_DIR}/.env")).unwrap().2;
    // Cold: through to the server; warm: from the store alone.
    let admin = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.admin), &p.name);
    let cold = admin.walk();
    assert_eq!(items(&cold), items(&server_walk(&server, Some(&p.admin), &p.name)), "the daemon answers as the server");
    assert!(d.stat("from_upstream") > 0, "cold: from the server");
    warm(&d, &admin, &[], &admin.root());
    let forwarded = d.stat("forwarded");
    assert_eq!(items(&admin.walk()), items(&cold));
    assert_eq!(d.stat("forwarded"), forwarded, "a warm walk asks the server nothing");
    assert!(d.store_files().iter().any(|(_, b)| b.windows(BILL_MARK.len()).any(|w| w == BILL_MARK.as_bytes())), "the store holds billing/");
    assert_no_marker(&d.store_files(), &[ENV_MARK], "the daemon's store (secrets only as ciphertext)");

    let all = restricted_markers();
    let not = |keep: &[&str]| all.iter().copied().filter(|m| !keep.contains(m)).collect::<Vec<_>>();
    let viewers: Vec<(&str, Option<&Person>, Vec<&str>, &str)> = vec![
        ("anyone", None, not(&[]), PUBLIC_MARK),
        ("dev", Some(&p.dev), not(&[]), PUBLIC_MARK),
        ("fin", Some(&p.fin), not(&[BILL_DIR, BILL_MARK, ENV_MARK]), BILL_DIR),
        ("carol", Some(&p.carol), not(&[PERSON_DIR, PERSON_MARK]), PERSON_MARK),
        ("sec", Some(&p.sec), not(&[NESTED_DIR, NESTED_MARK]), NESTED_MARK),
    ];
    for (who, person, hidden, mine) in viewers {
        let r = Reader::new(&server, &d.socket, &hub.authority(), person, &p.name);
        let first = r.walk();
        warm(&d, &r, &[], &r.root());
        let walked = r.walk();
        assert_eq!(items(&walked), items(&server_walk(&server, person, &p.name)), "{who}: the daemon's answer is the server's");
        assert_eq!(items(&first), items(&walked), "{who}");
        assert_no_marker(&items(&walked), &hidden, who);
        assert!(has_marker(&items(&walked), mine), "{who} did not receive {mine}");
        let reached: HashSet<ObjectId> = walked.iter().map(|w| w.1).collect();
        assert_eq!(reached.contains(&env_id), who == "fin", "{who}: billing's .env ciphertext");
        // Every real object they do not reach, all in the store, with every
        // chain they can build.
        let trees: Vec<Vec<ObjectId>> = walked
            .iter()
            .filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_))))
            .map(|(chain, id, _)| [chain.clone(), vec![*id]].concat())
            .collect();
        let mut attacks: Vec<(Vec<ObjectId>, ObjectId)> = Vec::new();
        for (_, chain, id) in real.iter().filter(|(_, _, id)| !reached.contains(id)) {
            attacks.push((Vec::new(), *id));
            attacks.push((chain.clone(), *id));
            if !chain.is_empty() {
                attacks.push(([vec![r.root()], chain[1..].to_vec()].concat(), *id));
                attacks.push(([vec![r.root()], chain.clone()].concat(), *id));
            }
            for t in &trees {
                attacks.push((t.clone(), *id));
            }
        }
        attacks.push((vec![r.root()], random_id()));
        assert!(attacks.iter().any(|a| a.1 == admin_root), "{who}: the admin's root is among the attacks");
        for part in attacks.chunks(2000) {
            let (got, end) = r.batch_as(&r.grant, r.id.as_ref(), part);
            assert!(got.is_empty(), "{who} received {} hidden objects from the daemon", got.len());
            // Per answer (the daemon's own counters also count its
            // follower's warm-up reads, which run beside the test).
            let end = end.expect("a whole answer");
            assert!(end.get("from_store").is_none(), "{who}: an attack was answered from the store: {end}");
        }
    }

    // Grants that do not hold for the requester: another device's
    // signature, none, another project's grant, a wider root under the
    // signature. The daemon holds the objects; none is served.
    let dev = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.dev), &p.name);
    warm(&d, &dev, &[], &dev.root());
    let fin_id = p.fin.identity();
    for (what, grant, signer) in [("fin's device", dev.grant.clone(), Some(&fin_id)), ("unsigned", dev.grant.clone(), None)] {
        let (got, end) = dev.batch_as(&grant, signer, &[(Vec::new(), dev.root())]);
        assert!(got.is_empty(), "{what}: served");
        assert_eq!(end.expect("a whole answer")["status"], 401, "{what}: the server's refusal passed on");
    }
    let body = Grant::read_unverified(&dev.grant).unwrap();
    let mut wider = body.clone();
    wider.root = admin_root;
    let tampered = format!("{}.{}", hex::encode(serde_json::to_vec(&wider).unwrap()), dev.grant.split_once('.').unwrap().1);
    let (got, end) = dev.batch_as(&tampered, dev.id.as_ref(), &[(Vec::new(), admin_root)]);
    assert!(got.is_empty(), "a wider root under the grant's signature");
    refused(end, "a wider root under the grant's signature");
    let by_identity = {
        let raw = serde_json::to_vec(&wider).unwrap();
        format!("{}.{}", hex::encode(&raw), hub.hub().identity.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_GRANT, &raw))
    };
    let (got, end) = dev.batch_as(&by_identity, dev.id.as_ref(), &[(Vec::new(), admin_root)]);
    assert!(got.is_empty(), "a grant signed by the server's identity key");
    refused(end, "a grant signed by the server's identity key");
    let expired = hub.hub().grants.issue(&veil_core::hub::grant::GrantBody { expires: veil_core::now_millis() - 1, ..body.clone() });
    let (got, end) = dev.batch_as(&expired, dev.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "an expired grant");
    refused(end, "an expired grant");
    let stale = hub.hub().grants.issue(&veil_core::hub::grant::GrantBody { epoch: body.epoch + 1, ..body.clone() });
    let (got, end) = dev.batch_as(&stale, dev.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "a grant of other epochs");
    refused(end, "a grant of other epochs");
    let other = Reader { project: unique("other"), ..Reader::new(&server, &d.socket, &hub.authority(), Some(&p.dev), &p.name) };
    let (got, end) = other.batch_as(&other.grant, other.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "a grant of another project (nothing, from the store or not)");
    refused(end, "a grant of another project");

    // Hostile requests: refused cleanly, and the daemon keeps serving.
    for bad in [
        serde_json::json!({"op": "batch", "upstream": "evil/../x", "project": p.name, "batch": {"grant": dev.grant, "ts": 0, "wants": []}}),
        serde_json::json!({"op": "batch", "upstream": hub.authority(), "project": "../etc", "batch": {"grant": dev.grant, "ts": 0, "wants": []}}),
        serde_json::json!({"op": "batch", "upstream": hub.authority(), "project": p.name, "batch": {"grant": "zz", "ts": 0, "wants": [{"id": random_id().hex()}]}}),
        serde_json::json!({"op": "nonsense"}),
        serde_json::json!({"op": "pin", "upstream": hub.authority(), "project": p.name, "key": "k", "roots": vec![random_id(); 65]}),
    ] {
        let (got, _) = ask(&d.socket, &bad);
        assert!(got.is_empty(), "{bad}");
    }
    for junk in [b"not a message at all".to_vec(), vec![b'Q', 0xff, 0xff, 0xff, 0xff], vec![b'Q', 0, 0, 0, 3, b'{', b'{', b'{']] {
        let mut s = UnixStream::connect(&d.socket).unwrap();
        s.write_all(&junk).unwrap();
        drop(s);
    }
    assert_eq!(dev.batch(&[(Vec::new(), dev.root())]).len(), 1, "still serving after hostile input");
}

// ---- 2. removal within the bound; fail closed ---------------------------------------

/// After an access change returned at `changed`: `r`'s old grant for
/// `(chain, id)` gets nothing from the daemon within the bound, and never
/// again.
fn refused_within_bound(r: &Reader, chain: &[ObjectId], id: &ObjectId, changed: Instant, what: &str) -> Duration {
    loop {
        if r.batch(&[(chain.to_vec(), *id)]).is_empty() {
            break;
        }
        assert!(changed.elapsed() <= STALE, "{what}: still served {:?} after the change", changed.elapsed());
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = changed.elapsed();
    for _ in 0..20 {
        assert!(r.batch(&[(chain.to_vec(), *id)]).is_empty(), "{what}: served again after a refusal");
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("daemon: {what}: refused {took:?} after the change returned");
    took
}

fn invoice(r: &Reader) -> (Vec<ObjectId>, ObjectId) {
    r.walk()
        .into_iter()
        .find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], BILL_MARK))
        .map(|(c, id, _)| (c, id))
        .expect("the invoice is reached")
}

/// Guarantee 2: a person removed from a group, a policy change and a
/// removed device are refused at the daemon within 5 s, though its store
/// holds the objects (design §6 row 4, product decision 1).
#[test]
fn a_removed_person_or_device_is_refused_at_the_daemon_within_the_bound() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let d = Daemon::start(&p.fin, None);
    let fin = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.fin), &p.name);
    let (chain, id) = invoice(&fin);
    warm(&d, &fin, &chain, &id);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let mut took = vec![refused_within_bound(&fin, &chain, &id, Instant::now(), "a person removed from finance")];
    let again = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.fin), &p.name);
    assert!(again.batch(&[(chain.clone(), id)]).is_empty(), "the new grant does not reach the invoice");
    // A policy change voids every grant of the project, anyone on Earth's.
    let anyone = Reader::new(&server, &d.socket, &hub.authority(), None, &p.name);
    let lib = anyone.walk().into_iter().find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PUBLIC_MARK)).unwrap();
    warm(&d, &anyone, &lib.0, &lib.1);
    p.admin.ok(&p.dir, &["access", "src/", "devs"]);
    p.admin.commit_main(&p.dir, "src/ no longer public");
    p.admin.ok(&p.dir, &["push"]);
    took.push(refused_within_bound(&anyone, &lib.0, &lib.1, Instant::now(), "anyone on Earth after src/ stopped being public"));
    // A device an admin removed.
    let sec = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.sec), &p.name);
    warm(&d, &sec, &[], &sec.root());
    p.admin.ok(&p.dir, &["identity", "remove", &p.sec.fingerprint()]);
    took.push(refused_within_bound(&sec, &[], &sec.root(), Instant::now(), "a device removed from the project"));
    assert!(d.stat("voided") >= 3, "the server's refusals voided the epochs");
    eprintln!("daemon: refusals after access changes: {took:?}");
}

/// A TCP proxy to `upstream` that can be cut (every connection closed and
/// new ones refused) and restored.
struct Proxy {
    addr: String,
    cut: std::sync::Arc<std::sync::atomic::AtomicBool>,
    conns: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
}

impl Proxy {
    fn start(upstream: String) -> Proxy {
        use std::{
            net::{Shutdown, TcpListener, TcpStream},
            sync::atomic::Ordering::SeqCst,
        };
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let cut = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conns: std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>> = Default::default();
        let (cut2, conns2) = (cut.clone(), conns.clone());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                if cut2.load(SeqCst) {
                    let _ = c.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(u) = TcpStream::connect(&upstream) else { continue };
                conns2.lock().unwrap().extend([c.try_clone().unwrap(), u.try_clone().unwrap()]);
                for (mut a, mut b) in [(c.try_clone().unwrap(), u.try_clone().unwrap()), (u, c)] {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut a, &mut b);
                        let _ = b.shutdown(Shutdown::Write);
                    });
                }
            }
        });
        Proxy { addr, cut, conns }
    }

    fn set_cut(&self, cut: bool) {
        self.cut.store(cut, std::sync::atomic::Ordering::SeqCst);
        if cut {
            for c in self.conns.lock().unwrap().drain(..) {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// Guarantee 2 (fail closed): without the server the daemon serves nothing
/// from its store 5 s after its last confirmation, public objects included;
/// it serves again once the server answers.
#[test]
fn the_daemon_fails_closed_without_the_server() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let proxy = Proxy::start(hub.authority());
    let d = Daemon::start(&p.fin, None);
    let fin = Reader::new(&server, &d.socket, &proxy.addr, Some(&p.fin), &p.name);
    let anyone = Reader::new(&server, &d.socket, &proxy.addr, None, &p.name);
    let (chain, id) = invoice(&fin);
    warm(&d, &fin, &chain, &id);
    warm(&d, &anyone, &[], &anyone.root());
    proxy.set_cut(true);
    let cut = Instant::now();
    std::thread::sleep((STALE + Duration::from_millis(300)).saturating_sub(cut.elapsed()));
    let local = d.stat("from_store");
    for _ in 0..10 {
        for (r, chain, id) in [(&fin, &chain[..], &id), (&anyone, &[][..], &anyone.root())] {
            let (got, end) = r.batch_as(&r.grant, r.id.as_ref(), &[(chain.to_vec(), *id)]);
            assert!(got.is_empty(), "served without the server");
            assert_eq!(end.expect("a whole answer")["status"], 503);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(d.stat("from_store"), local, "nothing from the store without the server");
    assert!(d.stat("poll_errors") > 0);
    proxy.set_cut(false);
    let back = until(Duration::from_secs(10), "served again with the server back", || !fin.batch(&[(chain.clone(), id)]).is_empty());
    warm(&d, &fin, &chain, &id);
    eprintln!("daemon: fail-closed checked; serving again {back:?} after the server returned");
}

/// The server's state of `project` and of the person of device `device`
/// (their rows, as text): a request that changes nothing on the server
/// leaves it as it was. Scoped to them: the suite's other tests share the
/// database.
fn server_state(hub: &TestHub, project: &str, device: &str) -> Vec<(&'static str, String)> {
    let db = &hub.hub().db;
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(project).fetch_one(db)).unwrap();
    let person: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT person_id FROM devices WHERE signing_key = $1").bind(device).fetch_one(db)).unwrap();
    [
        ("audit_log", "project_id = $1 OR actor = $2"),
        ("access_epochs", "project_id = $1 OR person_id = $2"),
        ("sessions", "person_id = $2 AND $1 = $1"),
        ("devices", "person_id = $2 AND $1 = $1"),
        ("projections", "project_id = $1 AND $2 = $2"),
        ("snapshots", "project_id = $1 AND $2 = $2"),
        ("branches", "project_id = $1 AND $2 = $2"),
    ]
    .into_iter()
    .map(|(t, w)| {
        let q = format!("SELECT coalesce(string_agg(t::text, '|' ORDER BY t::text), '') FROM {t} t WHERE {w}");
        let rows: String = hub.rt.block_on(sqlx::query_scalar(&q).bind(pid).bind(person).fetch_one(db)).unwrap();
        (t, rows)
    })
    .collect()
}

/// Guarantee 3 (the resend the daemon renews its confirmations with,
/// §13.29): a signed request sent again with every object skipped returns
/// no object and changes nothing on the server; once the device's access
/// changes, the same recorded request is refused whatever its `skip`, as
/// the device's own request under that grant is; and a recorded request
/// cannot be widened (another want, another root) without its signature
/// failing. What S5's window lets a recording do is only what the device
/// asked for, while its access holds.
#[test]
fn a_resent_request_changes_nothing_and_holds_no_longer_than_the_access() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let fin = Reader::new(&server, Path::new("/nonexistent"), &hub.authority(), Some(&p.fin), &p.name);
    let (chain, id, raw) = server_walk(&server, Some(&p.fin), &p.name)
        .into_iter()
        .find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], BILL_MARK))
        .expect("fin reaches the invoice");
    let g = Grant::verify(&fin.grant, &fin.key).unwrap();
    let signed = |wants: &[(Vec<ObjectId>, ObjectId)], ts: i64| BatchRequest {
        grant: fin.grant.clone(),
        ts,
        signature: Some(sign_request(fin.id.as_ref().unwrap(), &g, ts, &wants.iter().map(|w| w.1).collect::<Vec<_>>())),
        wants: wants.iter().map(|(c, i)| ChainWant { chain: c.clone(), id: *i }).collect(),
        skip: Vec::new(),
    };
    let send = |req: &BatchRequest| server.post(None, &format!("/v1/objects/{}:batch", p.name), &serde_json::to_vec(req).unwrap(), true);
    let recorded = signed(&[(chain.clone(), id)], veil_core::now_millis());
    let r = send(&recorded);
    assert_eq!(r.status, 200, "the device's own request");
    assert_eq!(r.frames(), vec![(id, raw.clone())]);
    // Sent again with every object skipped: nothing, and no state changes.
    let resent = BatchRequest { skip: vec![id], ..recorded.clone() };
    let device = g.body.device.clone().expect("fin's grant names a device");
    let before = server_state(&hub, &p.name, &device);
    for t in ["sessions", "devices", "snapshots", "branches"] {
        assert!(before.iter().any(|(n, rows)| *n == t && !rows.is_empty()), "no {t} rows to compare: {before:?}");
    }
    for _ in 0..20 {
        let r = send(&resent);
        assert_eq!(r.status, 200, "a resend within the window is accepted");
        assert!(r.frames().is_empty(), "a resend with every object skipped returns an object");
    }
    assert_eq!(server_state(&hub, &p.name, &device), before, "resends changed the server's state");
    // Widened under the recorded signature: refused.
    let admin_root = real_chains(&p.dir)[0].2;
    for (what, wants) in [
        ("another want", vec![(chain.clone(), id), (Vec::new(), fin.root())]),
        ("another root", vec![(Vec::new(), admin_root)]),
    ] {
        let wider = BatchRequest { wants: wants.iter().map(|(c, i)| ChainWant { chain: c.clone(), id: *i }).collect(), ..recorded.clone() };
        let r = send(&wider);
        assert_eq!(r.status, 401, "{what}: a recorded signature over other wants");
        assert!(!has_marker(&[(String::new(), r.body.clone())], BILL_MARK), "{what}");
    }
    // Access removed: the recording is refused whatever its skip, as is the
    // device's own new request under the same grant.
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    for (what, req) in [("resent, all skipped", resent.clone()), ("resent whole", recorded.clone()), ("the device's own, now", signed(&[(chain.clone(), id)], veil_core::now_millis()))] {
        let r = send(&req);
        assert_eq!(r.status, 401, "{what}: after the access change");
        assert!(!has_marker(&[(String::new(), r.body.clone())], BILL_MARK), "{what}");
    }
}

/// Guarantee 4: `GET /v1/grant-key` answers anyone the server's public
/// grant key and nothing else (the same key every tips answer carries, the
/// same with a session), and a client cannot make the daemon trust another
/// key: a grant signed by a key of its own, with that key named in the
/// request, gets nothing from the store, and the daemon serves the real
/// grant as before.
#[test]
fn the_grant_key_route_says_only_the_public_key_and_the_daemon_trusts_no_other() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let r = server.get(None, "/v1/grant-key");
    assert_eq!(r.status, 200, "the route answers anyone");
    let v = r.json();
    assert_eq!(v.as_object().map(|o| o.len()), Some(1), "only the key: {v}");
    let key = v["grant_key"].as_str().expect("the key").to_string();
    assert_eq!(key, hub.hub().grants.key_hex(), "the grant key's public half");
    assert!(key.len() == 64 && hex::decode(&key).is_ok(), "{key}");
    assert_eq!(server.tips(None, &p.name).unwrap().grant_key.as_deref(), Some(key.as_str()));
    assert_eq!(server.tips(Some(&p.admin.token()), &p.name).unwrap().grant_key.as_deref(), Some(key.as_str()));
    assert_eq!(server.get(Some(&p.admin.token()), "/v1/grant-key").json(), v, "a session adds nothing");
    // A grant of another key, for the admin's root, signed by dev's device.
    let d = Daemon::start(&p.admin, None);
    let admin = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.admin), &p.name);
    warm(&d, &admin, &[], &admin.root());
    let dev = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.dev), &p.name);
    warm(&d, &dev, &[], &dev.root());
    let own = veil_core::identity::SeedSigner::from_seed(&veil_core::crypto::random_bytes::<32>());
    let body = veil_core::hub::grant::GrantBody { root: admin.root(), ..Grant::read_unverified(&dev.grant).unwrap() };
    let forged = Grant::issue(&own, &body);
    let fg = Grant::verify(&forged, &own.verifying_hex()).unwrap();
    let ts = veil_core::now_millis();
    let req = serde_json::json!({
        "op": "batch", "upstream": hub.authority(), "project": p.name,
        "batch": {
            "grant": forged, "ts": ts, "grant_key": own.verifying_hex(),
            "signature": sign_request(dev.id.as_ref().unwrap(), &fg, ts, &[admin.root()]),
            "wants": [{"chain": [], "id": admin.root().hex()}],
        },
    });
    let (got, end) = ask(&d.socket, &req);
    assert!(got.is_empty(), "a grant of the client's own key was served");
    let end = end.expect("a whole answer");
    assert!(end.get("from_store").is_none(), "{end}");
    assert_eq!(end["status"], 401, "the server's refusal is passed on: {end}");
    let (got, end) = dev.batch_as(&dev.grant, dev.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert_eq!(got.len(), 1, "the real grant is still served");
    assert_eq!(end.expect("a whole answer")["from_store"], 1);
}

// ---- 3. the same answers with and without the daemon --------------------------------

/// A working copy's files (not `.veil/`), by path relative to it.
fn working_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let path = e.path();
            if path.file_name().is_some_and(|n| n == ".veil") {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                stack.push(path);
            } else {
                out.push((path.strip_prefix(root).unwrap().display().to_string(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Guarantee 3: a thin clone made and read through the daemon (cold, then
/// warm from another clone's reads) answers every command as one made
/// with the daemon off, for the admin and for a person without billing/.
#[test]
fn a_thin_clone_answers_the_same_with_and_without_the_daemon() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let cmds: Vec<Vec<&str>> = vec![
        vec!["log", "--json"],
        vec!["ls", "-r", "main", "--json"],
        vec!["files", "-r", "main"],
        vec!["show", "--json", "main"],
        vec!["diff", "--json", "--from", "main-", "--to", "main"],
        vec!["cat", "-r", "main", "src/lib.rs"],
        vec!["cat", "-r", "main", &invoice],
        vec!["status"],
    ];
    let normal = |out: &str| -> String {
        match serde_json::from_str::<serde_json::Value>(out.trim()) {
            Ok(mut v) => {
                if let Some(e) = v.get_mut("entries").and_then(|e| e.as_array_mut()) {
                    e.retain(|x| x["current"] != serde_json::json!(true));
                }
                v.to_string()
            }
            // Each clone's own working-copy change.
            Err(_) => out.lines().filter(|l| !l.starts_with("Working copy :")).collect::<Vec<_>>().join("\n"),
        }
    };
    for who in [&p.admin, &p.dev] {
        let answers = |dir: &Path| -> Vec<(bool, String)> {
            cmds.iter()
                .map(|c| {
                    let o = who.run(dir, c);
                    (o.status.success(), normal(&format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))))
                })
                .collect()
        };
        who.ok(who.home.path(), &["daemon", "stop"]);
        let without = who.dir("without");
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), without.to_str().unwrap()]);
        assert!(!Daemon::of(who).socket.exists(), "{}: off means not started", who.name);
        let want = answers(&without);
        let want_files = working_files(&without);
        let d = Daemon::start(who, None);
        let cold = who.dir("cold");
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), cold.to_str().unwrap()]);
        assert!(d.stat("from_upstream") > 0, "{}: the thin clone read through the daemon", who.name);
        let warm = who.dir("warm");
        let before = d.stat("from_store");
        // A clone soon after: from the daemon's store.
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), warm.to_str().unwrap()]);
        assert!(d.stat("from_store") > before, "{}: the second clone read from the daemon's store", who.name);
        for dir in [&cold, &warm] {
            assert_eq!(answers(dir), want, "{}: a thin clone through the daemon answers otherwise", who.name);
            assert_eq!(working_files(dir), want_files, "{}: the files checked out", who.name);
        }
    }
    // dev never received billing/ through the daemon.
    assert_no_marker(&Daemon::of(&p.dev).store_files(), &[BILL_MARK, ENV_MARK, PERSON_MARK, NESTED_MARK, ROOT_MARK], "dev's daemon");
}

// ---- warm trees ---------------------------------------------------------------------

/// Is object `id` of `project` at `upstream` in the daemon's store (its
/// file, by the store's key)?
fn stored(d: &Daemon, upstream: &str, project: &str, id: &ObjectId) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(b"veil-daemon-object\0");
    h.update(upstream.as_bytes());
    h.update(b"\0");
    h.update(project.as_bytes());
    h.update(b"\0");
    h.update(&id.0);
    let k = h.finalize().to_hex().to_string();
    d.dir.join("store/objects").join(&k[..2]).join(&k[2..]).exists()
}

/// Warm start (design §4.6): once a thin clone read a project through the
/// daemon, its follower keeps the default branch's top trees in the store:
/// after a landing, the new root and the trees below it to depth 3 arrive
/// without any `vl` reading them, and a new clone reads them from the store.
#[test]
fn the_daemon_keeps_the_top_trees_of_followed_projects_warm() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = Daemon::start(&p.dev, None);
    let thin = p.dev.dir("thin");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), thin.to_str().unwrap()]);
    assert_eq!(d.stat("follows"), 1, "the project is followed");
    write_files(&p.dir, &[("src/w1/w2/w3/w4/deep.txt", "warm"), ("src/w1/top.txt", "warm")]);
    p.admin.commit_main(&p.dir, "new folders");
    p.admin.ok(&p.dir, &["push"]);
    // dev's projection of the new tip, from the server alone.
    let server = hub.api();
    let walked = server_walk(&server, Some(&p.dev), &p.name);
    let trees: Vec<(usize, ObjectId)> =
        walked.iter().filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_)))).map(|(chain, id, _)| (chain.len(), *id)).collect();
    let deep = trees.iter().filter(|(depth, _)| *depth > 3).count();
    assert!(deep > 0 && trees.iter().any(|(depth, _)| *depth == 3), "the project has trees below depth 3");
    let took = until(Duration::from_secs(15), "the new top trees are in the store", || {
        trees.iter().filter(|(depth, _)| *depth <= 3).all(|(_, id)| stored(&d, &hub.authority(), &p.name, id))
    });
    eprintln!("daemon: the new tip's top trees were in the store {took:?} after the push returned");
    assert!(trees.iter().filter(|(depth, _)| *depth > 3).all(|(_, id)| !stored(&d, &hub.authority(), &p.name, id)), "only down to depth 3");
    // A new clone reads them from the store.
    let before = d.stat("from_store");
    let again = p.dev.dir("again");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), again.to_str().unwrap()]);
    assert!(d.stat("from_store") > before);
    assert_eq!(std::fs::read_to_string(again.join("src/w1/w2/w3/w4/deep.txt")).unwrap(), "warm");
}

// ---- 4. bounds ----------------------------------------------------------------------

/// Guarantee 4 (disk): the store keeps to `--cache-size` while a clone
/// reads more than it holds; the clone is whole.
#[test]
fn the_daemons_store_keeps_to_its_bound() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("big");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    for i in 0..200 {
        write_files(&dir, &[(&format!("f/{i:03}.txt"), &format!("{i}:{}", "x".repeat(4000)))]);
    }
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "files");
    admin.ok(&dir, &["push"]);
    let d = Daemon::start(&admin, Some("64K"));
    let thin = admin.dir("thin");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), thin.to_str().unwrap()]);
    let s = d.status();
    assert!(s["store"]["bytes"].as_u64().unwrap() <= 64 << 10, "{s}");
    admin.ok(&thin, &["status"]);
    assert_eq!(d.status()["store"]["pins"], 1, "the clone pins what it checks out (one entry per clone)");
    assert!(s["store"]["evicted"].as_u64().unwrap() > 0 || s["store"]["not_kept"].as_u64().unwrap() > 0, "{s}");
    assert!(d.stat("from_upstream") >= 200, "every file came through the daemon");
    assert_eq!(std::fs::read_to_string(thin.join("f/123.txt")).unwrap(), format!("123:{}", "x".repeat(4000)));
    let files: u64 = d.store_files().iter().filter(|(p, _)| p.contains("/objects/")).map(|(_, b)| b.len() as u64).sum();
    assert!(files <= 64 << 10, "{files} bytes on disk");
}

/// Peak resident memory of process `pid` (kB).
fn hwm(pid: i32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap()
}

/// Guarantee 4 (memory): 24 readers at once of two 12 MiB files each (1.1
/// GiB of answers), cold and warm, hold the daemon within its budget: every
/// object it holds is counted, and an object is held only while it is sent.
#[test]
fn the_daemons_memory_stays_within_its_budget() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("large");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    for i in 0..2 {
        // Incompressible: random bytes.
        let big: Vec<u8> = (0..(12 << 20) / 32).flat_map(|_| veil_core::crypto::random_bytes::<32>()).collect();
        std::fs::write(dir.join(format!("big{i}.bin")), big).unwrap();
    }
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "large files");
    admin.ok(&dir, &["push"]);
    let d = Daemon::start(&admin, None);
    let server = hub.api();
    let r = Reader::new(&server, &d.socket, &hub.authority(), Some(&admin), &name);
    let root = r.root();
    let tree = r.batch(&[(Vec::new(), root)]);
    let Ok(Object::Tree(t)) = Object::decode(&tree[0].1) else { panic!("the root is a tree") };
    let files: Vec<(Vec<ObjectId>, ObjectId)> = t.entries.iter().filter(|e| e.name.starts_with("big")).map(|e| (vec![root], e.id)).collect();
    assert_eq!(files.len(), 2);
    let base = hwm(d.pid());
    for round in ["cold", "warm"] {
        std::thread::scope(|s| {
            for _ in 0..24 {
                // One grant for all (24 tips requests at once would test
                // the server's database pool, not the daemon).
                s.spawn(|| {
                    let got = r.batch(&files);
                    assert_eq!(got.len(), 2, "{round}: every file arrives");
                });
            }
        });
    }
    assert!(d.stat("from_store") >= 2, "the warm round read from the store");
    let peak = hwm(d.pid());
    eprintln!("daemon: peak {} MiB (before the readers {} MiB)", peak / 1024, base / 1024);
    // Its budget (64 MiB) and 24 connections' buffers (at most 512 KiB
    // each) above what it held before; were objects held outside the
    // budget, 24 readers would hold at least 288 MiB (one object each).
    assert!(peak - base < (64 + 12) * 1024, "the daemon grew by {} MiB", (peak - base) / 1024);
}

// ---- 5. without the daemon ----------------------------------------------------------

/// Guarantee 5: off, killed, or lying, the daemon changes nothing a `vl`
/// answers: off is not started again; a killed one leaves `vl` working; a
/// daemon that answers nothing, or bytes that are not the object, is
/// passed over.
#[test]
fn vl_works_without_the_daemon() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = Daemon::of(who);
    let out = who.ok(who.home.path(), &["daemon", "stop"]);
    assert!(out.contains("stays off"), "{out}");
    assert!(who.ok(who.home.path(), &["daemon", "status"]).contains("off"));
    let a = who.dir("a");
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), a.to_str().unwrap()]);
    let lib = std::fs::read_to_string(a.join("src/lib.rs")).unwrap();
    assert_eq!(lib, PUBLIC_MARK);
    assert!(!d.socket.exists(), "the daemon was not started while off");
    // On, then killed: vl still works (and starts it again).
    let d = Daemon::start(who, None);
    let pid = d.pid();
    // A process this test started (its daemon), by its pid.
    assert!(std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().unwrap().success());
    until(Duration::from_secs(5), "the daemon is gone", || std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| s.contains(") Z ")));
    let b = who.dir("b");
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), b.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(b.join("src/lib.rs")).unwrap(), lib);
    // A daemon that lies: nothing at all, then wrong bytes for every
    // object. The clone answers as the server.
    who.ok(who.home.path(), &["daemon", "stop"]);
    std::fs::remove_file(d.dir.join("off")).unwrap();
    for lie in ["nothing", "wrong bytes"] {
        let _ = std::fs::remove_file(&d.socket);
        let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let wrong = lie == "wrong bytes";
        let fake = std::thread::spawn(move || {
            l.set_nonblocking(true).unwrap();
            while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((mut s, _)) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                s.set_nonblocking(false).unwrap();
                let mut head = [0u8; 5];
                if s.read_exact(&mut head).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(head[1..].try_into().unwrap()) as usize];
                let _ = s.read_exact(&mut body);
                let req: serde_json::Value = serde_json::from_slice(body.get(1..).unwrap_or_default()).unwrap_or_default();
                // Acknowledged as a daemon of this version is: the lie is in
                // what follows.
                let mut out = vec![b'A', 0, 0, 0, 1, PROTOCOL];
                if wrong {
                    for w in req["batch"]["wants"].as_array().into_iter().flatten() {
                        let id = ObjectId::from_hex(w["id"].as_str().unwrap()).unwrap();
                        let raw = b"veil:blob\nnot the object".to_vec();
                        out.push(b'O');
                        out.extend_from_slice(&((raw.len() + 32) as u32).to_be_bytes());
                        out.extend_from_slice(&id.0);
                        out.extend_from_slice(&raw);
                    }
                }
                out.extend_from_slice(&[b'E', 0, 0, 0, 2, b'{', b'}']);
                let _ = s.write_all(&out);
            }
        });
        let c = who.dir(&format!("lie-{}", lie.replace(' ', "-")));
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
        assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), lib, "{lie}");
        assert_eq!(who.ok(&c, &["cat", "-r", "main", "src/lib.rs"]).trim(), lib, "{lie}");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        fake.join().unwrap();
    }
}

/// Guarantee 5, a daemon that stalls (§13.29: "a daemon that lies, stalls
/// or is gone changes no answer"): one that takes each connection and never
/// answers (a daemon wedged, stopped, or its disk hung) costs a `vl` at
/// most one wait, not one wait for every request it would have sent there.
#[test]
fn a_stalled_daemon_costs_a_vl_at_most_one_wait() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = Daemon::start(who, None);
    who.ok(who.home.path(), &["daemon", "stop"]);
    std::fs::remove_file(d.dir.join("off")).unwrap();
    let _ = std::fs::remove_file(&d.socket);
    let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let stalled = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let mut held = Vec::new();
        while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
            match l.accept() {
                Ok((s, _)) => held.push(s),
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        held.len()
    });
    let c = who.dir("stalled");
    let t = Instant::now();
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let took = t.elapsed();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let asked = stalled.join().unwrap();
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    assert!(asked > 0, "the clone never asked the daemon");
    eprintln!("a clone with a stalled daemon: {took:?}, {asked} connection(s)");
    // One wait for an acknowledgement (0.5 s), then the server: the same
    // clone without a daemon takes a second or two here.
    assert!(took < Duration::from_secs(15), "a clone with a stalled daemon took {took:?} ({asked} connections)");
}

/// A `vl` and a daemon of other protocol versions agree (the socket's
/// version, `proto::PROTOCOL`): the daemon serves nothing to a request of
/// another version and says its own; a `vl` that meets an older daemon
/// stops it and reads from the server, so the next `vl` starts its own; a
/// clone meanwhile answers as the server.
#[test]
fn a_vl_and_a_daemon_of_other_versions_agree() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = Daemon::start(who, None);
    // A request of another version: refused, nothing served.
    let mut s = UnixStream::connect(&d.socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let server = hub.api();
    let r = Reader::new(&server, &d.socket, &hub.authority(), Some(who), &p.name);
    let req = serde_json::json!({"op": "status"});
    let mut body = vec![PROTOCOL + 1];
    body.extend_from_slice(&serde_json::to_vec(&req).unwrap());
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    s.write_all(&msg).unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert_eq!(&all[..6], &[b'A', 0, 0, 0, 1, PROTOCOL], "acknowledged with the daemon's version");
    let end: serde_json::Value = serde_json::from_slice(&all[11..]).unwrap();
    assert_eq!((all[6], end["status"].as_u64(), end["body"]["version"].as_u64()), (b'E', Some(426), Some(PROTOCOL as u64)), "{end}");
    assert_eq!(r.batch(&[(Vec::new(), r.root())]).len(), 1, "a request of this version is still served");
    // A stop naming this version (meant for an older daemon) is ignored;
    // an empty one (`vl daemon stop`) stops it (BUG-1517).
    let pid = d.pid();
    let mut s = UnixStream::connect(&d.socket).unwrap();
    s.write_all(&[b'S', 0, 0, 0, 1, PROTOCOL]).unwrap();
    drop(s);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(d.pid(), pid, "a stop meant for an older daemon stopped this one");
    let mut s = UnixStream::connect(&d.socket).unwrap();
    s.write_all(&[b'S', 0, 0, 0, 0]).unwrap();
    drop(s);
    until(Duration::from_secs(5), "an empty stop stops the daemon", || UnixStream::connect(&d.socket).is_err());
    let d = Daemon::start(who, None);
    // An older daemon: acknowledges with version 0. The clone stops it
    // (the empty `S`, the same in every version) and reads from the server.
    who.ok(who.home.path(), &["daemon", "stop"]);
    std::fs::remove_file(d.dir.join("off")).unwrap();
    let _ = std::fs::remove_file(&d.socket);
    let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let older = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let t = Instant::now();
        let mut kinds = Vec::new();
        while t.elapsed() < Duration::from_secs(60) && !kinds.contains(&b'S') {
            let Ok((mut s, _)) = l.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            s.set_nonblocking(false).unwrap();
            let mut head = [0u8; 5];
            if s.read_exact(&mut head).is_err() {
                continue;
            }
            let mut body = vec![0u8; u32::from_be_bytes(head[1..].try_into().unwrap()) as usize];
            let _ = s.read_exact(&mut body);
            kinds.push(head[0]);
            let _ = s.write_all(&[b'A', 0, 0, 0, 1, 0]);
        }
        kinds
    });
    let c = who.dir("older");
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    let kinds = older.join().unwrap();
    assert!(kinds.contains(&b'S'), "the older daemon was not stopped: {kinds:?}");
    assert_eq!(kinds.iter().filter(|k| **k == b'Q').count(), 1, "asked once, then the server: {kinds:?}");
}

// ---- 6. its user's alone ------------------------------------------------------------

/// Guarantee 6: the socket's directory and the store are 0700 and the
/// socket 0600, a directory left wider is made private, and a damaged
/// object in the store is never served.
#[test]
fn the_daemons_socket_and_store_are_its_users_alone() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = Daemon::of(&p.admin);
    std::fs::create_dir_all(&d.dir).unwrap();
    std::fs::set_permissions(&d.dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let d = Daemon::start(&p.admin, None);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&d.dir), 0o700, "the daemon's directory");
    assert_eq!(mode(&d.dir.join("store")), 0o700, "the store");
    assert_eq!(mode(&d.socket), 0o600, "the socket");
    assert_eq!(d.stat("peer_refused"), 0);
    // A damaged object in the store: never served, read again from the
    // server.
    let server = hub.api();
    let admin = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.admin), &p.name);
    let good = admin.walk();
    warm(&d, &admin, &[], &admin.root());
    let mut flipped = 0;
    for (path, mut b) in d.store_files().into_iter().filter(|(path, _)| path.contains("/objects/")) {
        let i = b.len() / 2;
        b[i] ^= 0x20;
        std::fs::write(&path, b).unwrap();
        flipped += 1;
    }
    assert!(flipped >= good.len() - 1, "{flipped} objects in the store for {}", good.len());
    assert_eq!(items(&admin.walk()), items(&good), "never wrong bytes");
    assert!(d.status()["store"]["damaged"].as_u64().unwrap() > 0);
}

/// A daemon never outlives its Veil home: it exits once the home's
/// identity is gone, and a daemon (or a `vl` starting one) that comes too
/// late, after the home was removed, makes nothing again (found running the
/// suites: a removed test home brought back by a daemon starting as it
/// went, which then ran on with no one to use it).
#[test]
fn the_daemon_never_outlives_its_veil_home() {
    let hub = TestHub::start();
    let who = hub.person("gone");
    let d = Daemon::start(&who, None);
    let pid = d.pid();
    let alive = |pid: i32| std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.contains(") Z "));
    assert!(alive(pid));
    let home = who.home.path().join("veil");
    std::fs::remove_file(home.join("identity.json")).unwrap();
    let took = until(Duration::from_secs(5), "the daemon exits once its home's identity is gone", || !alive(pid));
    eprintln!("daemon: exited {took:?} after its home's identity went");
    // The whole home removed; then a daemon starting late.
    std::fs::remove_dir_all(&home).unwrap();
    let o = who.run(who.home.path(), &["daemon", "run"]);
    assert!(!o.status.success(), "a daemon of a removed Veil home refuses to run");
    assert!(String::from_utf8_lossy(&o.stderr).contains("is not there"), "{}", String::from_utf8_lossy(&o.stderr));
    let o = who.run(who.home.path(), &["daemon", "start"]);
    assert!(!o.status.success(), "nor is one started");
    assert!(!home.exists(), "the removed Veil home was made again");
}

// ---- S6 review, cycle 2 -----------------------------------------------------------

/// One message from a fake daemon's connection: its kind and payload.
fn s6r2_read_msg(s: &mut UnixStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(head[1..].try_into().unwrap()) as usize];
    s.read_exact(&mut body).ok()?;
    Some((head[0], body))
}

/// The daemon's socket of `who` taken over by the test: the real daemon
/// stopped, `off` removed, the socket's path free.
fn s6r2_take_socket(who: &Person) -> Daemon {
    let d = Daemon::start(who, None);
    who.ok(who.home.path(), &["daemon", "stop"]);
    std::fs::remove_file(d.dir.join("off")).unwrap();
    let _ = std::fs::remove_file(&d.socket);
    d
}

/// Guarantee 3 of the S6 review, cycle 2: stopping an older daemon never
/// stops the one that replaced it. A `vl` meets a daemon of an older
/// version and stops it; meanwhile (between its acknowledgement and the
/// stop) another `vl` stopped that daemon and started one of this version
/// at the same socket. The stop must not reach the newer daemon.
#[test]
fn s6r2_stopping_an_older_daemon_never_stops_the_one_that_replaced_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = s6r2_take_socket(who);
    let older = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let socket = d.socket.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let fake = std::thread::spawn(move || {
        older.set_nonblocking(true).unwrap();
        let t = Instant::now();
        let mut first = loop {
            match older.accept() {
                Ok((s, _)) => break s,
                Err(_) if t.elapsed() < Duration::from_secs(60) && !done2.load(std::sync::atomic::Ordering::SeqCst) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return None,
            }
        };
        first.set_nonblocking(false).unwrap();
        let (kind, _) = s6r2_read_msg(&mut first).expect("the first request");
        // Replaced, before it answers: the older daemon is gone and one of
        // this version holds the socket.
        drop(older);
        std::fs::remove_file(&socket).unwrap();
        let newer = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        // The older daemon's acknowledgement: version 0.
        let _ = first.write_all(&[b'A', 0, 0, 0, 1, 0]);
        drop(first);
        // The newer daemon: acknowledges as this version and serves
        // nothing (a whole, empty answer: the rest from the server).
        newer.set_nonblocking(true).unwrap();
        let mut kinds = vec![kind];
        while !done2.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok((mut s, _)) = newer.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let Some((k, payload)) = s6r2_read_msg(&mut s) else { continue };
            // A stop a daemon of this version obeys: empty, or naming a
            // newer version than its own (BUG-1517: the stop names its
            // sender's version, and only an older daemon obeys it).
            let obeyed = k == b'S' && payload.first().is_none_or(|v| *v > PROTOCOL);
            kinds.push(if obeyed { b'!' } else { k });
            if k == b'Q' {
                let _ = s.write_all(&[b'A', 0, 0, 0, 1, PROTOCOL, b'E', 0, 0, 0, 2, b'{', b'}']);
            }
        }
        Some(kinds)
    });
    let c = who.dir("replaced");
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    // A second `vl` meanwhile (it asks the newer daemon).
    who.ok(&c, &["cat", "-r", "main", "src/lib.rs"]);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let kinds = fake.join().unwrap().expect("the clone never asked the daemon");
    assert_eq!(kinds[0], b'Q', "the older daemon was asked first: {kinds:?}");
    assert!(!kinds[1..].contains(&b'!'), "the stop meant for the older daemon stopped the newer one: {:?}", kinds.iter().map(|k| *k as char).collect::<String>());
}

/// Guarantee 3, a daemon that acknowledges and then stalls (its store on a
/// hung disk, wedged after reading the request, or a same-user process on
/// its socket that lies): a `vl` waits at most one short wait for it.
#[test]
fn s6r2_a_daemon_that_stalls_after_its_acknowledgement_costs_a_vl_one_short_wait() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = s6r2_take_socket(who);
    let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let stalled = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let mut held = Vec::new();
        while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok((mut s, _)) = l.accept() else {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            if let Some((b'Q', _)) = s6r2_read_msg(&mut s) {
                // Acknowledged at once, as the daemon does; then nothing.
                let _ = s.write_all(&[b'A', 0, 0, 0, 1, PROTOCOL]);
            }
            held.push(s);
        }
        held.len()
    });
    let c = who.dir("stalled-after-ack");
    let t = Instant::now();
    who.ok(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let took = t.elapsed();
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    // A local command in the thin clone (it only pins its working copy's
    // trees at the daemon).
    let t = Instant::now();
    let status = who.ok(&c, &["status"]);
    let took_status = t.elapsed();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let asked = stalled.join().unwrap();
    assert!(asked > 0, "the clone never asked the daemon");
    eprintln!("a daemon stalled after acknowledging: a clone {took:?}, `vl status` {took_status:?}, {asked} connection(s): {status}");
    assert!(took_status < Duration::from_secs(5), "`vl status` in a thin clone took {took_status:?}");
    // The same bound as a daemon that never acknowledges
    // (`a_stalled_daemon_costs_a_vl_at_most_one_wait`).
    assert!(took < Duration::from_secs(15), "a clone with a daemon stalled after its acknowledgement took {took:?} ({asked} connections)");
}

/// Guarantee 3 of the S6 review, cycle 3: a daemon that acknowledges and
/// then only says it is working, forever, costs a `vl` one wait (between
/// whole objects, 35 s), not forever. This is what the real daemon does
/// once wedged after its acknowledgement (its store on a hung disk, a
/// budget never granted): its progress thread keeps sending `P` every 0.1 s
/// while the request's thread never answers (BUG-1582); and what a lying
/// same-user process on its socket may do (`docs/HUB.md` §13.29, threat row
/// 8). The clone (which would send several requests across its walk) and
/// `vl status` must each end after one between-objects wait, well inside
/// two.
#[test]
fn s6r3_a_daemon_that_only_reports_progress_costs_a_vl_one_short_wait() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = s6r2_take_socket(who);
    let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let beating = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let mut conns: Vec<UnixStream> = Vec::new();
        let mut asked = 0;
        while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                if let Some((b'Q', _)) = s6r2_read_msg(&mut s) {
                    // Acknowledged at once, as the daemon does; then
                    // "working" every 0.1 s, as its progress thread does
                    // while the request's thread never answers.
                    let _ = s.write_all(&[b'A', 0, 0, 0, 1, PROTOCOL]);
                    asked += 1;
                    conns.push(s);
                }
            }
            conns.retain_mut(|s| s.write_all(&[b'P', 0, 0, 0, 0]).is_ok());
            std::thread::sleep(Duration::from_millis(100));
        }
        asked
    });
    // `timeout` ends a `vl` that never returns, so the test can say so.
    let run = |cwd: &Path, args: &[&str]| -> (std::process::Output, Duration) {
        let cmd = who.command(cwd, args);
        let t = Instant::now();
        let o = std::process::Command::new("timeout")
            .arg("60")
            .arg(cmd.get_program())
            .args(cmd.get_args())
            .envs(cmd.get_envs().filter_map(|(k, v)| Some((k, v?))))
            .current_dir(cwd)
            .output()
            .unwrap();
        (o, t.elapsed())
    };
    let c = who.dir("beating-forever");
    let (o, took) = run(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    assert!(o.status.success(), "a clone with a daemon that only reports progress failed or never ended ({took:?}): {}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    let (o, took_status) = run(&c, &["status"]);
    assert!(o.status.success(), "`vl status` in the thin clone failed or never ended ({took_status:?}): {}", String::from_utf8_lossy(&o.stderr));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let asked = beating.join().unwrap();
    assert!(asked > 0, "the clone never asked the daemon");
    eprintln!("a daemon that only reports progress: a clone {took:?}, `vl status` {took_status:?}, {asked} request(s)");
    // One 35 s wait per process (not one per request: two requests in the
    // clone would take >= 70 s).
    assert!(took_status < Duration::from_secs(50), "`vl status` in a thin clone took {took_status:?}");
    assert!(took < Duration::from_secs(50), "a clone with a daemon that only reports progress took {took:?} ({asked} requests)");
}

/// BUG-1582's class, its other route: the bound is on each gap, not on the
/// answer. A daemon that acknowledges and then sends one object a byte at
/// a time (every 0.3 s, inside the 0.5 s gap) holds a `vl` for as long as
/// the object lasts; this one never ends it. The clone must end after one
/// between-objects wait (35 s), well inside two.
#[test]
fn s6r3_a_daemon_that_trickles_an_object_costs_a_vl_one_short_wait() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    let d = s6r2_take_socket(who);
    let l = std::os::unix::net::UnixListener::bind(&d.socket).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let trickling = std::thread::spawn(move || {
        l.set_nonblocking(true).unwrap();
        let mut conns: Vec<UnixStream> = Vec::new();
        let mut asked = 0;
        while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                if let Some((b'Q', _)) = s6r2_read_msg(&mut s) {
                    // Acknowledged, then an object of 32 + 2^20 bytes begun.
                    let len = (32u32 + (1 << 20)).to_be_bytes();
                    let _ = s.write_all(&[b'A', 0, 0, 0, 1, PROTOCOL, b'O', len[0], len[1], len[2], len[3]]);
                    asked += 1;
                    conns.push(s);
                }
            }
            conns.retain_mut(|s| s.write_all(&[0]).is_ok());
            std::thread::sleep(Duration::from_millis(300));
        }
        asked
    });
    let c = who.dir("trickled");
    let cmd = who.command(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let t = Instant::now();
    // `timeout` ends a `vl` that never returns, so the test can say so.
    let o = std::process::Command::new("timeout")
        .arg("60")
        .arg(cmd.get_program())
        .args(cmd.get_args())
        .envs(cmd.get_envs().filter_map(|(k, v)| Some((k, v?))))
        .current_dir(who.home.path())
        .output()
        .unwrap();
    let took = t.elapsed();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let asked = trickling.join().unwrap();
    assert!(o.status.success(), "a clone with a daemon that trickles an object failed or never ended ({took:?}): {}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    assert!(asked > 0, "the clone never asked the daemon");
    eprintln!("a daemon that trickles an object: a clone {took:?}, {asked} request(s)");
    assert!(took < Duration::from_secs(50), "a clone with a daemon that trickles an object took {took:?}");
}

/// Guarantee 3 and the threat model ("Other OS users share nothing with
/// it"): a `vl` never sends a request (its grant and its device's
/// signature, which the server accepts again for ±5 minutes) to a socket
/// another OS user listens on. Here `XDG_RUNTIME_DIR` is a folder every
/// user can write (as `/tmp` is, where some setups point it), and another
/// OS user made `veil/daemon.sock` there first. Needs root, to be another
/// OS user (the listener runs as `nobody`).
#[test]
#[ignore = "needs root (a second OS user): run it with sudo -E; BUG-1515 is fixed (a vl connects only to a socket its own user listens on)"]
fn s6r2_a_vl_never_asks_another_os_users_daemon() {
    let root = std::process::Command::new("id").arg("-u").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&root.stdout).trim(), "0", "this reproduction needs root (a second OS user): run it with sudo -E");
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    // The default layout (no VEIL_HOME): the socket in XDG_RUNTIME_DIR.
    // As `/tmp` is: a folder every user can reach and write.
    let tmp = tempfile::Builder::new().prefix("veil-s6r2-").tempdir_in("/tmp").unwrap();
    let shared = tmp.path().to_path_buf();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let log = shared.join("veil/got");
    let listener = format!(
        "import socket,os\nos.mkdir({dir:?})\nos.chmod({dir:?},0o777)\ns=socket.socket(socket.AF_UNIX)\ns.bind({sock:?})\nos.chmod({sock:?},0o777)\ns.listen(64)\nopen({ready:?},'w').close()\n\
         while True:\n  c,_=s.accept()\n  b=c.recv(1<<20)\n  open({log:?},'ab').write(b[:1])\n  c.close()\n",
        dir = shared.join("veil").display().to_string(),
        sock = shared.join("veil/daemon.sock").display().to_string(),
        ready = shared.join("veil/ready").display().to_string(),
        log = log.display().to_string()
    );
    let mut other = std::process::Command::new("setpriv").args(["--reuid=nobody", "--regid=nogroup", "--clear-groups", "python3", "-c", &listener]).spawn().unwrap();
    until(Duration::from_secs(10), "the other user's listener is up", || shared.join("veil/ready").exists());
    let c = who.dir("other-user");
    let cmd = who.command(who.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let o = std::process::Command::new(cmd.get_program())
        .args(cmd.get_args())
        .envs(cmd.get_envs().filter_map(|(k, v)| Some((k, v?))))
        .env_remove("VEIL_HOME")
        .env("XDG_CONFIG_HOME", who.home.path())
        .env("XDG_CACHE_HOME", who.home.path().join("cache"))
        .env("XDG_RUNTIME_DIR", &shared)
        .current_dir(who.home.path())
        .output()
        .unwrap();
    // A process this test started, by its own handle.
    let _ = other.kill();
    let _ = other.wait();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    let got = std::fs::read(&log).unwrap_or_default();
    assert!(!got.contains(&b'Q'), "the clone sent {} request(s) to another OS user's socket", got.iter().filter(|b| **b == b'Q').count());
}

/// BUG-1515's class without a second OS user: the daemon's place is taken
/// from the environment as it is. An empty `XDG_CACHE_HOME` and
/// `XDG_RUNTIME_DIR` (the XDG rules: empty or relative means unset) must
/// leave the daemon in its default place, never a folder made where `vl`
/// happens to run (here a thin clone's working copy).
#[test]
fn s6r2_an_empty_xdg_variable_never_puts_the_daemon_where_vl_runs() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let who = &p.dev;
    // A short HOME of its own (the default socket, `~/.cache/veil/daemon/
    // run/daemon.sock`, must fit a socket address: under a long TMPDIR the
    // person's home is too long, and no daemon starts); the Veil home stays
    // the person's (`XDG_CONFIG_HOME`).
    let short = tempfile::Builder::new().prefix("vh").tempdir_in("/tmp").unwrap();
    let home = short.path();
    let config = who.home.path();
    let run = |cwd: &Path, args: &[&str]| {
        let cmd = who.command(cwd, args);
        let o = std::process::Command::new("timeout")
            .arg("120")
            .arg(cmd.get_program())
            .args(cmd.get_args())
            .envs(cmd.get_envs().filter_map(|(k, v)| Some((k, v?))))
            .env_remove("VEIL_HOME")
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", config)
            .env("XDG_CACHE_HOME", "")
            .env("XDG_RUNTIME_DIR", "")
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(o.status.success(), "vl {args:?}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let work = who.dir("work");
    std::fs::create_dir_all(&work).unwrap();
    let c = work.join("clone");
    run(&work, &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("src/lib.rs")).unwrap(), PUBLIC_MARK);
    let t = Instant::now();
    assert_eq!(run(&c, &["cat", "-r", "main", "src/lib.rs"]).trim(), PUBLIC_MARK);
    let took = t.elapsed();
    for dir in [&work, &c] {
        assert!(!dir.join("veil").exists(), "the daemon's folders were made in {}", dir.display());
    }
    assert!(home.join(".cache/veil/daemon").is_dir(), "the daemon is not in its default place");
    assert!(took < Duration::from_secs(2), "a command in the clone took {took:?}");
}

// ---- BUG-1680: renewals only while reading; re-confirm after idle; server back-off ----

/// BUG-1680 (guarantees 2, 3 and 4):
/// - **No idle traffic:** once nothing has been read through a grant for a
///   few seconds (`ACTIVE_MS`, 5 s), the daemon sends no renewal polls for
///   it at all (`polls` and the server's `requests` counter stop moving).
/// - **The cache still works after idle:** when a read arrives after the
///   confirmation went stale, the daemon confirms once with a skipped
///   request (`polls` +1, `forwarded` +0, `from_upstream` +0) and serves
///   the walk from its store (`from_store` grows by every object of the
///   walk); if access was revoked while idle, that confirmation gets `401`,
///   voids the grant (`voided` +1) and serves nothing from the store.
/// - **The server's back-off is respected:** when the server answers `429`
///   with `retry_after_ms`, the daemon sends nothing more on its own
///   account (`polls` does not move) until that time has passed, while a
///   read it cannot confirm still goes to the server as the client signed
///   it (`forwarded` +1, answered with the server's `429`).
#[test]
fn bug_1680_no_idle_renewals_warm_store_after_idle_and_server_backoff() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let d = Daemon::start(&p.fin, None);
    let fin = Reader::new(&server, &d.socket, &hub.authority(), Some(&p.fin), &p.name);
    let cold = fin.walk();
    assert!(!cold.is_empty(), "the cold walk succeeded");
    warm(&d, &fin, &[], &fin.root());
    assert!(d.stat("confirmed") >= 1, "fin's grant is confirmed");

    // 1. No idle traffic: wait past ACTIVE_MS (5 s); background polls stop
    // completely, and 5 s after the last poll the confirmation is stale.
    std::thread::sleep(STALE + Duration::from_millis(1200));
    let polls_idle = d.stat("polls");
    std::thread::sleep(STALE);
    assert_eq!(d.stat("polls"), polls_idle, "the daemon sent renewal polls while idle");
    assert_eq!(d.stat("confirmed"), 0, "the confirmation went stale while idle");

    // 2. Cache still works after idle: a full walk after the confirmation is
    // stale sends one skipped confirmation poll (`polls` +1, `forwarded` +0,
    // `from_upstream` +0) and serves every object from the store.
    let (before_store, before_up, before_fwd, before_polls) = (d.stat("from_store"), d.stat("from_upstream"), d.stat("forwarded"), d.stat("polls"));
    let after_idle = fin.walk();
    assert_eq!(items(&after_idle), items(&cold), "the walk after idle succeeded and matches");
    assert_eq!(d.stat("polls"), before_polls + 1, "one confirmation request re-confirmed the stale grant");
    assert_eq!(d.stat("forwarded"), before_fwd, "no batch was forwarded upstream after idle");
    assert_eq!(d.stat("from_upstream"), before_up, "no object was re-fetched from upstream after idle");
    assert!(d.stat("from_store") >= before_store + after_idle.len() as u64, "every object came from the store after idle");

    // 3. Unchanged access rule after idle: let the confirmation go stale
    // again, revoke fin's access while idle, then ask for the invoice; the
    // on-demand confirmation gets 401 and nothing is served from the store.
    let (chain, id) = invoice(&fin);
    std::thread::sleep(2 * STALE + Duration::from_millis(1200));
    assert_eq!(d.stat("confirmed"), 0, "stale again before revocation");
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let before_store = d.stat("from_store");
    let before_voided = d.stat("voided");
    let (got, end) = fin.batch_as(&fin.grant, fin.id.as_ref(), &[(chain, id)]);
    assert!(got.is_empty(), "revoked object served after idle");
    refused(end, "revoked while idle");
    assert_eq!(d.stat("from_store"), before_store, "nothing served from the store after revocation");
    assert!(d.stat("voided") > before_voided, "the 401 voided the epochs");

    // 4. Server back-off respected: on a server whose device limit is 100/s
    // and 20/hour, exhausting the device's 20/hour budget makes the server
    // answer 429 with a long `retry_after_ms`. The daemon records the
    // back-off and sends no more polls on its own account, while a client's
    // unconfirmed read still forwards as signed and receives the 429.
    let device = veil_server::limits::bucket::Rate { per_second: 100, per_hour: 20 };
    let lim_hub = TestHub::start_with_limits(veil_server::limits::Settings { device, ..TestHub::limits() });
    let lim_api = lim_hub.api();
    let lim_admin = lim_hub.person("limadmin");
    let proj = unique("limproj");
    let pdir = lim_admin.dir("proj");
    std::fs::create_dir_all(&pdir).unwrap();
    lim_admin.ok(&pdir, &["init"]);
    write_files(&pdir, &[("a.txt", "hello")]);
    lim_admin.ok(&pdir, &["remote", "add", "origin", &lim_hub.url(&proj)]);
    lim_admin.commit_main(&pdir, "init");
    lim_admin.ok(&pdir, &["push"]);
    let lim_d = Daemon::start(&lim_admin, None);
    let token = lim_admin.token();
    let dev_r = Reader::new(&lim_api, &lim_d.socket, &lim_hub.authority(), Some(&lim_admin), &proj);
    // First read: fetches grant-key (anonymous) and forwards the batch,
    // caching the root and confirming the grant.
    let (got, end) = dev_r.batch_as(&dev_r.grant, dev_r.id.as_ref(), &[(Vec::new(), dev_r.root())]);
    assert_eq!(got.len(), 1, "first read succeeded: {end:?}");
    assert!(end.expect("whole answer")["status"].is_null());
    let errs_before = lim_d.stat("poll_errors");
    // Spend the remaining device tokens and trigger 429 on the server.
    let mut saw_429 = false;
    for _ in 0..30 {
        let r = lim_api.get(Some(&token), &format!("/v1/projects/{proj}/tips"));
        if r.status == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "the device budget is exhausted (429)");
    // The next background renewal poll hits 429 with `retry_after_ms` and
    // backs off the upstream; after that, `polls` stops moving.
    until(Duration::from_secs(4), "a renewal poll sees the 429", || lim_d.stat("poll_errors") > errs_before);
    let polls_after_429 = lim_d.stat("polls");
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(lim_d.stat("polls"), polls_after_429, "the daemon kept polling a server that answered 429 retry_after_ms");
    // Wait for the confirmation to expire; while backed off, an unconfirmed
    // read is not polled by the daemon (`polls` unchanged), and is forwarded
    // to the server as the client signed it (`forwarded` +1, status 429).
    std::thread::sleep(STALE);
    let (polls_before, fwd_before) = (lim_d.stat("polls"), lim_d.stat("forwarded"));
    let (got, end) = dev_r.batch_as(&dev_r.grant, dev_r.id.as_ref(), &[(Vec::new(), dev_r.root())]);
    assert!(got.is_empty(), "unconfirmed read during backoff must not serve from store");
    assert_eq!(end.expect("whole answer")["status"], 429, "client's signed request forwarded and answered 429");
    assert_eq!(lim_d.stat("polls"), polls_before, "no daemon poll sent while backed off");
    assert_eq!(lim_d.stat("forwarded"), fwd_before + 1, "the client's request was forwarded to the server");
}

/// BUG-1681: `vl daemon follow` (`crates/vl/src/daemon/follow.rs`) sends
/// `GET /v1/projects/{p}/tips` once a second for every project in
/// `follow.json` (kept for 7 days after a single thin clone read), even
/// when nothing is being read through the daemon.
#[test]
#[ignore = "BUG-1681: vl daemon follow polls GET /tips every second for 7 days while idle"]
fn bug_1681_daemon_follow_polls_tips_every_second_while_idle() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let health_requests = || {
        let r = api.get(Some(&admin), &format!("/v1/projects/{}/health", p.name));
        assert_eq!(r.status, 200);
        r.json()["since_start"]["requests"].as_u64().unwrap()
    };
    let _d = Daemon::start(&p.dev, None);
    let thin = p.dev.dir("thin-idle");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), thin.to_str().unwrap()]);
    std::thread::sleep(STALE + Duration::from_millis(1500));
    let before = health_requests();
    std::thread::sleep(Duration::from_secs(4));
    let after = health_requests();
    assert_eq!(after - before, 1, "only the health check itself should hit the server while idle (got {} extra requests)", after - before - 1);
}


