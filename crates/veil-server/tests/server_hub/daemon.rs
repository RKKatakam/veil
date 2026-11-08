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
    let body = serde_json::to_vec(req).unwrap();
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    s.write_all(&msg).unwrap();
    let mut got = Vec::new();
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
            b'O' => {
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
    let (got, _) = dev.batch_as(&tampered, dev.id.as_ref(), &[(Vec::new(), admin_root)]);
    assert!(got.is_empty(), "a wider root under the grant's signature");
    let by_identity = {
        let raw = serde_json::to_vec(&wider).unwrap();
        format!("{}.{}", hex::encode(&raw), hub.hub().identity.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_GRANT, &raw))
    };
    let (got, _) = dev.batch_as(&by_identity, dev.id.as_ref(), &[(Vec::new(), admin_root)]);
    assert!(got.is_empty(), "a grant signed by the server's identity key");
    let expired = hub.hub().grants.issue(&veil_core::hub::grant::GrantBody { expires: veil_core::now_millis() - 1, ..body.clone() });
    let (got, _) = dev.batch_as(&expired, dev.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "an expired grant");
    let stale = hub.hub().grants.issue(&veil_core::hub::grant::GrantBody { epoch: body.epoch + 1, ..body.clone() });
    let (got, _) = dev.batch_as(&stale, dev.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "a grant of other epochs");
    let other = Reader { project: unique("other"), ..Reader::new(&server, &d.socket, &hub.authority(), Some(&p.dev), &p.name) };
    let (got, _) = other.batch_as(&other.grant, other.id.as_ref(), &[(Vec::new(), dev.root())]);
    assert!(got.is_empty(), "a grant of another project (nothing, from the store or not)");

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

/// How many rows the server's state tables hold: a request that changes
/// nothing on the server leaves every count as it was.
fn state_counts(hub: &TestHub) -> Vec<(&'static str, i64)> {
    ["audit_log", "access_epochs", "sessions", "devices", "projections", "snapshots", "branches"]
        .into_iter()
        .map(|t| {
            let n: i64 = hub.rt.block_on(sqlx::query_scalar(&format!("SELECT count(*) FROM {t}")).fetch_one(&hub.hub().db)).unwrap();
            (t, n)
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
    let before = state_counts(&hub);
    for _ in 0..20 {
        let r = send(&resent);
        assert_eq!(r.status, 200, "a resend within the window is accepted");
        assert!(r.frames().is_empty(), "a resend with every object skipped returns an object");
    }
    assert_eq!(state_counts(&hub), before, "resends changed the server's state");
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
                let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let mut out = Vec::new();
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
#[ignore = "BUG-1514: a stalled daemon costs vl 60 s for every request, so a clone takes minutes"]
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
    assert!(took < Duration::from_secs(75), "a clone with a stalled daemon took {took:?} ({asked} connections)");
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
