//! The regional cache (S9, `docs/HUB.md` §13.18): it never serves anyone
//! an object the server would not, whatever id, chain, grant or signature
//! they send, cold or warm; a removal reaches it within the owner's bound
//! (5 s); without the server's epoch feed it stops serving from its store;
//! damaged objects are never served; its store holds no plaintext secret;
//! only the server's caches read the epoch feed for caches.

use std::{
    collections::HashSet,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use veil_core::{
    hub::grant::{sign_request, BatchRequest, ChainWant, Grant, GrantBody, MAX_CHAIN},
    hub::wire::MAX_WANTS,
    object::{EntryKind, Object},
    Identity, ObjectId,
};
use veil_server::cache::{self, feed::FEED_KEYS};

use crate::support::*;

/// A cache in front of `upstream` (`127.0.0.1:PORT`: the server, or a proxy
/// to it), in the hub's runtime, with its own directory.
struct TestCache {
    running: cache::Running,
    api: Api,
    dir: tempfile::TempDir,
}

impl TestCache {
    fn start(hub: &TestHub, upstream: &str, size: u64) -> TestCache {
        TestCache::start_with(hub, upstream, size, 1024)
    }

    fn start_with(hub: &TestHub, upstream: &str, size: u64, max_connections: usize) -> TestCache {
        let dir = tempfile::Builder::new().prefix("veil-cache-test").tempdir().unwrap();
        let token = std::fs::read_to_string(hub.ca.parent().unwrap().join("hub-cache-token")).unwrap();
        let running = hub
            .rt
            .block_on(cache::start(cache::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: format!("https://{upstream}"),
                upstream_ca: Some(hub.cert_pem.clone()),
                token,
                dir: dir.path().to_path_buf(),
                tls: veil_server::tls::TlsSource::SelfSigned,
                size,
                memory: 64 << 20,
                max_connections,
            }))
            .expect("the cache starts");
        let api = Api::at(&running.addr.to_string(), &running.cert_pem);
        TestCache { running, api, dir }
    }

    fn stat(&self, name: &str) -> u64 {
        cache::stats_json(&self.running.cache)[name].as_u64().unwrap()
    }

    /// Every file of the cache's directory (its store).
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![self.dir.path().to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
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

/// Someone who gets grants from the server and reads objects through
/// `via` (a cache, or the server).
struct Reader<'a> {
    via: &'a Api,
    project: String,
    id: Option<Identity>,
    grant: String,
    key: String,
}

impl<'a> Reader<'a> {
    fn new(server: &Api, via: &'a Api, who: Option<&Person>, project: &str) -> Reader<'a> {
        let tips = server.tips(who.map(|p| p.token()).as_deref(), project).expect("tips");
        Reader {
            via,
            project: project.to_string(),
            id: who.map(|p| p.identity()),
            grant: tips.grants.get("main").expect("a grant for main").clone(),
            key: tips.grant_key.unwrap(),
        }
    }

    fn body(&self) -> GrantBody {
        Grant::read_unverified(&self.grant).unwrap()
    }

    fn root(&self) -> ObjectId {
        self.body().root
    }

    fn signature(&self, grant: &str, ts: i64, ids: &[ObjectId]) -> Option<String> {
        let g = Grant::verify(grant, &self.key)?;
        self.id.as_ref().map(|i| sign_request(i, &g, ts, ids))
    }

    fn batch_as(&self, grant: &str, wants: &[(Vec<ObjectId>, ObjectId)], skip: Vec<ObjectId>) -> Reply {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: grant.to_string(),
            ts,
            signature: self.signature(grant, ts, &ids),
            wants: wants.iter().map(|(chain, id)| ChainWant { chain: chain.clone(), id: *id }).collect(),
            skip,
        };
        self.via.post(None, &format!("/v1/objects/{}:batch", self.project), &serde_json::to_vec(&req).unwrap(), true)
    }

    fn batch(&self, wants: &[(Vec<ObjectId>, ObjectId)]) -> Vec<(ObjectId, Vec<u8>)> {
        self.batch_as(&self.grant, wants, Vec::new()).frames()
    }

    fn get_as(&self, grant: &str, chain: &[ObjectId], id: &ObjectId, sig: Option<(i64, String)>, extra: &[(&str, &str)]) -> Reply {
        let sig = sig.or_else(|| {
            let ts = veil_core::now_millis();
            self.signature(grant, ts, &[*id]).map(|s| (ts, s))
        });
        let chain = chain.iter().map(|c| c.hex()).collect::<Vec<_>>().join(",");
        let sig = sig.map(|(ts, s)| format!("{ts}.{s}"));
        let mut h: Vec<(&str, &str)> = vec![("veil-grant", grant), ("veil-chain", &chain)];
        if let Some(s) = &sig {
            h.push(("veil-signature", s));
        }
        h.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
        h.extend_from_slice(extra);
        self.via.get_with(&format!("/v1/objects/{}/{}", self.project, id.hex()), &h)
    }

    fn get(&self, chain: &[ObjectId], id: &ObjectId) -> Reply {
        self.get_as(&self.grant, chain, id, None, &[])
    }

    /// Everything reachable from the grant's root, level by level, with
    /// the chain each object was met at.
    fn walk(&self) -> Vec<(Vec<ObjectId>, ObjectId, Vec<u8>)> {
        let mut out = Vec::new();
        let mut wants = vec![(Vec::new(), self.root())];
        let mut seen = HashSet::new();
        while !wants.is_empty() {
            let mut got = self.fetch(&wants);
            let mut next = Vec::new();
            for (chain, id) in wants {
                let Some(raw) = got.remove(&id) else { continue };
                if !seen.insert((chain.clone(), id)) {
                    continue;
                }
                match Object::decode(&raw) {
                    Ok(Object::Tree(t)) => {
                        let c = [chain.clone(), vec![id]].concat();
                        next.extend(t.entries.iter().map(|e| (c.clone(), e.id)));
                    }
                    Ok(Object::Conflict(k)) => {
                        let c = [chain.clone(), vec![id]].concat();
                        next.extend(k.referenced_ids().into_iter().map(|t| (c.clone(), t)));
                    }
                    _ => {}
                }
                out.push((chain, id, raw));
            }
            wants = next;
        }
        out
    }
}

impl Reader<'_> {
    /// Every one of `wants`, asking again for what did not arrive (as a
    /// client does: a cache leaves out an object it lost since its check).
    /// Each answer is in the request's order, each object once.
    fn fetch(&self, wants: &[(Vec<ObjectId>, ObjectId)]) -> std::collections::HashMap<ObjectId, Vec<u8>> {
        let mut got = std::collections::HashMap::new();
        let mut left = wants.to_vec();
        for _ in 0..5 {
            let frames = self.batch(&left);
            let order = dedup(&left);
            let mut at = 0;
            for (id, _) in &frames {
                let i = order[at..].iter().position(|o| o == id).unwrap_or_else(|| panic!("{} out of order, or twice, or not asked", id.short()));
                at += i + 1;
            }
            got.extend(frames);
            left.retain(|w| !got.contains_key(&w.1));
            if left.is_empty() {
                return got;
            }
        }
        panic!("{} reachable objects never arrived", left.len());
    }
}

/// Ids of `wants` in order, each once.
fn dedup(wants: &[(Vec<ObjectId>, ObjectId)]) -> Vec<ObjectId> {
    let mut seen = HashSet::new();
    wants.iter().map(|w| w.1).filter(|id| seen.insert(*id)).collect()
}

/// The admin's real tree of `main`: every object with its path and the
/// chain of real tree ids above it.
fn real_chains(dir: &Path) -> Vec<(String, Vec<ObjectId>, ObjectId)> {
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let root = repo.snapshot(&tip).unwrap().tree;
    let mut out = vec![(String::new(), Vec::new(), root)];
    let mut stack = vec![(String::new(), vec![root])];
    while let Some((p, chain)) = stack.pop() {
        let t = repo.store().tree(chain.last().unwrap()).unwrap();
        for e in &t.entries {
            let path = if p.is_empty() { e.name.clone() } else { format!("{p}/{}", e.name) };
            out.push((path.clone(), chain.clone(), e.id));
            if e.kind == EntryKind::Dir {
                let c = [chain.clone(), vec![e.id]].concat();
                stack.push((path, c));
            }
        }
    }
    out
}

fn items(walked: &[(Vec<ObjectId>, ObjectId, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    walked.iter().map(|(_, id, raw)| (format!("object {}", id.short()), raw.clone())).collect()
}

fn random_id() -> ObjectId {
    ObjectId(veil_core::crypto::random_bytes::<32>())
}

fn invalid(r: &Reply) -> bool {
    r.status == 401 && r.json()["code"] == "grant_invalid"
}

/// Ask until `ok` holds of `f()`, for at most `limit`; how long it took.
fn until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Duration {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < limit, "{what}: not within {limit:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    t.elapsed()
}

/// Read `(chain, id)` through the cache until the cache serves it from its
/// store (its epochs confirmed, the object kept).
fn warm(c: &TestCache, r: &Reader, chain: &[ObjectId], id: &ObjectId) {
    until(Duration::from_secs(10), "served from the cache's store", || {
        let before = c.stat("local");
        assert_eq!(r.get(chain, id).status, 200);
        c.stat("local") > before
    });
}

#[test]
fn the_cache_serves_only_what_a_grant_reaches() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let real = real_chains(&p.dir);
    let env_id = real.iter().find(|(path, _, _)| *path == format!("{BILL_DIR}/.env")).unwrap().2;
    let admin_root = real[0].2;
    // Cold: the cache asks the server for everything, and what it passes
    // on is what the server gives.
    let admin = Reader::new(&server, &c.api, Some(&p.admin), &p.name);
    let direct = Reader::new(&server, &server, Some(&p.admin), &p.name);
    let cold = admin.walk();
    assert_eq!(items(&cold), items(&direct.walk()), "the cache answers as the server");
    assert!(c.stat("upstream") > 0 && c.stat("local") == 0, "cold: from the server");
    // Warm: every object of the project is in the cache's store, and a
    // second walk is served from it alone.
    warm(&c, &admin, &[], &admin.root());
    let forwarded = c.stat("forwarded");
    assert_eq!(items(&admin.walk()), items(&cold));
    assert_eq!(c.stat("forwarded"), forwarded, "a warm walk asks the server nothing");
    assert!(c.files().iter().any(|(_, b)| b.windows(BILL_MARK.len()).any(|w| w == BILL_MARK.as_bytes())), "the store holds billing/");

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
        let r = Reader::new(&server, &c.api, person, &p.name);
        // Twice: once before the cache confirmed their epochs (through
        // the server), once after (from the store).
        let first = r.walk();
        warm(&c, &r, &[], &r.root());
        let walked = r.walk();
        assert_no_marker(&items(&first), &hidden, who);
        assert_no_marker(&items(&walked), &hidden, who);
        assert_eq!(items(&first), items(&walked), "{who}");
        let reached: HashSet<ObjectId> = walked.iter().map(|w| w.1).collect();
        assert_eq!(reached.contains(&env_id), who == "fin", "{who}: billing's .env ciphertext");
        assert!(has_marker(&items(&walked), mine), "{who} did not receive {mine}");
        // Every real object they do not reach, all in the cache's store,
        // with every chain they can build.
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
        assert!(attacks.iter().any(|a| a.1 == admin_root), "{who}: the admin's root is among the attacks");
        let local = c.stat("local");
        for part in attacks.chunks(5000) {
            let got = r.batch(part);
            assert!(got.is_empty(), "{who} received {} hidden objects from the cache", got.len());
        }
        // One at a time: the server's answer for an object nobody has.
        let absent = r.get(&[r.root()], &random_id());
        assert_eq!(absent.status, 404);
        for (chain, id) in attacks.iter().step_by(7).take(60) {
            let g = r.get(chain, id);
            assert_eq!((g.status, &g.body), (404, &absent.body), "{who}: a hidden object answers like an absent one");
        }
        assert_eq!(c.stat("local"), local, "{who}: no attack was answered from the store");
        // And what they reach, one at a time, is served.
        for (chain, id, raw) in walked.iter().take(20) {
            let g = r.get(chain, id);
            assert_eq!((g.status, &g.body), (200, raw), "{who}");
        }
    }
    // A grant of one project at another project's URL: the same objects
    // are no help.
    let other = unique("other");
    let d = p.dev.dir("other");
    std::fs::create_dir_all(&d).unwrap();
    p.dev.ok(&d, &["init"]);
    write_files(&d, &[("a.txt", "another project")]);
    p.dev.ok(&d, &["remote", "add", "origin", &hub.url(&other)]);
    p.dev.commit_main(&d, "other");
    p.dev.ok(&d, &["push"]);
    let fin = Reader::new(&server, &c.api, Some(&p.fin), &p.name);
    let elsewhere = Reader { project: other.clone(), ..Reader::new(&server, &c.api, Some(&p.fin), &p.name) };
    assert!(invalid(&elsewhere.get(&[], &fin.root())), "another project's URL");
    assert!(invalid(&elsewhere.batch_as(&elsewhere.grant, &[(Vec::new(), fin.root())], Vec::new())));
    // The store holds secrets as ciphertext only.
    assert_no_marker(&c.files(), &[ENV_MARK], "the cache's store");
    // `skip`: the server leaves out what a cache sent, and a client's own
    // skip is honoured by the cache too.
    let dev = Reader::new(&server, &server, Some(&p.dev), &p.name);
    let dev_c = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
    let kids = dev.walk().into_iter().filter(|w| w.0 == vec![dev.root()]).map(|w| (w.0, w.1)).collect::<Vec<_>>();
    let mut wants = vec![(Vec::new(), dev.root())];
    wants.extend(kids.clone());
    for (who, r) in [("server", &dev), ("cache", &dev_c)] {
        let got = r.batch_as(&r.grant, &wants, vec![dev.root()]).frames();
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), dedup(&kids), "{who}");
    }
}

#[test]
fn grants_at_the_cache_hold_only_for_their_device_and_time() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
    let root = dev.root();
    // In the store, epochs confirmed: whatever is refused below is refused
    // by the cache, which holds the object.
    warm(&c, &dev, &[], &root);
    let local = c.stat("local");
    let ts = veil_core::now_millis();
    let g = Grant::verify(&dev.grant, &dev.key).unwrap();
    let sig = |who: &Identity, ts: i64, ids: &[ObjectId]| Some((ts, sign_request(who, &g, ts, ids)));
    for (what, s) in [
        ("fin's device", sig(&p.fin.identity(), ts, &[root])),
        ("other ids", sig(&p.dev.identity(), ts, &[random_id()])),
        ("six minutes old", sig(&p.dev.identity(), ts - 6 * 60_000, &[root])),
        ("an hour ahead", sig(&p.dev.identity(), ts + 3_600_000, &[root])),
    ] {
        assert!(invalid(&dev.get_as(&dev.grant, &[], &root, s, &[])), "{what}");
    }
    let path = format!("/v1/objects/{}/{}", p.name, root.hex());
    assert!(invalid(&c.api.get_with(&path, &[("veil-grant", &dev.grant)])), "no signature");
    let body = dev.body();
    let raw = serde_json::to_vec(&body).unwrap();
    let by_identity = format!("{}.{}", hex::encode(&raw), hub.hub().identity.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_GRANT, &raw));
    assert!(invalid(&dev.get_as(&by_identity, &[], &root, None, &[])), "signed by the server's identity");
    let admin_root = real_chains(&p.dir)[0].2;
    let mut wider = body.clone();
    wider.root = admin_root;
    let tampered = format!("{}.{}", hex::encode(serde_json::to_vec(&wider).unwrap()), dev.grant.split_once('.').unwrap().1);
    assert!(invalid(&dev.get_as(&tampered, &[], &admin_root, None, &[])), "a wider root under the signature");
    let grants = &hub.hub().grants;
    let expired = grants.issue(&GrantBody { expires: veil_core::now_millis() - 1, ..body.clone() });
    assert!(invalid(&dev.get_as(&expired, &[], &root, None, &[])), "expired");
    // Other epochs than the current ones: the cache asks the server, which
    // refuses.
    for (e, pe) in [(body.epoch + 1, body.person_epoch), (0, body.person_epoch), (body.epoch, body.person_epoch + 1)] {
        let stale = grants.issue(&GrantBody { epoch: e, person_epoch: pe, ..body.clone() });
        assert!(invalid(&dev.get_as(&stale, &[], &root, None, &[])), "epochs {e} {pe}");
    }
    assert_eq!(c.stat("local"), local, "nothing served from the store under a grant that does not hold");
    // Hostile input: nothing crashes, nothing is served.
    for h in [vec![("veil-grant", "zz")], vec![("veil-grant", ".")], vec![("veil-grant", &*"a".repeat(10_000))]] {
        assert!(invalid(&c.api.get_with(&path, &h)));
    }
    assert_eq!(c.api.get_with(&path, &[]).status, 401);
    assert_eq!(dev.get(&vec![root; MAX_CHAIN + 5], &root).status, 404);
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("veil-chain", "nothex,also")]).status, 400);
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("veil-signature", "garbage")]).status, 400);
    assert_eq!(c.api.get_with(&format!("/v1/objects/{}/nothex", p.name), &[("veil-grant", &dev.grant)]).status, 400);
    assert_eq!(c.api.post(None, &format!("/v1/objects/{}", p.name), b"{}", true).status, 404);
    assert_eq!(c.api.post(None, &format!("/v1/objects/{}:batch", p.name), b"{not json", true).status, 400);
    let many: Vec<(Vec<ObjectId>, ObjectId)> = (0..=MAX_WANTS).map(|_| (Vec::new(), root)).collect();
    assert_eq!(dev.batch_as(&dev.grant, &many, Vec::new()).status, 400);
    assert_eq!(c.api.get_with("/v1/projects/x/tips", &[]).status, 404, "the cache answers object routes only");
    // Range from the store, as the server answers it.
    let whole = dev.get(&[], &root).body;
    let part = dev.get_as(&dev.grant, &[], &root, None, &[("range", "bytes=2-5")]);
    assert_eq!((part.status, &part.body[..]), (206, &whole[2..6]));
    let tail = dev.get_as(&dev.grant, &[], &root, None, &[("range", "bytes=3-")]);
    assert_eq!((tail.status, &tail.body[..]), (206, &whole[3..]));
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("range", &format!("bytes={}-", whole.len()))]).status, 416);
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("range", "bytes=0-0")]).status, 206);
    assert_eq!(dev.get_as(&dev.grant, &[], &admin_root, None, &[("range", "bytes=0-0")]).status, 404, "a hidden object's range");
}

/// A TCP proxy to `upstream` that can be cut (every connection closed and
/// new ones refused) and restored.
struct Proxy {
    addr: String,
    cut: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<std::net::TcpStream>>>,
}

impl Proxy {
    fn start(upstream: String) -> Proxy {
        use std::net::{Shutdown, TcpListener, TcpStream};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let cut = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
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
        self.cut.store(cut, SeqCst);
        if cut {
            for c in self.conns.lock().unwrap().drain(..) {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// The billing invoice as `r` meets it: (chain, id).
fn invoice(r: &Reader) -> Option<(Vec<ObjectId>, ObjectId)> {
    r.walk().into_iter().find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], BILL_MARK)).map(|(c, id, _)| (c, id))
}

/// After an access change returned at `changed`: `r`'s old grant for
/// `(chain, id)` is refused at the cache within the owner's bound (5 s),
/// and never served again; how long it took.
fn refused_within_bound(r: &Reader, chain: &[ObjectId], id: &ObjectId, changed: Instant, what: &str) -> Duration {
    loop {
        let g = r.get(chain, id);
        if invalid(&g) {
            break;
        }
        assert_eq!(g.status, 200, "{what}: {}", String::from_utf8_lossy(&g.body));
        assert!(changed.elapsed() <= cache::epochs::STALE, "{what}: still served {:?} after the change", changed.elapsed());
        std::thread::sleep(Duration::from_millis(20));
    }
    let took = changed.elapsed();
    for _ in 0..20 {
        assert!(invalid(&r.get(chain, id)), "{what}: served again after a refusal");
        assert!(invalid(&r.batch_as(&r.grant, &[(chain.to_vec(), *id)], Vec::new())), "{what}: batch");
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!("cache: {what}: refused {took:?} after the change returned");
    took
}

/// The gate (design §6 row 4, product decision 1): a removed person, a
/// changed policy and a removed device are refused at the cache within 5
/// seconds, though the cache holds the objects.
#[test]
fn a_removed_person_is_refused_at_the_cache_within_the_bound() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    // A person removed from a group.
    let fin = Reader::new(&server, &c.api, Some(&p.fin), &p.name);
    let (chain, id) = invoice(&fin).expect("fin reads the invoice");
    warm(&c, &fin, &chain, &id);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let mut took = vec![refused_within_bound(&fin, &chain, &id, Instant::now(), "a person removed from finance")];
    let again = Reader::new(&server, &c.api, Some(&p.fin), &p.name);
    assert!(invoice(&again).is_none(), "the new grant reaches no billing file");
    assert!(again.batch(&[(chain.clone(), id)]).is_empty());
    // A policy change voids every grant of the project, anyone on Earth's.
    let anyone = Reader::new(&server, &c.api, None, &p.name);
    let lib = anyone.walk().into_iter().find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PUBLIC_MARK)).unwrap();
    warm(&c, &anyone, &lib.0, &lib.1);
    p.admin.ok(&p.dir, &["access", "src/", "devs"]);
    p.admin.commit_main(&p.dir, "src/ no longer public");
    p.admin.ok(&p.dir, &["push"]);
    took.push(refused_within_bound(&anyone, &lib.0, &lib.1, Instant::now(), "anyone on Earth after src/ stopped being public"));
    // A device an admin removed from the project.
    let sec = Reader::new(&server, &c.api, Some(&p.sec), &p.name);
    warm(&c, &sec, &[], &sec.root());
    p.admin.ok(&p.dir, &["identity", "remove", &p.sec.fingerprint()]);
    took.push(refused_within_bound(&sec, &[], &sec.root(), Instant::now(), "a device removed from the project"));
    eprintln!("cache: refusals after access changes: {took:?}");
}

/// Without the epoch feed the cache serves nothing from its store 5 s
/// after its last answer, public objects included, and only passes
/// requests on (here it cannot: 503). Back with the feed, it serves again.
#[test]
fn the_cache_fails_closed_without_the_feed() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let proxy = Proxy::start(hub.authority());
    let c = TestCache::start(&hub, &proxy.addr, 1 << 30);
    let fin = Reader::new(&server, &c.api, Some(&p.fin), &p.name);
    let anyone = Reader::new(&server, &c.api, None, &p.name);
    let (chain, id) = invoice(&fin).unwrap();
    warm(&c, &fin, &chain, &id);
    warm(&c, &anyone, &[], &anyone.root());
    proxy.set_cut(true);
    let cut = Instant::now();
    // Within the bound it may still serve from the store; past it, never.
    std::thread::sleep(cache::epochs::STALE + Duration::from_millis(300) - cut.elapsed());
    let local = c.stat("local");
    for _ in 0..10 {
        for (r, chain, id) in [(&fin, &chain[..], &id), (&anyone, &[][..], &anyone.root())] {
            let g = r.get(chain, id);
            assert_eq!((g.status, g.json()["code"].as_str()), (503, Some("unavailable")), "{}", String::from_utf8_lossy(&g.body));
            let b = r.batch_as(&r.grant, &[(chain.to_vec(), *id)], Vec::new());
            assert_eq!(b.status, 503);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(c.stat("local"), local, "nothing from the store without the feed");
    assert!(c.stat("poll_errors") > 0);
    proxy.set_cut(false);
    let back = until(Duration::from_secs(10), "served again with the feed back", || fin.get(&chain, &id).status == 200);
    warm(&c, &fin, &chain, &id);
    eprintln!("cache: fail-closed checked; serving again {back:?} after the feed returned");
}

/// A damaged object in the cache's store is never served: the cache asks
/// the server again (design §6 row 8).
#[test]
fn a_damaged_object_in_the_cache_is_never_served() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let admin = Reader::new(&server, &c.api, Some(&p.admin), &p.name);
    let good = admin.walk();
    warm(&c, &admin, &[], &admin.root());
    assert_eq!(items(&admin.walk()), items(&good));
    let mut flipped = 0;
    for (path, mut b) in c.files().into_iter().filter(|(path, _)| path.contains("/store/objects/")) {
        let i = b.len() / 2;
        b[i] ^= 0x20;
        std::fs::write(&path, b).unwrap();
        flipped += 1;
    }
    assert!(flipped >= good.len() - 1, "{flipped} objects in the store for {}", good.len());
    let forwarded = c.stat("forwarded");
    assert_eq!(items(&admin.walk()), items(&good), "the right bytes, from the server");
    for (chain, id, raw) in good.iter().take(10) {
        assert_eq!(&admin.get(chain, id).body, raw);
    }
    assert!(c.stat("forwarded") > forwarded);
    // The store is whole again.
    let forwarded = c.stat("forwarded");
    assert_eq!(items(&admin.walk()), items(&good));
    assert_eq!(c.stat("forwarded"), forwarded);
}

/// The store keeps to its size: reading more than it holds evicts, and
/// every answer is still whole and right.
#[test]
fn the_cache_store_keeps_to_its_size() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let files: Vec<(String, String)> = (0..200).map(|i| (format!("src/bulk/f{i:03}.txt"), format!("{i} {}", "y".repeat(4000)))).collect();
    write_files(&p.dir, &files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
    p.admin.commit_main(&p.dir, "bulk");
    p.admin.ok(&p.dir, &["push"]);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 64 << 10);
    let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
    let direct = Reader::new(&server, &server, Some(&p.dev), &p.name);
    let want = items(&direct.walk());
    for _ in 0..3 {
        assert_eq!(items(&dev.walk()), want);
        let stored: u64 = c.files().iter().filter(|(path, _)| path.contains("/store/objects/")).map(|(_, b)| b.len() as u64).sum();
        assert!(stored <= 64 << 10 && c.stat("stored_bytes") <= 64 << 10, "{stored} bytes stored");
    }
}

/// `POST /v1/cache/epochs` answers only the server's caches.
#[test]
fn the_epoch_feed_for_caches_needs_the_caches_token() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = std::fs::read_to_string(hub.ca.parent().unwrap().join("hub-cache-token")).unwrap();
    let dev = p.dev.identity().verifying_hex();
    let req = serde_json::json!({"projects": [p.name, unique("nothere")], "devices": [dev, hex::encode([7u8; 32])]});
    let body = serde_json::to_vec(&req).unwrap();
    let session = format!("Bearer {}", p.admin.token());
    for (what, h) in [
        ("no token", vec![]),
        ("a wrong token", vec![("veil-cache-token", "0".repeat(64))]),
        ("an admin's session", vec![("authorization", session.clone())]),
        ("a session as the token", vec![("veil-cache-token", p.admin.token())]),
    ] {
        let h: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = api.post_with("/v1/cache/epochs", &body, &h);
        assert_eq!(r.status, 401, "{what}");
        assert!(!String::from_utf8_lossy(&r.body).contains(&p.name), "{what}");
    }
    let r = api.post_with("/v1/cache/epochs", &body, &[("veil-cache-token", token.trim())]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let a = r.json();
    let g = Grant::read_unverified(api.tips(Some(&p.dev.token()), &p.name).unwrap().grants.get("main").unwrap()).unwrap();
    assert_eq!(a["grant_key"].as_str(), api.tips(None, &p.name).unwrap().grant_key.as_deref());
    assert_eq!(a["projects"].as_object().unwrap().len(), 1, "{a}: a project that does not exist is left out");
    assert_eq!(a["projects"][&p.name].as_i64(), Some(g.epoch));
    assert_eq!(a["devices"].as_object().unwrap().len(), 1, "{a}: an unknown device is left out");
    assert_eq!(a["devices"][&dev].as_i64(), Some(g.person_epoch));
    // A device its person removed is left out.
    hub.rt
        .block_on(sqlx::query("UPDATE devices SET removed_at = 1 WHERE signing_key = $1").bind(&dev).execute(&hub.hub().db))
        .unwrap();
    let a = api.post_with("/v1/cache/epochs", &body, &[("veil-cache-token", token.trim())]).json();
    assert!(a["devices"].as_object().unwrap().is_empty(), "{a}");
    // Hostile input.
    let many: Vec<String> = (0..=FEED_KEYS).map(|i| format!("p{i}")).collect();
    let big = serde_json::to_vec(&serde_json::json!({"projects": many})).unwrap();
    assert_eq!(api.post_with("/v1/cache/epochs", &big, &[("veil-cache-token", token.trim())]).status, 400);
    for junk in [&b"{not json"[..], br#"{"projects": [], "extra": 1}"#, br#"{"projects": 5}"#] {
        assert_eq!(api.post_with("/v1/cache/epochs", junk, &[("veil-cache-token", token.trim())]).status, 400);
    }
}

/// Many readers of a new object at once (every agent after a landing) cost
/// the server one request, not one each: later requests wait for the one
/// fetching it.
#[test]
fn concurrent_readers_of_a_new_object_cost_the_server_one_request() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let server = hub.api();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
    warm(&c, &dev, &[], &dev.root());
    // A landing: a new root the cache has never seen.
    write_files(&p.dir, &[("src/new-after-landing.txt", "new")]);
    p.admin.commit_main(&p.dir, "a landing");
    p.admin.ok(&p.dir, &["push"]);
    let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
    let root = dev.root();
    let want = server_bytes(&server, &dev, root);
    let forwarded = c.stat("forwarded");
    let n = 24;
    let barrier = std::sync::Barrier::new(n);
    std::thread::scope(|s| {
        for i in 0..n {
            let (dev, barrier, want) = (&dev, &barrier, &want);
            s.spawn(move || {
                barrier.wait();
                if i % 2 == 0 {
                    assert_eq!(&dev.batch(&[(Vec::new(), root)])[0].1, want);
                } else {
                    let g = dev.get(&[], &root);
                    assert_eq!((g.status, &g.body), (200, want));
                }
            });
        }
    });
    let asked = c.stat("forwarded") - forwarded;
    eprintln!("cache: {n} concurrent readers of a new root: {asked} requests to the server, {} waited", c.stat("joined"));
    assert!(asked <= 3, "{asked} requests to the server for {n} readers of one object");
}

/// The bytes of `id` (met at the root) as the server itself serves it to `r`.
fn server_bytes(server: &Api, r: &Reader, id: ObjectId) -> Vec<u8> {
    let direct = Reader { via: server, project: r.project.clone(), id: r.id.clone(), grant: r.grant.clone(), key: r.key.clone() };
    let g = direct.get(&[], &id);
    assert_eq!(g.status, 200);
    g.body
}

/// The security review of S9, cycle 1 (`docs/BUGS.md`, "S9 cycle 1").
mod s9_adversarial {
    use super::*;
    use veil_core::object::Tree;

    const MIB: usize = 1 << 20;

    fn rss() -> usize {
        let s = std::fs::read_to_string("/proc/self/status").unwrap();
        let kib: usize = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
        kib << 10
    }

    /// Tree `id` met at `chain`, as `r` reads it.
    fn tree(r: &Reader, chain: &[ObjectId], id: &ObjectId) -> Tree {
        let g = r.get(chain, id);
        assert_eq!(g.status, 200, "{}", String::from_utf8_lossy(&g.body));
        match Object::decode(&g.body) {
            Ok(Object::Tree(t)) => t,
            _ => panic!("not a tree"),
        }
    }

    /// A batch of `wants` under anyone on Earth's grant `r` (no signature),
    /// its answer left unread: a client that stalls.
    fn stall(c: &TestCache, r: &Reader, wants: &[(Vec<ObjectId>, ObjectId)]) -> ureq::http::Response<ureq::Body> {
        let req = BatchRequest {
            grant: r.grant.clone(),
            ts: veil_core::now_millis(),
            signature: None,
            wants: wants.iter().map(|(chain, id)| ChainWant { chain: chain.clone(), id: *id }).collect(),
            skip: Vec::new(),
        };
        let resp = c.api.post_unread(&format!("/v1/objects/{}:batch", r.project), &serde_json::to_vec(&req).unwrap());
        assert_eq!(resp.status().as_u16(), 200);
        resp
    }

    /// Add `files` (public: under `src/`) to `main` and push.
    fn land(p: &Project, files: &[(&str, &str)], msg: &str) {
        write_files(&p.dir, files);
        p.admin.commit_main(&p.dir, msg);
        p.admin.ok(&p.dir, &["push"]);
    }

    /// BUG-1180 (a): a request fetching an object the store will never keep
    /// (larger than its largest object) still marks it in flight, until its
    /// client has read the whole answer; every other reader of it waits
    /// for that fetch (up to 2 s), gains nothing, and asks the server anyway.
    #[test]
    fn bug_1180_readers_wait_on_a_fetch_of_an_object_never_kept() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let huge = "h".repeat(17 * MIB);
        land(&p, &[("src/huge.bin", &huge)], "a file larger than a cache keeps");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let huge_id = tree(&r, &[root], &src).get("huge.bin").unwrap().id;
        // A reader whose client is slow (here: stalled) fetches it.
        let slow = stall(&c, &r, &[(vec![root, src], huge_id)]);
        let joined = c.stat("joined");
        let t = Instant::now();
        let g = r.get(&[root, src], &huge_id);
        let took = t.elapsed();
        assert_eq!(g.status, 200);
        assert!(g.body.len() > huge.len());
        eprintln!("cache: a reader of a 17 MiB object while another's client stalls: {took:?}, joined {}", c.stat("joined") - joined);
        assert_eq!(c.stat("joined"), joined, "a reader waited {took:?} for a fetch whose object the store never keeps");
        drop(slow);
    }

    /// BUG-1180 (b): one batch of anyone on Earth's (100,000 wants are
    /// allowed; 65,536 objects may be in flight) marks every want after a
    /// miss in flight, ids nobody has included, and holds them while its
    /// client does not read: coalescing stops for every project, and every
    /// reader of a new object asks the server itself.
    #[test]
    fn bug_1180_one_stalled_request_fills_the_in_flight_map() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let huge = "h".repeat(17 * MIB);
        land(&p, &[("src/huge.bin", &huge), ("src/sub/x.txt", "never read through the cache")], "files");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let anyone = Reader::new(&server, &c.api, None, &p.name);
        let root = anyone.root();
        warm(&c, &anyone, &[], &root);
        let src_id = tree(&anyone, &[], &root).get("src").unwrap().id;
        let src = tree(&anyone, &[root], &src_id);
        let (sub, huge_id) = (src.get("sub").unwrap().id, src.get("huge.bin").unwrap().id);
        let x = {
            let direct = Reader { via: &server, project: anyone.project.clone(), id: None, grant: anyone.grant.clone(), key: anyone.key.clone() };
            tree(&direct, &[root, src_id], &sub).get("x.txt").unwrap().id
        };
        // A tree the store does not hold (so nothing after it is final),
        // an answer too large to buffer, then 70,000 ids nobody has.
        let mut wants = vec![(vec![root, src_id, sub], x), (vec![root, src_id], huge_id)];
        wants.extend((0..70_000).map(|_| (vec![root, random_id()], random_id())));
        let stalled = stall(&c, &anyone, &wants);
        // A landing, and every agent reads the new root at once.
        land(&p, &[("src/new-after-landing.txt", "new")], "a landing");
        let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
        warm(&c, &dev, &[], &dev.root());
        land(&p, &[("src/second-landing.txt", "newer")], "another landing");
        let dev = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
        let new_root = dev.root();
        let want = server_bytes(&server, &dev, new_root);
        let forwarded = c.stat("forwarded");
        let n = 24;
        let barrier = std::sync::Barrier::new(n);
        std::thread::scope(|s| {
            for i in 0..n {
                let (dev, barrier, want) = (&dev, &barrier, &want);
                s.spawn(move || {
                    barrier.wait();
                    if i % 2 == 0 {
                        assert_eq!(&dev.batch(&[(Vec::new(), new_root)])[0].1, want);
                    } else {
                        let g = dev.get(&[], &new_root);
                        assert_eq!((g.status, &g.body), (200, want));
                    }
                });
            }
        });
        let asked = c.stat("forwarded") - forwarded;
        eprintln!("cache: {n} readers of a new root while one request stalls with 70,000 wants: {asked} requests to the server");
        assert!(asked <= 3, "{asked} requests to the server for {n} readers of one object: coalescing is off");
        drop(stalled);
    }

    /// BUG-1181: `--memory` does not bound the cache's memory. An answer
    /// takes its share of the budget only while it reads an object from the
    /// store, and gives it back before the bytes are sent, so a client that
    /// does not read keeps up to 16 MiB per request (an object served by
    /// `GET`, a batch's frames) outside the budget; anyone on Earth opens
    /// as many as they like. (The same for what a forwarded answer keeps:
    /// `forward_get`'s whole object, a relay's frame, never budgeted.)
    #[test]
    fn bug_1181_stalled_clients_hold_memory_outside_the_budget() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let big = "b".repeat(15 * MIB);
        land(&p, &[("src/big.bin", &big)], "a 15 MiB public file");
        let server = hub.api();
        // `--memory 64M`: 32 MiB for objects being read, so two of these
        // at a time.
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let big_id = tree(&r, &[root], &src).get("big.bin").unwrap().id;
        warm(&c, &r, &[root, src], &big_id);
        let mut stalled = Vec::new();
        let (local, before) = (c.stat("local"), rss());
        for _ in 0..8 {
            stalled.push(stall(&c, &r, &[(vec![root, src], big_id)]));
        }
        let chain = format!("{},{}", root.hex(), src.hex());
        let path = format!("/v1/objects/{}/{}", p.name, big_id.hex());
        for _ in 0..8 {
            stalled.push(c.api.get_unread(&path, &[("veil-grant", &r.grant), ("veil-chain", &chain)]));
        }
        std::thread::sleep(Duration::from_secs(2));
        let (served, grew) = (c.stat("local") - local, rss().saturating_sub(before) / MIB);
        eprintln!("cache: 16 stalled answers of a 15 MiB object at --memory 64M: {served} read from the store, RSS +{grew} MiB");
        assert!(served <= 3, "{served} answers of 15 MiB hold their bytes at once, within a 32 MiB budget (RSS +{grew} MiB)");
        // Since BUG-1186's fix a stalled answer of a large object holds a
        // slice or two and counts as served only once whole, so this count
        // no longer measures what is held: `s9_cycle2::bug_1186_…` checks
        // that the budget stays free beside slow readers, and the
        // `cache_process` tests measure the cache's own memory (this
        // process's RSS includes the tests running beside it).
        drop(stalled);
    }

    /// BUG-1182: a batch that names one object twice, first through a tree
    /// the cache does not hold and then through trees it holds, gets the
    /// object at its second place; the server sends it at its first (the
    /// first want its root reaches). The cache plans the id twice (once
    /// for the server, once from its store) and tells the server to skip it.
    #[test]
    fn bug_1182_a_repeated_id_keeps_the_servers_order() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        land(&p, &[("src/a/same.txt", "the same file twice"), ("src/b/same.txt", "the same file twice"), ("src/b/other.txt", "so b is another tree")], "a copy");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src_id = tree(&r, &[], &root).get("src").unwrap().id;
        let src = tree(&r, &[root], &src_id);
        let (a, b, lib) = (src.get("a").unwrap().id, src.get("b").unwrap().id, src.get("lib.rs").unwrap().id);
        assert_ne!(a, b);
        let same = tree(&r, &[root, src_id], &a).get("same.txt").unwrap().id;
        warm(&c, &r, &[root, src_id], &lib);
        warm(&c, &r, &[root, src_id, a], &same);
        // `b`'s tree was never read through the cache.
        let wants = vec![(vec![root, src_id, b], same), (vec![root, src_id], lib), (vec![root, src_id, a], same)];
        let direct = Reader { via: &server, project: r.project.clone(), id: None, grant: r.grant.clone(), key: r.key.clone() };
        let order = |rd: &Reader| rd.batch(&wants).into_iter().map(|f| f.0).collect::<Vec<_>>();
        let want = order(&direct);
        assert_eq!(want, vec![same, lib], "the server: each id at the first want its root reaches");
        assert_eq!(order(&r), want, "the cache's order");
    }

    /// BUG-1182's class, as a property: for random batches (real wants,
    /// real ids under other trees, hidden ids, random ids, repeats under
    /// other chains) over caches holding random parts of the project, the
    /// cache's answer is the server's, byte for byte: status, body, order;
    /// and so is each `GET`. A fixed seed, so a failure repeats.
    #[test]
    fn the_caches_answers_are_the_servers_byte_for_byte() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        land(
            &p,
            &[("src/a/same.txt", "the same bytes"), ("src/b/same.txt", "the same bytes"), ("src/b/o.txt", "o"), ("src/c/d/same.txt", "the same bytes"), ("src/c/d/e.txt", "e")],
            "copies in several folders",
        );
        let server = hub.api();
        let hidden: Vec<ObjectId> = {
            let dev = Reader::new(&server, &server, Some(&p.dev), &p.name);
            let reached: HashSet<ObjectId> = dev.walk().iter().map(|w| w.1).collect();
            real_chains(&p.dir).into_iter().map(|r| r.2).filter(|id| !reached.contains(id)).collect()
        };
        assert!(!hidden.is_empty());
        let mut seed = 0x5eed_1182_u64;
        let mut rnd = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let (mut batches, mut gets) = (0, 0);
        for case in 0..16 {
            let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
            let r = Reader::new(&server, &c.api, Some(&p.dev), &p.name);
            let direct = Reader { via: &server, project: r.project.clone(), id: r.id.clone(), grant: r.grant.clone(), key: r.key.clone() };
            let walked = direct.walk();
            let trees: Vec<Vec<ObjectId>> = walked
                .iter()
                .filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_))))
                .map(|(chain, id, _)| [chain.clone(), vec![*id]].concat())
                .collect();
            warm(&c, &r, &[], &r.root());
            // The cache holds a random part of the project.
            for (chain, id, _) in &walked {
                if rnd(2) == 0 {
                    assert_eq!(r.get(chain, id).status, 200);
                }
            }
            for _ in 0..12 {
                let mut wants: Vec<(Vec<ObjectId>, ObjectId)> = Vec::new();
                for _ in 0..1 + rnd(10) {
                    let real = &walked[rnd(walked.len())];
                    let other = trees[rnd(trees.len())].clone();
                    wants.push(match rnd(10) {
                        0..=4 => (real.0.clone(), real.1),
                        5 => (other, real.1),
                        6 => (other, hidden[rnd(hidden.len())]),
                        7 => (other, random_id()),
                        // An id wanted before, under another chain.
                        _ => match wants.get(rnd(wants.len().max(1))) {
                            Some(w) => (if rnd(2) == 0 { other } else { real.0.clone() }, w.1),
                            None => (real.0.clone(), real.1),
                        },
                    });
                }
                let (a, b) = (r.batch_as(&r.grant, &wants, Vec::new()), direct.batch_as(&direct.grant, &wants, Vec::new()));
                assert_eq!((a.status, &a.body), (b.status, &b.body), "case {case}: the batch {wants:?}");
                batches += 1;
                for (chain, id) in wants.iter().take(2) {
                    let (a, b) = (r.get(chain, id), direct.get(chain, id));
                    assert_eq!((a.status, &a.body), (b.status, &b.body), "case {case}: GET {chain:?} {id:?}");
                    gets += 1;
                }
            }
        }
        eprintln!("cache: {batches} random batches and {gets} GETs answered as the server answers them");
    }

    /// The rest of BUG-1181: what each connection's HTTP layer buffers is
    /// outside `--memory`, so connections are capped: past
    /// `--max-connections`, the next one waits until one closes.
    #[test]
    fn connections_past_the_cap_wait_for_one_to_close() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let server = hub.api();
        let c = TestCache::start_with(&hub, &hub.authority(), 1 << 30, 2);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        // Two clients hold both connections (they never even say hello).
        let held: Vec<std::net::TcpStream> = (0..2).map(|_| std::net::TcpStream::connect(c.running.addr).unwrap()).collect();
        std::thread::sleep(Duration::from_millis(300));
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (done, api) = (done.clone(), Api::at(&c.running.addr.to_string(), &c.running.cert_pem));
            let (grant, project) = (r.grant.clone(), p.name.clone());
            std::thread::spawn(move || {
                let g = api.get_with(&format!("/v1/objects/{project}/{}", root.hex()), &[("veil-grant", &grant)]);
                done.store(true, SeqCst);
                g.status
            })
        };
        std::thread::sleep(Duration::from_secs(2));
        assert!(!done.load(SeqCst), "a third connection was served while two held the cap");
        drop(held);
        let waited = until(Duration::from_secs(10), "served once a connection closed", || done.load(SeqCst));
        assert_eq!(reader.join().unwrap(), 200);
        eprintln!("cache: a connection past the cap of 2 was served {waited:?} after one closed");
    }
}

/// The security review of S9, cycle 2 (`docs/BUGS.md`, "S9 cycle 2"): the
/// cycle-1 fixes' guarantees (same answers, bounded memory, bounded
/// connection slots, no circular waits, cut-off bodies are errors).
mod s9_cycle2 {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use veil_core::object::Tree;

    const MIB: usize = 1 << 20;
    /// What one connection may hold outside `--memory` (`docs/HUB.md` §13.18).
    const PER_CONNECTION_KIB: usize = 352;

    fn tree(r: &Reader, chain: &[ObjectId], id: &ObjectId) -> Tree {
        let g = r.get(chain, id);
        assert_eq!(g.status, 200, "{}", String::from_utf8_lossy(&g.body));
        match Object::decode(&g.body) {
            Ok(Object::Tree(t)) => t,
            _ => panic!("not a tree"),
        }
    }

    fn land(p: &Project, files: &[(&str, &str)], msg: &str) {
        write_files(&p.dir, files);
        p.admin.commit_main(&p.dir, msg);
        p.admin.ok(&p.dir, &["push"]);
    }

    /// A request body of `len` bytes of JSON whitespace, then nothing until
    /// `gate`'s sender is dropped: a client that sends slowly, or stops.
    /// `sent` counts the bytes handed over.
    struct Stops {
        left: usize,
        gate: std::sync::mpsc::Receiver<()>,
        sent: Arc<AtomicUsize>,
    }

    impl std::io::Read for Stops {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                let _ = self.gate.recv();
                return Err(std::io::Error::other("the client went away"));
            }
            let n = buf.len().min(self.left).min(64 << 10);
            buf[..n].fill(b' ');
            self.left -= n;
            self.sent.fetch_add(n, Relaxed);
            Ok(n)
        }
    }

    /// Start a `POST …:batch` to the cache whose body stops after `len`
    /// bytes; dropping the returned sender ends it.
    fn stopping_post(c: &TestCache, project: &str, len: usize, sent: &Arc<AtomicUsize>) -> std::sync::mpsc::Sender<()> {
        stopping_post_at(Api::at(&c.running.addr.to_string(), &c.running.cert_pem), project, len, sent)
    }

    fn stopping_post_at(api: Api, project: &str, len: usize, sent: &Arc<AtomicUsize>) -> std::sync::mpsc::Sender<()> {
        let (tx, gate) = std::sync::mpsc::channel();
        let (path, sent) = (format!("/v1/objects/{project}:batch"), sent.clone());
        std::thread::spawn(move || drop(api.post_reader(&path, Stops { left: len, gate, sent })));
        tx
    }

    /// Guarantee 4: every connection slot is released in bounded time. A
    /// request whose head arrived but whose body never does holds its slot
    /// for as long as the client likes: `header_read_timeout` (20 s) covers
    /// only the head, the write deadline (30 s) only writes, and nothing
    /// bounds reading the body. 1,024 such connections (anyone on Earth,
    /// no grant needed) close the cache to everyone. Fixed: a body is due at
    /// 16 KiB/s after a 20 s grace, so both are answered `408` and let go.
    #[test]
    fn bug_1183_a_body_that_never_arrives_holds_its_connection_slot() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let server = hub.api();
        let c = TestCache::start_with(&hub, &hub.authority(), 1 << 30, 2);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        let sent = Arc::new(AtomicUsize::new(0));
        // Two clients send a request's head and a few bytes of its body, then stop.
        let gates: Vec<_> = (0..2).map(|_| stopping_post(&c, &p.name, 10, &sent)).collect();
        until(Duration::from_secs(10), "both heads sent", || sent.load(Relaxed) >= 20);
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let (done, api) = (done.clone(), Api::at(&c.running.addr.to_string(), &c.running.cert_pem));
            let (grant, project) = (r.grant.clone(), p.name.clone());
            std::thread::spawn(move || {
                let g = api.get_with(&format!("/v1/objects/{project}/{}", root.hex()), &[("veil-grant", &grant)]);
                done.store(true, SeqCst);
                g.status
            })
        };
        // Past the head's 20 s and the write deadline's 30 s, with margin.
        let t = Instant::now();
        while !done.load(SeqCst) && t.elapsed() < Duration::from_secs(50) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let served = done.load(SeqCst);
        eprintln!("cache: a third client while two bodies stall (cap 2): served {served} after {:?}", t.elapsed());
        drop(gates);
        assert!(served, "two requests whose bodies never arrive held the cache's 2 connections for {:?}", t.elapsed());
        assert_eq!(reader.join().unwrap(), 200);
    }

    /// Guarantee 3: the cache's memory stays within `--memory` plus its
    /// connections' buffers. A batch's body was read whole into memory
    /// before anything else (axum's `Bytes`, up to the 64 MiB body limit),
    /// outside the budget: 8 clients that each sent 56 MiB of a body and
    /// stopped held about 450 MiB at `--memory 64M`. Fixed: a body is held
    /// only under a share of the requests' pool, and one larger than the
    /// cache decides itself goes to the server as it arrives. Measured on
    /// the cache's own process: the server, in this one, holds the bodies
    /// the cache passes on (its own limit, 64 MiB a request).
    #[test]
    fn bug_1184_request_bodies_are_held_outside_the_memory_bound() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let dir = tempfile::Builder::new().prefix("veil-cache-proc").tempdir().unwrap();
        let (mut child, addr, pem) = cache_process(&hub, dir.path());
        std::thread::sleep(Duration::from_secs(1));
        let (n, len) = (8, 56 * MIB);
        let sent = Arc::new(AtomicUsize::new(0));
        let before = rss_of(child.id());
        let gates: Vec<_> = (0..n).map(|_| stopping_post_at(Api::at(&addr, &pem), &p.name, len, &sent)).collect();
        until(Duration::from_secs(60), "the bodies sent", || sent.load(Relaxed) >= n * len);
        std::thread::sleep(Duration::from_secs(1));
        let grew = rss_of(child.id()).saturating_sub(before) / MIB;
        let _ = child.kill();
        let _ = child.wait();
        drop(gates);
        // --memory 64M, plus the connections' buffers, plus slack for the test.
        let bound = 64 + n * PER_CONNECTION_KIB / 1024 + 32;
        eprintln!("cache process: {n} bodies of {} MiB, stopped before their end, at --memory 64M: RSS +{grew} MiB (bound about {bound} MiB)", len / MIB);
        assert!(grew <= bound, "{n} unfinished request bodies grew the cache by {grew} MiB, past --memory 64M and its connections' buffers");
    }

    /// Guarantee 5: no circular waits. An answer relaying a frame it keeps
    /// takes that frame's whole share of the budget at once (up to 16 MiB)
    /// and holds it while it waits in `Out::reserve` for the share of the
    /// next chunk; `forward_get`'s `whole` does the same. Two such answers
    /// whose kept frames take nearly all the budget wait for each other
    /// forever, though their clients read everything: the semaphore hands
    /// every share given back to the first waiter, whose chunk is larger
    /// than what is left. Then every answer of the cache that needs the
    /// budget waits too. Anyone on Earth: four cold public files. Fixed: an
    /// answer gives up keeping before it waits for the budget.
    #[test]
    fn bug_1185_kept_frames_hold_the_budget_while_their_answers_wait_for_it() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        // --memory 64M: a budget of 20,480 KiB (32,768 when found, with
        // objects of 16,234 KiB); each object 10,090 KiB, so two kept frames
        // leave 300 KiB, less than a chunk can be.
        let size = 10_090 * 1024 - 64;
        let files: Vec<(String, String)> = (0..4).map(|i| (format!("src/big{i}.bin"), format!("{i}{}", "k".repeat(size - 1)))).collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        land(&p, &refs, "four large public files");
        let server = hub.api();
        // It hangs in about half the rounds: stop at the first.
        let mut hung = 0;
        for round in 0..8 {
            if hung > 0 {
                break;
            }
            let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
            let r = Reader::new(&server, &c.api, None, &p.name);
            let root = r.root();
            warm(&c, &r, &[], &root);
            let src = tree(&r, &[], &root).get("src").unwrap().id;
            let st = tree(&r, &[root], &src);
            let ids: Vec<ObjectId> = (0..4).map(|i| st.get(&format!("big{i}.bin")).unwrap().id).collect();
            let (tx, rx) = std::sync::mpsc::channel();
            let barrier = Arc::new(std::sync::Barrier::new(ids.len()));
            for id in ids.clone() {
                let (tx, barrier) = (tx.clone(), barrier.clone());
                let api = Api::at(&c.running.addr.to_string(), &c.running.cert_pem);
                let (grant, project) = (r.grant.clone(), p.name.clone());
                std::thread::spawn(move || {
                    let req = BatchRequest {
                        grant,
                        ts: veil_core::now_millis(),
                        signature: None,
                        wants: vec![ChainWant { chain: vec![root, src], id }],
                        skip: Vec::new(),
                    };
                    barrier.wait();
                    let got = api.post(None, &format!("/v1/objects/{project}:batch"), &serde_json::to_vec(&req).unwrap(), true);
                    let _ = tx.send(got.status == 200 && got.frames().len() == 1);
                });
            }
            drop(tx);
            let t = Instant::now();
            let mut done = 0;
            while done < ids.len() {
                match rx.recv_timeout(Duration::from_secs(60).saturating_sub(t.elapsed())) {
                    Ok(ok) => {
                        assert!(ok, "an answer failed");
                        done += 1;
                    }
                    Err(_) => break,
                }
            }
            eprintln!("cache: round {round}: {done} of {} answers of 10 MiB cold objects within {:?}", ids.len(), t.elapsed());
            if done < ids.len() {
                hung += 1;
                // A later small answer waits too: the whole cache is stuck.
                let t = Instant::now();
                let (tx, rx) = std::sync::mpsc::channel();
                let api = Api::at(&c.running.addr.to_string(), &c.running.cert_pem);
                let (grant, project) = (r.grant.clone(), p.name.clone());
                std::thread::spawn(move || {
                    let _ = tx.send(api.get_with(&format!("/v1/objects/{project}/{}", root.hex()), &[("veil-grant", &grant)]).status);
                });
                let small = rx.recv_timeout(Duration::from_secs(10));
                eprintln!("cache: round {round}: a GET of the root afterwards: {small:?} after {:?}", t.elapsed());
                // The server itself answers the same batch at once: the cache is what waits.
                let direct = Reader { via: &server, project: r.project.clone(), id: None, grant: r.grant.clone(), key: r.key.clone() };
                let t = Instant::now();
                assert_eq!(direct.batch(&[(vec![root, src], ids[0])]).len(), 1);
                eprintln!("cache: round {round}: the server answers the same batch directly in {:?}", t.elapsed());
                std::mem::forget(c);
            }
        }
        assert_eq!(hung, 0, "four readers of cold 10 MiB objects never got their answers (clients reading)");
    }

    /// BUG-1185's class: no answer waits for the budget while holding any
    /// of it. Many large cold reads at once (`GET`s and batches of one and
    /// two objects, 16 clients reading promptly, 40 MiB of objects through
    /// a 20 MiB budget) all complete, each object whole, and a small `GET`
    /// from the store is fast afterwards, in every round.
    #[test]
    fn many_large_cold_reads_at_once_all_complete() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let size = 10 * MIB;
        let files: Vec<(String, String)> = (0..4).map(|i| (format!("src/cold{i}.bin"), format!("{i}{}", "c".repeat(size - 1)))).collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        land(&p, &refs, "four large public files");
        let server = hub.api();
        for round in 0..3 {
            let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
            let r = Reader::new(&server, &c.api, None, &p.name);
            let root = r.root();
            warm(&c, &r, &[], &root);
            let src = tree(&r, &[], &root).get("src").unwrap().id;
            let st = tree(&r, &[root], &src);
            let ids: Vec<ObjectId> = (0..4).map(|i| st.get(&format!("cold{i}.bin")).unwrap().id).collect();
            let chain = format!("{},{}", root.hex(), src.hex());
            let n = 16;
            let barrier = Arc::new(std::sync::Barrier::new(n));
            let (tx, rx) = std::sync::mpsc::channel();
            for i in 0..n {
                let (tx, barrier, chain) = (tx.clone(), barrier.clone(), chain.clone());
                let api = Api::at(&c.running.addr.to_string(), &c.running.cert_pem);
                let (grant, project) = (r.grant.clone(), p.name.clone());
                let wanted: Vec<ObjectId> = match i % 3 {
                    0 | 1 => vec![ids[i % 4]],
                    _ => vec![ids[i % 4], ids[(i + 1) % 4]],
                };
                std::thread::spawn(move || {
                    barrier.wait();
                    let got: Vec<(ObjectId, Vec<u8>)> = if i % 3 == 0 {
                        let g = api.get_with(&format!("/v1/objects/{project}/{}", wanted[0].hex()), &[("veil-grant", &grant), ("veil-chain", &chain)]);
                        if g.status == 200 { vec![(wanted[0], g.body)] } else { Vec::new() }
                    } else {
                        let req = BatchRequest {
                            grant,
                            ts: veil_core::now_millis(),
                            signature: None,
                            wants: wanted.iter().map(|id| ChainWant { chain: vec![root, src], id: *id }).collect(),
                            skip: Vec::new(),
                        };
                        let got = api.post(None, &format!("/v1/objects/{project}:batch"), &serde_json::to_vec(&req).unwrap(), true);
                        if got.status == 200 { got.frames() } else { Vec::new() }
                    };
                    let whole = got.len() == wanted.len() && got.iter().zip(&wanted).all(|((id, raw), w)| id == w && ObjectId::hash(raw) == *w);
                    let _ = tx.send(whole);
                });
            }
            drop(tx);
            let t = Instant::now();
            let mut done = 0;
            while done < n {
                match rx.recv_timeout(Duration::from_secs(90).saturating_sub(t.elapsed())) {
                    Ok(whole) => {
                        assert!(whole, "round {round}: an answer was not the objects asked for");
                        done += 1;
                    }
                    Err(_) => break,
                }
            }
            eprintln!("cache: round {round}: {done} of {n} large cold reads within {:?}", t.elapsed());
            assert_eq!(done, n, "round {round}: large cold reads at once never got their answers");
            let t = Instant::now();
            let g = c.api.get_with(&format!("/v1/objects/{}/{}", p.name, root.hex()), &[("veil-grant", &r.grant)]);
            assert_eq!(g.status, 200);
            eprintln!("cache: round {round}: a GET of the root afterwards in {:?}", t.elapsed());
            assert!(t.elapsed() < Duration::from_secs(2), "round {round}: a small GET waited {:?} after the large reads", t.elapsed());
        }
    }

    /// The budget is shared fairly in time: an answer that holds a large
    /// share gives it back in bounded time even to clients that read at the
    /// minimum rate. A `GET` from the store takes its whole object's share
    /// (up to 16 MiB) and holds it until its last byte is written, so two
    /// clients reading a 15 MiB public object at 32 KiB/s (twice the
    /// minimum: never cut off) hold the 20 MiB budget of `--memory 64M` for
    /// minutes, and every other answer waits; at the default `--memory`, three
    /// such clients (96 KiB/s from anyone on Earth) hold it all.
    /// Fixed: an object larger than a slice is read and sent a slice at a
    /// time, each under its own share, so a slow client holds a slice or two.
    #[test]
    fn bug_1186_slow_readers_of_a_large_object_hold_the_budget() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let big = "s".repeat(15 * MIB);
        land(&p, &[("src/slow.bin", &big)], "a large public file");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let big_id = tree(&r, &[root], &src).get("slow.bin").unwrap().id;
        warm(&c, &r, &[root, src], &big_id);
        let chain = format!("{},{}", root.hex(), src.hex());
        let path = format!("/v1/objects/{}/{}", p.name, big_id.hex());
        let stop = Arc::new(AtomicBool::new(false));
        let slow: Vec<_> = (0..2)
            .map(|_| {
                let resp = c.api.get_unread(&path, &[("veil-grant", &r.grant), ("veil-chain", &chain)]);
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut body = resp.into_body();
                    let mut reader = body.as_reader();
                    let mut buf = vec![0u8; 32 << 10];
                    while !stop.load(SeqCst) {
                        if std::io::Read::read_exact(&mut reader, &mut buf).is_err() {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_secs(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let api = Api::at(&c.running.addr.to_string(), &c.running.cert_pem);
        let (grant, project) = (r.grant.clone(), p.name.clone());
        let t = Instant::now();
        std::thread::spawn(move || {
            let _ = tx.send(api.get_with(&format!("/v1/objects/{project}/{}", root.hex()), &[("veil-grant", &grant)]).status);
        });
        let small = rx.recv_timeout(Duration::from_secs(20));
        eprintln!("cache: a GET of the root while two clients read a 15 MiB object at 32 KiB/s: {small:?} after {:?}", t.elapsed());
        stop.store(true, SeqCst);
        drop(slow);
        assert_eq!(small, Ok(200), "two clients reading at twice the minimum rate held the budget for {:?}", t.elapsed());
    }

    /// BUG-1186's fix reads large objects in slices, checking their hash as
    /// they go: a large object damaged in the store (a flipped byte near its
    /// end, a truncated file) ends its answer unfinished (`GET`, a range of
    /// it, a batch), never whole with wrong bytes; it is removed, and the
    /// next read gets the right bytes from the server.
    #[test]
    fn a_large_damaged_object_ends_its_answer_unfinished() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let big = "d".repeat(3 * MIB);
        land(&p, &[("src/damaged.bin", &big)], "a large public file");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let id = tree(&r, &[root], &src).get("damaged.bin").unwrap().id;
        let good = server_bytes_at(&server, &r, &[root, src], id);
        let chain = format!("{},{}", root.hex(), src.hex());
        let path = format!("/v1/objects/{}/{}", p.name, id.hex());
        for (case, how) in ["get", "range", "batch"].iter().enumerate() {
            for damage in 0..2 {
                warm(&c, &r, &[root, src], &id);
                let file: Vec<String> = c.files().into_iter().filter(|(_, b)| *b == good).map(|(f, _)| f).collect();
                assert_eq!(file.len(), 1, "{how}: the object's file in the store");
                let mut b = good.clone();
                match damage {
                    0 => b[good.len() - 10] ^= 1,
                    _ => b.truncate(good.len() - 1000),
                }
                std::fs::write(&file[0], &b).unwrap();
                let read = match *how {
                    "batch" => {
                        let req = BatchRequest {
                            grant: r.grant.clone(),
                            ts: veil_core::now_millis(),
                            signature: None,
                            wants: vec![ChainWant { chain: vec![root, src], id }],
                            skip: Vec::new(),
                        };
                        let body = std::io::Cursor::new(serde_json::to_vec(&req).unwrap());
                        c.api.post_reader(&format!("/v1/objects/{}:batch", p.name), body).map_err(|e| e.to_string()).and_then(|resp| resp.into_body().read_to_vec().map_err(|e| e.to_string()))
                    }
                    _ => {
                        let mut h = vec![("veil-grant", r.grant.as_str()), ("veil-chain", chain.as_str())];
                        if *how == "range" {
                            h.push(("range", "bytes=100-200"));
                        }
                        c.api.get_unread(&path, &h).into_body().read_to_vec().map_err(|e| e.to_string())
                    }
                };
                eprintln!("cache: case {case} ({how}), damage {damage}: {:?}", read.as_ref().map(|b| b.len()));
                assert!(read.is_err(), "{how}, damage {damage}: a damaged object's answer read as whole ({:?} bytes)", read.map(|b| b.len()));
                assert!(c.files().iter().all(|(_, f)| *f != b), "{how}, damage {damage}: the damaged file is removed");
                assert_eq!(r.get(&[root, src], &id).body, good, "{how}, damage {damage}: then the right bytes, from the server");
            }
        }
    }

    /// Guarantee 6: a cut-off body is an error, never a short object. A
    /// `GET` from the store sends its head at once when the budget is
    /// taken, and its bytes once its share is free; if the object left the
    /// store meanwhile, the answer ends unfinished, and the client's read
    /// fails (a chunked body without its last chunk), never a short `200`.
    #[test]
    fn a_get_cut_off_after_its_head_is_an_error_for_the_client() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let big = "b".repeat(15 * MIB);
        land(&p, &[("src/big.bin", &big), ("src/small.txt", "a small file that leaves the store")], "files");
        let server = hub.api();
        let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
        let r = Reader::new(&server, &c.api, None, &p.name);
        let root = r.root();
        warm(&c, &r, &[], &root);
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let st = tree(&r, &[root], &src);
        let (big_id, small_id) = (st.get("big.bin").unwrap().id, st.get("small.txt").unwrap().id);
        warm(&c, &r, &[root, src], &big_id);
        warm(&c, &r, &[root, src], &small_id);
        let small_raw = server_bytes_at(&server, &r, &[root, src], small_id);
        // Three stalled answers of 15 MiB take the 32 MiB budget (the third
        // waits holding what was left).
        let chain = format!("{},{}", root.hex(), src.hex());
        let big_path = format!("/v1/objects/{}/{}", p.name, big_id.hex());
        let stalled: Vec<_> = (0..3).map(|_| c.api.get_unread(&big_path, &[("veil-grant", &r.grant), ("veil-chain", &chain)])).collect();
        std::thread::sleep(Duration::from_millis(500));
        let small_path = format!("/v1/objects/{}/{}", p.name, small_id.hex());
        let resp = c.api.get_unread(&small_path, &[("veil-grant", &r.grant), ("veil-chain", &chain)]);
        assert_eq!(resp.status().as_u16(), 200);
        // The object leaves the store after its check, before its bytes.
        let gone: Vec<String> = c.files().into_iter().filter(|(_, b)| *b == small_raw).map(|(f, _)| f).collect();
        assert_eq!(gone.len(), 1, "the small object's file in the store");
        std::fs::remove_file(&gone[0]).unwrap();
        drop(stalled);
        let read = resp.into_body().read_to_vec();
        eprintln!("cache: a GET whose object left the store after its head: {:?}", read.as_ref().map(|b| b.len()).map_err(|e| e.to_string()));
        match read {
            Err(_) => {}
            Ok(b) => assert_eq!(b, small_raw, "a cut-off answer read as a whole one ({} bytes)", b.len()),
        }
    }

    /// The bytes of `id` at `chain` as the server serves it to `r`.
    fn server_bytes_at(server: &Api, r: &Reader, chain: &[ObjectId], id: ObjectId) -> Vec<u8> {
        let direct = Reader { via: server, project: r.project.clone(), id: r.id.clone(), grant: r.grant.clone(), key: r.key.clone() };
        let g = direct.get(chain, &id);
        assert_eq!(g.status, 200);
        g.body
    }

    /// A `veil-server cache` process (the binary beside `vl`) in front of
    /// `hub`, at `--memory 64M`: its child, address and certificate.
    fn cache_process(hub: &TestHub, dir: &Path) -> (std::process::Child, String, String) {
        let bin = vl_bin().with_file_name("veil-server");
        let ca = dir.join("upstream.pem");
        std::fs::write(&ca, &hub.cert_pem).unwrap();
        let token = hub.ca.parent().unwrap().join("hub-cache-token");
        let mut child = std::process::Command::new(bin)
            .args(["cache", "--upstream", &format!("https://{}", hub.authority()), "--upstream-ca", ca.to_str().unwrap()])
            .args(["--token-file", token.to_str().unwrap(), "--dir", dir.join("cache").to_str().unwrap(), "--listen", "127.0.0.1:0", "--memory", "64M"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
        let addr = line.trim().rsplit("https://").next().unwrap().to_string();
        let pem = std::fs::read_to_string(dir.join("cache").join("self-signed-cert.pem")).unwrap();
        (child, addr, pem)
    }

    fn rss_of(pid: u32) -> usize {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let kib: usize = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
        kib << 10
    }

    /// Guarantee 3, measured on its own process: `--memory` + about
    /// 128 KiB per connection, with 192 clients that stall on answers the
    /// server sends through the cache (cold objects). Once the budget is
    /// taken, each answer waits in `Out::reserve` holding the chunk it read
    /// from the server (at most the HTTP client's read buffer), beside its
    /// connection's TLS and HTTP buffers. (Measured +6 MiB: the kernel's
    /// socket buffers, outside the process, take most of each answer.)
    #[test]
    fn a_cache_process_with_stalled_clients_stays_within_its_bound() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let files: Vec<(String, String)> = (0..4).map(|i| (format!("src/m{i}.bin"), format!("{i}{}", "m".repeat(MIB - 1)))).collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        land(&p, &refs, "four 1 MiB public files");
        let server = hub.api();
        let dir = tempfile::Builder::new().prefix("veil-cache-proc").tempdir().unwrap();
        let (mut child, addr, pem) = cache_process(&hub, dir.path());
        let api = Api::at(&addr, &pem);
        let r = Reader::new(&server, &api, None, &p.name);
        let root = r.root();
        let src = tree(&r, &[], &root).get("src").unwrap().id;
        let st = tree(&r, &[root], &src);
        let ids: Vec<ObjectId> = (0..4).map(|i| st.get(&format!("m{i}.bin")).unwrap().id).collect();
        std::thread::sleep(Duration::from_secs(1));
        let before = rss_of(child.id());
        let n = 192;
        let chain = format!("{},{}", root.hex(), src.hex());
        let stalled: Vec<_> = (0..n)
            .map(|i| api.get_unread(&format!("/v1/objects/{}/{}", p.name, ids[i % ids.len()].hex()), &[("veil-grant", &r.grant), ("veil-chain", &chain)]))
            .collect();
        std::thread::sleep(Duration::from_secs(3));
        let grew = rss_of(child.id()).saturating_sub(before) / MIB;
        let _ = child.kill();
        let _ = child.wait();
        drop(stalled);
        let bound = 64 + n * PER_CONNECTION_KIB / 1024;
        eprintln!("cache process: {n} stalled GETs of cold 1 MiB objects at --memory 64M: RSS +{grew} MiB (bound {bound} MiB)");
        assert!(grew <= bound, "{n} stalled clients grew the cache by {grew} MiB, past --memory 64M + {PER_CONNECTION_KIB} KiB a connection ({bound} MiB)");
    }

    /// Guarantee 1, widened: the cache's answers are the server's, byte for
    /// byte, for several viewers (anyone on Earth, a developer, finance, the
    /// admin), with wants that name ids and trees of another project (which
    /// the cache also holds), ids the viewer may not see under their real
    /// chains and under the viewer's trees, repeats under refused chains,
    /// random `skip` lists, and `GET`s with ranges. A fixed seed.
    #[test]
    fn the_caches_answers_are_the_servers_for_every_viewer_and_project() {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        land(
            &p,
            &[("src/a/same.txt", "the same bytes"), ("src/b/same.txt", "the same bytes"), ("src/b/o.txt", "o"), ("src/c/d/same.txt", "the same bytes"), ("src/c/d/e.txt", "e")],
            "copies in several folders",
        );
        let q = setup_project(&hub);
        land(&q, &[("src/a/same.txt", "the same bytes"), ("src/q-only.txt", "only in q")], "another project's copies");
        let server = hub.api();
        let real = real_chains(&p.dir);
        let q_real = real_chains(&q.dir);
        // q's trees and ids as its admin reads them (through the server).
        let q_walked = Reader::new(&server, &server, Some(&q.admin), &q.name).walk();
        let q_trees: Vec<Vec<ObjectId>> = q_walked
            .iter()
            .filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_))))
            .map(|(chain, id, _)| [chain.clone(), vec![*id]].concat())
            .collect();
        let mut seed = 0x5eed_1183_u64;
        let mut rnd = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let viewers: [Option<&Person>; 4] = [None, Some(&p.dev), Some(&p.fin), Some(&p.admin)];
        let (mut batches, mut gets) = (0, 0);
        for case in 0..12 {
            let who = viewers[case % viewers.len()];
            let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
            let r = Reader::new(&server, &c.api, who, &p.name);
            let direct = Reader { via: &server, project: r.project.clone(), id: r.id.clone(), grant: r.grant.clone(), key: r.key.clone() };
            let walked = direct.walk();
            let reached: HashSet<ObjectId> = walked.iter().map(|w| w.1).collect();
            let hidden: Vec<&(String, Vec<ObjectId>, ObjectId)> = real.iter().filter(|x| !reached.contains(&x.2)).collect();
            let trees: Vec<Vec<ObjectId>> = walked
                .iter()
                .filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_))))
                .map(|(chain, id, _)| [chain.clone(), vec![*id]].concat())
                .collect();
            warm(&c, &r, &[], &r.root());
            for (chain, id, _) in &walked {
                if rnd(2) == 0 {
                    assert_eq!(r.get(chain, id).status, 200);
                }
            }
            // The cache also holds parts of the other project, under its name.
            let qr = Reader::new(&server, &c.api, Some(&q.admin), &q.name);
            for (chain, id, _) in &q_walked {
                if rnd(2) == 0 {
                    assert_eq!(qr.get(chain, id).status, 200);
                }
            }
            for _ in 0..10 {
                let mut wants: Vec<(Vec<ObjectId>, ObjectId)> = Vec::new();
                for _ in 0..1 + rnd(10) {
                    let w = &walked[rnd(walked.len())];
                    let other = trees[rnd(trees.len())].clone();
                    let qw = &q_walked[rnd(q_walked.len())];
                    wants.push(match rnd(14) {
                        0..=4 => (w.0.clone(), w.1),
                        5 => (other, w.1),
                        6 if !hidden.is_empty() => {
                            let h = hidden[rnd(hidden.len())];
                            (if rnd(2) == 0 { h.1.clone() } else { other }, h.2)
                        }
                        7 => (other, random_id()),
                        // The other project's ids, under its trees or ours.
                        8 => (qw.0.clone(), qw.1),
                        9 => (if rnd(2) == 0 { q_trees[rnd(q_trees.len())].clone() } else { other }, q_real[rnd(q_real.len())].2),
                        // An id wanted before, under another chain (often refused).
                        _ => match wants.get(rnd(wants.len().max(1))) {
                            Some(prev) => (if rnd(2) == 0 { other } else { q_trees[rnd(q_trees.len())].clone() }, prev.1),
                            None => (w.0.clone(), w.1),
                        },
                    });
                }
                let skip: Vec<ObjectId> = match rnd(3) {
                    0 => wants.iter().filter(|_| rnd(3) == 0).map(|w| w.1).collect(),
                    _ => Vec::new(),
                };
                let (a, b) = (r.batch_as(&r.grant, &wants, skip.clone()), direct.batch_as(&direct.grant, &wants, skip.clone()));
                assert_eq!((a.status, &a.body), (b.status, &b.body), "case {case} ({:?}): the batch {wants:?} skipping {skip:?}", who.map(|w| &w.name));
                batches += 1;
                for (chain, id) in wants.iter().take(3) {
                    let range = match rnd(4) {
                        0 => Some(format!("bytes={}-{}", rnd(8), 4 + rnd(8))),
                        1 => Some(format!("bytes={}-", rnd(40))),
                        _ => None,
                    };
                    let extra: Vec<(&str, &str)> = range.iter().map(|v| ("range", v.as_str())).collect();
                    let (a, b) = (r.get_as(&r.grant, chain, id, None, &extra), direct.get_as(&direct.grant, chain, id, None, &extra));
                    assert_eq!((a.status, &a.body), (b.status, &b.body), "case {case}: GET {chain:?} {id:?} {range:?}");
                    gets += 1;
                }
            }
        }
        eprintln!("cache: {batches} random batches and {gets} GETs (4 viewers, 2 projects, skips, ranges) answered as the server answers them");
    }
}

/// BUG-1592: the cache's TLS advertised HTTP/2 (ALPN `h2`, `tls.rs` sets it
/// for the server and the cache alike) while its connections are served
/// HTTP/1-only (`serve_tls` with connection limits), so an HTTP/2 client
/// (curl, reqwest with http2) negotiated h2 and got a broken stream:
/// `curl: (18) HTTP/2 stream 1 was not closed cleanly` (found by the
/// deployment kit's health check; `vl` and `veil-bench` use HTTP/1.1 and
/// never saw it). Fixed: a listener that speaks HTTP/1 only offers only
/// `http/1.1` (`serve`), and an HTTP/2 client's request is answered.
#[test]
fn bug_1592_the_cache_offers_only_the_protocol_it_serves() {
    use rustls::pki_types::pem::PemObject;
    let hub = TestHub::start();
    let c = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(c.running.cert_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut tcp = std::net::TcpStream::connect(c.running.addr).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).expect("the handshake completes");
    }
    assert_eq!(conn.alpn_protocol(), Some(&b"http/1.1"[..]), "a client offering h2 and http/1.1 must get http/1.1, the only protocol the cache serves");
    // And its request, in the protocol agreed, gets an HTTP answer (a
    // refusal: it carries no grant).
    use std::io::{Read as _, Write as _};
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(b"GET /v1/objects/p/x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 4"), "{answer}");
}

/// BUG-1332 (S24): what a regional cache forwards counted against the
/// cache's own address at the server, as one client's. Fixed: the cache
/// says it is one (the caches' token) and whose request it passes on (its
/// client's address); the server counts a signed request against its
/// device. 40 first reads of public files by one signed-in reader through
/// a cold cache, at the default anonymous rate (20 a second), are all
/// served, and the cache's own address keeps its rate for its own clients.
#[test]
fn bug_1332_a_caches_forwarded_reads_count_against_its_address() {
    use veil_server::limits::{bucket::Rate, Settings};
    let hub = TestHub::start_with_limits(Settings { anonymous: Rate { per_second: 20, per_hour: 100_000 }, ..TestHub::limits() });
    let p = setup_project(&hub);
    let files: Vec<(String, String)> = (0..40).map(|i| (format!("src/r{i}.txt"), format!("public {i}"))).collect();
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&p.dir, &refs);
    p.admin.commit_main(&p.dir, "forty public files");
    p.admin.ok(&p.dir, &["push"]);
    let server = hub.api();
    let cache = TestCache::start(&hub, &hub.authority(), 1 << 30);
    std::thread::sleep(Duration::from_millis(1500));
    let r = Reader::new(&server, &cache.api, Some(&p.dev), &p.name);
    let root = r.root();
    let tree = |chain: &[ObjectId], id: &ObjectId| match Object::decode(&r.get(chain, id).body).unwrap() {
        Object::Tree(t) => t,
        _ => panic!("not a tree"),
    };
    let src = tree(&[], &root).get("src").unwrap().id;
    let st = tree(&[root], &src);
    for i in 0..40 {
        let id = st.get(&format!("r{i}.txt")).unwrap().id;
        let got = r.get(&[root, src], &id);
        assert_eq!(got.status, 200, "read {i}: {}", String::from_utf8_lossy(&got.body));
    }
    assert!(cache.stat("forwarded") >= 40, "every read went to the server");
    // And 25 cold batch reads through a fresh cache: each batch's grant is in
    // its body (`deferred` in `limits::admit`), and counts against the
    // reader's device, not the cache's address.
    let cache2 = TestCache::start(&hub, &hub.authority(), 1 << 30);
    let r2 = Reader::new(&server, &cache2.api, Some(&p.dev), &p.name);
    for i in 0..25 {
        let id = st.get(&format!("r{i}.txt")).unwrap().id;
        let frames = r2.batch(&[(vec![root, src], id)]);
        assert_eq!(frames.len(), 1, "batch {i}");
    }
    assert!(cache2.stat("forwarded") >= 25, "every batch went to the server");
    let r = server.post_json(None, "/v1/auth/challenge", &serde_json::json!({"key": Identity::generate("x").verifying_hex()}));
    assert_eq!(r.status, 200, "the address kept its own rate: {}", String::from_utf8_lossy(&r.body));
}
