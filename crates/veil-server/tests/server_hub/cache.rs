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
    let root = repo.store().snapshot(&tip).unwrap().tree;
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
