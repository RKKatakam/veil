//! Read grants and the object routes (S5, `docs/HUB.md` §13.13): an object
//! route never hands anyone an object they cannot see, whatever id or chain
//! they send; "not reachable" and "not there" look the same; grants work
//! only for their device, project and key, and stop working at the next
//! request after an access change.

use std::{collections::HashSet, path::Path, sync::Arc};

use veil_core::{
    hub::grant::{sign_request, BatchRequest, ChainWant, Grant, GrantBody, MAX_CHAIN},
    hub::wire::MAX_WANTS,
    object::{EntryKind, Object},
    Identity, ObjectId,
};

use crate::support::*;

/// Someone who reads through the object routes.
struct Reader<'a> {
    api: &'a Api,
    project: String,
    /// Their device (`None`: anyone on Earth).
    id: Option<Identity>,
    grant: String,
    /// The server's grant key, from the tips.
    key: String,
}

impl<'a> Reader<'a> {
    fn new(api: &'a Api, who: Option<&Person>, project: &str) -> Reader<'a> {
        let token = who.map(|p| p.token());
        let tips = api.tips(token.as_deref(), project).expect("tips");
        assert!(tips.grant_key.is_some() && tips.revision >= 2);
        Reader {
            api,
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

    fn batch_as(&self, grant: &str, wants: &[(Vec<ObjectId>, ObjectId)]) -> Reply {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: grant.to_string(),
            ts,
            signature: self.signature(grant, ts, &ids),
            wants: wants.iter().map(|(chain, id)| ChainWant { chain: chain.clone(), id: *id }).collect(),
        };
        self.api.post(None, &format!("/v1/objects/{}:batch", self.project), &serde_json::to_vec(&req).unwrap(), true)
    }

    fn batch(&self, wants: &[(Vec<ObjectId>, ObjectId)]) -> Vec<(ObjectId, Vec<u8>)> {
        self.batch_as(&self.grant, wants).frames()
    }

    /// `GET` one object, with `sig` (ts, signature) or this reader's own.
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
        // An extra header replaces the reader's own.
        h.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
        h.extend_from_slice(extra);
        self.api.get_with(&format!("/v1/objects/{}/{}", self.project, id.hex()), &h)
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
            let got = self.batch(&wants);
            assert_eq!(got.len(), wants.len(), "every reachable object arrives");
            let mut next = Vec::new();
            for ((chain, id), (gid, raw)) in wants.into_iter().zip(got) {
                assert_eq!(id, gid);
                if !seen.insert((chain.clone(), id)) {
                    continue;
                }
                match Object::decode(&raw) {
                    Ok(Object::Tree(t)) => {
                        let mut c = chain.clone();
                        c.push(id);
                        for e in &t.entries {
                            next.push((c.clone(), e.id));
                        }
                    }
                    Ok(Object::Conflict(k)) => {
                        let mut c = chain.clone();
                        c.push(id);
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
                let mut c = chain.clone();
                c.push(e.id);
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

#[test]
fn object_routes_serve_only_what_a_grant_reaches() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let real = real_chains(&p.dir);
    let env_id = real.iter().find(|(path, _, _)| *path == format!("{BILL_DIR}/.env")).unwrap().2;
    let admin_root = real[0].2;
    let all = restricted_markers();
    let not = |keep: &[&str]| all.iter().copied().filter(|m| !keep.contains(m)).collect::<Vec<_>>();
    let viewers: Vec<(&str, Option<&Person>, Vec<&str>, &str)> = vec![
        ("anyone", None, not(&[]), PUBLIC_MARK),
        ("dev", Some(&p.dev), not(&[]), PUBLIC_MARK),
        ("fin", Some(&p.fin), not(&[BILL_DIR, BILL_MARK, ENV_MARK]), BILL_DIR),
        ("carol", Some(&p.carol), not(&[PERSON_DIR, PERSON_MARK]), PERSON_MARK),
        ("sec", Some(&p.sec), not(&[NESTED_DIR, NESTED_MARK]), NESTED_MARK),
    ];
    let mut missing_body = None;
    for (who, person, hidden, mine) in viewers {
        let r = Reader::new(&api, person, &p.name);
        assert_eq!(r.body().device.is_some(), person.is_some(), "{who}: a signed-in grant names the device");
        let walked = r.walk();
        // Safety first: no marker they may not see, in any object.
        assert_no_marker(&items(&walked), &hidden, who);
        let reached: HashSet<ObjectId> = walked.iter().map(|w| w.1).collect();
        // Secrets' ciphertext follows the folder's access.
        assert_eq!(reached.contains(&env_id), who == "fin", "{who}: billing's .env ciphertext");
        // Liveness: what they may see arrives.
        assert!(has_marker(&items(&walked), mine), "{who} did not receive {mine}");
        // Every real object they did not reach, with every chain they can
        // build: their own trees, the admin's real chain, the admin's
        // chain from their own root, the admin's root.
        let trees: Vec<Vec<ObjectId>> = walked
            .iter()
            .filter(|(_, _, raw)| matches!(Object::decode(raw), Ok(Object::Tree(_))))
            .map(|(c, id, _)| [c.clone(), vec![*id]].concat())
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
        if who != "fin" {
            assert!(attacks.iter().any(|a| a.1 == env_id));
        }
        assert!(attacks.iter().any(|a| a.1 == admin_root), "{who}: the admin's root is among the attacks");
        for part in attacks.chunks(5000) {
            let got = r.batch(part);
            assert!(got.is_empty(), "{who} received {} hidden objects", got.len());
        }
        // One at a time: the answer is the one an object nobody has gets.
        let absent = r.get(&[r.root()], &random_id());
        assert_eq!(absent.status, 404);
        let body = missing_body.get_or_insert_with(|| absent.body.clone()).clone();
        assert_eq!(absent.body, body);
        for (chain, id) in attacks.iter().step_by(7).take(60) {
            let g = r.get(chain, id);
            assert_eq!((g.status, &g.body), (404, &body), "{who}: a hidden object answers like an absent one");
        }
        // And what they reach, one at a time, is served.
        for (chain, id, raw) in walked.iter().take(20) {
            let g = r.get(chain, id);
            assert_eq!((g.status, &g.body), (200, raw), "{who}");
        }
    }
    // An object at a visible and at a hidden path: served through the
    // visible one only (it is the same bytes there).
    let dir = &p.dir;
    write_files(dir, &[("src/shared-copy.txt", BILL_MARK)]);
    p.admin.commit_main(dir, "same bytes in src/ and billing/");
    p.admin.ok(dir, &["push"]);
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let walked = dev.walk();
    let real = real_chains(dir);
    let shared = real.iter().find(|(path, _, _)| path == "src/shared-copy.txt").unwrap();
    let in_billing: Vec<_> = real.iter().filter(|(path, _, id)| path.starts_with(BILL_DIR) && *id != shared.2).collect();
    let hit = walked.iter().find(|w| w.1 == shared.2).expect("dev reads src/shared-copy.txt");
    assert!(has_marker(&[(String::new(), hit.2.clone())], BILL_MARK), "the same bytes");
    for (_, chain, id) in in_billing {
        assert!(dev.batch(&[(chain.clone(), *id), ([vec![dev.root()], chain[1..].to_vec()].concat(), *id)]).is_empty());
    }
}

fn invalid(r: &Reply) -> bool {
    r.status == 401 && r.json()["code"] == "grant_invalid"
}

/// The epoch feed, as the signed-in `token` sees it for `projects`.
fn feed(api: &Api, token: &str, projects: &[&str]) -> serde_json::Value {
    let r = api.get(Some(token), &format!("/v1/epochs?projects={}", projects.join(",")));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

#[test]
fn grants_hold_only_for_their_device_project_key_and_time() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let root = dev.root();
    assert_eq!(dev.get(&[], &root).status, 200);
    let ts = veil_core::now_millis();
    let g = Grant::verify(&dev.grant, &dev.key).unwrap();
    // Another device's signature, none, one over other ids, an old one.
    let sig = |who: &Identity, ts: i64, ids: &[ObjectId]| Some((ts, sign_request(who, &g, ts, ids)));
    for (what, s) in [
        ("fin's device", sig(&p.fin.identity(), ts, &[root])),
        ("other ids", sig(&p.dev.identity(), ts, &[random_id()])),
        ("six minutes old", sig(&p.dev.identity(), ts - 6 * 60_000, &[root])),
        ("an hour ahead", sig(&p.dev.identity(), ts + 3_600_000, &[root])),
    ] {
        assert!(invalid(&dev.get_as(&dev.grant, &[], &root, s, &[])), "{what}");
    }
    let unsigned = api.get_with(&format!("/v1/objects/{}/{}", p.name, root.hex()), &[("veil-grant", &dev.grant)]);
    assert!(invalid(&unsigned), "no signature");
    // Its project only, under the grant key only, as signed only.
    let elsewhere = Reader { project: unique("other"), ..Reader::new(&api, Some(&p.dev), &p.name) };
    assert!(invalid(&elsewhere.get(&[], &root)), "another project's URL");
    let body = dev.body();
    let raw = serde_json::to_vec(&body).unwrap();
    let by_identity = format!("{}.{}", hex::encode(&raw), hub.hub().identity.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_GRANT, &raw));
    assert!(invalid(&dev.get_as(&by_identity, &[], &root, None, &[])), "signed by the server's identity, not its grant key");
    let admin_root = real_chains(&p.dir)[0].2;
    let mut wider = body.clone();
    wider.root = admin_root;
    let tampered = format!("{}.{}", hex::encode(serde_json::to_vec(&wider).unwrap()), dev.grant.split_once('.').unwrap().1);
    assert!(invalid(&dev.get_as(&tampered, &[], &admin_root, None, &[])), "a root changed under the signature");
    // Expired, and from before the project's newest access change (its
    // policy was accepted in setup).
    let grants = &hub.hub().grants;
    let expired = grants.issue(&GrantBody { expires: veil_core::now_millis() - 1, ..body.clone() });
    assert!(invalid(&dev.get_as(&expired, &[], &root, None, &[])), "expired");
    let f = feed(&api, &p.dev.token(), &[&p.name]);
    assert_eq!((f["projects"][&p.name].as_i64(), f["person"].as_i64()), (Some(body.epoch), Some(body.person_epoch)));
    assert_ne!(body.epoch, 0, "setup accepted a policy");
    for (e, pe) in [(body.epoch + 1, body.person_epoch), (body.epoch - 1, body.person_epoch), (0, body.person_epoch), (body.epoch, body.person_epoch + 1)] {
        let stale = grants.issue(&GrantBody { epoch: e, person_epoch: pe, ..body.clone() });
        assert!(invalid(&dev.get_as(&stale, &[], &root, None, &[])), "another epoch than the current ones");
    }
    let fresh = grants.issue(&body);
    assert_eq!(dev.get_as(&fresh, &[], &root, None, &[]).status, 200, "the same grant, re-signed, still works");
    // Anyone on Earth's grant names no device and needs no signature.
    let anyone = Reader::new(&api, None, &p.name);
    assert!(anyone.body().device.is_none() && anyone.body().person.is_none());
    assert_eq!(api.get_with(&format!("/v1/objects/{}/{}", p.name, anyone.root().hex()), &[("veil-grant", &anyone.grant)]).status, 200);

    // Hostile input: nothing crashes, nothing is served.
    let path = format!("/v1/objects/{}/{}", p.name, root.hex());
    for h in [
        vec![("veil-grant", "zz")],
        vec![("veil-grant", ".")],
        vec![("veil-grant", &*"a".repeat(10_000))],
    ] {
        assert!(invalid(&api.get_with(&path, &h)), "{:?}", &h[0].1[..h[0].1.len().min(20)]);
    }
    assert_eq!(api.get_with(&path, &[]).status, 401);
    let long: Vec<ObjectId> = vec![root; MAX_CHAIN + 5];
    assert_eq!(dev.get(&long, &root).status, 404);
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("veil-chain", "nothex,also")]).status, 400);
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("veil-signature", "garbage")]).status, 400);
    assert_eq!(api.get_with(&format!("/v1/objects/{}/nothex", p.name), &[("veil-grant", &dev.grant)]).status, 400);
    assert_eq!(api.post(None, &format!("/v1/objects/{}", p.name), b"{}", true).status, 404);
    assert_eq!(api.post(None, &format!("/v1/objects/{}:batch", p.name), b"{not json", true).status / 100, 4);
    let many: Vec<(Vec<ObjectId>, ObjectId)> = (0..=MAX_WANTS).map(|_| (Vec::new(), root)).collect();
    assert_eq!(dev.batch_as(&dev.grant, &many).status, 400);
    // Range: a part of the object, or 416 past its end.
    let whole = dev.get(&[], &root).body;
    let part = dev.get_as(&dev.grant, &[], &root, None, &[("range", "bytes=2-5")]);
    assert_eq!((part.status, &part.body[..]), (206, &whole[2..6]));
    let tail = dev.get_as(&dev.grant, &[], &root, None, &[("range", "bytes=3-")]);
    assert_eq!((tail.status, &tail.body[..]), (206, &whole[3..]));
    assert_eq!(dev.get_as(&dev.grant, &[], &root, None, &[("range", &format!("bytes={}-", whole.len()))]).status, 416);
    // A Range on an object the grant does not reach: the same 404.
    let hidden = dev.get_as(&dev.grant, &[], &admin_root, None, &[("range", "bytes=0-0")]);
    assert_eq!(hidden.status, 404);
    // A batch larger than the read-ahead window and the send chunk arrives
    // whole and in order, the objects it does not reach left out.
    let files: Vec<(String, String)> = (0..300).map(|i| (format!("src/bulk/f{i:03}.txt"), format!("{i} {}", "y".repeat(20_000)))).collect();
    write_files(&p.dir, &files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
    p.admin.commit_main(&p.dir, "bulk");
    p.admin.ok(&p.dir, &["push"]);
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let bulk: Vec<(Vec<ObjectId>, ObjectId)> = dev.walk().into_iter().filter(|(_, _, raw)| raw.len() > 20_000).map(|(c, id, _)| (c, id)).collect();
    assert_eq!(bulk.len(), 300);
    let mut asked = bulk.clone();
    asked.insert(150, (vec![dev.root()], admin_root));
    let got = dev.batch(&asked);
    assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), bulk.iter().map(|b| b.1).collect::<Vec<_>>());
}

#[test]
fn access_changes_void_grants_at_the_next_request() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let invoice = |r: &Reader| {
        r.walk().into_iter().find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], BILL_MARK)).map(|(c, id, _)| (c, id))
    };
    // A person removed from a group.
    let fin = Reader::new(&api, Some(&p.fin), &p.name);
    let (chain, id) = invoice(&fin).expect("fin reads the invoice");
    assert_eq!(fin.get(&chain, &id).status, 200);
    let (before, project_before) = (fin.body().person_epoch, fin.body().epoch);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(invalid(&fin.get(&chain, &id)), "the old grant stops at once");
    assert!(invalid(&fin.batch_as(&fin.grant, &[(chain.clone(), id)])));
    let f = feed(&api, &p.fin.token(), &[&p.name]);
    assert_ne!(f["person"].as_i64(), Some(before), "{f}");
    assert_eq!(f["projects"][&p.name].as_i64(), Some(project_before), "{f}: a person's change leaves the project's epoch");
    let again = Reader::new(&api, Some(&p.fin), &p.name);
    assert_eq!(again.body().person_epoch, f["person"].as_i64().unwrap());
    assert!(invoice(&again).is_none(), "the new grant reaches no billing file");
    assert!(again.batch(&[(chain.clone(), id)]).is_empty());

    // A policy change: the project's grants, anyone on Earth's included.
    let anyone = Reader::new(&api, None, &p.name);
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let lib = anyone.walk().into_iter().find(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PUBLIC_MARK)).unwrap();
    assert_eq!(anyone.get(&lib.0, &lib.1).status, 200);
    p.admin.ok(&p.dir, &["access", "src/", "devs"]);
    p.admin.commit_main(&p.dir, "src/ no longer public");
    p.admin.ok(&p.dir, &["push"]);
    assert!(invalid(&anyone.get(&lib.0, &lib.1)), "anyone's grant from before the policy");
    assert!(invalid(&dev.get(&[], &dev.root())), "every grant of the project");
    assert!(api.tips(None, &p.name).is_none(), "nothing public is left");
    let dev2 = Reader::new(&api, Some(&p.dev), &p.name);
    assert!(dev2.walk().iter().any(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PUBLIC_MARK)));

    // A device removed from the project by an admin.
    let sec = Reader::new(&api, Some(&p.sec), &p.name);
    assert_eq!(sec.get(&[], &sec.root()).status, 200);
    p.admin.ok(&p.dir, &["identity", "remove", &p.sec.fingerprint()]);
    assert!(invalid(&sec.get(&[], &sec.root())), "a removed device's grant");
    // Each change is in the feed of whom it concerns: the project's new
    // epoch for dev (the grants made since carry it), sec's new one for sec.
    let f = feed(&api, &p.dev.token(), &[&p.name]);
    assert_eq!(f.as_object().unwrap().keys().collect::<Vec<_>>(), ["person", "projects"]);
    assert_eq!(f["projects"][&p.name].as_i64(), Some(dev2.body().epoch));
    assert_ne!(dev2.body().epoch, dev.body().epoch);
    let f = feed(&api, &p.sec.token(), &[&p.name]);
    assert_ne!(f["person"].as_i64(), Some(sec.body().person_epoch), "{f}");
    assert!(f["projects"].as_object().unwrap().is_empty(), "a device barred from the project sees no epoch of it: {f}");
}

fn percentile(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

/// The S5 gates: an object fetch's server time and the cost of the chain
/// check. Run in release: `bench-quiet.sh` around
/// `cargo test --release … grants::bench -- --ignored --nocapture`.
#[test]
#[ignore = "benchmark"]
fn bench_object_routes() {
    use axum::extract::{Path as P, State};
    use std::time::Instant;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    const FILES: usize = 2000;
    let files: Vec<(String, String)> = (0..FILES).map(|i| (format!("src/many/f{i:05}.txt"), format!("file {i} {}", "x".repeat(200)))).collect();
    write_files(&p.dir, &files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
    p.admin.commit_main(&p.dir, "many files");
    p.admin.ok(&p.dir, &["push"]);
    let api = hub.api();
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let walked = dev.walk();
    let many: Vec<(Vec<ObjectId>, ObjectId)> = walked.iter().filter(|(c, _, _)| c.len() == 3).map(|(c, id, _)| (c.clone(), *id)).collect();
    assert!(many.len() >= FILES, "{}", many.len());
    let state = hub.hub();
    let identity = p.dev.identity();
    let g = Grant::verify(&dev.grant, &dev.key).unwrap();
    let headers = |chain: &[ObjectId], id: &ObjectId| {
        let mut h = axum::http::HeaderMap::new();
        let ts = veil_core::now_millis();
        h.insert("veil-grant", dev.grant.parse().unwrap());
        h.insert("veil-chain", chain.iter().map(|c| c.hex()).collect::<Vec<_>>().join(",").parse().unwrap());
        h.insert("veil-signature", format!("{ts}.{}", sign_request(&identity, &g, ts, &[*id])).parse().unwrap());
        h
    };
    // One object at a time, in process: the server's time only.
    let mut times = Vec::new();
    for (i, (chain, id)) in many.iter().cycle().take(3000).enumerate() {
        let h = headers(chain, id);
        let t = Instant::now();
        let r = hub.rt.block_on(veil_server::grant::get_object(State(state.clone()), P((p.name.clone(), id.hex())), h)).unwrap();
        if i >= 500 {
            times.push(t.elapsed().as_secs_f64() * 1e6);
        }
        assert_eq!(r.status(), 200);
    }
    println!(
        "GET /v1/objects, in process (µs): p50 {:.0}  p90 {:.0}  p99 {:.0}",
        percentile(&mut times, 0.5),
        percentile(&mut times, 0.9),
        percentile(&mut times, 0.99)
    );
    // Parts of it: the epoch query, the grant and request signatures.
    let mut q = Vec::new();
    for _ in 0..1000 {
        let t = Instant::now();
        hub.rt.block_on(state.grants.current(&state.db, g.body.project_id, g.body.person)).unwrap();
        q.push(t.elapsed().as_secs_f64() * 1e6);
    }
    println!("   of which the epoch query (µs): p50 {:.0}  p99 {:.0}", percentile(&mut q.clone(), 0.5), percentile(&mut q, 0.99));
    let ts = veil_core::now_millis();
    let sig = sign_request(&identity, &g, ts, &[many[0].1]);
    let t = Instant::now();
    for _ in 0..1000 {
        let g = Grant::verify(&dev.grant, &dev.key).unwrap();
        assert!(veil_core::hub::grant::request_signed(&g, ts, &[many[0].1], Some(&sig), ts));
    }
    println!("   grant and request signature checks (µs): {:.0}", t.elapsed().as_secs_f64() * 1e6 / 1000.0);
    // The chain check alone, against the server's store and tree cache.
    let src = veil_server::sync::Source { hub: state.clone(), project: g.body.project_id, rt: hub.rt.handle().clone(), pending: Default::default() };
    let mut cold = Vec::new();
    for (chain, id) in &many {
        let t = Instant::now();
        assert!(veil_core::hub::grant::Chains::new(&src, g.body.root).allows(chain, id).unwrap());
        cold.push(t.elapsed().as_secs_f64() * 1e6);
    }
    let mut chains = veil_core::hub::grant::Chains::new(&src, g.body.root);
    let t = Instant::now();
    for (chain, id) in &many {
        assert!(chains.allows(chain, id).unwrap());
    }
    let warm = t.elapsed().as_secs_f64() * 1e6 / many.len() as f64;
    println!(
        "chain check, depth 3, a folder of {} entries (µs): per object, new check p50 {:.0} p99 {:.0}; within one batch {:.2}",
        many.len(),
        percentile(&mut cold.clone(), 0.5),
        percentile(&mut cold, 0.99),
        warm
    );
    // A batch of every file, in process, and S1's fetch of the same.
    let ids: Vec<ObjectId> = many.iter().map(|w| w.1).collect();
    let mut b = Vec::new();
    for _ in 0..10 {
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: dev.grant.clone(),
            ts,
            signature: Some(sign_request(&identity, &g, ts, &ids)),
            wants: many.iter().map(|(c, id)| ChainWant { chain: c.clone(), id: *id }).collect(),
        };
        let body = axum::body::Bytes::from(serde_json::to_vec(&req).unwrap());
        let t = Instant::now();
        let r = hub.rt.block_on(veil_server::grant::batch(State(state.clone()), P(format!("{}:batch", p.name)), body)).unwrap();
        assert_eq!(r.status(), 200);
        let all = hub.rt.block_on(axum::body::to_bytes(r.into_body(), usize::MAX)).unwrap();
        b.push(t.elapsed().as_secs_f64() * 1e3);
        assert_eq!(veil_core::hub::wire::read_frames(&all).unwrap().len(), many.len());
    }
    println!("POST :batch of {} objects, in process (ms): p50 {:.1}", many.len(), percentile(&mut b, 0.5));
    // Over HTTPS: the batch, and S1's fetch of the same objects by path.
    let reals = real_chains(&p.dir);
    let tip = api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"];
    let by_path: Vec<serde_json::Value> =
        reals.iter().filter(|(path, _, _)| path.starts_with("src/many/")).map(|(path, _, id)| serde_json::json!({"path": path, "id": id.hex()})).collect();
    let token = p.dev.token();
    let (mut nb, mut nf) = (Vec::new(), Vec::new());
    for _ in 0..10 {
        let t = Instant::now();
        assert_eq!(dev.batch(&many).len(), many.len());
        nb.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        let r = api.post(Some(&token), &format!("/v1/projects/{}/fetch", p.name), &serde_json::to_vec(&serde_json::json!({"snapshot": tip.hex(), "objects": by_path})).unwrap(), true);
        assert_eq!(r.frames().len(), by_path.len());
        nf.push(t.elapsed().as_secs_f64() * 1e3);
    }
    println!("over HTTPS, {} objects (ms): :batch p50 {:.1}; S1 fetch p50 {:.1}", many.len(), percentile(&mut nb, 0.5), percentile(&mut nf, 0.5));
    // Over HTTPS (one connection), end to end.
    let mut net = Vec::new();
    for (chain, id) in many.iter().take(1000) {
        let t = Instant::now();
        assert_eq!(dev.get(chain, id).status, 200);
        net.push(t.elapsed().as_secs_f64() * 1e6);
    }
    println!("GET /v1/objects over HTTPS, client side (µs): p50 {:.0}  p99 {:.0}", percentile(&mut net.clone(), 0.5), percentile(&mut net, 0.99));
}

// ---- Adversarial pass: S5 (docs/BUGS.md, "Adversarial pass: S5") ----------

/// The view key `View::key` gives `viewer` of the project in `dir` for
/// the policy `text`: what anyone holding a grant can compute offline from
/// a guess of the whole `.veilpolicy`.
fn guessed_view(text: &str, member_of: &[&str]) -> String {
    let policy = veil_core::hub::access::AccessPolicy::parse(text);
    veil_core::hub::access::View::new(&policy, false, |_, name| member_of.contains(&name)).key()
}

/// BUG-1080. A grant held nothing that confirms a guess of hidden access
/// lines (it carried the view key: an unkeyed hash of every line's path,
/// hidden ones included). Now no value a viewer receives with the tips is
/// the view key of the true policy, and the grant has no `view`.
#[test]
fn bug_1080_a_grants_view_key_confirms_a_guess_of_hidden_folder_names() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    // The key depends on the hidden names: a wrong guess gives another one.
    let wrong = policy.replace(BILL_DIR, "bill-00000000");
    assert_ne!(guessed_view(&policy, &[]), guessed_view(&wrong, &[]));
    for (who, person, groups) in [("anyone on Earth", None, vec![]), ("dev", Some(&p.dev), vec!["devs"])] {
        let token = person.map(|p| p.token());
        let tips = api.get(token.as_deref(), &format!("/v1/projects/{}/tips", p.name));
        assert_eq!(tips.status, 200);
        let right = guessed_view(&policy, &groups);
        let mut all = tips.body.clone();
        for g in tips.json()["grants"].as_object().unwrap().values() {
            let body = hex::decode(g.as_str().unwrap().split_once('.').unwrap().0).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v.get("view").is_none(), "{who}'s grant has a view: {v}");
            all.extend(body);
        }
        assert!(
            !has_marker(&[(String::new(), all)], &right),
            "{who}'s tips confirm, offline, the guess that the policy holds {BILL_DIR}/, {PERSON_DIR}/ and src/{NESTED_DIR}/"
        );
        if let Some(t) = &token {
            let f = api.get(Some(t), &format!("/v1/epochs?projects={}", p.name));
            assert!(!has_marker(&[(String::new(), f.body)], &right), "{who}'s epochs");
        }
    }
}

/// BUG-1081. The epoch feed answered anyone on Earth, and listed a project
/// that has nothing public. Now it needs a session and answers only for
/// the caller and the projects they can see; and a grant's epochs are its
/// project's and person's own, untouched by changes elsewhere.
#[test]
fn bug_1081_the_epoch_feed_shows_anyone_a_project_with_nothing_public() {
    let hub = TestHub::start();
    let api = hub.api();
    let admin = hub.person("quiet");
    let other = hub.person("other");
    let name = unique("quiet");
    let dir = admin.dir("quiet");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, &[("plans/q4.txt", "MARKER-QUIET-PLANS-6b1e0c2a")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "plans");
    admin.ok(&dir, &["push"]);
    admin.ok(&dir, &["access", "plans/", &admin.name]);
    admin.commit_main(&dir, "access");
    admin.ok(&dir, &["push"]);
    // Nothing public: anyone on Earth does not see the project at all.
    assert!(api.tips(None, &name).is_none());
    let r = api.get(None, &format!("/v1/epochs?projects={name}"));
    assert_eq!(r.status, 401, "anyone on Earth reads no epochs");
    let r = api.get(None, "/v1/epochs");
    assert_eq!(r.status, 401);
    // Someone signed in who cannot see it: left out, as a project that
    // does not exist is.
    let f = feed(&api, &other.token(), &[&name, "no-such-project-0f3a"]);
    assert!(f["projects"].as_object().unwrap().is_empty(), "{f}");
    // Its admin: listed, with the epoch their grant carries.
    let g = Grant::read_unverified(&api.tips(Some(&admin.token()), &name).unwrap().grants["main"]).unwrap();
    let f = feed(&api, &admin.token(), &[&name]);
    assert_eq!(f["projects"][&name].as_i64(), Some(g.epoch));
    // Access changes in other projects leave this project's epoch, and the
    // admin's person epoch, as they were: a grant shows no server-wide count.
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let g2 = Grant::read_unverified(&api.tips(Some(&admin.token()), &name).unwrap().grants["main"]).unwrap();
    assert_eq!((g2.epoch, g2.person_epoch), (g.epoch, g.person_epoch));
}

/// A new, empty database on the test server, as a URL; dropped with the
/// run's (`VEIL_TEST_DB_PREFIX`).
fn fresh_database(rt: &tokio::runtime::Runtime) -> String {
    let admin = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let name = format!("{}{}", std::env::var("VEIL_TEST_DB_PREFIX").unwrap_or_default(), unique("veil_epochs_"));
    rt.block_on(async {
        let db = veil_server::db::connect(&admin, 1).await.unwrap();
        sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&db).await.unwrap();
        db.close().await;
    });
    format!("{}/{name}", admin.rsplit_once('/').unwrap().0)
}

/// BUG-1082. The feed paged over a log keeping one row per key, and passed
/// over the change of a key that changed again past a full page. Now it
/// answers each key asked for with its current epoch: after a change, ten
/// thousand changes of other keys and another change of the same key, it
/// gives the newest, and the grants of each earlier epoch are void.
#[test]
fn bug_1082_the_epoch_feed_skips_a_change_whose_key_changed_again() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    // A database of its own: the other keys bumped here are nobody's.
    let hub = TestHub::start_on(&fresh_database(&rt), std::time::Duration::from_secs(3600));
    let p = setup_project(&hub);
    let api = hub.api();
    let db = hub.hub().db.clone();
    let token = p.dev.token();
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    let pid = dev.body().project_id;
    let mut seen = vec![dev.body().epoch];
    // SQL straight in the database, run again on a lost race or a catalog
    // another test's DDL changed (YugabyteDB: 40001), as the routes are.
    let sql = |q: &str, a: i64, b: i64| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        while let Err(e) = hub.rt.block_on(sqlx::query(q).bind(a).bind(b).execute(&db)) {
            let retryable = matches!(&e, sqlx::Error::Database(d) if matches!(d.code().as_deref(), Some("40001" | "40P01")));
            assert!(retryable && std::time::Instant::now() < deadline, "{e:?}");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };
    let bump = |key: i64| sql("SELECT veil_bump_epoch($1, $2)", key, 0);
    bump(pid);
    let mut a = pid + 1;
    while a <= pid + 10_001 {
        let b = (a + 999).min(pid + 10_001);
        sql("SELECT veil_bump_epoch(g, 0) FROM generate_series($1::bigint, $2::bigint) g", a, b);
        a = b + 1;
    }
    seen.push(feed(&api, &token, &[&p.name])["projects"][&p.name].as_i64().unwrap());
    bump(pid);
    let now = feed(&api, &token, &[&p.name])["projects"][&p.name].as_i64().unwrap();
    let current: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = 0").bind(pid).fetch_one(&db))
        .unwrap();
    assert_eq!(now, current, "the feed gives the project's current epoch");
    assert!(!seen.contains(&now), "each change gives a new epoch: {seen:?} then {now}");
    assert!(invalid(&dev.get(&[], &dev.root())), "a grant of an earlier epoch");
    let fresh = Reader::new(&api, Some(&p.dev), &p.name);
    assert_eq!(fresh.body().epoch, now);
    assert_eq!(fresh.get(&[], &fresh.root()).status, 200);
}

/// Set every directory under `root` to `mode`.
fn chmod_dirs(root: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            }
        }
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// BUG-1083. Making a grant stores the projected trees; when the store
/// could not be written, the whole tips request failed, so every pull of
/// everyone but admins failed with it (S1 needed no write to pull). Now the
/// branch only gets no grant.
#[test]
fn bug_1083_a_store_that_cannot_be_written_fails_every_pull() {
    let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    // Objects in a directory, whatever VEIL_TEST_S3_ENDPOINT says.
    let hub = TestHub::start_with_s3(&url, std::time::Duration::from_secs(3600), None);
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    // The server's own projection memo key for dev (computed here from the
    // policy the test wrote; no client receives it).
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let (pid, view) = (dev.body().project_id, guessed_view(&policy, &["devs"]));
    // A change dev sees, in src/ (rewritten for dev: it holds a hidden folder).
    write_files(&p.dir, &[("src/lib.rs", "MARKER-PUBLIC-CHANGED-77c1d0e2")]);
    p.admin.commit_main(&p.dir, "src changed");
    p.admin.ok(&p.dir, &["push"]);
    let tip = {
        let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
        repo.view().tags["main"].target
    };
    // The deriver memoises dev's projection of the new tip after the push
    // (its snapshot is stored then; no grant, so no tree).
    let db = hub.hub().db.clone();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let memo: Option<String> = hub.rt.block_on(
            sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                .bind(pid)
                .bind(&view)
                .bind(tip.hex())
                .fetch_optional(&db),
        )
        .unwrap();
        if memo.is_some() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the deriver memoised dev's projection");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // The store still reads, but cannot be written (a full disk, a
    // read-only bucket policy, an outage of writes).
    let objects = hub._dir.path().join("objects");
    chmod_dirs(&objects, 0o555);
    let r = api.get(Some(&p.dev.token()), &format!("/v1/projects/{}/tips", p.name));
    chmod_dirs(&objects, 0o755);
    assert_eq!(r.status, 200, "dev's pull fails: {}", String::from_utf8_lossy(&r.body));
}

/// Held up (S5 adversarial pass): every other change that takes access
/// away bumps an epoch and voids the grants it should, at the next
/// request: a group deleted, a group created under the name a line gave a
/// person, and a device removed by its person (everywhere).
#[test]
fn grants_are_void_after_a_group_deleted_a_name_rebound_and_a_device_removed() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    // A group deleted: its people lose what it gave them.
    let fin = Reader::new(&api, Some(&p.fin), &p.name);
    assert_eq!(fin.get(&[], &fin.root()).status, 200);
    let r = api.delete(Some(&admin), &format!("/v1/projects/{}/groups/finance", p.name));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(invalid(&fin.get(&[], &fin.root())), "a deleted group's member's grant");
    // A group created under carol's name: the line naming carol now names
    // the (empty) group, and carol loses the folder.
    let carol = Reader::new(&api, Some(&p.carol), &p.name);
    assert!(carol.walk().iter().any(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PERSON_MARK)));
    p.admin.ok(&p.dir, &["group", "create", &p.carol.name]);
    assert!(invalid(&carol.get(&[], &carol.root())), "carol's grant, after her line was rebound to a group");
    let again = Reader::new(&api, Some(&p.carol), &p.name);
    assert!(!again.walk().iter().any(|(_, _, raw)| has_marker(&[(String::new(), raw.clone())], PERSON_MARK)));
    // A device removed by its person, everywhere (what `POST
    // /v1/devices/remove` does for the person's own device).
    let dev = Reader::new(&api, Some(&p.dev), &p.name);
    assert_eq!(dev.get(&[], &dev.root()).status, 200);
    // Retried as the routes are: every bump updates the one clock row, so
    // on YugabyteDB it may conflict with another test's (40001).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    while let Err(e) = hub.rt.block_on(
        sqlx::query("UPDATE devices SET removed_at = $1 WHERE signing_key = $2").bind(1i64).bind(p.dev.identity().verifying_hex()).execute(&hub.hub().db),
    ) {
        let retryable = matches!(&e, sqlx::Error::Database(d) if matches!(d.code().as_deref(), Some("40001" | "40P01")));
        assert!(retryable && std::time::Instant::now() < deadline, "{e:?}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(invalid(&dev.get(&[], &dev.root())), "a device its person removed");
}

/// Held up (S5 adversarial pass): a grant made while its person is being
/// removed from a group either has the narrower view, or is void once the
/// removal committed. Never the wider view, still valid.
#[test]
fn a_grant_racing_a_removal_never_outlives_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let fin_token = p.fin.token();
    let members = format!("/v1/projects/{}/groups/finance/members", p.name);
    let people = serde_json::json!({"people": [p.fin.name]});
    let wide = Reader::new(&api, Some(&p.fin), &p.name).root();
    let (mut wider, mut narrower) = (0, 0);
    for i in 0..32u64 {
        // Either side starts first, by 0 to 15 ms.
        let (wait_tips, wait_removal) = if i % 2 == 0 { (i % 16, 0) } else { (0, i % 6) };
        let (tips, removed) = std::thread::scope(|s| {
            let t = s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(wait_tips));
                api.tips(Some(&fin_token), &p.name).unwrap()
            });
            let r = s.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(wait_removal));
                api.post_json(Some(&admin), &format!("{members}/remove"), &people)
            });
            (t.join().unwrap(), r.join().unwrap())
        });
        assert_eq!(removed.status, 200, "{}", String::from_utf8_lossy(&removed.body));
        let r = Reader {
            api: &api,
            project: p.name.clone(),
            id: Some(p.fin.identity()),
            grant: tips.grants["main"].clone(),
            key: tips.grant_key.clone().unwrap(),
        };
        if r.root() == wide {
            wider += 1;
            assert!(invalid(&r.get(&[], &r.root())), "round {i}: a grant with finance's view outlived fin's removal");
        } else {
            narrower += 1;
        }
        let back = api.post_json(Some(&admin), &members, &people);
        assert_eq!(back.status, 200, "{}", String::from_utf8_lossy(&back.body));
    }
    eprintln!("racing grants: {wider} with the wider view (all void), {narrower} with the narrower one");
}
