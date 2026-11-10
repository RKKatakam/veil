//! Phase 2 deep security review (`p2review`): cross-milestone guarantees
//! across S3 (thin clones), S4 (request caches), S5 (read grants & epochs),
//! S6 (Veil daemon), S7 (watcher), S8 (first-read workspaces & sandbox socket),
//! S9 (regional cache), S10 (API commits), S11 (agent sessions & narrowing),
//! S27/S28/S29 (compressed objects, packs & range reads, pack merge & GC),
//! and their interactions with S17–S22 and S24.
//!
//! Every test asserts its setup/action succeeded first before checking safety,
//! isolation, or bounds. Ignored reproductions (`BUG-1780` to `BUG-1786`) fail
//! today on the confirmed cross-milestone bugs recorded in `docs/BUGS.md`.

use std::{
    collections::HashSet,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::{Duration, Instant},
};

use serde_json::{json, Value};
use veil_core::{
    hub::{
        grant::{sign_request, BatchRequest, ChainWant, Grant, MAX_CHAIN},
        wire::MAX_WANTS,
    },
    object::Object,
    Identity, ObjectId,
};
use veil_server::{
    cache,
    limits::Settings,
    pack_gc::{self, Options},
};

use crate::support::*;

// ---- shared helpers ----------------------------------------------------------------

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

fn agent_token(hub: &TestHub, person_tok: &str, project: &str, only: &[&str]) -> String {
    let r = hub.api().post_json(
        Some(person_tok),
        "/v1/sessions/agent",
        &json!({
            "project": project,
            "attribution": {"agent": "claude-opus/5.5", "task": "P2-REVIEW", "run": "r-1"},
            "only": only,
        }),
    );
    assert_eq!(r.status, 200, "mint agent session: {}", body(&r));
    r.json()["token"].as_str().unwrap().to_string()
}

fn ci_token(hub: &TestHub, person_tok: &str, project: &str, only: &[&str]) -> String {
    let r = hub.api().post_json(
        Some(person_tok),
        "/v1/sessions/ci",
        &json!({
            "project": project,
            "only": only,
            "attribution": {"agent": "ci-runner/1.0", "run": "ci-1"},
        }),
    );
    assert_eq!(r.status, 200, "mint ci session: {}", body(&r));
    r.json()["token"].as_str().unwrap().to_string()
}

/// Format millisecond UTC timestamp as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`) for `vl merge --until`.
fn iso_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn parse_embargo_id(out: &str) -> String {
    for word in out.split_whitespace() {
        let clean = word.trim_end_matches(':');
        if clean.len() == 10 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return clean.to_string();
        }
    }
    panic!("no embargo id in output: {out}");
}

struct TestCache {
    _running: cache::Running,
    api: Api,
    dir: tempfile::TempDir,
}

impl TestCache {
    fn start(hub: &TestHub) -> TestCache {
        let dir = tempfile::Builder::new().prefix("veil-p2-cache").tempdir().unwrap();
        let token = std::fs::read_to_string(hub.ca.parent().unwrap().join("hub-cache-token")).unwrap();
        let running = hub
            .rt
            .block_on(cache::start(cache::Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstream: format!("https://{}", hub.authority()),
                upstream_ca: Some(hub.cert_pem.clone()),
                token,
                dir: dir.path().to_path_buf(),
                tls: veil_server::tls::TlsSource::SelfSigned,
                size: 64 << 20,
                memory: 32 << 20,
                max_connections: 256,
            }))
            .expect("regional cache starts");
        let api = Api::at(&running.addr.to_string(), &running.cert_pem);
        TestCache { _running: running, api, dir }
    }

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

struct DaemonGuard<'a> {
    who: &'a Person,
    socket: PathBuf,
    dir: PathBuf,
}

impl<'a> DaemonGuard<'a> {
    fn start(who: &'a Person) -> Self {
        let out = who.ok(who.home.path(), &["daemon", "start"]);
        assert!(out.contains("the Veil daemon runs"), "{out}");
        let dir = who.home.path().join("veil/daemon");
        Self { who, socket: dir.join("sock"), dir }
    }

    fn ask(&self, req: &Value) -> (Vec<(ObjectId, Vec<u8>)>, Value) {
        let mut s = UnixStream::connect(&self.socket).expect("connect daemon socket");
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut payload = vec![1u8];
        payload.extend_from_slice(&serde_json::to_vec(req).unwrap());
        let mut msg = vec![b'Q'];
        msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        msg.extend_from_slice(&payload);
        s.write_all(&msg).unwrap();
        let mut got = Vec::new();
        loop {
            let mut head = [0u8; 5];
            s.read_exact(&mut head).unwrap();
            let len = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).unwrap();
            match head[0] {
                b'A' | b'P' => {}
                b'O' => {
                    let id = ObjectId(buf[..32].try_into().unwrap());
                    got.push((id, buf[32..].to_vec()));
                }
                b'E' => return (got, serde_json::from_slice(&buf).unwrap()),
                other => panic!("unexpected daemon tag {other}"),
            }
        }
    }

    fn store_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![self.dir.join("store")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.file_type().unwrap().is_dir() {
                    stack.push(e.path());
                } else {
                    out.push((e.path().display().to_string(), stored_bytes(&e.path())));
                }
            }
        }
        out
    }
}

impl Drop for DaemonGuard<'_> {
    fn drop(&mut self) {
        let _ = self.who.run(self.who.home.path(), &["daemon", "stop"]);
    }
}

fn signed_object_get(
    via: &Api,
    project: &str,
    grant: &str,
    grant_key: &str,
    signer: Option<&Identity>,
    chain: &[ObjectId],
    id: &ObjectId,
    extra: &[(&str, &str)],
) -> Reply {
    let ts = veil_core::now_millis();
    let sig = Grant::verify(grant, grant_key).and_then(|g| signer.map(|i| format!("{ts}.{}", sign_request(i, &g, ts, &[*id]))));
    let chain_s = chain.iter().map(|c| c.hex()).collect::<Vec<_>>().join(",");
    let mut headers: Vec<(&str, &str)> = vec![("veil-grant", grant), ("veil-chain", &chain_s)];
    if let Some(s) = &sig {
        headers.push(("veil-signature", s));
    }
    headers.extend_from_slice(extra);
    via.get_with(&format!("/v1/objects/{project}/{}", id.hex()), &headers)
}

fn signed_object_batch(
    via: &Api,
    project: &str,
    grant: &str,
    grant_key: &str,
    signer: Option<&Identity>,
    wants: &[(Vec<ObjectId>, ObjectId)],
) -> Reply {
    let ts = veil_core::now_millis();
    let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
    let signature = Grant::verify(grant, grant_key).and_then(|g| signer.map(|i| sign_request(i, &g, ts, &ids)));
    let req = BatchRequest {
        grant: grant.to_string(),
        ts,
        signature,
        wants: wants.iter().map(|(c, id)| ChainWant { chain: c.clone(), id: *id }).collect(),
        skip: vec![],
    };
    via.post_json(None, &format!("/v1/objects/{project}:batch"), &serde_json::to_value(&req).unwrap())
}

// ============================================================================
// Guarantee 1–6 Positive + Cross-Milestone Interaction Tests (Held Paths)
// ============================================================================

/// Guarantee 1 (held read paths): across direct fetch, `history`, S3 thin-clone
/// fetch, S6 daemon, S9 regional cache, S8 workspace first-read, S28 packs and
/// range reads, and S10 API commit reads — before and after S29 pack merge —
/// a viewer (`dev`), narrowed agent session, CI runner, and anonymous caller
/// each read only what projection + narrowing allow, and never any hidden marker.
#[test]
fn g1_all_phase2_read_routes_enforce_projection_narrowing_and_pack_merge() {
    const API_IN: &str = "MARKER-P2-API-INSIDE-71a0";
    const API_OUT: &str = "MARKER-P2-API-OUTSIDE-82b1";
    const PACK_BILL: &str = "MARKER-P2-PACKED-BILL-93c2";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    // Create two multi-file pushes (>= 16 objects each so S28 writes packs) + one S10 API commit.
    let mut batch1 = Vec::new();
    for i in 0..18 {
        batch1.push((format!("src/api/f{i}.rs"), format!("{API_IN} {i}\n")));
    }
    batch1.push(("src/other/out.rs".into(), format!("{API_OUT}\n")));
    batch1.push((format!("{BILL_DIR}/packed.txt"), format!("{PACK_BILL}\n")));
    let refs1: Vec<(&str, &str)> = batch1.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&p.dir, &refs1);
    p.admin.commit_main(&p.dir, "packed push 1");
    p.admin.ok(&p.dir, &["push"]);

    let mut batch2 = Vec::new();
    for i in 0..18 {
        batch2.push((format!("src/api/g{i}.rs"), format!("{API_IN} g{i}\n")));
    }
    let refs2: Vec<(&str, &str)> = batch2.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&p.dir, &refs2);
    p.admin.commit_main(&p.dir, "packed push 2");
    p.admin.ok(&p.dir, &["push"]);

    // S10 API commit on top of `main`.
    let admin_tok = p.admin.token();
    let main_tip = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let c_res = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "s10 api commit",
            "edits": [{"path": "src/api/s10.rs", "put": {"text": format!("{API_IN} s10\n")}}],
            "onto": {"branch": "main", "expected": main_tip.hex()}
        }),
    );
    assert_eq!(c_res.status, 200, "S10 commit succeeded: {}", body(&c_res));
    assert_eq!(c_res.json()["branch"]["status"], "ok");

    // Collect admin's real billing blob ID to attempt direct object/fetch/daemon/cache reads.
    let admin_paths = real_paths(&p.dir);
    let (_, bill_blob_id) = admin_paths
        .iter()
        .find(|(path, _)| path == &format!("{BILL_DIR}/packed.txt"))
        .expect("billing file in admin tree");
    let bill_blob_id = *bill_blob_id;

    // Run S29 pack merge across the listed packs and confirm packs merged cleanly.
    let merge_rep = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 2,
                run_gc: false,
                pack_grace_ms: 0,
                ..Options::default()
            },
        ))
        .unwrap();
    assert!(merge_rep.packs_merged >= 2, "S29 merged packs: {merge_rep:?}");

    let rcache = TestCache::start(&hub);
    let dev_daemon = DaemonGuard::start(&p.dev);

    let dev_tok = p.dev.token();
    let agent_tok = agent_token(&hub, &dev_tok, &p.name, &["src/api"]);
    let runner_tok = ci_token(&hub, &dev_tok, &p.name, &["src/api"]);

    let mut forbidden: Vec<&str> = restricted_markers();
    forbidden.push(PACK_BILL);

    // 1. Viewer (`dev`) & Anonymous (`None`): grants, range reads, S9 regional cache, S6 daemon, S3 thin clone, S8 workspace.
    for (label, who) in [("dev", Some(&p.dev)), ("anon", None)] {
        let tok = who.map(|u| u.token());
        let tips = api.tips(tok.as_deref(), &p.name).expect("tips");
        let tip = tips.branches["main"];
        let grant = tips.grants.get("main").expect("viewer grant");
        let gkey = tips.grant_key.as_ref().unwrap();
        let root = Grant::read_unverified(grant).unwrap().root;
        let id_ref = who.map(|u| u.identity());

        // Positive read via S9 regional cache + S28 range read (`Range: bytes=0-15`).
        let r_root = signed_object_get(&rcache.api, &p.name, grant, gkey, id_ref.as_ref(), &[], &root, &[]);
        assert_eq!(r_root.status, 200, "{label} root via S9: {}", body(&r_root));
        let Object::Tree(t_root) = Object::decode(&r_root.body).unwrap() else { panic!() };
        let src_id = t_root.get("src").unwrap().id;
        let r_src = signed_object_get(&rcache.api, &p.name, grant, gkey, id_ref.as_ref(), &[root], &src_id, &[]);
        let Object::Tree(t_src) = Object::decode(&r_src.body).unwrap() else { panic!() };
        let api_dir_id = t_src.get("api").unwrap().id;
        let r_api = signed_object_get(&rcache.api, &p.name, grant, gkey, id_ref.as_ref(), &[root, src_id], &api_dir_id, &[]);
        let Object::Tree(t_api) = Object::decode(&r_api.body).unwrap() else { panic!() };
        let f0_id = t_api.get("f0.rs").unwrap().id;

        // S28 range read of packed blob on server.
        let r_range = signed_object_get(
            &api,
            &p.name,
            grant,
            gkey,
            id_ref.as_ref(),
            &[root, src_id, api_dir_id],
            &f0_id,
            &[("range", "bytes=0-15")],
        );
        assert_eq!(r_range.status, 206, "{label} range read: {}", body(&r_range));
        assert_eq!(r_range.body.len(), 16);

        // Negative: hidden billing blob is unreachable via server object GET, S9 cache batch, and `/fetch`.
        let bad_get = signed_object_get(&api, &p.name, grant, gkey, id_ref.as_ref(), &[root], &bill_blob_id, &[]);
        assert_eq!(bad_get.status, 404, "{label} direct object GET of billing blob");
        let bad_cache = signed_object_batch(&rcache.api, &p.name, grant, gkey, id_ref.as_ref(), &[(vec![root], bill_blob_id)]);
        assert!(bad_cache.frames().is_empty(), "{label} S9 cache batch must omit billing blob");
        let bad_fetch = api.post_json(
            tok.as_deref(),
            &format!("/v1/projects/{}/fetch", p.name),
            &json!({"snapshot": tip.hex(), "objects": [{"path": format!("{BILL_DIR}/packed.txt"), "id": bill_blob_id.hex()}]}),
        );
        assert_eq!(bad_fetch.status, 404, "{label} /fetch billing blob");

        let hist = api.post_json(tok.as_deref(), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip.hex()]}));
        assert_eq!(hist.status, 200);
        let items: Vec<(String, Vec<u8>)> = hist.frames().into_iter().map(|(i, b)| (i.hex(), b)).collect();
        assert_no_marker(&items, &forbidden, label);
    }

    // S6 daemon + S3 thin clone + S8 workspace first-read for `dev`.
    let dev_thin = p.dev.dir("thin-g1");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_thin.to_str().unwrap()]);
    p.dev.ok(&dev_thin, &["ws", "new", "w1", "-r", "main"]);
    assert_no_marker(&everything_in(&dev_thin), &forbidden, "dev thin clone before ws exec");
    let exec_out = p.dev.ok(&dev_thin, &["ws", "exec", "w1", "--", "cat", "src/api/s10.rs"]);
    assert!(exec_out.contains(API_IN), "S8 workspace read S10 file: {exec_out}");
    {
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&dev_thin)), None, "test").unwrap();
        let mut held = Vec::new();
        for id in repo.store().list_objects().unwrap() {
            if let Ok(raw) = repo.store().get_raw(&id) {
                held.push((format!("obj {id}"), raw));
            }
        }
        if let Some(c) = repo.store().cache() {
            for id in c.list_objects().unwrap() {
                if let Ok(raw) = c.get_raw(&id) {
                    held.push((format!("cached {id}"), raw));
                }
            }
        }
        assert_no_marker(&held, &forbidden, "dev thin clone + workspace objects");
    }
    assert_no_marker(&dev_daemon.store_files(), &forbidden, "dev S6 daemon store");

    // 2. Narrowed S11 agent session & S19 CI runner (`--only src/api`):
    for (label, tok) in [("narrowed-agent", &agent_tok), ("narrowed-ci-runner", &runner_tok)] {
        let tips = api.tips(Some(tok), &p.name).expect("narrowed tips");
        assert!(tips.grants.is_empty(), "{label} must receive no grants");
        let ok_q = api.get(Some(tok), &format!("/v1/projects/{}/q/file?path=src/api/s10.rs", p.name));
        assert_eq!(ok_q.status, 200, "{label} reads inside narrowing: {}", body(&ok_q));
        assert!(body(&ok_q).contains(API_IN));

        for outside in ["src/other/out.rs", &format!("{BILL_DIR}/packed.txt"), ROOT_FILE] {
            let r = api.get(Some(tok), &format!("/v1/projects/{}/q/file?path={outside}", p.name));
            assert_ne!(r.status, 200, "{label} must not read {outside}");
            assert!(!body(&r).contains(API_OUT) && !body(&r).contains(PACK_BILL));
        }
    }
}

/// Guarantee 2 (held access-removal & staging paths): S28 staged packs are never
/// served before push commits them; after access removal, the server's S4/S5
/// caches refuse immediately and both S9 regional cache and S6 daemon stop
/// serving warm cached objects within the 5 s epoch bound.
#[test]
fn g2_caches_and_staged_packs_never_outlive_access_beyond_epoch_bound() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let rcache = TestCache::start(&hub);
    let fin_daemon = DaemonGuard::start(&p.fin);

    // 1. Upload >= 16 blobs without pushing -> S28 stages a pack (`state = 0`).
    // Verify neither `/v1/objects/...` nor S9 cache serves staged objects.
    let mut staged = Vec::new();
    for i in 0..18 {
        let raw = Object::Blob(format!("STAGED-UNCOMMITTED-{i}").into_bytes()).encode();
        staged.push((ObjectId::hash(&raw), raw));
    }
    let up = api.upload(&p.admin.token(), &p.name, &staged);
    assert_eq!(up.status, 200, "staged upload succeeded: {}", body(&up));
    let admin_tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    let admin_grant = admin_tips.grants.get("main").unwrap();
    let gkey = admin_tips.grant_key.as_ref().unwrap();
    let admin_root = Grant::read_unverified(admin_grant).unwrap().root;
    let admin_id = p.admin.identity();
    let r_staged = signed_object_get(&api, &p.name, admin_grant, gkey, Some(&admin_id), &[admin_root], &staged[0].0, &[]);
    assert_eq!(r_staged.status, 404, "uncommitted staged pack object must not be served");

    // 2. Warm both S9 regional cache and `fin`'s S6 daemon with `fin`'s billing blob.
    let fin_tips = api.tips(Some(&p.fin.token()), &p.name).unwrap();
    let fin_grant = fin_tips.grants.get("main").unwrap().clone();
    let fin_root = Grant::read_unverified(&fin_grant).unwrap().root;
    let fin_id = p.fin.identity();

    let r_root = signed_object_get(&rcache.api, &p.name, &fin_grant, gkey, Some(&fin_id), &[], &fin_root, &[]);
    assert_eq!(r_root.status, 200);
    let Object::Tree(t_root) = Object::decode(&r_root.body).unwrap() else { panic!() };
    let bill_dir_id = t_root.get(BILL_DIR).expect("fin sees billing dir").id;
    let r_bill = signed_object_get(&rcache.api, &p.name, &fin_grant, gkey, Some(&fin_id), &[fin_root], &bill_dir_id, &[]);
    assert_eq!(r_bill.status, 200);
    let Object::Tree(t_bill) = Object::decode(&r_bill.body).unwrap() else { panic!() };
    let acme_id = t_bill.get("acme").unwrap().id;
    let r_acme = signed_object_get(&rcache.api, &p.name, &fin_grant, gkey, Some(&fin_id), &[fin_root, bill_dir_id], &acme_id, &[]);
    let Object::Tree(t_acme) = Object::decode(&r_acme.body).unwrap() else { panic!() };
    let inv_id = t_acme.get("invoice.txt").unwrap().id;
    let chain = vec![fin_root, bill_dir_id, acme_id];

    // Warm S9 regional cache and assert billing content arrived first.
    let warm_s9 = signed_object_get(&rcache.api, &p.name, &fin_grant, gkey, Some(&fin_id), &chain, &inv_id, &[]);
    assert_eq!(warm_s9.status, 200);
    assert!(body(&warm_s9).contains(BILL_MARK), "S9 served billing object before revocation");

    // Warm S6 daemon and assert billing content arrived first.
    let ts = veil_core::now_millis();
    let g_ver = Grant::verify(&fin_grant, gkey).unwrap();
    let batch_req = BatchRequest {
        grant: fin_grant.clone(),
        ts,
        signature: Some(sign_request(&fin_id, &g_ver, ts, &[fin_root, bill_dir_id, acme_id, inv_id])),
        wants: vec![
            ChainWant { chain: vec![], id: fin_root },
            ChainWant { chain: vec![fin_root], id: bill_dir_id },
            ChainWant { chain: vec![fin_root, bill_dir_id], id: acme_id },
            ChainWant { chain: chain.clone(), id: inv_id },
        ],
        skip: vec![],
    };
    let (daemon_got, daemon_end) = fin_daemon.ask(&json!({
        "op": "batch",
        "upstream": hub.authority(),
        "project": p.name,
        "batch": batch_req,
    }));
    assert!(daemon_end["status"].is_null(), "S6 daemon served before revocation: {daemon_end}");
    assert!(daemon_got.iter().any(|(i, _)| *i == inv_id), "S6 cached invoice.txt");

    // 3. Remove `fin` from `finance`: server refuses IMMEDIATELY, S9 and S6 refuse within 5 s!
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let removed_at = Instant::now();

    // Server S4/S5 refuses immediately on the very next request (`401 grant_invalid`).
    let srv_after = signed_object_get(&api, &p.name, &fin_grant, gkey, Some(&fin_id), &chain, &inv_id, &[]);
    assert_eq!(srv_after.status, 401, "server refuses stale grant immediately: {}", body(&srv_after));
    let q_after = api.get(Some(&p.fin.token()), &format!("/v1/projects/{}/q/file?path={BILL_DIR}/acme/invoice.txt", p.name));
    assert_eq!(q_after.status, 404, "S4 perm cache invalidated immediately");

    // Poll S9 and S6 until epoch feed propagates; assert elapsed <= 5.5 s (5 s bound + request slack).
    let mut s9_refused = false;
    let mut s6_refused = false;
    while removed_at.elapsed() < Duration::from_millis(5500) {
        if !s9_refused {
            let r = signed_object_get(&rcache.api, &p.name, &fin_grant, gkey, Some(&fin_id), &chain, &inv_id, &[]);
            if r.status == 401 || r.status == 403 {
                s9_refused = true;
            }
        }
        if !s6_refused {
            let ts2 = veil_core::now_millis();
            let req2 = BatchRequest {
                grant: fin_grant.clone(),
                ts: ts2,
                signature: Some(sign_request(&fin_id, &g_ver, ts2, &[inv_id])),
                wants: vec![ChainWant { chain: chain.clone(), id: inv_id }],
                skip: vec![],
            };
            let (got2, end2) = fin_daemon.ask(&json!({
                "op": "batch",
                "upstream": hub.authority(),
                "project": p.name,
                "batch": req2,
            }));
            if got2.is_empty() && !end2["status"].is_null() {
                s6_refused = true;
            }
        }
        if s9_refused && s6_refused {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(s9_refused, "S9 regional cache stopped serving revoked object within 5 s bound");
    assert!(s6_refused, "S6 daemon stopped serving revoked object within 5 s bound");
}

/// Guarantee 3 (held narrowing paths): a narrowed S11 agent session cannot mint
/// wider sessions, gets no S5 grants (so S6/S9 grant routes are unavailable),
/// cannot land an out-of-scope change (`BUG-1636`), cannot push or API-commit
/// outside `--only` or to `.veilpolicy`/`.veilrules`, and inside S8's sandbox
/// socket (`vl ws exec`) cannot run `session`, `access`, or `push`.
#[test]
fn g3_narrowed_agent_session_cannot_widen_via_grants_sessions_stack_on_or_sandbox() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();

    write_files(&p.dir, &[("src/api/mod.rs", "pub fn ok() {}\n"), ("src/core/lib.rs", "pub fn secret_core() {}\n")]);
    p.admin.commit_main(&p.dir, "add api and core");
    p.admin.ok(&p.dir, &["push"]);

    let admin_tok = p.admin.token();
    let main_tip = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];

    // Person creates an out-of-scope unlanded S10 change touching `src/core/lib.rs`.
    let out_change = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "person outside change",
            "edits": [{"path": "src/core/lib.rs", "put": {"text": "updated\n"}}]
        }),
    );
    assert_eq!(out_change.status, 200, "person creates outside change: {}", body(&out_change));
    let out_snap = out_change.json()["snapshot"].as_str().unwrap().to_string();

    // Narrowed agent session (`--only src/api`) for `admin`.
    let agent = agent_token(&hub, &admin_tok, &p.name, &["src/api"]);

    // Positive: agent commits inside `src/api` cleanly.
    let ok_commit = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "agent inside",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn v2() {}\n"}}]
        }),
    );
    assert_eq!(ok_commit.status, 200, "agent commits inside narrowing: {}", body(&ok_commit));

    // 1. Cannot mint a wider agent or CI session (`person_only`).
    let sub_agent = api.post_json(
        Some(&agent),
        "/v1/sessions/agent",
        &json!({"project": p.name, "attribution": {"agent": "sub"}, "only": []}),
    );
    assert_eq!(sub_agent.status, 403, "agent cannot mint sub-session: {}", body(&sub_agent));
    let sub_ci = api.post_json(Some(&agent), "/v1/sessions/ci", &json!({"project": p.name, "only": []}));
    assert_eq!(sub_ci.status, 403, "agent cannot mint CI session: {}", body(&sub_ci));

    // 2. Gets no grants in `tips`.
    assert!(api.tips(Some(&agent), &p.name).unwrap().grants.is_empty());

    // 3. Cannot land or move `main` onto person's out-of-scope change (`src/core/lib.rs`).
    let bad_land = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "snapshot": out_snap}),
    );
    assert_ne!(bad_land.status, 200, "agent cannot land outside change: {}", body(&bad_land));

    // 4. Cannot write `.veilpolicy` or `.veilrules` even on an un-narrowed agent session.
    let agent_full = agent_token(&hub, &admin_tok, &p.name, &[]);
    for protected_file in [".veilpolicy", ".veilrules", "src/api/.veilpolicy"] {
        let r = api.post_json(
            Some(&agent_full),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({
                "base": main_tip.hex(),
                "description": "touch policy",
                "edits": [{"path": protected_file, "put": {"text": "# hacked\n"}}]
            }),
        );
        assert_eq!(r.status, 403, "agent cannot write {protected_file}: {}", body(&r));
    }

    // 5. S8 workspace sandbox socket refuses `session`, `access`, `push`, and other workspaces.
    let clone = p.dev.dir("ws-g3");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), clone.to_str().unwrap()]);
    p.dev.ok(&clone, &["ws", "new", "sbx", "-r", "main"]);
    let out = p.dev.ok(
        &clone,
        &[
            "ws",
            "exec",
            "sbx",
            "--",
            "sh",
            "-c",
            "vl session agent --agent x 2>&1 || true; vl push 2>&1 || true; vl status",
        ],
    );
    assert!(out.contains("not available inside a sandbox"), "sandbox socket refused session/push: {out}");
}

/// Guarantee 4: Secrets (`.env`, keys) are stored only encrypted across server
/// loose/packed storage (S27/S28/S29), S9 regional cache, and S6 daemon store,
/// refused in plaintext via S10 API commits, and never served decrypted without
/// the key.
#[test]
fn g4_secrets_stay_encrypted_across_server_packs_regional_cache_and_daemon_store() {
    const P2_SEC: &str = "MARKER-P2-SUPER-SECRET-ENV-4499aa";
    const PLAIN_ATTEMPT: &str = "MARKER-P2-PLAINTEXT-ENV-REFUSED-1122";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    // 1. S10 API commit of a plaintext `.env` is refused (`403`) and never stored on the server.
    let admin_tok = p.admin.token();
    let tip0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let bad_env = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": tip0.hex(),
            "description": "try plaintext .env",
            "edits": [{"path": "src/.env", "put": {"text": format!("TOKEN={PLAIN_ATTEMPT}\n")}}]
        }),
    );
    assert_eq!(bad_env.status, 403, "S10 must refuse plaintext .env: {}", body(&bad_env));

    // 2. Push >= 16 files including a sealed `.env` in `BILL_DIR/.env`, then merge packs (S29).
    let mut files = vec![(format!("{BILL_DIR}/.env"), format!("API_SECRET={P2_SEC}\n"))];
    for i in 0..18 {
        files.push((format!("{BILL_DIR}/doc_{i}.txt"), format!("finance doc {i}\n")));
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    write_files(&p.dir, &refs);
    p.admin.commit_main(&p.dir, "sealed env in pack");
    p.admin.ok(&p.dir, &["push"]);

    let _ = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: false,
                pack_grace_ms: 0,
                ..Options::default()
            },
        ))
        .unwrap();

    // 3. `fin` (in `finance`) clones thinly with S6 daemon running -> decrypts `.env` locally!
    let fin_daemon = DaemonGuard::start(&p.fin);
    let fin_clone = p.fin.dir("fin-thin-g4");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), fin_clone.to_str().unwrap()]);
    let decrypted = std::fs::read_to_string(fin_clone.join(format!("{BILL_DIR}/.env"))).expect("fin checked out .env");
    assert!(decrypted.contains(P2_SEC), "fin with key decrypts .env locally: {decrypted}");

    // Warm S9 regional cache with `fin`'s entire reachable object graph.
    let rcache = TestCache::start(&hub);
    let fin_tips = api.tips(Some(&p.fin.token()), &p.name).unwrap();
    let fin_grant = fin_tips.grants.get("main").unwrap();
    let gkey = fin_tips.grant_key.as_ref().unwrap();
    let fin_root = Grant::read_unverified(fin_grant).unwrap().root;
    let fin_id = p.fin.identity();
    let mut stack = vec![(vec![], fin_root)];
    let mut seen = HashSet::new();
    while let Some((chain, id)) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let r = signed_object_get(&rcache.api, &p.name, fin_grant, gkey, Some(&fin_id), &chain, &id, &[]);
        assert_eq!(r.status, 200);
        if let Ok(Object::Tree(t)) = Object::decode(&r.body) {
            let mut next_chain = chain.clone();
            next_chain.push(id);
            for e in &t.entries {
                stack.push((next_chain.clone(), e.id));
            }
        }
    }

    // 4. Inspect raw/decoded object bytes on server storage, S9 regional cache, and S6 daemon store:
    // NONE may contain `ENV_MARK`, `P2_SEC`, or `PLAIN_ATTEMPT`!
    let secret_markers = [ENV_MARK, P2_SEC, PLAIN_ATTEMPT];

    // Server storage (every object & merged pack decoded via `stored_bytes` / `BlobStore`):
    let store = hub.hub().objects.blob_store().clone();
    let keys = hub.rt.block_on(store.list(&format!("p/{pid}/"))).unwrap();
    assert!(!keys.is_empty(), "server storage holds objects");
    let mut server_items = Vec::new();
    for k in keys {
        let raw = hub.rt.block_on(store.get(&k)).unwrap().unwrap().to_vec();
        if raw.starts_with(veil_server::pack::MAGIC) {
            let idx = veil_server::pack::parse_index(&raw, Some(raw.len() as u64)).unwrap();
            for (id, sl) in idx.iter() {
                let enc = veil_server::pack::entry(id, *sl, &raw[sl.offset as usize..=sl.last() as usize]).unwrap();
                let dec = veil_core::hub::encoding::decode(id, enc, u64::MAX).unwrap().into_owned();
                server_items.push((format!("pack {k} obj {id}"), dec));
            }
        } else {
            server_items.push((k, raw));
        }
    }
    assert_no_marker(&server_items, &secret_markers, "server storage & packs");
    assert_no_marker(&rcache.files(), &secret_markers, "S9 regional cache disk");
    assert_no_marker(&fin_daemon.store_files(), &secret_markers, "S6 daemon store");

    // 5. `dev`, anonymous, and narrowed agent cannot fetch the `finance` key ring.
    let agent = agent_token(&hub, &p.fin.token(), &p.name, &["src"]);
    for (who, tok) in [("dev", Some(p.dev.token())), ("anon", None), ("fin-agent-src", Some(agent))] {
        let rings = api.get(tok.as_deref(), &format!("/v1/projects/{}/rings/finance", p.name));
        assert_ne!(rings.status, 200, "{who} must not receive finance key ring: {}", body(&rings));
    }
}

/// Guarantee 5 (held GC retention paths): S29 `pack_gc` preserves unreferenced
/// objects inside `retention_window_ms` (for thin clones), active staged uploads,
/// S21 PR revisions, S22 unreleased embargo lines, S17/S18 queued landings, and
/// S19 CI check results.
#[test]
fn g5_pack_gc_retains_thin_window_staged_uploads_prs_embargoes_landings_and_ci() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let admin_tok = p.admin.token();

    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);

    // 1. S21 open PR on a branch subsequently deleted.
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let mut pr_c = Craft::new(&api, &p.admin, &p.name, "main");
    pr_c.file("src/pr_keep.rs", "KEEP-PR-S21\n");
    let (_client_pr_snap, pr_push) = pr_c.push_edited("pr-br", None, |_| {});
    assert_eq!(pr_push.status, 200, "push pr-br: {}", body(&pr_push));
    assert_eq!(pr_push.json()["results"][0]["ok"], json!(true), "push pr-br ok: {}", body(&pr_push));
    let pr_snap = ObjectId::from_hex(pr_push.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
    let pr_create = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"onto": "main", "head": pr_snap.hex(), "title": "keep me"}),
    );
    assert!(pr_create.status == 200 || pr_create.status == 201, "create PR: {}", body(&pr_create));
    // Delete `pr-br` so ONLY `prs`/`pr_revisions` holds `pr_snap`!
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "pr-br", "expected": pr_snap.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200);
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete pr-br ok: {}", body(&del));

    // 2. S22 unreleased embargo line.
    let sec_dir = p.sec.dir("emb-g5");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(&sec_dir, &[("src/emb_g5.rs", "KEEP-EMBARGO-S22\n")]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo g5"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    p.sec.ok(&sec_dir, &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "embargo"]);
    let emb_log = p.sec.ok(&sec_dir, &["log", "-r", "main", "-n", "1", "--json"]);
    let emb_snap = ObjectId::from_hex(serde_json::from_str::<Value>(&emb_log).unwrap()["entries"][0]["snapshot_id"].as_str().unwrap()).unwrap();
    p.sec.ok(&sec_dir, &["push"]);

    // 3. S17/S18 landing (`submitted` rebased onto advanced `main`, so `submitted != landed`
    // and once `change_refs` is cleared ONLY `landings.submitted` retains `land_submitted`).
    write_files(&p.dir, &[("src/advance_main.rs", "MAIN-MOVED\n")]);
    p.admin.commit_main(&p.dir, "advance main");
    p.admin.ok(&p.dir, &["push"]);
    let land_ch = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "base": main0.hex(),
            "onto": "main",
            "description": "landing rebase snap",
            "edits": [{"path": "src/land_keep.rs", "put": {"text": "KEEP-LANDING-S17\n"}}]
        }),
    );
    assert_eq!(land_ch.status, 200, "land onto advanced main: {}", body(&land_ch));
    let land_submitted_hex: String = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT submitted FROM landings WHERE project_id = $1 AND submitted <> landed LIMIT 1")
                .bind(pid)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    let land_submitted = ObjectId::from_hex(&land_submitted_hex).unwrap();

    // 4. S19 CI check result on an otherwise unreferenced snapshot (`onto: null`, `change_refs` cleared).
    let ci_ch = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main0.hex(),
            "description": "ci snap",
            "edits": [{"path": "src/ci_keep.rs", "put": {"text": "KEEP-CI-S19\n"}}]
        }),
    );
    assert_eq!(ci_ch.status, 200);
    let ci_snap = ObjectId::from_hex(ci_ch.json()["snapshot"].as_str().unwrap()).unwrap();
    let ci_post = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({"snapshot": ci_snap.hex(), "name": "unit", "state": "pass", "summary": "ok"}),
    );
    assert_eq!(ci_post.status, 200, "record check: {}", body(&ci_post));
    hub.rt
        .block_on(sqlx::query("DELETE FROM change_refs WHERE project_id = $1").bind(pid).execute(&hub.hub().db))
        .unwrap();

    // 5. Active staged upload (`packs.state = 0`) + truly dead loose object.
    let mut staged = Vec::new();
    for i in 0..18 {
        let raw = Object::Blob(format!("KEEP-STAGED-{i}").into_bytes()).encode();
        staged.push((ObjectId::hash(&raw), raw));
    }
    assert_eq!(api.upload(&admin_tok, &p.name, &staged).status, 200);

    let dead_raw = Object::Blob(b"DEAD-LOOSE-BLOB".to_vec()).encode();
    let dead_id = ObjectId::hash(&dead_raw);
    hub.rt.block_on(hub.hub().objects.put(pid, &dead_id, dead_raw.into())).unwrap();

    let fresh_objects = || {
        veil_server::store::Objects::with_db(
            hub.hub().objects.blob_store().clone(),
            1 << 10,
            Some(hub.hub().db.clone()),
        )
    };

    // Inside retention window (`60_000 ms`, `now_offset_ms = 0`): `dead_id` is retained for thin clones!
    let r_in = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 2,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 0,
                ..Options::default()
            },
        ))
        .unwrap();
    assert_eq!(r_in.loose_objects_deleted, 0);
    assert!(hub.rt.block_on(fresh_objects().exists(pid, &dead_id)).unwrap());

    // Past retention window (`now_offset_ms = 120_000`), while staged upload is still within `staged_ttl_ms` (1 h):
    let r_out = hub
        .rt
        .block_on(pack_gc::run_project(
            &hub.hub(),
            pid,
            &Options {
                min_packs_to_merge: 2,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 120_000,
                ..Options::default()
            },
        ))
        .unwrap();
    assert!(r_out.loose_objects_deleted >= 1, "dead loose object collected: {r_out:?}");
    let store_after = fresh_objects();
    assert!(!hub.rt.block_on(store_after.exists(pid, &dead_id)).unwrap(), "dead loose gone from persistent storage");
    for (why, id) in [
        ("S21 PR", pr_snap),
        ("S22 embargo", emb_snap),
        ("S17/S18 landing", land_submitted),
        ("S19 CI", ci_snap),
    ] {
        assert!(hub.rt.block_on(store_after.exists(pid, &id)).unwrap(), "{why} snapshot {id} must survive GC");
    }
    let staged_pack_name: Option<String> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = 0 LIMIT 1").bind(pid).fetch_optional(&hub.hub().db))
        .unwrap();
    let staged_pack_name = staged_pack_name.expect("pending staged pack row survives GC inside staged_ttl_ms");
    let staged_key = veil_server::pack::key(pid, &staged_pack_name);
    assert!(
        hub.rt.block_on(hub.hub().objects.blob_store().len(&staged_key)).unwrap().is_some(),
        "pending staged pack file {staged_key} must survive GC inside staged_ttl_ms"
    );
}

/// Guarantee 6 (held bounds): batch wants > `MAX_WANTS`, chains > `MAX_CHAIN`,
/// decompression bombs on object upload, and oversized S10 inline payloads are
/// each refused cleanly without unbounded allocation.
#[test]
fn g6_phase2_routes_enforce_batch_chain_upload_and_inline_bounds() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let tips = api.tips(None, &p.name).expect("public tips");
    let grant = tips.grants.get("main").unwrap();
    let gkey = tips.grant_key.as_ref().unwrap();
    let root = Grant::read_unverified(grant).unwrap().root;

    // Positive control: a 1-want batch succeeds.
    let ok_batch = signed_object_batch(&api, &p.name, grant, gkey, None, &[(vec![], root)]);
    assert_eq!(ok_batch.status, 200);
    assert_eq!(ok_batch.frames().len(), 1);

    // 1. Batch with `MAX_WANTS + 1` wants is refused (`400`).
    let too_many: Vec<(Vec<ObjectId>, ObjectId)> = (0..=MAX_WANTS).map(|_| (vec![], root)).collect();
    let r_many = signed_object_batch(&api, &p.name, grant, gkey, None, &too_many);
    assert_eq!(r_many.status, 400, "oversized batch refused: {}", body(&r_many));

    // 2. Object GET with chain length `MAX_CHAIN + 1` is refused (`404`).
    let deep_chain = vec![root; MAX_CHAIN + 1];
    let r_deep = signed_object_get(&api, &p.name, grant, gkey, None, &deep_chain, &root, &[]);
    assert_eq!(r_deep.status, 404, "over-deep chain refused: {}", body(&r_deep));

    // 3. Corrupted / malformed zstd compressed frame on upload is refused (`400`).
    let mut bad_frame = Vec::new();
    let fake_id = ObjectId::hash(b"not-this");
    veil_core::hub::wire::put_frame(&mut bad_frame, &fake_id, &[veil_core::hub::encoding::ZSTD, 0xff, 0x00, 0x01, 0x02]);
    let r_bomb = api.upload_encoded_body(&p.admin.token(), &p.name, &bad_frame);
    assert_eq!(r_bomb.status, 400, "malformed compressed frame refused: {}", body(&r_bomb));
}

// ============================================================================
// Ignored Failing Bug Reproductions (`BUG-1780` to `BUG-1786`)
// ============================================================================

/// Run a complete S29 GC cycle: pass 1 marks newly unreferenced objects in
/// `unreferenced_objects`, pass 2 rewrites packs / deletes loose objects past
/// `retention_window_ms`, and pass 3 sweeps `DISCARDED` packs from storage.
fn run_full_gc(hub: &TestHub, pid: i64) -> pack_gc::Report {
    for off in [0i64, 120_000, 120_001] {
        let rep = hub
            .rt
            .block_on(pack_gc::run_project(
                &hub.hub(),
                pid,
                &Options {
                    min_packs_to_merge: 1,
                    run_gc: true,
                    retention_window_ms: 60_000,
                    pack_grace_ms: 0,
                    now_offset_ms: off,
                    ..Options::default()
                },
            ))
            .unwrap();
        if off == 120_000 {
            let _ = hub
                .rt
                .block_on(pack_gc::run_project(
                    &hub.hub(),
                    pid,
                    &Options {
                        min_packs_to_merge: 2,
                        run_gc: true,
                        retention_window_ms: 60_000,
                        pack_grace_ms: 0,
                        now_offset_ms: 120_001,
                        ..Options::default()
                    },
                ))
                .unwrap();
            return rep;
        }
    }
    unreachable!()
}

/// BUG-1780 (blocking): S29 `pack_gc` deletes unreferenced snapshots, trees, and
/// blobs past `retention_window_ms` while leaving `snapshots` and `projections`
/// rows and S4's `hub.caches` (`committed`, `memo`, `resolved`) intact. When a
/// client later re-uploads those objects (`POST .../objects` -> `200 OK`) and
/// pushes a branch to that snapshot (`POST .../push` -> `200 OK`), `sync::push`
/// sees the stale `snapshots` / `hub.caches.committed` entry, skips `complete`,
/// **discards the newly uploaded staged pack**, and points the branch at missing
/// storage objects — causing every read/clone/query of the branch to fail with
/// `500 Internal Server Error`.
#[test]
#[ignore = "BUG-1780: pack_gc deletes snapshot/tree/blob objects while leaving snapshots/projections rows and S4 caches intact, discarding re-uploads and leaving branches dangling (500)"]
fn bug_1780_pack_gc_leaves_stale_db_and_s4_caches_causing_repush_data_loss_and_500() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let admin_tok = p.admin.token();

    // 1. Craft and push a new commit `snap_id` on branch `scratch`, saving all uploaded objects.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    for i in 0..18 {
        c.file(&format!("src/repush_{i}.txt"), &format!("BUG-1780-CONTENT-{i}\n"));
    }
    let mut saved_objects = c.objects.clone();
    let (_client_snap_id, push1) = c.push_edited("scratch", None, |_| {});
    assert_eq!(push1.status, 200, "initial push succeeded: {}", body(&push1));
    assert_eq!(push1.json()["results"][0]["ok"], json!(true), "initial push ok: {}", body(&push1));
    let snap_id = ObjectId::from_hex(push1.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
    let (_, snap_raw) = api.history(&admin_tok, &p.name, &[snap_id]).frames().into_iter().find(|(id, _)| *id == snap_id).unwrap();
    saved_objects.push((snap_id, snap_raw));

    // Confirm `scratch` is readable before deletion.
    let q_before = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev=scratch&path=src/repush_0.txt", p.name));
    assert_eq!(q_before.status, 200, "readable before GC: {}", body(&q_before));
    assert!(body(&q_before).contains("BUG-1780-CONTENT-0"));

    // 2. Delete branch `scratch` and run full S29 `pack_gc` past retention window.
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "scratch", "expected": snap_id.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200);
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete scratch ok: {}", body(&del));
    let gc_rep = run_full_gc(&hub, pid);
    assert!(gc_rep.packed_objects_deleted + gc_rep.loose_objects_deleted >= 1, "GC reclaimed scratch's objects: {gc_rep:?}");

    // 3. Re-upload ALL objects of `snap_id` fresh via `POST .../objects` and push branch `revived` -> `snap_id`.
    let reup = api.upload(&admin_tok, &p.name, &saved_objects);
    assert_eq!(reup.status, 200, "re-upload succeeded: {}", body(&reup));
    let receipts = reup.json()["receipts"].as_array().unwrap().clone();
    let rmap: serde_json::Map<String, Value> = saved_objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();

    let push2 = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [{"branch": "revived", "expected": null, "new": snap_id.hex()}],
            "receipts": rmap,
        }),
    );
    assert_eq!(push2.status, 200, "re-push HTTP 200: {}", body(&push2));
    assert_eq!(push2.json()["results"][0]["ok"], json!(true), "server accepted branch `revived`: {}", body(&push2));

    // 4. Every read of `revived` from persistent storage (peer server or after `Objects::cache` eviction)
    // must succeed (`200 OK`) — FAILS today with `500 Internal Server Error` because `hub` discarded the re-upload!
    let hub2 = TestHub::beside(&hub);
    let q_after = hub2.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev=revived&path=src/repush_0.txt", p.name));
    assert_eq!(q_after.status, 200, "reading `revived` after re-upload + push failed: {}", body(&q_after));
    assert!(body(&q_after).contains("BUG-1780-CONTENT-0"));
}

/// BUG-1781 (blocking): `hub.grants.stored` memoizes `(project_id, root_tree)`
/// across S29 `pack_gc` sweeps without invalidation. Because rewritten projected
/// trees (`pr.created`) are written to storage ONLY by `grant_root` (`grant.rs:193`),
/// when a branch is deleted and `pack_gc` collects that loose projected root tree
/// `T_proj`, a subsequent commit with the same visible tree (and different hidden
/// edits) hits `hub.grants.stored`, skips writing `T_proj`, and issues a signed
/// grant whose `root` is missing from storage — breaking S3/S5/S6/S8/S9 object
/// reads (`404`) for non-admin viewers.
#[test]
#[ignore = "BUG-1781: hub.grants.stored caches projected root tree existence across pack_gc, issuing grants whose root tree was deleted (404 on object reads)"]
fn bug_1781_grants_stored_cache_outlives_pack_gc_breaking_object_reads() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let dev_id = p.dev.identity();

    // 1. Admin creates branch `b1` touching both `src/visible_1781.txt` and hidden `BILL_DIR/h1.txt`.
    let mut c1 = Craft::new(&api, &p.admin, &p.name, "main");
    c1.file("src/visible_1781.txt", "VISIBLE-1781\n");
    c1.file(&format!("{BILL_DIR}/h1.txt"), "HIDDEN-V1\n");
    let (_client_s1, r1) = c1.push_edited("b1", None, |_| {});
    assert_eq!(r1.status, 200);
    assert_eq!(r1.json()["results"][0]["ok"], json!(true), "push b1 ok: {}", body(&r1));
    let b1_tip = ObjectId::from_hex(r1.json()["results"][0]["tip"].as_str().unwrap()).unwrap();

    // 2. `dev` gets `tips` (populating `hub.grants.stored` for `T_proj`) and reads `T_proj` (`200 OK`).
    let tips1 = api.tips(Some(&dev_tok), &p.name).unwrap();
    let g1 = tips1.grants.get("b1").expect("dev grant for b1");
    let gkey = tips1.grant_key.as_ref().unwrap();
    let t_proj = Grant::read_unverified(g1).unwrap().root;
    let read1 = signed_object_get(&api, &p.name, g1, gkey, Some(&dev_id), &[], &t_proj, &[]);
    assert_eq!(read1.status, 200, "dev reads projected root tree before GC: {}", body(&read1));

    // 3. Admin deletes `b1`, and S29 `pack_gc` collects loose `t_proj` past retention window.
    let del = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "b1", "expected": b1_tip.hex(), "new": null}], "force": true}),
    );
    assert_eq!(del.status, 200);
    assert_eq!(del.json()["results"][0]["ok"], json!(true), "delete b1 ok: {}", body(&del));
    let gc_rep = run_full_gc(&hub, pid);
    assert!(gc_rep.loose_objects_deleted >= 1, "loose projected root tree deleted by GC: {gc_rep:?}");

    // 4. Admin pushes a brand-new commit `s2` on `b2` with the SAME visible tree (`src/visible_1781.txt`)
    // and a DIFFERENT hidden billing file (`BILL_DIR/h2.txt`).
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.file("src/visible_1781.txt", "VISIBLE-1781\n");
    c2.file(&format!("{BILL_DIR}/h2.txt"), "HIDDEN-V2\n");
    let (_s2, r2) = c2.push_edited("b2", None, |_| {});
    assert_eq!(r2.status, 200);
    assert_eq!(r2.json()["results"][0]["ok"], json!(true), "push b2 ok: {}", body(&r2));

    // 5. `dev` fetches `tips` for `b2` from `hub` (which hits `hub.grants.stored` and skips re-writing
    // `t_proj` to shared storage), then reads `t_proj` from a peer server (`hub2`) — FAILS today with `404`!
    let tips2 = api.tips(Some(&dev_tok), &p.name).unwrap();
    let g2 = tips2.grants.get("b2").expect("dev grant for b2");
    assert_eq!(Grant::read_unverified(g2).unwrap().root, t_proj);
    let hub2 = TestHub::beside(&hub);
    let read2 = signed_object_get(&hub2.api(), &p.name, g2, gkey, Some(&dev_id), &[], &t_proj, &[]);
    assert_eq!(read2.status, 200, "dev's fresh grant for b2 cannot read its own root tree: {}", body(&read2));
}

/// BUG-1782 (blocking): S29 `pack_gc::collect_db_roots` and `read_ref_stamp`
/// ignore S20's `bisects` and `bisect_reverts` tables completely. When a bisect
/// records `candidates` or `revert_snapshot` and the branch later moves/resets,
/// `pack_gc` deletes those snapshots from storage — losing the S20 revert and
/// causing `GET /v1/projects/{p}/bisect/{branch}` to fail with `500`.
#[test]
#[ignore = "BUG-1782: pack_gc ignores bisects and bisect_reverts tables, deleting bisect candidates and revert_snapshot objects and breaking GET .../bisect/{branch} (500)"]
fn bug_1782_pack_gc_deletes_bisect_revert_and_candidate_snapshots() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let admin_tok = p.admin.token();

    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];

    // Create a real revert snapshot via `POST .../changes` (`onto: null`) and clear `change_refs`
    // (exactly how `bisect::queue_auto_revert` creates an unlanded server revert snapshot!).
    let rev_ch = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main0.hex(),
            "description": "Revert broken landing",
            "edits": [{"path": "src/reverted_1782.rs", "put": {"text": "REVERT-1782\n"}}]
        }),
    );
    assert_eq!(rev_ch.status, 200);
    let revert_snap = ObjectId::from_hex(rev_ch.json()["snapshot"].as_str().unwrap()).unwrap();
    hub.rt
        .block_on(sqlx::query("DELETE FROM change_refs WHERE project_id = $1").bind(pid).execute(&hub.hub().db))
        .unwrap();

    // Record the bisect state referencing `revert_snap` in `bisects` and `bisect_reverts`.
    let lineage: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT lineage FROM branches WHERE project_id = $1 AND name = 'main'").bind(pid).fetch_one(&hub.hub().db))
        .unwrap();
    let now = veil_core::now_millis();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO bisects (project_id, branch, lineage, check_name, good, bad, candidates, lo, hi, phase, probes, culprit, culprit_parent, session_paths, revert_snapshot, created_at, updated_at) \
                 VALUES ($1, 'main', $2, 'ci/src', $3, $5, $4, 0, 0, 'reverted', '[]', $5, $3, '[\"src\"]', $5, $6, $6)",
            )
            .bind(pid)
            .bind(lineage)
            .bind(main0.hex())
            .bind(json!([revert_snap.hex()]).to_string())
            .bind(revert_snap.hex())
            .bind(now)
            .execute(&hub.hub().db),
        )
        .unwrap();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO bisect_reverts (project_id, branch, lineage, culprit, check_name, ticket, revert_snapshot, state, created_at) \
                 VALUES ($1, 'main', $2, $3, 'ci/src', 'tkt-1782', $3, 'reverted', $4)",
            )
            .bind(pid)
            .bind(lineage)
            .bind(revert_snap.hex())
            .bind(now)
            .execute(&hub.hub().db),
        )
        .unwrap();

    // Verify `GET /v1/projects/{p}/bisect/main` succeeds (`200 OK`) and returns `revert` before GC!
    let status_before = api.get(Some(&admin_tok), &format!("/v1/projects/{}/bisect/main", p.name));
    assert_eq!(status_before.status, 200, "bisect status works before GC: {}", body(&status_before));
    assert_eq!(status_before.json()["revert"], json!(revert_snap.hex()));

    // Run full S29 `pack_gc` past retention window -> deletes `revert_snap` because `bisects` & `bisect_reverts` are omitted!
    let _ = run_full_gc(&hub, pid);

    let hub2 = TestHub::beside(&hub);
    let status_after = hub2.api().get(Some(&admin_tok), &format!("/v1/projects/{}/bisect/main", p.name));
    assert_eq!(status_after.status, 200, "bisect status 500s after pack_gc: {}", body(&status_after));
    let fresh = veil_server::store::Objects::with_db(
        hub.hub().objects.blob_store().clone(),
        1 << 10,
        Some(hub.hub().db.clone()),
    );
    assert!(
        hub.rt.block_on(fresh.exists(pid, &revert_snap)).unwrap(),
        "S20 revert_snapshot {revert_snap} was deleted by pack_gc!"
    );
}

/// BUG-1783 (blocking): `ci.rs` (`GET /v1/projects/{p}/checks` and
/// `POST /v1/projects/{p}/checks`) resolves snapshots via `resolve_snapshot_for_write`
/// without checking `embargo::is_withheld_from_viewer` / `is_withheld_for_query`.
/// When an unreleased S22 embargo commit touches a `public` folder (`src/`),
/// outsiders (`dev`) and anonymous callers receive `200 OK` with the secret
/// embargo's CI check summaries, logs, and URLs, and outsiders in `devs` can
/// overwrite the unreleased embargo's check results!
#[test]
fn bug_1783_checks_routes_bypass_embargo_withholding_leaking_unreleased_checks_and_allowing_outsider_writes() {
    const SECRET_CHECK_LOG: &str = "EMBARGO-CVE-ZERO-DAY-DETAILS-1783";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    std::fs::remove_dir_all(p.dir.join(BILL_DIR)).unwrap();
    write_files(&p.dir, &[(".veilpolicy", "src public devs\n")]);
    p.admin.commit_main(&p.dir, "public repo for OSS security embargo");
    p.admin.ok(&p.dir, &["push"]);

    // `p.sec` creates an unreleased embargo commit for `security` touching `src/lib.rs` (`public devs`).
    let sec_dir = p.sec.dir("emb-1783");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(&sec_dir, &[("src/lib.rs", &format!("{PUBLIC_MARK}\n// security patch\n"))]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo patch"]);
    let fix_log = p.sec.ok(&sec_dir, &["log", "-r", "@-", "-n", "1", "--json"]);
    let fix_id = ObjectId::from_hex(serde_json::from_str::<Value>(&fix_log).unwrap()["entries"][0]["snapshot_id"].as_str().unwrap()).unwrap();
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    p.sec.ok(&sec_dir, &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "embargo merge"]);
    p.sec.ok(&sec_dir, &["push"]);

    let sec_tok = p.sec.token();
    let dev_tok = p.dev.token();
    let emb_branch_and_tip: Option<(String, ObjectId)> = api
        .tips(Some(&sec_tok), &p.name)
        .unwrap()
        .branches
        .into_iter()
        .find(|(b, _)| b.starts_with("embargo/"));
    let (emb_branch, emb_tip) = emb_branch_and_tip.expect("insider sees hidden embargo branch");

    // Confirm `fix_id` IS withheld from `dev` and `anon` on `/history` (`404`).
    for tok in [Some(dev_tok.as_str()), None] {
        let h = api.post_json(tok, &format!("/v1/projects/{}/history", p.name), &json!({"tips": [fix_id.hex()]}));
        assert_eq!(h.status, 404, "history withholds embargo snapshot: {}", body(&h));
    }

    // Insider `p.sec` pages `/history` with `limit` to warm `caches.resolved` and `view_graph`
    // for their shared `view_key` (`src public devs`).
    let warm = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/history", p.name),
        &json!({"tips": [fix_id.hex(), emb_tip.hex()], "limit": 5}),
    );
    assert_eq!(warm.status, 200, "insider pages embargo history: {}", body(&warm));

    // A CI runner narrowed to `["src"]` (minted by `p.sec` inside `security`) records a check on `fix_id` (`200 OK`).
    let sec_runner = ci_token(&hub, &sec_tok, &p.name, &["src"]);
    let post_sec = api.post_json(
        Some(&sec_runner),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({
            "snapshot": fix_id.hex(),
            "name": "sec-audit",
            "state": "fail",
            "summary": SECRET_CHECK_LOG,
            "log": SECRET_CHECK_LOG,
        }),
    );
    assert_eq!(post_sec.status, 200, "security CI runner records check: {}", body(&post_sec));
    let sec_read = api.get(Some(&sec_tok), &format!("/v1/projects/{}/checks?rev={}", p.name, fix_id.hex()));
    assert_eq!(sec_read.status, 200, "insider reads embargo checks: {}", body(&sec_read));
    assert!(body(&sec_read).contains(SECRET_CHECK_LOG));

    // Outsider (`dev`) and anonymous (`None`) query `GET .../checks` on `fix_id`, `emb_tip`, and `emb_branch`:
    // MUST return `404`, identical to a missing snapshot, and leak nothing!
    let missing_hex = "ff".repeat(32);
    for (who, tok) in [("dev", Some(dev_tok.as_str())), ("anon", None)] {
        let missing_get = api.get(tok, &format!("/v1/projects/{}/checks?rev={missing_hex}", p.name));
        assert_eq!(missing_get.status, 404);
        for rev in [fix_id.hex(), emb_tip.hex(), emb_branch.clone()] {
            let r = api.get(tok, &format!("/v1/projects/{}/checks?rev={rev}", p.name));
            assert_eq!(r.status, 404, "{who} read unreleased embargo checks on {rev} ({}): {}", r.status, body(&r));
            assert_eq!(body(&r), body(&missing_get), "{who} response on {rev} differs from missing revision");
            assert!(!body(&r).contains(SECRET_CHECK_LOG), "{who} leaked {SECRET_CHECK_LOG}");
        }
    }

    // Outsider `dev` tries to overwrite `sec-audit` on `fix_id` or `emb_tip`: MUST return `404`,
    // identical to posting on a missing snapshot!
    let missing_post = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({"snapshot": missing_hex, "name": "sec-audit", "state": "pass", "summary": "spoofed"}),
    );
    assert_eq!(missing_post.status, 404);
    for snap in [fix_id, emb_tip] {
        let overwrite = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/checks", p.name),
            &json!({"snapshot": snap.hex(), "name": "sec-audit", "state": "pass", "summary": "spoofed"}),
        );
        assert_eq!(overwrite.status, 404, "outsider dev overwrote unreleased embargo check: {}", body(&overwrite));
        assert_eq!(body(&overwrite), body(&missing_post), "outsider write refusal differs from missing snapshot");
    }

    // Cross-route shortcut checks (`land` via `changes::resolve_base`, `q/show` via `query::resolve_real`,
    // and `q/generations` via `view_graph` after `sec` warmed shared `view_key` caches):
    let land_emb = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "onto": "main",
            "base": fix_id.hex(),
            "edits": [{"path": "src/extra.rs", "put": {"text": "// x\n"}}],
        }),
    );
    assert_eq!(land_emb.status, 404, "outsider landed on unreleased embargo base via caches.resolved: {}", body(&land_emb));

    for rev in [fix_id.hex(), emb_tip.hex()] {
        let qs = api.get(Some(&dev_tok), &format!("/v1/projects/{}/q/show?rev={rev}", p.name));
        assert_eq!(qs.status, 404, "query show leaked cached view_graph embargo row {rev}: {}", body(&qs));
    }
    let qg = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/q/generations", p.name),
        &json!({"snapshots": [fix_id.hex(), emb_tip.hex()]}),
    );
    assert_eq!(qg.status, 200, "{}", body(&qg));
    assert_eq!(qg.json()["generations"], json!([null, null]), "q/generations leaked embargo generations: {}", body(&qg));
}

/// BUG-1784 (blocking): `changes::create_with` (`resolve_change`, `changes.rs:930-947`)
/// verifies only `by == person.id` on `change_refs`, without checking whether the
/// existing snapshot `s` (`predecessors[0]`) modified paths outside the agent
/// session's `--only` narrowing (or `.veilpolicy`/`.veilrules`). A narrowed S11
/// agent session can probe and overwrite its person's out-of-scope `change_id`,
/// clobbering `change_refs` so the person's subsequent `stack_on` loses their
/// out-of-scope edits!
#[test]
fn bug_1784_narrowed_agent_session_overwrites_persons_out_of_scope_change_id() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();

    write_files(&p.dir, &[("src/api/mod.rs", "pub fn a() {}\n")]);
    p.admin.commit_main(&p.dir, "add src/api");
    p.admin.ok(&p.dir, &["push"]);
    let main_tip = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let dev_tip = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];

    // 1. Admin creates an unlanded S10 change `cid` modifying `BILL_DIR/secret_plan.txt` (outside `src/api`),
    //    an unlanded `rules_cid` modifying `.veilrules` (`decides_access`), and `dev` creates `other_cid`.
    let c_person = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "admin billing plan",
            "edits": [{"path": format!("{BILL_DIR}/secret_plan.txt"), "put": {"text": "CONFIDENTIAL-PLAN\n"}}]
        }),
    );
    assert_eq!(c_person.status, 200, "person creates billing change: {}", body(&c_person));
    let cid = c_person.json()["change_id"].as_str().unwrap().to_string();
    let s_person = ObjectId::from_hex(c_person.json()["snapshot"].as_str().unwrap()).unwrap();

    let c_rules = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "admin rules change",
            "edits": [{"path": ".veilrules", "put": {"text": "[branches.main]\n"}}]
        }),
    );
    assert_eq!(c_rules.status, 200, "person creates rules change: {}", body(&c_rules));
    let rules_cid = c_rules.json()["change_id"].as_str().unwrap().to_string();

    let c_other = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": dev_tip.hex(),
            "description": "dev change",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn dev() {}\n"}}]
        }),
    );
    assert_eq!(c_other.status, 200, "dev creates change: {}", body(&c_other));
    let other_cid = c_other.json()["change_id"].as_str().unwrap().to_string();
    let missing_cid = veil_core::ChangeId::random().to_string();

    // 2. Narrowed agent session (`--only src/api`) gets the exact same `403` narrowed refusal on
    //    person's out-of-scope `cid`, person's `.veilrules` `rules_cid`, `dev`'s `other_cid`, and `missing_cid`!
    let agent = agent_token(&hub, &admin_tok, &p.name, &["src/api"]);
    let hijack = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "change_id": cid,
            "description": "agent clobbers cid",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn hijacked() {}\n"}}]
        }),
    );
    assert_eq!(hijack.status, 403, "narrowed agent hijacked out-of-scope change_id {cid}: {}", body(&hijack));
    assert_eq!(hijack.json()["code"], json!("agent_session"));
    assert_eq!(
        hijack.json()["message"],
        json!("this agent session is narrowed: this would change files outside its paths")
    );
    for (label, target_cid) in [("rules_cid", &rules_cid), ("other_cid", &other_cid), ("missing_cid", &missing_cid)] {
        let r = api.post_json(
            Some(&agent),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({
                "base": main_tip.hex(),
                "change_id": target_cid,
                "description": "probe",
                "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn hijacked() {}\n"}}]
            }),
        );
        assert_eq!((r.status, body(&r)), (403, body(&hijack)), "{label} refusal differed from out-of-scope change");
    }

    // 3. Un-narrowed agent session cannot rewrite `rules_cid` touching `.veilrules` (`decides_access`).
    let wide_agent = agent_token(&hub, &admin_tok, &p.name, &[]);
    let r_access = api.post_json(
        Some(&wide_agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "change_id": rules_cid,
            "description": "agent rewrites rules change",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn ok() {}\n"}}]
        }),
    );
    assert_eq!(r_access.status, 403, "wide agent rewrote decides_access change: {}", body(&r_access));
    assert_eq!(r_access.json()["code"], json!("agent_session"));
    assert!(
        r_access.json()["message"].as_str().unwrap().contains("decides access or review"),
        "{}",
        body(&r_access)
    );

    // 4. Control: narrowed agent CAN create and rewrite an in-scope `change_id`, and `cid` was not clobbered.
    let c_in = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "description": "agent v1",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn v1() {}\n"}}]
        }),
    );
    assert_eq!(c_in.status, 200, "narrowed agent creates in-scope change: {}", body(&c_in));
    let in_cid = c_in.json()["change_id"].as_str().unwrap().to_string();
    let c_in2 = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "change_id": in_cid,
            "description": "agent v2",
            "edits": [{"path": "src/api/mod.rs", "put": {"text": "pub fn v2() {}\n"}}]
        }),
    );
    assert_eq!(c_in2.status, 200, "narrowed agent rewrites in-scope change: {}", body(&c_in2));

    // Verify admin's original `cid` still points to `s_person` by stacking a change onto an unprotected branch!
    let c_admin2 = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": main_tip.hex(),
            "change_id": cid,
            "description": "admin billing plan v2",
            "edits": [{"path": format!("{BILL_DIR}/secret_plan.txt"), "put": {"text": "CONFIDENTIAL-PLAN-V2\n"}}]
        }),
    );
    assert_eq!(c_admin2.status, 200, "{}", body(&c_admin2));
    let s_person2 = ObjectId::from_hex(c_admin2.json()["snapshot"].as_str().unwrap()).unwrap();
    let hist = api.post_json(Some(&admin_tok), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [s_person2.hex()]}));
    let (_, raw) = hist.frames().into_iter().find(|(id, _)| *id == s_person2).unwrap();
    let Object::Snapshot(snap2) = Object::decode(&raw).unwrap() else { panic!() };
    assert_eq!(snap2.predecessors, vec![s_person], "cid kept original billing predecessor");
}

/// BUG-1785 (non-blocking DoS / memory bound gap): `GET /v1/objects/{p}/{id}`
/// calls `limits::answers::prepay` (`BUG-1330`) ONLY when `Range` is absent
/// (`grant.rs:435-447`). Sending `Range: bytes=0-` skips `prepay` and calls
/// `hub.objects.get_range(project, &id, 0, u64::MAX)`, reading and decompressing
/// the entire multi-MiB object from storage even when the caller's answer-memory
/// budget is already exhausted.
#[test]
fn bug_1785_object_range_zero_dash_bypasses_answers_prepay() {
    use std::sync::atomic::Ordering;

    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let p = setup_project(&hub);

    // Push two distinct 10 MiB incompressible public files in two commits via `hub_writer`
    // (10 MiB + 10 MiB = 20 MiB > 16 MiB per-address answer quarter, while `hub`'s
    // `Objects::cache` stays completely cold for `target.bin`!).
    let hub_writer = TestHub::beside(&hub);
    let w_api = hub_writer.api();
    let _ = w_api.tips(Some(&p.admin.token()), &p.name).unwrap();
    let make_ascii = |mut x: u64| {
        let mut s = String::with_capacity(10 << 20);
        for _ in 0..(10 << 20) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push((b'!' + (x as u8 % 90)) as char);
        }
        s
    };
    let mut cw = Craft::new(&w_api, &p.admin, &p.name, "main");
    cw.file("src/stall.bin", &make_ascii(0x9e37_79b9_7f4a_7c15));
    cw.file("src/target.bin", &make_ascii(0x517c_c1b7_2722_0a95));
    let (_s, pr) = cw.push_edited("b-1785", None, |_| {});
    assert_eq!(pr.status, 200, "push b-1785: {}", body(&pr));
    assert_eq!(pr.json()["results"][0]["ok"], json!(true));

    let api = hub.api();
    let tips = api.tips(None, &p.name).unwrap();
    let grant = tips.grants.get("b-1785").unwrap().clone();
    let gkey = tips.grant_key.unwrap();
    let root = Grant::read_unverified(&grant).unwrap().root;

    // Warm `root` and `src_id` trees on `hub` (`target.bin` remains completely cold in `hub.objects`!).
    let r_root = signed_object_get(&api, &p.name, &grant, &gkey, None, &[], &root, &[]);
    let Object::Tree(t_root) = Object::decode(&r_root.body).unwrap() else { panic!() };
    let src_id = t_root.get("src").unwrap().id;
    let r_src = signed_object_get(&api, &p.name, &grant, &gkey, None, &[root], &src_id, &[]);
    let Object::Tree(t_src) = Object::decode(&r_src.body).unwrap() else { panic!() };
    let stall_id = t_src.get("stall.bin").unwrap().id;
    let file_id = t_src.get("target.bin").unwrap().id;
    let chain = format!("{},{}", root.hex(), src_id.hex());

    // 1. Hold one unread 10 MiB response (`stall_id`) open on `hub` so only 6 MiB remains in the 16 MiB quarter.
    let stalled = api.get_unread(
        &format!("/v1/objects/{}/{}", p.name, stall_id.hex()),
        &[("veil-grant", &grant), ("veil-chain", &chain)],
    );
    assert!(hub.hub().limits.answers.held_kib() >= 9 << 10, "10 MiB answer holds budget");

    // 2. Compare storage reads (`hub.objects.reads`) for uncached `file_id` (`target.bin`) on plain `GET` vs `Range`:
    // - Plain `GET` calls `answers::prepay` BEFORE reading storage -> `503` with `0` storage reads (`BUG-1330`).
    // - `Range: bytes=0-` and `Range: bytes=0-7340031` (7 MiB > ~6 MiB left) MUST ALSO prepay and refuse with `0` reads.
    let reads0 = hub.hub().objects.reads.load(Ordering::Relaxed);
    let plain_refused = signed_object_get(&api, &p.name, &grant, &gkey, None, &[root, src_id], &file_id, &[]);
    assert_eq!(plain_refused.status, 503, "plain GET refused when budget full: {}", body(&plain_refused));
    let reads_after_plain = hub.hub().objects.reads.load(Ordering::Relaxed);
    assert_eq!(reads_after_plain, reads0, "plain GET prepays before reading storage (0 storage reads)");

    let range_refused = signed_object_get(
        &api,
        &p.name,
        &grant,
        &gkey,
        None,
        &[root, src_id],
        &file_id,
        &[("range", "bytes=0-")],
    );
    assert_eq!(range_refused.status, 503);
    let reads_after_range = hub.hub().objects.reads.load(Ordering::Relaxed);
    assert_eq!(
        reads_after_range,
        reads_after_plain,
        "Range: bytes=0- bypassed answers::prepay and performed {} storage reads while answer budget was exhausted!",
        reads_after_range - reads_after_plain
    );

    let subrange_refused = signed_object_get(
        &api,
        &p.name,
        &grant,
        &gkey,
        None,
        &[root, src_id],
        &file_id,
        &[("range", "bytes=0-7340031")],
    );
    assert_eq!(subrange_refused.status, 503);
    assert_eq!(
        hub.hub().objects.reads.load(Ordering::Relaxed),
        reads_after_plain,
        "oversized subrange must also fail prepay with 0 storage reads"
    );

    // 3. A 1 MiB subrange fits within the remaining ~6 MiB budget and succeeds with 206.
    let small_range = signed_object_get(
        &api,
        &p.name,
        &grant,
        &gkey,
        None,
        &[root, src_id],
        &file_id,
        &[("range", "bytes=0-1048575")],
    );
    assert_eq!(small_range.status, 206);
    assert_eq!(small_range.body.len(), 1 << 20);

    // 4. Unsatisfiable range returns 416 and releases all held KiB once `stalled` drops.
    let bad_range = signed_object_get(
        &api,
        &p.name,
        &grant,
        &gkey,
        None,
        &[root, src_id],
        &file_id,
        &[("range", "bytes=99999999-")],
    );
    assert_eq!(bad_range.status, 416);
    drop(stalled);
    for _ in 0..40 {
        if hub.hub().limits.answers.held_kib() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert_eq!(hub.hub().limits.answers.held_kib(), 0, "all held answer budget must be released");
}

/// BUG-1786 (non-blocking): S8's workspace sandbox socket (`ws_socket::check_revisions`,
/// `crates/vl/src/ws_socket.rs:147-155`) checks only `B` in `vl log -r A..B`,
/// omitting `within(A, "log")` (unlike `vl diff`, which checks both `from` and
/// `to`). Inside `vl ws exec`, `vl log -r other_ws@..@` and `vl log -r secret_tag..@`
/// resolve `A` across the entire repository instead of refusing revisions outside
/// `@` and its ancestors (`BUG-1361`).
#[test]
fn bug_1786_sandbox_socket_vl_log_range_resolves_revisions_outside_workspace_history() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let clone = p.dev.dir("ws-1786");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), clone.to_str().unwrap()]);

    // Create workspace `agent` on `main`, and another workspace `secretws` + tag `secrettag` with separate work.
    p.dev.ok(&clone, &["ws", "new", "agent", "-r", "main"]);
    p.dev.ok(&clone, &["ws", "new", "secretws", "-r", "main"]);
    p.dev.ok(&clone, &["ws", "exec", "secretws", "--", "sh", "-c", "echo secret > src/secret_ws.txt && vl commit -m secret"]);
    p.dev.ok(&clone, &["tag", "set", "secrettag", "-r", "secretws@-"]);

    // Control: `vl show secretws@` inside `agent`'s sandbox IS refused (`not @ or one of its ancestors`).
    let ctl = p.dev.run(&clone, &["ws", "exec", "agent", "--", "vl", "show", "secretws@"]);
    assert!(!ctl.status.success(), "control: vl show secretws@ must fail");

    // Every revision in a range or revset outside `@` and its ancestors must be refused.
    for revset in ["secretws@..@", "secrettag..@", "@..secretws@", "..secretws@", "agent(*)"] {
        let r = p.dev.run(&clone, &["ws", "exec", "agent", "--", "vl", "log", "-r", revset]);
        let out = format!("{}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
        assert!(
            !r.status.success() && out.contains("inside a sandbox"),
            "sandbox `vl log -r {revset}` must be refused:\n{out}"
        );
    }

    // Valid ranges within `@`'s own history continue to work.
    let ok = p.dev.run(&clone, &["ws", "exec", "agent", "--", "vl", "log", "-r", "@-..@"]);
    assert!(ok.status.success(), "valid range @-..@ failed: {}", String::from_utf8_lossy(&ok.stderr));
}
