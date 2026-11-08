//! The Veil daemon's numbers (S6, `docs/HUB.md` §13.29; the design's §4.8
//! table): a fresh agent workspace with no daemon, a cold one and a warm
//! one, on projects of 4 KiB files in folders of 100 (as `openscion`).
//!
//! | case | what is timed |
//! |---|---|
//! | workspace ready | the steps before an agent can `ls` a mounted workspace (§4.8 rows 1–2): the tips and their grant from the server, then the root tree and every top-level tree, through the daemon or straight from the server's object routes |
//! | thin clone | `vl clone` (thin, the default), a separate process: every tree and file the checkout writes |
//!
//! "Warm" is the daemon after one clone of the project read it; "cold" a
//! daemon just started with an empty store; "no daemon" `vl daemon stop`.
//! The FUSE mount (10–50 ms in §4.8) is S8's and not in these numbers.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use veil_core::{
    hub::grant::{sign_request, BatchRequest, ChainWant, Grant},
    object::{EntryKind, Object},
    Identity, ObjectId,
};

pub struct Args {
    pub vl: PathBuf,
    pub server: crate::server::ServerArgs,
    pub dir: PathBuf,
    pub sizes: Vec<usize>,
    pub runs: usize,
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// The bench person's session token and identity, from their Veil home.
fn credentials(home: &Path) -> Result<(String, Identity)> {
    let hub: serde_json::Value = serde_json::from_slice(&std::fs::read(home.join("hub.json"))?)?;
    let token = hub["servers"].as_object().and_then(|s| s.values().next()).and_then(|e| e["token"].as_str()).ok_or_else(|| anyhow!("no session"))?.to_string();
    Ok((token, Identity::from_json(&std::fs::read_to_string(home.join("identity.json"))?)?))
}

/// One batch through the daemon's socket: the objects that arrived.
fn via_daemon(socket: &Path, authority: &str, project: &str, batch: &BatchRequest) -> Result<Vec<(ObjectId, Vec<u8>)>> {
    let mut s = UnixStream::connect(socket).with_context(|| format!("the daemon at {}", socket.display()))?;
    let body = serde_json::to_vec(&json!({"op": "batch", "upstream": authority, "project": project, "batch": batch}))?;
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    s.write_all(&msg)?;
    let mut out = Vec::new();
    loop {
        let mut head = [0u8; 5];
        s.read_exact(&mut head)?;
        let mut payload = vec![0u8; u32::from_be_bytes(head[1..].try_into()?) as usize];
        s.read_exact(&mut payload)?;
        match head[0] {
            b'O' => out.push((ObjectId(payload[..32].try_into()?), payload[32..].to_vec())),
            b'E' => return Ok(out),
            k => bail!("an unknown message {k}"),
        }
    }
}

/// The steps before an agent can `ls` a mounted workspace: tips and grant
/// (always the server), the root tree, then every top-level tree (the
/// daemon, or the server's object routes when `socket` is `None`).
fn ready(agent: &ureq::Agent, authority: &str, project: &str, token: &str, id: &Identity, socket: Option<&Path>) -> Result<usize> {
    let mut r = agent.get(format!("https://{authority}/v1/projects/{project}/tips")).header("authorization", &format!("Bearer {token}")).call()?;
    let tips: veil_core::hub::wire::Tips = serde_json::from_slice(&r.body_mut().read_to_vec()?)?;
    let grant = tips.grants.get(&tips.default_branch).ok_or_else(|| anyhow!("no grant"))?.clone();
    let g = Grant::verify(&grant, tips.grant_key.as_deref().unwrap_or_default()).ok_or_else(|| anyhow!("the grant does not verify"))?;
    let batch = |wants: Vec<(Vec<ObjectId>, ObjectId)>| -> Result<Vec<(ObjectId, Vec<u8>)>> {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: grant.clone(),
            ts,
            signature: Some(sign_request(id, &g, ts, &ids)),
            wants: wants.into_iter().map(|(chain, id)| ChainWant { chain, id }).collect(),
            skip: Vec::new(),
        };
        match socket {
            Some(s) => via_daemon(s, authority, project, &req),
            None => {
                let mut r = agent.post(format!("https://{authority}/v1/objects/{project}:batch")).header("content-type", "application/json").send(&serde_json::to_vec(&req)?[..])?;
                Ok(veil_core::hub::encoding::read_frames(&r.body_mut().with_config().limit(1 << 30).read_to_vec()?, 1 << 30)?.into_iter().map(|(i, b)| (i, b.into_owned())).collect())
            }
        }
    };
    let root = g.body.root;
    let got = batch(vec![(Vec::new(), root)])?;
    let Some(Ok(Object::Tree(t))) = got.first().map(|(_, raw)| Object::decode(raw)) else { bail!("no root tree") };
    let dirs: Vec<(Vec<ObjectId>, ObjectId)> = t.entries.iter().filter(|e| e.kind == EntryKind::Dir).map(|e| (vec![root], e.id)).collect();
    let n = dirs.len();
    let got = batch(dirs)?;
    if got.len() != n {
        bail!("{} of {n} top-level trees arrived", got.len());
    }
    Ok(n + 1)
}

pub fn run_all(a: &Args) -> Result<serde_json::Value> {
    std::fs::create_dir_all(&a.dir)?;
    let home = a.dir.join("home");
    let vl = |cwd: &Path| {
        let mut c = Command::new(&a.vl);
        c.current_dir(cwd).env("VEIL_HOME", &home).env("NO_COLOR", "1").stdout(Stdio::null()).stderr(Stdio::piped());
        c
    };
    let run = |c: &mut Command| -> Result<f64> {
        let t = Instant::now();
        let o = c.output()?;
        if !o.status.success() {
            bail!("{c:?} failed: {}", String::from_utf8_lossy(&o.stderr));
        }
        Ok(t.elapsed().as_secs_f64() * 1000.0)
    };
    let server = crate::server::Server::start(&a.server, &a.dir.join("server"), 32)?;
    let hub = format!("veil://{}", server.authority);
    let tag = server.pid();
    run(vl(&a.dir).args(["login", &hub, "--name", &format!("bench{tag}"), "--ca"]).arg(&server.cert))?;
    let (token, id) = credentials(&home)?;
    let pem = std::fs::read_to_string(&server.cert)?;
    let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem.as_bytes())
        .filter_map(|i| match i {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    let agent = ureq::Agent::config_builder()
        .tls_config(ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls).root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certs))).build())
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .new_agent();
    let socket = home.join("daemon/sock");
    let mut cases = Vec::new();
    for &files in &a.sizes {
        let name = format!("dm{files}-{tag}");
        let proj = a.dir.join(format!("src-{files}"));
        crate::openscion::generate(&proj, files, files as u64)?;
        run(vl(&proj).arg("init"))?;
        run(vl(&proj).args(["remote", "add", "origin", &format!("{hub}/{name}")]))?;
        run(vl(&proj).args(["commit", "-m", "import"]))?;
        run(vl(&proj).args(["tag", "set", "main", "-r", "@-"]))?;
        run(vl(&proj).args(["push"]))?;
        let url = format!("{hub}/{name}");
        let mut n = 0;
        let mut clone = |mode: &str| -> Result<f64> {
            n += 1;
            run(vl(&a.dir).args(["clone", &url]).arg(a.dir.join(format!("c-{files}-{mode}-{n}"))))
        };
        let mut ready_ms: Vec<(&str, f64)> = Vec::new();
        let mut clone_ms: Vec<(&str, f64)> = Vec::new();
        // No daemon.
        run(vl(&a.dir).args(["daemon", "stop"]))?;
        for _ in 0..a.runs {
            let t = Instant::now();
            ready(&agent, &server.authority, &name, &token, &id, None)?;
            ready_ms.push(("no daemon", t.elapsed().as_secs_f64() * 1000.0));
            clone_ms.push(("no daemon", clone("off")?));
        }
        // Cold: a daemon just started, with an empty store.
        for _ in 0..a.runs {
            run(vl(&a.dir).args(["daemon", "stop"]))?;
            let store = home.join("daemon/store");
            if store.starts_with(&a.dir) && store.exists() {
                std::fs::remove_dir_all(&store)?;
            }
            run(vl(&a.dir).args(["daemon", "start"]))?;
            clone_ms.push(("cold daemon", clone("cold")?));
        }
        for _ in 0..a.runs {
            run(vl(&a.dir).args(["daemon", "stop"]))?;
            let store = home.join("daemon/store");
            if store.starts_with(&a.dir) && store.exists() {
                std::fs::remove_dir_all(&store)?;
            }
            run(vl(&a.dir).args(["daemon", "start"]))?;
            let t = Instant::now();
            ready(&agent, &server.authority, &name, &token, &id, Some(&socket))?;
            ready_ms.push(("cold daemon", t.elapsed().as_secs_f64() * 1000.0));
        }
        // Warm: the store holds the project (the last cold clone read it).
        clone("prime")?;
        for _ in 0..a.runs {
            let t = Instant::now();
            let trees = ready(&agent, &server.authority, &name, &token, &id, Some(&socket))?;
            ready_ms.push(("warm daemon", t.elapsed().as_secs_f64() * 1000.0));
            clone_ms.push(("warm daemon", clone("warm")?));
            eprintln!("{files} files: workspace ready read {trees} trees");
        }
        let status = Command::new(&a.vl).args(["daemon", "status"]).env("VEIL_HOME", &home).output()?;
        eprintln!("{}", String::from_utf8_lossy(&status.stdout));
        for (case, all) in [("workspace ready (tips, grant, root and top-level trees)", &ready_ms), ("thin clone (every tree and file)", &clone_ms)] {
            for mode in ["no daemon", "cold daemon", "warm daemon"] {
                let v: Vec<f64> = all.iter().filter(|(m, _)| *m == mode).map(|(_, t)| *t).collect();
                if v.is_empty() {
                    continue;
                }
                let target = (case.starts_with("workspace") && mode == "warm daemon").then_some(300.0);
                cases.push(json!({ "files": files, "case": case, "mode": mode, "ms": median(v), "target_ms": target, "runs": a.runs }));
            }
        }
    }
    run(vl(&a.dir).args(["daemon", "stop"]))?;
    Ok(json!({ "profile": "daemon", "cases": cases }))
}

pub fn markdown(v: &serde_json::Value) -> Result<String> {
    let mut out = String::from("| Files | Case | Mode | Median (ms) | Target (ms) |\n|---:|---|---|---:|---:|\n");
    for c in v["cases"].as_array().ok_or_else(|| anyhow!("no cases"))? {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {} |\n",
            c["files"],
            c["case"].as_str().unwrap_or(""),
            c["mode"].as_str().unwrap_or(""),
            c["ms"].as_f64().unwrap_or(f64::NAN),
            c["target_ms"].as_f64().map(|t| format!("{t:.0}")).unwrap_or_default()
        ));
    }
    Ok(out)
}
