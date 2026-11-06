//! Test support: a server per test (in process), people with their own
//! `VEIL_HOME` driving the real `vl`, and a raw API client for attacks.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

use veil_core::{
    hub::wire::{put_frame, read_frames, Tips},
    Identity, ObjectId,
};
use veil_server::{tls::TlsSource, Config, Running, Storage};

pub fn unique(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(veil_core::crypto::random_bytes::<4>()))
}

pub struct TestHub {
    pub rt: tokio::runtime::Runtime,
    running: Option<Running>,
    pub port: u16,
    pub ca: PathBuf,
    pub cert_pem: String,
    pub _dir: tempfile::TempDir,
}

impl TestHub {
    pub fn start() -> TestHub {
        TestHub::start_with_ttl(Duration::from_secs(3600))
    }

    pub fn start_with_ttl(ttl: Duration) -> TestHub {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(8).build().unwrap();
        let dir = tempfile::Builder::new().prefix("veil-hub-test").tempdir().unwrap();
        let storage = match std::env::var("VEIL_TEST_S3_ENDPOINT") {
            Ok(endpoint) => Storage::S3 {
                endpoint,
                bucket: std::env::var("VEIL_TEST_S3_BUCKET").unwrap_or_else(|_| "veil-test".into()),
                region: "us-east-1".into(),
                key: std::env::var("VEIL_TEST_S3_KEY").unwrap(),
                secret: std::env::var("VEIL_TEST_S3_SECRET").unwrap(),
            },
            Err(_) => Storage::Dir(dir.path().join("objects")),
        };
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            database_url: std::env::var("VEIL_TEST_DATABASE_URL").expect("VEIL_TEST_DATABASE_URL (run scripts/verify-server.sh)"),
            storage,
            tls: TlsSource::SelfSigned,
            data_dir: dir.path().join("data"),
            session_ttl: ttl,
            db_connections: 16,
        };
        let running = rt.block_on(veil_server::start(config)).expect("server starts");
        let ca = dir.path().join("data/self-signed-cert.pem");
        TestHub {
            port: running.addr.port(),
            cert_pem: running.cert_pem.clone(),
            running: Some(running),
            rt,
            ca,
            _dir: dir,
        }
    }

    pub fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn url(&self, project: &str) -> String {
        format!("veil://{}/{project}", self.authority())
    }

    /// A new person, signed up under a unique name starting with `prefix`.
    pub fn person(&self, prefix: &str) -> Person {
        let p = Person::new(self, &unique(prefix));
        p.ok(p.home.path(), &["login", &format!("veil://{}", self.authority()), "--name", &p.name, "--ca", self.ca.to_str().unwrap()]);
        p
    }

    /// Anyone on Earth: never signed in.
    pub fn anyone(&self) -> Person {
        Person::new(self, "anyone")
    }

    pub fn api(&self) -> Api {
        Api::new(self)
    }

    pub fn hub(&self) -> Arc<veil_server::Hub> {
        self.running.as_ref().unwrap().hub.clone()
    }
}

impl Drop for TestHub {
    fn drop(&mut self) {
        if let Some(r) = self.running.take() {
            self.rt.block_on(r.stop());
        }
    }
}

pub struct Person {
    pub name: String,
    pub home: tempfile::TempDir,
    ca: PathBuf,
}

pub fn vl_bin() -> PathBuf {
    PathBuf::from(std::env::var("VEIL_TEST_VL").expect("VEIL_TEST_VL (run scripts/verify-server.sh)"))
}

impl Person {
    fn new(hub: &TestHub, name: &str) -> Person {
        Person {
            name: name.to_string(),
            home: tempfile::Builder::new().prefix("veil-person").tempdir().unwrap(),
            ca: hub.ca.clone(),
        }
    }

    pub fn run(&self, dir: &Path, args: &[&str]) -> Output {
        // `timeout` ends a `vl` that never returns: the test then fails.
        Command::new("timeout")
            .arg("300")
            .arg(vl_bin())
            .args(args)
            .current_dir(dir)
            .env("VEIL_HOME", self.home.path().join("veil"))
            .env("VEIL_USER", &self.name)
            .env("VEIL_HUB_CA", &self.ca)
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    pub fn ok(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.run(dir, args);
        let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{} vl {args:?} failed:\n{all}", self.name);
        all
    }

    pub fn fails(&self, dir: &Path, args: &[&str]) -> String {
        let o = self.run(dir, args);
        let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(!o.status.success(), "{} vl {args:?} should have failed:\n{all}", self.name);
        all
    }

    /// A directory of this person's (for clones and projects).
    pub fn dir(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    pub fn identity(&self) -> Identity {
        Identity::from_json(&std::fs::read_to_string(self.home.path().join("veil/identity.json")).unwrap()).unwrap()
    }

    pub fn token(&self) -> String {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.home.path().join("veil/hub.json")).unwrap()).unwrap();
        let servers = v["servers"].as_object().unwrap();
        servers.values().next().unwrap()["token"].as_str().unwrap().to_string()
    }

    /// Commit everything in `dir` and move tag `main` to it.
    pub fn commit_main(&self, dir: &Path, msg: &str) {
        self.ok(dir, &["commit", "-m", msg]);
        self.ok(dir, &["tag", "set", "main", "-r", "@-", "--force"]);
    }
}

/// Write `files` (path, content) under `root`.
pub fn write_files(root: &Path, files: &[(&str, &str)]) {
    for (p, c) in files {
        let path = root.join(p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, c).unwrap();
    }
}

/// A raw client of the server's API.
pub struct Api {
    agent: ureq::Agent,
    base: String,
    pub authority: String,
}

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    pub fn frames(&self) -> Vec<(ObjectId, Vec<u8>)> {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        read_frames(&self.body).unwrap().into_iter().map(|(i, r)| (i, r.to_vec())).collect()
    }
}

impl Api {
    fn new(hub: &TestHub) -> Api {
        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(hub.cert_pem.as_bytes())
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect();
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)))
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            // A request that never answers fails the test instead of hanging it.
            .timeout_global(Some(std::time::Duration::from_secs(120)))
            .build()
            .new_agent();
        Api {
            agent,
            base: format!("https://{}", hub.authority()),
            authority: hub.authority(),
        }
    }

    fn finish(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Reply {
        let r = r.unwrap();
        let status = r.status().as_u16();
        let body = r.into_body().with_config().limit(1 << 32).read_to_vec().unwrap();
        Reply { status, body }
    }

    pub fn get(&self, token: Option<&str>, path: &str) -> Reply {
        let mut r = self.agent.get(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        Self::finish(r.call())
    }

    pub fn post(&self, token: Option<&str>, path: &str, body: &[u8], json: bool) -> Reply {
        let mut r = self.agent.post(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        r = r.header("content-type", if json { "application/json" } else { "application/octet-stream" });
        Self::finish(r.send(body))
    }

    pub fn post_json(&self, token: Option<&str>, path: &str, v: &serde_json::Value) -> Reply {
        self.post(token, path, &serde_json::to_vec(v).unwrap(), true)
    }

    /// Sign in as `id` (registering `name` if given); the session token.
    pub fn login(&self, id: &Identity, name: Option<&str>) -> Result<String, Reply> {
        let ch = self.post_json(None, "/v1/auth/challenge", &serde_json::json!({"key": id.verifying_hex()}));
        assert_eq!(ch.status, 200);
        let challenge = ch.json()["challenge"].as_str().unwrap().to_string();
        let sig = id.sign(
            veil_core::crypto::domains::SIG_CONTEXT_HUB_LOGIN,
            &veil_core::hub::wire::login_message(&self.authority, &challenge),
        );
        let r = self.post_json(
            None,
            "/v1/auth/login",
            &serde_json::json!({"key": id.verifying_hex(), "challenge": challenge, "hub": self.authority,
                "signature": sig, "identity": id.public_id(), "name": name}),
        );
        if r.status == 200 {
            Ok(r.json()["token"].as_str().unwrap().to_string())
        } else {
            Err(r)
        }
    }

    pub fn tips(&self, token: Option<&str>, project: &str) -> Option<Tips> {
        let r = self.get(token, &format!("/v1/projects/{project}/tips"));
        (r.status == 200).then(|| serde_json::from_slice(&r.body).unwrap())
    }

    pub fn upload_anon(&self, project: &str) -> Reply {
        self.post(None, &format!("/v1/projects/{project}/objects"), b"", false)
    }

    pub fn upload(&self, token: &str, project: &str, objects: &[(ObjectId, Vec<u8>)]) -> Reply {
        let mut body = Vec::new();
        for (id, raw) in objects {
            put_frame(&mut body, id, raw);
        }
        self.post(Some(token), &format!("/v1/projects/{project}/objects"), &body, false)
    }
}

/// Every byte someone could obtain through `vl` and the API: the raw
/// objects in their clone's store (packs decoded), every other file of the
/// clone, and `extra` (API answers).
pub fn everything_in(clone: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if clone.join(".veil").exists() {
        let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(clone)), None, "test").unwrap();
        for id in repo.store().list_objects().unwrap() {
            if let Ok(raw) = repo.store().get_raw(&id) {
                out.push((format!("object {}", id.short()), raw));
            }
        }
    }
    let mut stack = vec![clone.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            } else {
                out.push((p.display().to_string(), std::fs::read(&p).unwrap_or_default()));
                out.push((format!("name {}", p.display()), p.to_string_lossy().as_bytes().to_vec()));
            }
        }
    }
    out
}

/// Assert no item contains any of `markers` (whole markers only).
pub fn assert_no_marker(items: &[(String, Vec<u8>)], markers: &[&str], who: &str) {
    for (what, bytes) in items {
        for m in markers {
            assert!(
                !bytes.windows(m.len()).any(|w| w == m.as_bytes()),
                "{who} received marker {m} in {what}"
            );
        }
    }
}

pub fn has_marker(items: &[(String, Vec<u8>)], marker: &str) -> bool {
    items.iter().any(|(_, b)| b.windows(marker.len()).any(|w| w == marker.as_bytes()))
}

/// The standard project: one folder per rule kind, each with a unique
/// marker in its content and in a name.
pub struct Project {
    pub name: String,
    pub admin: Person,
    pub dir: PathBuf,
    /// In `devs` (src/ is `public devs`: read for all, write for devs).
    pub dev: Person,
    /// In `finance` (billing).
    pub fin: Person,
    /// Named directly on a rule.
    pub carol: Person,
    /// In `security` (src/sec…/, nested inside the public src/).
    pub sec: Person,
}

pub const ROOT_FILE: &str = "README-root-6a1f09e2.md";
pub const ROOT_MARK: &str = "MARKER-ROOT-PRIVATE-7f3a91c4";
pub const BILL_DIR: &str = "bill-77a1c3d9";
pub const BILL_MARK: &str = "MARKER-BILLING-CONTENT-a8e0bb51";
pub const NESTED_DIR: &str = "sec-9d0e4b12";
pub const NESTED_MARK: &str = "MARKER-NESTED-CONTENT-41d2aa07";
pub const PERSON_DIR: &str = "carol-only-3e8f21aa";
pub const PERSON_MARK: &str = "MARKER-PERSON-CONTENT-2c6fcc90";
pub const ENV_MARK: &str = "MARKER-SECRET-ENV-e51a55f3";
pub const DESC_MARK: &str = "MARKER-DESC-HIDDEN-ONLY-0b77ee42";
pub const PUBLIC_MARK: &str = "MARKER-PUBLIC-CONTENT-90ab12cd";

/// Everything only finance, carol, security or admins may see.
pub fn restricted_markers() -> Vec<&'static str> {
    vec![ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, NESTED_DIR, NESTED_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK, DESC_MARK]
}

pub fn setup_project(hub: &TestHub) -> Project {
    let admin = hub.person("admin");
    let dev = hub.person("dev");
    let fin = hub.person("fin");
    let carol = hub.person("carol");
    let sec = hub.person("sec");
    let name = unique("acme");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(
        &dir,
        &[
            (ROOT_FILE, ROOT_MARK),
            ("src/lib.rs", PUBLIC_MARK),
            (&format!("src/{NESTED_DIR}/key.txt"), NESTED_MARK),
            (&format!("{BILL_DIR}/acme/invoice.txt"), BILL_MARK),
            (&format!("{BILL_DIR}/.env"), &format!("KEY={ENV_MARK}\n")),
            (&format!("{PERSON_DIR}/notes.txt"), PERSON_MARK),
        ],
    );
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "initial import");
    let out = admin.ok(&dir, &["push"]);
    assert!(out.contains("Created project"), "{out}");
    for g in ["devs", "finance", "security"] {
        admin.ok(&dir, &["group", "create", g]);
    }
    admin.ok(&dir, &["group", "add", "devs", &dev.name]);
    admin.ok(&dir, &["group", "add", "finance", &fin.name]);
    admin.ok(&dir, &["group", "add", "security", &sec.name]);
    admin.ok(&dir, &["access", "src/", "public", "devs"]);
    admin.ok(&dir, &["access", &format!("src/{NESTED_DIR}/"), "security"]);
    admin.ok(&dir, &["access", &format!("{BILL_DIR}/"), "finance"]);
    admin.ok(&dir, &["access", &format!("{PERSON_DIR}/"), &carol.name]);
    admin.commit_main(&dir, "access rules");
    admin.ok(&dir, &["push"]);
    // A change of billing only: not in anyone else's history.
    write_files(&dir, &[(&format!("{BILL_DIR}/acme/invoice.txt"), &format!("{BILL_MARK}\nsecond"))]);
    admin.commit_main(&dir, DESC_MARK);
    admin.ok(&dir, &["push"]);
    Project {
        name,
        admin,
        dir,
        dev,
        fin,
        carol,
        sec,
    }
}

/// The real (admin's) tree of the `main` tag in `dir`: every path and id.
pub fn real_paths(dir: &Path) -> Vec<(String, ObjectId)> {
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let mut out = vec![(String::new(), repo.store().snapshot(&tip).unwrap().tree)];
    let mut stack = vec![(String::new(), repo.store().snapshot(&tip).unwrap().tree)];
    while let Some((p, id)) = stack.pop() {
        if let Ok(t) = repo.store().tree(&id) {
            for e in &t.entries {
                let c = if p.is_empty() { e.name.clone() } else { format!("{p}/{}", e.name) };
                out.push((c.clone(), e.id));
                if e.kind == veil_core::EntryKind::Dir {
                    stack.push((c, e.id));
                }
            }
        }
    }
    out
}

/// Every real snapshot id in `dir`'s history.
pub fn real_snapshots(dir: &Path) -> Vec<ObjectId> {
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    let mut out = Vec::new();
    let mut stack = vec![repo.view().tags["main"].target];
    while let Some(id) = stack.pop() {
        if out.contains(&id) {
            continue;
        }
        out.push(id);
        if let Ok(s) = repo.store().snapshot(&id) {
            stack.extend(s.parents.iter().copied());
        }
    }
    out
}

/// A hand-made push through the API, as a hostile client would send it.
pub struct Craft<'a> {
    pub api: &'a Api,
    pub token: String,
    pub identity: Identity,
    pub project: String,
    /// The tip the crafter builds on (as the server showed it to them).
    pub tip: ObjectId,
    pub root: ObjectId,
    pub objects: Vec<(ObjectId, Vec<u8>)>,
}

use veil_core::object::{EntryKind as K, Object as O, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility};

impl<'a> Craft<'a> {
    pub fn new(api: &'a Api, person: &Person, project: &str, branch: &str) -> Craft<'a> {
        Craft::with(api, person.token(), person.identity(), project, branch)
    }

    pub fn with(api: &'a Api, token: String, identity: Identity, project: &str, branch: &str) -> Craft<'a> {
        let tip = api.tips(Some(&token), project).unwrap().branches[branch];
        let h = api.post_json(Some(&token), &format!("/v1/projects/{project}/history"), &serde_json::json!({"tips": [tip.hex()]}));
        let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
        let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!() };
        Craft {
            api,
            token,
            identity,
            project: project.to_string(),
            tip,
            root: s.tree,
            objects: Vec::new(),
        }
    }

    fn tree(&self, path: &str, id: ObjectId) -> Tree {
        if let Some((_, raw)) = self.objects.iter().find(|(i, _)| *i == id) {
            if let O::Tree(t) = O::decode(raw).unwrap() {
                return t;
            }
        }
        let r = self.api.post_json(
            Some(&self.token),
            &format!("/v1/projects/{}/fetch", self.project),
            &serde_json::json!({"snapshot": self.tip.hex(), "objects": [{"path": path, "id": id.hex()}]}),
        );
        match O::decode(&r.frames()[0].1).unwrap() {
            O::Tree(t) => t,
            _ => panic!("not a tree"),
        }
    }

    fn put(&mut self, o: O) -> ObjectId {
        let raw = o.encode_with(TreeEncoding::Binary);
        let id = ObjectId::hash(&raw);
        self.objects.push((id, raw));
        id
    }

    /// Set `path` to an object (`raw`) with `vis`: plain, or sealed under a
    /// scope label.
    pub fn set(&mut self, path: &str, object: O, vis: Visibility) {
        let id = self.put(object);
        let parts: Vec<&str> = path.split('/').collect();
        let entry = TreeEntry {
            name: parts.last().unwrap().to_string(),
            kind: K::File,
            id,
            size: 1,
            executable: false,
            visibility: vis,
            fallback: None,
        };
        self.root = self.set_at("", Some(self.root), &parts, entry);
    }

    fn set_at(&mut self, dir: &str, tree: Option<ObjectId>, parts: &[&str], entry: TreeEntry) -> ObjectId {
        let mut t = match tree {
            Some(id) => self.tree(dir, id),
            None => Tree::default(),
        };
        if parts.len() == 1 {
            t.remove(parts[0]);
            t.insert(entry);
        } else {
            let child = t.get(parts[0]).filter(|e| e.kind == K::Dir).map(|e| e.id);
            let sub = if dir.is_empty() { parts[0].to_string() } else { format!("{dir}/{}", parts[0]) };
            let id = self.set_at(&sub, child, &parts[1..], entry);
            t.remove(parts[0]);
            t.insert(TreeEntry::dir(parts[0], id));
        }
        self.put(O::Tree(t))
    }

    pub fn file(&mut self, path: &str, content: &str) {
        self.set(path, O::Blob(content.as_bytes().to_vec()), Visibility::Public);
    }

    /// Commit and push to `branch`; the push's reply.
    pub fn push(mut self, branch: &str, msg: &str) -> Reply {
        let mut s = Snapshot {
            parents: vec![self.tip],
            change_id: veil_core::ChangeId::random(),
            tree: self.root,
            description: Text::Plain(msg.to_string()),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        };
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        let up = self.api.upload(&self.token, &self.project, &self.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        self.api.post_json(
            Some(&self.token),
            &format!("/v1/projects/{}/push", self.project),
            &serde_json::json!({"updates": [{"branch": branch, "expected": self.tip.hex(), "new": id.hex()}]}),
        )
    }
}

impl Craft<'_> {
    /// The root tree of snapshot `id` (one the crafter was given).
    pub fn tree_of(&self, id: ObjectId) -> ObjectId {
        let h = self.api.post_json(Some(&self.token), &format!("/v1/projects/{}/history", self.project), &serde_json::json!({"tips": [id.hex()]}));
        let (_, raw) = h.frames().into_iter().find(|(i, _)| *i == id).unwrap();
        match O::decode(&raw).unwrap() {
            O::Snapshot(s) => s.tree,
            _ => panic!(),
        }
    }

    /// Commit and push to `branch`, expecting it at `expected` (`None`: a
    /// new branch).
    pub fn push_to(mut self, branch: &str, expected: Option<ObjectId>) -> Reply {
        let mut s = Snapshot {
            parents: vec![self.tip],
            change_id: veil_core::ChangeId::random(),
            tree: self.root,
            description: Text::Plain(format!("to {branch}")),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            cloak: None,
            embargo: None,
            signature: None,
        };
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        let up = self.api.upload(&self.token, &self.project, &self.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        self.api.post_json(
            Some(&self.token),
            &format!("/v1/projects/{}/push", self.project),
            &serde_json::json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": id.hex()}]}),
        )
    }
}
