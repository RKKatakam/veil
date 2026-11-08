//! Test support: a server per test (in process), people with their own
//! `VEIL_HOME` driving the real `vl`, and a raw API client for attacks.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

use veil_core::{
    hub::{
        encoding,
        wire::{put_frame, Tips},
    },
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
    config: Config,
    pub _dir: tempfile::TempDir,
}

impl TestHub {
    pub fn start() -> TestHub {
        TestHub::start_with_ttl(Duration::from_secs(3600))
    }

    pub fn start_with_ttl(ttl: Duration) -> TestHub {
        TestHub::start_on(&std::env::var("VEIL_TEST_DATABASE_URL").expect("VEIL_TEST_DATABASE_URL (run scripts/verify-server.sh)"), ttl)
    }

    /// A server on the database at `database_url`.
    pub fn start_on(database_url: &str, ttl: Duration) -> TestHub {
        TestHub::start_with_s3(database_url, ttl, std::env::var("VEIL_TEST_S3_ENDPOINT").ok())
    }

    /// A server whose objects are in the S3 store at `endpoint` (MinIO, or
    /// something in front of it), or in a temporary directory.
    pub fn start_with_s3(database_url: &str, ttl: Duration, endpoint: Option<String>) -> TestHub {
        let dir = tempfile::Builder::new().prefix("veil-hub-test").tempdir().unwrap();
        let storage = match endpoint {
            Some(endpoint) => Storage::S3 {
                endpoint,
                bucket: std::env::var("VEIL_TEST_S3_BUCKET").unwrap_or_else(|_| "veil-test".into()),
                region: "us-east-1".into(),
                key: std::env::var("VEIL_TEST_S3_KEY").unwrap(),
                secret: std::env::var("VEIL_TEST_S3_SECRET").unwrap(),
            },
            None => Storage::Dir(dir.path().join("objects")),
        };
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            database_url: database_url.to_string(),
            storage,
            tls: TlsSource::SelfSigned,
            data_dir: dir.path().join("data"),
            session_ttl: ttl,
            db_connections: 16,
            // Tests count their own derive runs; `derived.rs` checks the
            // start-up catch-up by calling it.
            catch_up_at_start: false,
        };
        TestHub::run(config, dir)
    }

    /// Another server beside `other`, as a deployment runs several: the
    /// same database, data directory (identity, certificate, receipt key)
    /// and object storage.
    pub fn beside(other: &TestHub) -> TestHub {
        let dir = tempfile::Builder::new().prefix("veil-hub-test").tempdir().unwrap();
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..other.config.clone()
        };
        TestHub::run(config, dir)
    }

    fn run(config: Config, dir: tempfile::TempDir) -> TestHub {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(8)
            .thread_stack_size(veil_server::THREAD_STACK)
            .build()
            .unwrap();
        let running = rt.block_on(veil_server::start(config.clone())).expect("server starts");
        let ca = config.data_dir.join("self-signed-cert.pem");
        TestHub {
            port: running.addr.port(),
            cert_pem: running.cert_pem.clone(),
            running: Some(running),
            rt,
            ca,
            config,
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

    /// A new device of `of`'s: it signs in under their name and waits for
    /// one of their devices to confirm it (pending; `vl login` fails).
    pub fn new_device_of(&self, of: &Person) -> Person {
        let p = Person::new(self, &of.name);
        let out = p.fails(p.home.path(), &["login", &format!("veil://{}", self.authority()), "--name", &p.name, "--ca", self.ca.to_str().unwrap()]);
        assert!(out.contains("vl identity confirm"), "{out}");
        p
    }

    /// Anyone on Earth: never signed in.
    pub fn anyone(&self) -> Person {
        Person::new(self, "anyone")
    }

    /// Someone new, not signed in yet, under a unique name starting with
    /// `prefix` (an invite's recipient).
    pub fn newcomer(&self, prefix: &str) -> Person {
        Person::new(self, &unique(prefix))
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

    /// `vl args` in `dir` as this person.
    pub fn command(&self, dir: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(vl_bin());
        c.args(args)
            .current_dir(dir)
            .env("VEIL_HOME", self.home.path().join("veil"))
            .env("VEIL_USER", &self.name)
            .env("VEIL_HUB_CA", &self.ca)
            .env("NO_COLOR", "1");
        c
    }

    pub fn run(&self, dir: &Path, args: &[&str]) -> Output {
        // `timeout` ends a `vl` that never returns: the test then fails.
        let c = self.command(dir, args);
        Command::new("timeout")
            .arg("300")
            .arg(c.get_program())
            .args(c.get_args())
            .envs(c.get_envs().filter_map(|(k, v)| Some((k, v?))))
            .current_dir(dir)
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

    /// This device's fingerprint, as `vl identity show` prints it: what
    /// the person reads to an admin.
    pub fn fingerprint(&self) -> String {
        let out = self.ok(self.home.path(), &["identity", "show"]);
        let line = out.lines().find(|l| l.starts_with("device ")).expect("vl identity show prints the device fingerprint");
        line.split_whitespace().nth(1).unwrap().to_string()
    }

    pub fn token(&self) -> String {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.home.path().join("veil/hub.json")).unwrap()).unwrap();
        let servers = v["servers"].as_object().unwrap();
        servers.values().next().unwrap()["token"].as_str().unwrap().to_string()
    }

    /// The project fingerprint this person's clone `dir` trusts, as `vl
    /// identity show` prints it there (what an admin reads to a person).
    pub fn project_fingerprint(&self, dir: &Path) -> String {
        let out = self.ok(dir, &["identity", "show"]);
        let line = out.lines().find(|l| l.starts_with("project ")).unwrap_or_else(|| panic!("no project line in:\n{out}"));
        let fp = line.split_whitespace().nth(1).unwrap().to_string();
        assert!(veil_core::hub::wire::normalize_fingerprint(&fp).is_some(), "the clone trusts no project fingerprint: {line}");
        fp
    }

    /// Clone `url` into `dir` and confirm the project's fingerprint `fp`
    /// (compared with an admin out of band): the clone trusts its keys.
    pub fn clone_trusting(&self, url: &str, dir: &Path, fp: &str) {
        self.ok(self.home.path(), &["clone", url, dir.to_str().unwrap()]);
        self.ok(dir, &["identity", "confirm", fp]);
    }

    /// Confirm the fingerprint `fp` of `project` on this device (in a clone
    /// made for it): every later clone of the project here trusts its keys.
    pub fn trust_project(&self, hub: &TestHub, project: &str, fp: &str) {
        let d = self.dir(&format!("trust-{}", unique("c")));
        self.clone_trusting(&hub.url(project), &d, fp);
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
    /// The objects of an answer of frames, plain or encoded (decoded).
    pub fn frames(&self) -> Vec<(ObjectId, Vec<u8>)> {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        encoding::read_frames(&self.body, 1 << 32).unwrap().into_iter().map(|(i, r)| (i, r.into_owned())).collect()
    }

    /// The frames of the answer as sent: ids and encodings.
    pub fn raw_frames(&self) -> Vec<(ObjectId, Vec<u8>)> {
        assert_eq!(self.status, 200, "{}", String::from_utf8_lossy(&self.body));
        encoding::split_frames(&self.body).unwrap().into_iter().map(|(i, e)| (i, e.to_vec())).collect()
    }
}

impl Api {
    fn new(hub: &TestHub) -> Api {
        Api::at(&hub.authority(), &hub.cert_pem)
    }

    /// A client of the HTTPS server at `authority` (a regional cache, say)
    /// whose certificate is `cert_pem`.
    pub fn at(authority: &str, cert_pem: &str) -> Api {
        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(cert_pem.as_bytes())
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
            base: format!("https://{authority}"),
            authority: authority.to_string(),
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

    /// GET with extra headers (the object routes' `Veil-Grant`, …).
    pub fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Reply {
        let mut r = self.agent.get(format!("{}{path}", self.base));
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        Self::finish(r.call())
    }

    pub fn delete(&self, token: Option<&str>, path: &str) -> Reply {
        let mut r = self.agent.delete(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        Self::finish(r.call())
    }

    pub fn agent_delete(&self, token: &str, path: &str) -> Reply {
        Self::finish(self.agent.delete(format!("{}{path}", self.base)).header("authorization", &format!("Bearer {token}")).call())
    }

    pub fn post(&self, token: Option<&str>, path: &str, body: &[u8], json: bool) -> Reply {
        let mut r = self.agent.post(format!("{}{path}", self.base));
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        r = r.header("content-type", if json { "application/json" } else { "application/octet-stream" });
        Self::finish(r.send(body))
    }

    /// POST JSON with extra headers (a cache's token, …).
    pub fn post_with(&self, path: &str, body: &[u8], headers: &[(&str, &str)]) -> Reply {
        let mut r = self.agent.post(format!("{}{path}", self.base)).header("content-type", "application/json");
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        Self::finish(r.send(body))
    }

    /// `POST …/history` as this release's `vl` asks it: saying which
    /// repository format it reads (BUG-1379).
    pub fn history(&self, token: &str, project: &str, tips: &[ObjectId]) -> Reply {
        let body = serde_json::to_vec(&serde_json::json!({"tips": tips.iter().map(|t| t.hex()).collect::<Vec<_>>()})).unwrap();
        let auth = format!("Bearer {token}");
        let format = veil_core::repo::REPO_FORMAT.to_string();
        self.post_with(
            &format!("/v1/projects/{project}/history"),
            &body,
            &[("authorization", &auth), (veil_core::hub::wire::FORMAT_HEADER, &format)],
        )
    }

    pub fn post_json(&self, token: Option<&str>, path: &str, v: &serde_json::Value) -> Reply {
        self.post(token, path, &serde_json::to_vec(v).unwrap(), true)
    }

    /// POST JSON, failing the test only after `limit` (instead of the
    /// agent's 120 s): for requests whose duration a test scales from a
    /// baseline measured in the same run.
    pub fn post_json_within(&self, token: &str, path: &str, v: &serde_json::Value, limit: std::time::Duration) -> Reply {
        let r = self.agent.post(format!("{}{path}", self.base)).header("authorization", &format!("Bearer {token}")).header("content-type", "application/json");
        Self::finish(r.config().timeout_global(Some(limit)).build().send(&serde_json::to_vec(v).unwrap()[..]))
    }

    /// POST JSON, leaving the answer's body unread (a client that stalls).
    pub fn post_unread(&self, path: &str, body: &[u8]) -> ureq::http::Response<ureq::Body> {
        self.agent.post(format!("{}{path}", self.base)).header("content-type", "application/json").send(body).unwrap()
    }

    /// POST a body read from `body` as it is sent (chunked): a client that
    /// sends slowly, or stops.
    pub fn post_reader(&self, path: &str, body: impl std::io::Read + Send + 'static) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        self.agent.post(format!("{}{path}", self.base)).header("content-type", "application/json").send(ureq::SendBody::from_owned_reader(body))
    }

    /// GET with extra headers, leaving the answer's body unread (a client
    /// that stalls).
    pub fn get_unread(&self, path: &str, headers: &[(&str, &str)]) -> ureq::http::Response<ureq::Body> {
        let mut r = self.agent.get(format!("{}{path}", self.base));
        for (k, v) in headers {
            r = r.header(*k, *v);
        }
        r.call().unwrap()
    }

    /// POST JSON as a `vl` that reads encoded frames (compressed objects).
    pub fn post_json_encoded(&self, token: Option<&str>, path: &str, v: &serde_json::Value) -> (Reply, Option<String>) {
        let mut r = self.agent.post(format!("{}{path}", self.base)).header("content-type", "application/json").header("accept", encoding::FRAMES);
        if let Some(t) = token {
            r = r.header("authorization", &format!("Bearer {t}"));
        }
        let resp = r.send(&serde_json::to_vec(v).unwrap()[..]).unwrap();
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_string);
        (Self::finish(Ok(resp)), ct)
    }

    /// POST object frames as they are (encoded or not, well formed or not).
    pub fn upload_body(&self, token: &str, project: &str, body: &[u8]) -> Reply {
        self.post(Some(token), &format!("/v1/projects/{project}/objects"), body, false)
    }

    /// POST encoded object frames (S27), under the encoded frames' media
    /// type (which the server does not need: it reads every upload as
    /// encoded frames).
    pub fn upload_encoded_body(&self, token: &str, project: &str, body: &[u8]) -> Reply {
        let r = self
            .agent
            .post(format!("{}/v1/projects/{project}/objects", self.base))
            .header("authorization", &format!("Bearer {token}"))
            .header("content-type", encoding::FRAMES);
        Self::finish(r.send(body))
    }

    /// POST JSON with the `Host` header a relaying server would send.
    pub fn post_json_host(&self, path: &str, v: &serde_json::Value, host: &str) -> Reply {
        let r = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("host", host)
            .header("content-type", "application/json");
        Self::finish(r.send(&serde_json::to_vec(v).unwrap()[..]))
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

/// The bytes of a file in the server's data directory, an object's decoded
/// (S27: objects are stored compressed, so a scan of the raw files would
/// miss what they hold). Object files are `…/ab/cdef…` under their id.
pub fn stored_bytes(path: &Path) -> Vec<u8> {
    let b = std::fs::read(path).unwrap_or_default();
    let name = |p: Option<&Path>| p.and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let hex = format!("{}{}", name(path.parent()), name(Some(path)));
    match ObjectId::from_hex(&hex) {
        Ok(id) if encoding::is_compressed(&b) => encoding::decode(&id, &b, u64::MAX).map(|r| r.into_owned()).unwrap_or(b),
        _ => b,
    }
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
    /// The project's fingerprint (its `team` key ring's), as the admin's
    /// clone trusts it: what a person confirms before their device trusts
    /// the project's keys (BUG-845).
    pub fp: String,
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
    // The admin confirms each person's first device (docs/HUB.md §13.11).
    admin.ok(&dir, &["group", "add", "devs", &dev.name, "--confirm", &dev.fingerprint()]);
    admin.ok(&dir, &["group", "add", "finance", &fin.name, "--confirm", &fin.fingerprint()]);
    admin.ok(&dir, &["group", "add", "security", &sec.name, "--confirm", &sec.fingerprint()]);
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
    // Each of them also compared the project's fingerprint with the admin
    // (BUG-845): their devices trust its keys.
    let fp = admin.project_fingerprint(&dir);
    for who in [&dev, &fin, &carol, &sec] {
        who.trust_project(hub, &name, &fp);
    }
    Project {
        name,
        fp,
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
        let h = api.history(&token, project, &[tip]);
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

    pub fn put(&mut self, o: O) -> ObjectId {
        let raw = o.encode_with(TreeEncoding::Binary);
        let id = ObjectId::hash(&raw);
        self.objects.push((id, raw));
        id
    }

    /// Set `path` to an object (`raw`) with `vis`: plain, or sealed under a
    /// scope label.
    pub fn set(&mut self, path: &str, object: O, vis: Visibility) {
        self.set_kind(path, object, K::File, vis)
    }

    /// [`Craft::set`] with an entry of `kind` (a conflict, say).
    pub fn set_kind(&mut self, path: &str, object: O, kind: K, vis: Visibility) {
        // What `vl` records: a file's content length (the server refuses an
        // entry recording less than its object holds, BUG-1087).
        let size = match &object {
            O::Blob(b) => b.len() as u64,
            o => o.encode().len() as u64,
        };
        let id = self.put(object);
        let parts: Vec<&str> = path.split('/').collect();
        let entry = TreeEntry {
            name: parts.last().unwrap().to_string(),
            kind,
            id,
            // A conflict entry carries no size (its terms do).
            size: if kind == K::Conflict { 0 } else { size },
            executable: false,
            visibility: vis,
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
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        self.send(serde_json::json!({"updates": [{"branch": branch, "expected": self.tip.hex(), "new": id.hex()}]}))
    }
}

impl Craft<'_> {
    /// Commit a merge of the tip and `others` (as the crafter was given
    /// them) and push it to `branch`.
    pub fn push_merge(mut self, branch: &str, others: &[ObjectId]) -> Reply {
        let mut parents = vec![self.tip];
        parents.extend_from_slice(others);
        let mut s = Snapshot {
            parents,
            change_id: veil_core::ChangeId::random(),
            tree: self.root,
            description: Text::Plain("merge".into()),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        self.send(serde_json::json!({"updates": [{"branch": branch, "expected": self.tip.hex(), "new": id.hex()}]}))
    }

    /// Commit and push to `branch` (expected at `expected`), letting `edit`
    /// change the snapshot before it is signed; the snapshot's id and the
    /// push's reply.
    pub fn push_edited(mut self, branch: &str, expected: Option<ObjectId>, edit: impl FnOnce(&mut Snapshot)) -> (ObjectId, Reply) {
        let mut s = Snapshot {
            parents: vec![self.tip],
            change_id: veil_core::ChangeId::random(),
            tree: self.root,
            description: Text::Plain(format!("to {branch}")),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        edit(&mut s);
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        let r = self.send(serde_json::json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": id.hex()}]}));
        (id, r)
    }

    /// Upload what the crafter made, then push `body` with the receipts
    /// the server gave for it, as `vl` does.
    fn send(&self, mut body: serde_json::Value) -> Reply {
        let up = self.api.upload(&self.token, &self.project, &self.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let map: serde_json::Map<String, serde_json::Value> =
            self.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        body["receipts"] = serde_json::Value::Object(map);
        self.api.post_json(Some(&self.token), &format!("/v1/projects/{}/push", self.project), &body)
    }

    /// Point `path` at a copy of object `id` (fetched where the crafter
    /// can read it, at `from` in snapshot `snap`), uploaded like any write.
    pub fn copy(&mut self, path: &str, snap: ObjectId, from: &str, id: ObjectId, size: u64) {
        let r = self.api.post_json(
            Some(&self.token),
            &format!("/v1/projects/{}/fetch", self.project),
            &serde_json::json!({"snapshot": snap.hex(), "objects": [{"path": from, "id": id.hex()}]}),
        );
        let (got, raw) = r.frames().into_iter().next().unwrap();
        assert_eq!(got, id);
        self.objects.push((id, raw));
        self.refer(path, id, size);
    }

    /// Upload `o` with the push and return its id.
    pub fn put_object(&mut self, o: O) -> ObjectId {
        self.put(o)
    }

    /// Set `path` to `entry` as given (its object is not uploaded).
    pub fn set_entry(&mut self, path: &str, mut entry: TreeEntry) {
        let parts: Vec<&str> = path.split('/').collect();
        entry.name = parts.last().unwrap().to_string();
        self.root = self.set_at("", Some(self.root), &parts, entry);
    }

    /// Point `path` at directory tree `id` without uploading it.
    pub fn refer_dir(&mut self, path: &str, id: ObjectId) {
        let parts: Vec<&str> = path.split('/').collect();
        let entry = TreeEntry::dir(parts.last().unwrap(), id);
        self.root = self.set_at("", Some(self.root), &parts, entry);
    }

    /// Point `path` at object `id` without uploading it.
    pub fn refer(&mut self, path: &str, id: ObjectId, size: u64) {
        let parts: Vec<&str> = path.split('/').collect();
        let entry = TreeEntry {
            name: parts.last().unwrap().to_string(),
            kind: K::File,
            id,
            size,
            executable: false,
            visibility: Visibility::Public,
        };
        self.root = self.set_at("", Some(self.root), &parts, entry);
    }

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
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        s.sign(&self.identity);
        let id = self.put(O::Snapshot(s));
        self.send(serde_json::json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": id.hex()}]}))
    }
}
