//! `vl`'s client for the Veil server (`docs/HUB.md`; milestone S1).
//!
//! * **URLs:** `veil://host[:port]/project` or `https://host[:port]/project`
//!   (HTTPS; the default port is 443).
//! * **Sign-in:** challenge-response with this device's identity key
//!   (`vl login`), then a session token kept in `$VEIL_HOME/hub.json`
//!   (mode 0600), with the server's certificate when it is self-signed
//!   (`--ca`). An expired session is renewed with the key, silently. Without
//!   a session the client is anyone on Earth: it sees `public` folders only.
//! * **Fetch on demand** (Scion): the client asks for the branch tips, the
//!   snapshots it lacks, then trees from the root down and the files it
//!   needs, each by id with the path where it met it. It never sends a list
//!   of what it has; it skips what it already holds.
//! * **Push:** the snapshots the server lacks and, of their trees, what
//!   differs from their parents at the same path ([`Introduced`]),
//!   uploaded as the walk finds it; then one request that moves each
//!   branch by compare-and-swap. Key rings (secret scopes only)
//!   go up first and come down with every pull.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    crypto::domains::{SIG_CONTEXT_HUB_DEVICE, SIG_CONTEXT_HUB_LOGIN},
    hub::encoding,
    hub::wire::{
        device_fingerprint, put_frame, vouch_message, AccessInfo, AdminsInfo, BranchUpdate, Challenge, ChallengeRequest, Devices, ErrorBody,
        FetchRequest, GroupChange, GroupInfo, HistoryRequest, LoginRequest, PushRequest, PushResult, Session, Tips, VouchRequest, Want,
    },
    identity::parse_public_identity,
    keychain::KeyRing,
    object::{EntryKind, Object},
    oplog::Tag,
    remote::{apply_remote_tags, Incoming, SyncReport},
    store::ObjectStore,
    Identity, ObjectId, Repo,
};

use crate::ctx::veil_home;

/// A Veil server project URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubUrl {
    /// `host[:port]` as given.
    pub authority: String,
    /// Empty for a bare server URL (`vl login veil://host`).
    pub project: String,
}

impl HubUrl {
    /// `Some` if `s` is a Veil server URL (then `Err` if it is malformed).
    pub fn parse(s: &str) -> Option<Result<HubUrl>> {
        let rest = s.strip_prefix("veil://").or_else(|| s.strip_prefix("https://"))?;
        Some((|| {
            let rest = rest.trim_end_matches('/');
            let (authority, project) = rest.split_once('/').unwrap_or((rest, ""));
            if authority.is_empty() || authority.contains(['@', '?', '#', ' ']) {
                bail!("invalid server URL {s:?}: expected veil://host[:port]/project");
            }
            if project.contains('/') {
                bail!("invalid server URL {s:?}: a project name has no '/'");
            }
            Ok(HubUrl {
                authority: authority.to_ascii_lowercase(),
                project: project.to_string(),
            })
        })())
    }

    fn base(&self) -> String {
        format!("https://{}", self.authority)
    }

    fn project_path(&self, rest: &str) -> String {
        format!("/v1/projects/{}{rest}", self.project)
    }
}

pub fn is_hub_url(s: &str) -> bool {
    HubUrl::parse(s).is_some()
}

// ---- $VEIL_HOME/hub.json ------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ServerEntry {
    /// The server's certificate (PEM), when it is not signed by a public CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default)]
    expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hub_key: Option<String>,
    /// Devices this device's person confirmed as an admin, by fingerprint
    /// (person → signing keys): trusted later, when a rule's key ring is
    /// created after the confirmation (`docs/HUB.md` §13.12).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    confirmed: BTreeMap<String, Vec<String>>,
    /// Invites this device made (public key → person): a join under one
    /// confirms the joining device for rings created after the invite.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    invites: BTreeMap<String, String>,
    /// Project fingerprints this device confirmed (project → fingerprint):
    /// the only `team` key ring of that project it trusts (BUG-845).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    anchors: BTreeMap<String, String>,
    /// Fields this `vl` does not know (a later release's, on the same
    /// machine), kept as they are by every rewrite (BUG-1393).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Default, Serialize, Deserialize)]
struct HubFile {
    #[serde(default)]
    servers: BTreeMap<String, ServerEntry>,
    /// Fields this `vl` does not know, kept as they are (BUG-1393).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

fn hub_file() -> std::path::PathBuf {
    veil_home().join("hub.json")
}

fn load_file() -> Result<HubFile> {
    match std::fs::read(hub_file()) {
        Ok(b) => Ok(serde_json::from_slice(&b).context("reading $VEIL_HOME/hub.json")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HubFile::default()),
        Err(e) => Err(e.into()),
    }
}

/// Write `hub.json` (it holds session tokens): owner-only, atomically.
fn save_file(f: &HubFile) -> Result<()> {
    use std::io::Write;
    let path = hub_file();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o.open(&tmp)?;
    file.write_all(&serde_json::to_vec_pretty(f)?)?;
    file.sync_all()?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn update_entry(authority: &str, f: impl FnOnce(&mut ServerEntry)) -> Result<()> {
    // One writer at a time: the background key sharing renews sessions
    // while a command records a confirmation.
    let lock = hub_file().with_extension("lock");
    std::fs::create_dir_all(lock.parent().unwrap())?;
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(lock)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: a valid descriptor; released when `lock` is closed.
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    }
    let mut file = load_file()?;
    f(file.servers.entry(authority.to_string()).or_default());
    let r = save_file(&file);
    drop(lock);
    r
}

/// The fingerprint of a full public identity (`4F2A-9C1E-…`): what
/// people compare out of band (`docs/HUB.md` §13.11).
pub fn fingerprint(public_identity: &str) -> Option<String> {
    parse_public_identity(public_identity).ok().and_then(|id| device_fingerprint(&id))
}

/// What this device confirmed on a server as an admin: devices (person →
/// signing keys) and invites (key → person).
pub type Remembered = (BTreeMap<String, Vec<String>>, BTreeMap<String, String>);

/// What this device confirmed on `authority` as an admin. Device-local.
pub fn remembered(authority: &str) -> Result<Remembered> {
    Ok(load_file()?.servers.remove(authority).map(|e| (e.confirmed, e.invites)).unwrap_or_default())
}

/// Remember that this device confirmed `signing_key` as `person`'s device.
pub fn remember_device(authority: &str, person: &str, signing_key: &str) -> Result<()> {
    update_entry(authority, |e| {
        let keys = e.confirmed.entry(person.to_string()).or_default();
        if !keys.iter().any(|k| k == signing_key) {
            keys.push(signing_key.to_string());
        }
    })
}

/// Remember an invite this device made.
pub fn remember_invite(authority: &str, key: &str, person: &str) -> Result<()> {
    update_entry(authority, |e| {
        e.invites.insert(key.to_string(), person.to_string());
    })
}

/// The fingerprint this device confirmed for `project` on `authority`.
pub fn anchor_for(authority: &str, project: &str) -> Result<Option<String>> {
    Ok(load_file()?.servers.remove(authority).and_then(|mut e| e.anchors.remove(project)))
}

/// Remember the fingerprint this device confirmed for `project`.
pub fn set_anchor_for(authority: &str, project: &str, fingerprint: &str) -> Result<()> {
    update_entry(authority, |e| {
        e.anchors.insert(project.to_string(), fingerprint.to_string());
    })
}

/// The servers this device has signed in to (`host:port`), with who it
/// signed in as.
/// The signing key of the server at `authority` that this device pinned
/// when it signed in (`hub_key` in `$VEIL_HOME/hub.json`).
pub fn pinned_server_key(authority: &str) -> Result<Option<String>> {
    Ok(load_file()?.servers.get(authority).and_then(|e| e.hub_key.clone()))
}

/// The pinned signing keys of the servers `repo` syncs with (its remotes):
/// a snapshot signed by one is the server's (`vl log` shows `✓server`).
/// `hub.json` is read once for a set of remotes (a log asks for every
/// row); nothing if it cannot be read.
pub fn server_keys(repo: &Repo) -> Arc<Vec<String>> {
    type Cached = (Vec<String>, Arc<Vec<String>>);
    static KEYS: std::sync::Mutex<Option<Cached>> = std::sync::Mutex::new(None);
    let urls: Vec<String> = repo.config().remotes.values().map(|r| r.url.clone()).collect();
    let mut cached = KEYS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((of, keys)) = cached.as_ref() {
        if *of == urls {
            return keys.clone();
        }
    }
    let file = load_file().unwrap_or_default();
    let mut keys: Vec<String> =
        urls.iter().filter_map(|u| HubUrl::parse(u)?.ok()).filter_map(|u| file.servers.get(&u.authority)?.hub_key.clone()).collect();
    keys.sort();
    keys.dedup();
    let keys = Arc::new(keys);
    *cached = Some((urls, keys.clone()));
    keys
}

pub fn signed_in_servers() -> Result<Vec<(String, String)>> {
    Ok(load_file()?.servers.into_iter().filter_map(|(a, e)| Some((a, e.person?))).collect())
}

// ---- the client -------------------------------------------------------------------------

/// An HTTPS agent's configuration for a server: its certificate as this
/// Veil home trusts it (`VEIL_HUB_CA`, or the one `vl login --ca`
/// remembered), else the public CAs.
fn agent_config(entry: Option<&ServerEntry>) -> Result<ureq::config::ConfigBuilder<ureq::typestate::AgentScope>> {
    let ca = match std::env::var_os("VEIL_HUB_CA") {
        Some(p) => Some(std::fs::read_to_string(&p).with_context(|| format!("reading VEIL_HUB_CA {}", Path::new(&p).display()))?),
        None => entry.and_then(|e| e.ca.clone()),
    };
    let mut tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::Rustls);
    if let Some(pem) = &ca {
        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(pem.as_bytes())
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect();
        if certs.is_empty() {
            bail!("no certificate in the server's CA file");
        }
        tls = tls.root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)));
    }
    Ok(ureq::Agent::config_builder().tls_config(tls.build()).http_status_as_error(false))
}

/// The configuration of an agent for the server at `authority`, trusted as
/// [`Client`] trusts it, holding no session (the Veil daemon's upstream).
pub(crate) fn upstream_agent_config(authority: &str) -> Result<ureq::config::ConfigBuilder<ureq::typestate::AgentScope>> {
    agent_config(load_file()?.servers.get(authority))
}

pub struct Client {
    agent: ureq::Agent,
    pub url: HubUrl,
    identity: Identity,
    token: std::cell::RefCell<Option<String>>,
    /// Signed in before (an entry in hub.json): renew the session silently.
    known: bool,
}

/// How often, how long each time and how long in all [`Client::send`]
/// waits out a server's `retry_after_ms` (BUG-1331) or `warming` (BUG-1913).
const RETRIES: u32 = 8;
const RETRY_WAIT: Duration = Duration::from_secs(30);
const RETRY_FOR: Duration = Duration::from_secs(120);

/// Is this answer `503 warming`: the server is preparing the caller's
/// history, and the same request succeeds a little later? [`Client::send`]
/// has waited it out already (BUG-1913): no caller asks again for it.
pub(crate) fn is_warming(status: u16, body: &[u8]) -> bool {
    status == 503 && serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| v["code"] == "warming")
}

/// How many milliseconds an answer asks for before the request is sent
/// again, after `tries` waits: the `retry_after_ms` of a `429` or a `503`
/// (BUG-1331); for a `503 warming`, which carries none (BUG-1913), half a
/// second, twice as long each time, up to 8 s (the server waits for the
/// history itself, up to a query's deadline, before each such answer).
/// `None`: the answer is the request's.
fn retry_after(status: u16, body: &[u8], tries: u32) -> Option<u64> {
    if !matches!(status, 429 | 503) {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    match v["retry_after_ms"].as_u64() {
        Some(ms) => Some(ms),
        None if v["code"] == "warming" => Some(500 << tries.min(4)),
        None => None,
    }
}

/// Fewest and most objects, and about the most bytes, per fetch request
/// when [`Client::fetch_each`] splits them, and how many requests it sends
/// at once.
const FETCH_PART_MIN: usize = 1_000;
const FETCH_PART: usize = 2_500;
const FETCH_BYTES: u64 = 8 << 20;
const FETCH_REQUESTS: usize = 8;

/// Body of a response: JSON or object frames.
fn read_body(resp: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
    let mut body = resp.into_body();
    Ok(body.with_config().limit(ANSWER_LIMIT).read_to_vec()?)
}

/// Most bytes one answer may hold, and its objects decoded.
const ANSWER_LIMIT: u64 = 4 << 30;

/// What `vl` reads: encoded frames (compressed objects, S27) as well as
/// JSON. A server from before S27 ignores it and sends plain frames, which
/// are encoded frames too.
const ACCEPT: &str = "application/x-veil-encoded-frames, application/json";
/// Every request says which repository format this `vl` reads (BUG-1379).
use veil_core::{hub::wire::FORMAT_HEADER, repo::REPO_FORMAT};

/// The objects of an answer of (encoded or plain) frames, each decoded
/// (bounded) and checked against its id.
pub(crate) fn objects_of(body: &[u8]) -> Result<Vec<(ObjectId, Vec<u8>)>> {
    Ok(encoding::read_frames(body, ANSWER_LIMIT)?.into_iter().map(|(id, raw)| (id, raw.into_owned())).collect())
}

/// Frames decoded into one buffer: each object's bytes' range, in order.
struct Decoded {
    bytes: Vec<u8>,
    objects: Vec<std::ops::Range<usize>>,
}

impl Decoded {
    /// `frames` decoded (each bounded, and at most `limit` bytes in all)
    /// and checked against their ids, into one buffer sized from what the
    /// encodings declare.
    fn of(frames: &[(ObjectId, &[u8])], limit: u64) -> Result<Decoded> {
        let size: u64 = frames.iter().map(|(_, enc)| encoding::decoded_len(enc).unwrap_or(0)).sum();
        let mut d = Decoded { bytes: Vec::with_capacity(size.min(limit).min(256 << 20) as usize), objects: Vec::with_capacity(frames.len()) };
        let mut left = limit;
        for (id, enc) in frames {
            let raw = encoding::decode(id, enc, left.min(veil_core::hub::wire::MAX_FRAME_OBJECT as u64))?;
            left -= raw.len() as u64;
            let start = d.bytes.len();
            d.bytes.extend_from_slice(&raw);
            d.objects.push(start..d.bytes.len());
        }
        Ok(d)
    }

    /// An answer's frames decoded on up to 8 threads, in order: one
    /// answer is decoded at a time, so only answers as sent (compressed)
    /// wait in flight.
    fn parallel(frames: &[(ObjectId, &[u8])]) -> Result<Vec<Decoded>> {
        let threads = (frames.len() / 256).clamp(1, 8);
        if threads == 1 {
            return Ok(vec![Decoded::of(frames, ANSWER_LIMIT)?]);
        }
        let chunk = frames.len().div_ceil(threads);
        std::thread::scope(|s| {
            let parts: Vec<_> = frames.chunks(chunk).map(|c| s.spawn(move || Decoded::of(c, ANSWER_LIMIT / threads as u64))).collect();
            parts.into_iter().map(|p| p.join().map_err(|_| anyhow!("a decoding thread panicked"))?).collect()
        })
    }
}

impl Client {
    /// This device's identity.
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn new(url: &HubUrl, identity: Identity) -> Result<Client> {
        let file = load_file()?;
        let entry = file.servers.get(&url.authority).cloned();
        let agent = agent_config(entry.as_ref())?.timeout_global(Some(Duration::from_secs(600))).build().new_agent();
        let known = entry.as_ref().is_some_and(|e| e.person.is_some());
        let token = entry
            .as_ref()
            .filter(|e| e.expires_at > veil_core::now_millis() + 30_000)
            .and_then(|e| e.token.clone());
        Ok(Client {
            agent,
            url: url.clone(),
            identity,
            token: std::cell::RefCell::new(token),
            known,
        })
    }

    /// Remember the server's certificate (a self-signed one, for development).
    pub fn trust_ca(authority: &str, pem: &str) -> Result<()> {
        update_entry(authority, |e| e.ca = Some(pem.to_string()))
    }

    fn error(status: u16, body: &[u8]) -> anyhow::Error {
        match serde_json::from_slice::<ErrorBody>(body) {
            Ok(e) => anyhow!("{} (server: {})", e.message, e.code),
            Err(_) => anyhow!("the server answered HTTP {status}"),
        }
    }

    /// [`Client::send_once`], waiting out a server that says to come back
    /// ([`retry_after`]): past its rate limits (`429`) or shedding load
    /// (`503`), its answer carries `retry_after_ms` (BUG-1331); preparing
    /// the caller's history, it answers `503 warming` (BUG-1913), on any
    /// route that reads history (a pull's `/history` among them). At most
    /// [`RETRIES`] waits of at most [`RETRY_WAIT`] each, within
    /// [`RETRY_FOR`] in all; then the server's last answer.
    fn send(&self, method: &str, path: &str, body: Option<(&str, Vec<u8>)>, auth: bool) -> Result<(u16, Vec<u8>)> {
        let start = std::time::Instant::now();
        let mut tries = 0;
        loop {
            let (status, out) = self.send_once(method, path, body.as_ref().map(|(ct, b)| (*ct, &b[..])), auth)?;
            let Some(ms) = retry_after(status, &out, tries) else { return Ok((status, out)) };
            let jitter = u64::from(veil_core::crypto::random_bytes::<1>()[0]);
            let wait = Duration::from_millis(ms.saturating_add(jitter)).min(RETRY_WAIT);
            if tries >= RETRIES || start.elapsed() + wait > RETRY_FOR {
                return Ok((status, out));
            }
            tries += 1;
            std::thread::sleep(wait);
        }
    }

    fn send_once(&self, method: &str, path: &str, body: Option<(&str, &[u8])>, auth: bool) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{path}", self.url.base());
        let token = if auth { self.token.borrow().clone() } else { None };
        let resp = match (method, body) {
            ("GET", _) => {
                let mut r = self.agent.get(&url).header(FORMAT_HEADER, &REPO_FORMAT.to_string());
                if let Some(t) = &token {
                    r = r.header("authorization", &format!("Bearer {t}"));
                }
                r.call()
            }
            (m, body) => {
                let mut r = if m == "DELETE" {
                    self.agent.delete(&url).force_send_body()
                } else {
                    self.agent.post(&url)
                };
                if let Some(t) = &token {
                    r = r.header("authorization", &format!("Bearer {t}"));
                }
                r = r.header("accept", ACCEPT).header(FORMAT_HEADER, &REPO_FORMAT.to_string());
                match body {
                    Some((ct, b)) => r.header("content-type", ct).send(b),
                    None => r.send_empty(),
                }
            }
        }
        .with_context(|| format!("connecting to the Veil server at {}", self.url.authority))?;
        let status = resp.status().as_u16();
        Ok((status, read_body(resp)?))
    }

    /// Send a request, signing in again once if the session expired.
    fn call(&self, method: &str, path: &str, body: Option<(&str, Vec<u8>)>) -> Result<(u16, Vec<u8>)> {
        if self.token.borrow().is_none() && self.known {
            self.login(None)?;
        }
        let (status, out) = self.send(method, path, body.clone(), true)?;
        if status == 401 && self.known {
            self.login(None)?;
            return self.send(method, path, body, true);
        }
        Ok((status, out))
    }

    fn ok(&self, method: &str, path: &str, body: Option<(&str, Vec<u8>)>) -> Result<Vec<u8>> {
        let (status, out) = self.call(method, path, body)?;
        if !(200..300).contains(&status) {
            return Err(Self::error(status, &out));
        }
        Ok(out)
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, method: &str, path: &str, req: Option<&impl Serialize>) -> Result<T> {
        let body = req.map(|r| ("application/json", serde_json::to_vec(r).unwrap()));
        let out = self.ok(method, path, body)?;
        serde_json::from_slice(&out).context("the server's answer")
    }

    /// Sign in with this device's key; `name` registers it as a new person.
    /// The server's signing key is pinned at the first sign-in (trust on
    /// first use) and never replaced by a session `vl` renews by itself:
    /// a server that presents another key is refused (BUG-1910).
    pub fn login(&self, name: Option<&str>) -> Result<Session> {
        Ok(self.sign_in(name, false)?.0)
    }

    /// `vl login`, typed by the person: [`Client::login`], which also
    /// accepts a server key other than the pinned one. Returns the key
    /// that was pinned before, when it was another.
    pub fn login_pinning(&self, name: Option<&str>) -> Result<(Session, Option<String>)> {
        self.sign_in(name, true)
    }

    fn sign_in(&self, name: Option<&str>, accept_new_key: bool) -> Result<(Session, Option<String>)> {
        let key = self.identity.verifying_hex();
        let (status, out) = self.send(
            "POST",
            "/v1/auth/challenge",
            Some(("application/json", serde_json::to_vec(&ChallengeRequest { key: key.clone() })?)),
            false,
        )?;
        if status != 200 {
            return Err(Self::error(status, &out));
        }
        let ch: Challenge = serde_json::from_slice(&out)?;
        let hub = self.url.authority.clone();
        let req = LoginRequest {
            signature: self
                .identity
                .sign(SIG_CONTEXT_HUB_LOGIN, &veil_core::hub::wire::login_message(&hub, &ch.challenge)),
            key,
            challenge: ch.challenge,
            hub,
            identity: self.identity.public_id(),
            name: name.map(str::to_string),
        };
        let (status, out) = self.send("POST", "/v1/auth/login", Some(("application/json", serde_json::to_vec(&req)?)), false)?;
        if status != 200 {
            if serde_json::from_slice::<ErrorBody>(&out).is_ok_and(|e| e.code == "device_pending") {
                let fp = fingerprint(&self.identity.public_id()).unwrap_or_default();
                bail!(
                    "the name '{}' is taken. If it is yours, confirm this device ({fp}) on a device you already use:\n    \
                     vl identity confirm {fp} --server veil://{}\n  then run `vl login` here again. Otherwise choose another name.",
                    name.unwrap_or("?"),
                    self.url.authority
                );
            }
            return Err(Self::error(status, &out));
        }
        let s: Session = serde_json::from_slice(&out)?;
        let pinned = pinned_server_key(&self.url.authority)?.filter(|p| *p != s.hub_key);
        if let Some(pinned) = pinned.as_ref().filter(|_| !accept_new_key) {
            bail!(
                "the server at {a} now signs with another key ({new}) than the one this device pinned when it signed in ({old}): not signed in. \
                 If the server's key was replaced on purpose (its data directory was made again), accept the new one with `vl login veil://{a}`; \
                 otherwise this is not the server you signed in to",
                a = self.url.authority,
                new = crate::render::safe(s.hub_key.get(..16).unwrap_or(&s.hub_key)),
                old = crate::render::safe(pinned.get(..16).unwrap_or(pinned)),
            );
        }
        *self.token.borrow_mut() = Some(s.token.clone());
        update_entry(&self.url.authority, |e| {
            e.token = Some(s.token.clone());
            e.expires_at = s.expires_at;
            e.person = Some(s.person.clone());
            e.hub_key = Some(s.hub_key.clone());
        })?;
        Ok((s, pinned))
    }

    /// The branch tips this caller may see; `None` if there is no project
    /// they can see.
    pub fn tips(&self) -> Result<Option<Tips>> {
        let (status, out) = self.call("GET", &self.url.project_path("/tips"), None)?;
        match status {
            200 => Ok(Some(serde_json::from_slice(&out)?)),
            404 => Ok(None),
            s => Err(Self::error(s, &out)),
        }
    }

    /// One background [`Client::tips`] check without waiting out a rate
    /// limit (`vl daemon follow`, BUG-1680): returns `(Some(tips), 0)` on
    /// `200`, `(None, ms)` on `429` or `503` with `retry_after_ms`, and
    /// `(None, 0)` otherwise.
    pub(crate) fn tips_once(&self) -> Result<(Option<Tips>, i64)> {
        if self.token.borrow().is_none() && self.known {
            self.login(None)?;
        }
        let path = self.url.project_path("/tips");
        let (mut status, mut out) = self.send_once("GET", &path, None, true)?;
        if status == 401 && self.known {
            self.login(None)?;
            (status, out) = self.send_once("GET", &path, None, true)?;
        }
        match status {
            200 => Ok((Some(serde_json::from_slice(&out)?), 0)),
            429 | 503 => {
                let ms = serde_json::from_slice::<serde_json::Value>(&out).ok().and_then(|v| v["retry_after_ms"].as_i64()).unwrap_or(5_000).max(5_000);
                Ok((None, ms))
            }
            _ => Ok((None, 0)),
        }
    }

    pub fn create_project(&self) -> Result<Tips> {
        self.json("POST", &self.url.project_path(""), None::<&()>)
    }

    /// The caller's projected history from `tips` down to `stop`: all of
    /// it, or one page of at most `limit` snapshots (and every tip; a
    /// server of revision 3).
    pub fn history(&self, tips: Vec<ObjectId>, stop: Vec<ObjectId>, limit: Option<usize>) -> Result<Vec<(ObjectId, Vec<u8>)>> {
        let out = self.ok(
            "POST",
            &self.url.project_path("/history"),
            Some(("application/json", serde_json::to_vec(&HistoryRequest { tips, stop, limit })?)),
        )?;
        objects_of(&out)
    }

    /// A request whose status the caller interprets: `Err` only when the
    /// server could not be reached (the connection failed or timed out).
    pub(crate) fn post_status(&self, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        self.call("POST", &self.url.project_path(path), Some(("application/json", body)))
    }

    /// [`Client::post_status`] of a GET.
    pub(crate) fn get_status(&self, path: &str) -> Result<(u16, Vec<u8>)> {
        self.call("GET", &self.url.project_path(path), None)
    }

    /// The answer to one fetch request: the object frames of `objects`.
    fn fetch_body(&self, snapshot: ObjectId, objects: Vec<Want>) -> Result<Vec<u8>> {
        self.ok(
            "POST",
            &self.url.project_path("/fetch"),
            Some(("application/json", serde_json::to_vec(&FetchRequest { snapshot, objects })?)),
        )
    }

    /// A fetch of many objects, each handed to `f` with its want
    /// as its part arrives (BUG-859): `wants` split into parts of about
    /// [`FETCH_BYTES`] by the sizes tree entries carry (`sizes`, one per
    /// want; 0 where unknown) and at most [`FETCH_PART`] objects (at least
    /// [`FETCH_REQUESTS`] parts of a large level), up to
    /// [`FETCH_REQUESTS`] of them in flight (the server reads and frames
    /// them on several threads). Each part's objects are checked against
    /// its wants, in order.
    pub fn fetch_each(&self, snapshot: ObjectId, wants: &[Want], sizes: &[u64], mut f: impl FnMut(&Want, Vec<u8>) -> Result<()>) -> Result<()> {
        // Fewer than 2,000 objects in one request; more in at least
        // FETCH_REQUESTS parts (the server serves each on its own threads).
        let most = match wants.len() < 2 * FETCH_PART_MIN {
            true => wants.len(),
            false => wants.len().div_ceil(FETCH_REQUESTS).clamp(FETCH_PART_MIN, FETCH_PART),
        };
        let mut parts: Vec<std::ops::Range<usize>> = Vec::new();
        let (mut start, mut bytes) = (0, 0u64);
        for (i, size) in sizes.iter().enumerate().take(wants.len()) {
            if i > start && (i - start >= most || bytes + size > FETCH_BYTES) {
                parts.push(start..i);
                (start, bytes) = (i, 0);
            }
            bytes += size;
        }
        if start < wants.len() {
            parts.push(start..wants.len());
        }
        // Each part's answer checked against its wants, then decoded here
        // (on several threads): only answers as sent (compressed) wait in
        // flight, and one answer at a time is held decoded.
        let mut check = |part: &[Want], body: &[u8]| -> Result<()> {
            let frames = encoding::split_frames(body)?;
            if frames.len() != part.len() {
                bail!("the server sent {} objects for {} asked", frames.len(), part.len());
            }
            if part.iter().zip(&frames).any(|(w, (id, _))| *id != w.id) {
                bail!("the server sent another object than asked");
            }
            let mut wants = part.iter();
            for d in Decoded::parallel(&frames)? {
                for range in d.objects {
                    f(wants.next().expect("one want per frame"), d.bytes[range].to_vec())?;
                }
            }
            Ok(())
        };
        if parts.len() == 1 {
            return check(wants, &self.fetch_body(snapshot, wants.to_vec())?);
        }
        let token = self.token.borrow().clone();
        let url = format!("{}{}", self.url.base(), self.url.project_path("/fetch"));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let (agent, parts) = (&self.agent, &parts);
        std::thread::scope(|s| -> Result<()> {
            // A part fetched waits here until the one before is written:
            // at most one answer per request in flight, plus this one.
            let (tx, rx) = std::sync::mpsc::sync_channel::<(usize, Option<Vec<u8>>)>(0);
            for _ in 0..FETCH_REQUESTS.min(parts.len()) {
                let (tx, url, token, next) = (tx.clone(), &url, &token, &next);
                s.spawn(move || loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(p) = parts.get(i) else { break };
                    let body = (|| -> Option<Vec<u8>> {
                        let body = serde_json::to_vec(&FetchRequest { snapshot, objects: wants[p.clone()].to_vec() }).ok()?;
                        let mut r = agent
                            .post(url)
                            .header("content-type", "application/json")
                            .header("accept", ACCEPT)
                            .header(FORMAT_HEADER, &REPO_FORMAT.to_string());
                        if let Some(t) = token {
                            r = r.header("authorization", &format!("Bearer {t}"));
                        }
                        let resp = r.send(&body[..]).ok()?;
                        (resp.status().as_u16() == 200).then(|| read_body(resp).ok()).flatten()
                    })();
                    // The receiver is gone when writing failed: stop.
                    if tx.send((i, body)).is_err() {
                        break;
                    }
                });
            }
            drop(tx);
            for _ in 0..parts.len() {
                let (i, body) = rx.recv().map_err(|_| anyhow!("a fetch thread stopped"))?;
                let part = &wants[parts[i].clone()];
                match body {
                    Some(body) => check(part, &body)?,
                    // Anything else (a session to renew, an error to
                    // report): this part again, the ordinary way.
                    None => check(part, &self.fetch_body(snapshot, part.to_vec())?)?,
                }
            }
            Ok(())
        })
    }

    /// Upload object frames (plain, or encoded for a server of revision 2);
    /// the server's receipt for each, in order.
    pub fn upload(&self, frames: Vec<u8>) -> Result<Vec<String>> {
        let out = self.ok("POST", &self.url.project_path("/objects"), Some(("application/octet-stream", frames)))?;
        Ok(serde_json::from_slice::<veil_core::hub::wire::Uploaded>(&out)?.receipts)
    }

    /// Push; `Ok(None)` when a branch moved during the push (retry).
    pub fn push(&self, req: &PushRequest) -> Result<Option<PushResult>> {
        let (status, out) = self.call(
            "POST",
            &self.url.project_path("/push"),
            Some(("application/json", serde_json::to_vec(req)?)),
        )?;
        match status {
            200 => Ok(Some(serde_json::from_slice(&out)?)),
            409 => Ok(None),
            403 if req.updates.iter().any(|u| u.new.is_none()) => Err(DeletionRefused(Self::error(403, &out).to_string()).into()),
            s => Err(Self::error(s, &out)),
        }
    }

    /// Submit a landing (`POST …/land`, `docs/HUB.md` §13.19).
    pub fn land(&self, req: &veil_core::hub::land::LandRequest) -> Result<veil_core::hub::land::LandResult> {
        self.json("POST", &self.url.project_path("/land"), Some(req))
    }

    pub fn land_status(&self, ticket: &str, wait: bool) -> Result<veil_core::hub::land::LandResult> {
        if ticket.is_empty() || !ticket.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            bail!("not a landing ticket: {}", crate::render::safe(ticket));
        }
        self.json("GET", &self.url.project_path(&format!("/land/{ticket}?wait={wait}")), None::<&()>)
    }

    /// A commit through the API (`POST …/changes`).
    /// `POST /v1/sessions/agent` (`docs/HUB.md` §13.27).
    pub fn agent_session(&self, req: &veil_core::hub::agent::AgentSessionRequest) -> Result<veil_core::hub::agent::AgentSession> {
        self.json("POST", "/v1/sessions/agent", Some(req))
    }

    pub fn change(&self, req: &veil_core::hub::changes::ChangeRequest) -> Result<veil_core::hub::changes::ChangeResult> {
        self.json("POST", &self.url.project_path("/changes"), Some(req))
    }

    pub fn access(&self, path: &str) -> Result<AccessInfo> {
        let mut q = String::new();
        for b in path.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                q.push(b as char);
            } else {
                q.push_str(&format!("%{b:02X}"));
            }
        }
        self.json("GET", &self.url.project_path(&format!("/access?path={q}")), None::<&()>)
    }

    pub fn groups(&self) -> Result<Vec<GroupInfo>> {
        self.json("GET", &self.url.project_path("/groups"), None::<&()>)
    }

    pub fn group(&self, method: &str, group: &str, what: &str, people: &[String]) -> Result<GroupInfo> {
        self.json(
            method,
            &self.url.project_path(&format!("/groups/{group}{what}")),
            Some(&GroupChange { people: people.to_vec() }),
        )
    }

    pub fn admins_list(&self) -> Result<AdminsInfo> {
        self.json("GET", &self.url.project_path("/admins"), None::<&()>)
    }

    pub fn admins(&self, what: &str, people: &[String]) -> Result<AdminsInfo> {
        self.json(
            "POST",
            &self.url.project_path(&format!("/admins{what}")),
            Some(&GroupChange { people: people.to_vec() }),
        )
    }

    /// A person's devices and vouches, as the server lists them: never
    /// enough on its own to wrap a key (`docs/HUB.md` §13.11). When scoped
    /// to a project, browser devices are omitted unless the project has
    /// enabled browser secrets.
    pub fn devices(&self, person: &str) -> Result<Devices> {
        let path = if self.url.project.is_empty() {
            format!("/v1/people/{person}/devices")
        } else {
            format!("/v1/people/{person}/devices?project={}", self.url.project)
        };
        self.json("GET", &path, None::<&()>)
    }

    /// A person's devices across the whole server (regardless of project
    /// browser-secret settings), for `vl identity remove` and `vl identity list`.
    pub fn devices_everywhere(&self, person: &str) -> Result<Devices> {
        self.json("GET", &format!("/v1/people/{person}/devices"), None::<&()>)
    }

    /// Mint a short-lived single-use browser passkey enrollment code (`vl web`).
    ///
    /// Signed by this device's identity key over a challenge of the server,
    /// as a sign-in is: the passkey it enrolls outlives this session.
    pub fn web_enroll(&self, label: Option<&str>) -> Result<veil_core::hub::web::WebEnrollResponse> {
        let ch: Challenge = self.json("POST", "/v1/auth/challenge", Some(&ChallengeRequest { key: self.identity.verifying_hex() }))?;
        let hub = self.url.authority.clone();
        let req = veil_core::hub::web::WebEnrollRequest {
            label: label.map(str::to_string),
            seconds: None,
            signature: self.identity.sign(
                veil_core::crypto::domains::SIG_CONTEXT_HUB_WEB_ENROLL,
                &veil_core::hub::wire::login_message(&hub, &ch.challenge),
            ),
            challenge: ch.challenge,
            hub,
        };
        self.json("POST", "/v1/sessions/web-enroll", Some(&req))
    }

    /// Vouch, with this device's key, that `device` (a full public
    /// identity) is this person's too.
    pub fn vouch(&self, device: &str) -> Result<Devices> {
        let id = parse_public_identity(device)?;
        let msg = vouch_message(&id).ok_or_else(|| anyhow!("that device has no signing key"))?;
        let req = VouchRequest {
            device: device.to_string(),
            signature: self.identity.sign(SIG_CONTEXT_HUB_DEVICE, &msg),
        };
        self.json("POST", "/v1/devices/vouch", Some(&req))
    }

    pub fn rings(&self) -> Result<Vec<KeyRing>> {
        let v: Vec<serde_json::Value> = self.json("GET", &self.url.project_path("/rings"), None::<&()>)?;
        Ok(v.into_iter().filter_map(|r| serde_json::from_value(r).ok()).collect())
    }

    pub fn post_ring(&self, ring: &KeyRing) -> Result<()> {
        let _: serde_json::Value = self.json("POST", &self.url.project_path(&format!("/rings/{}", ring.scope)), Some(ring))?;
        Ok(())
    }

    /// The server's ring of `scope`, if it has one.
    pub fn ring(&self, scope: &str) -> Result<Option<KeyRing>> {
        let (status, out) = self.call("GET", &self.url.project_path(&format!("/rings/{scope}")), None)?;
        match status {
            200 => Ok(serde_json::from_slice(&out).ok()),
            404 => Ok(None),
            s => Err(Self::error(s, &out)),
        }
    }

    /// Send a ring; `Err(Some(why))` if the server refused it as not
    /// following its ring (it moved on meanwhile, or diverged): fetch it and
    /// decide again.
    pub fn try_post_ring(&self, ring: &KeyRing) -> Result<std::result::Result<(), String>> {
        let (status, out) = self.call(
            "POST",
            &self.url.project_path(&format!("/rings/{}", ring.scope)),
            Some(("application/json", serde_json::to_vec(ring)?)),
        )?;
        match status {
            200 => Ok(Ok(())),
            409 => Ok(Err(Self::error(status, &out).to_string())),
            s => Err(Self::error(s, &out)),
        }
    }

    /// One of this person's pending devices, by fingerprint.
    pub fn pending_device(&self, person: &str, fingerprint: &str) -> Result<Option<String>> {
        let (status, out) = self.call("GET", &format!("/v1/people/{person}/pending/{fingerprint}"), None)?;
        match status {
            200 => Ok(Some(serde_json::from_slice::<veil_core::hub::wire::PendingDevice>(&out)?.identity)),
            404 => Ok(None),
            s => Err(Self::error(s, &out)),
        }
    }

    pub fn remove_device(&self, device: &str, project: Option<&str>) -> Result<Devices> {
        let req = veil_core::hub::wire::RemoveDevice {
            device: device.to_string(),
            project: project.map(str::to_string),
        };
        self.json("POST", "/v1/devices/remove", Some(&req))
    }

    pub fn create_invite(&self, req: &veil_core::hub::wire::InviteRequest) -> Result<()> {
        let _: veil_core::hub::wire::InviteRequest = self.json("POST", &self.url.project_path("/invites"), Some(req))?;
        Ok(())
    }

    pub fn join(&self, req: &veil_core::hub::wire::JoinRequest) -> Result<veil_core::hub::wire::Joined> {
        self.json("POST", &self.url.project_path("/invites/join"), Some(req))
    }

    /// People whose devices may wait for keys here (a hint).
    pub fn pending_keys(&self) -> Result<Vec<Devices>> {
        self.json("GET", &self.url.project_path("/keys/pending"), None::<&()>)
    }

    /// The secret shares this person makes or receives here (admins: every
    /// share of the project), `docs/HUB.md` §13.17.
    pub fn shares(&self) -> Result<Vec<veil_core::secret_share::ShareInfo>> {
        self.json("GET", &self.url.project_path("/shares"), None::<&()>)
    }

    /// Store a new version of a share; `Err(why)` if the server's share
    /// moved on meanwhile (409): read it and decide again.
    pub fn put_share(&self, req: &veil_core::secret_share::SharePut) -> Result<std::result::Result<(), String>> {
        let (status, out) = self.call("POST", &self.url.project_path("/shares"), Some(("application/json", serde_json::to_vec(req)?)))?;
        match status {
            200 => Ok(Ok(())),
            409 => Ok(Err(Self::error(status, &out).to_string())),
            s => Err(Self::error(s, &out)),
        }
    }

    pub fn remove_share(&self, path: &str, recipient: &str) -> Result<veil_core::secret_share::ShareInfo> {
        let req = veil_core::secret_share::ShareRemove {
            path: path.to_string(),
            recipient: recipient.to_string(),
        };
        self.json("POST", &self.url.project_path("/shares/remove"), Some(&req))
    }

    /// The project's health metrics (`GET …/health`, admins only; S24,
    /// `docs/HUB.md` §13.25).
    pub fn health(&self) -> Result<serde_json::Value> {
        self.json("GET", &self.url.project_path("/health"), None::<&()>)
    }

    /// A JSON request under the project (`path` from `/prs…`), for the
    /// commands whose answers are plain JSON documents (`vl pr`, S21).
    pub fn project_json(&self, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<serde_json::Value> {
        self.json(method, &self.url.project_path(path), body)
    }

    /// A query route (`GET …/q/ROUTE?PARAMS`, `docs/HUB.md` §13.23): its
    /// JSON answer, or the server's error code and message.
    pub fn query(&self, route: &str, params: &[(&str, String)]) -> Result<std::result::Result<serde_json::Value, (String, String)>> {
        let q: Vec<String> = params.iter().map(|(k, v)| format!("{k}={}", percent(v))).collect();
        let (status, out) = self.call("GET", &self.url.project_path(&format!("/q/{route}?{}", q.join("&"))), None)?;
        if (200..300).contains(&status) {
            return Ok(Ok(serde_json::from_slice(&out).context("the server's answer")?));
        }
        match serde_json::from_slice::<ErrorBody>(&out) {
            Ok(e) => Ok(Err((e.code, e.message))),
            Err(_) => Err(Self::error(status, &out)),
        }
    }

    /// Issue a narrowed CI runner session (`POST /v1/sessions/ci`, S19).
    pub fn ci_session(&self, req: &veil_core::hub::ci::CiSessionRequest) -> Result<veil_core::hub::agent::AgentSession> {
        self.json("POST", "/v1/sessions/ci", Some(req))
    }

    /// Record a CI check result (`POST /v1/projects/{p}/checks`, S19).
    pub fn post_check(&self, req: &veil_core::hub::ci::CheckRequest) -> Result<veil_core::hub::ci::CheckResult> {
        self.json("POST", &self.url.project_path("/checks"), Some(req))
    }

    /// List CI checks on a revision (`GET /v1/projects/{p}/checks`, S19).
    pub fn checks(&self, rev: Option<&str>) -> Result<veil_core::hub::ci::ChecksResponse> {
        let path = match rev {
            Some(r) => self.url.project_path(&format!("/checks?rev={}", percent(r))),
            None => self.url.project_path("/checks"),
        };
        self.json("GET", &path, None::<&()>)
    }

    /// The newest tested snapshot on `branch` (`GET /v1/projects/{p}/tested/{branch}`, S19).
    pub fn tested(&self, branch: &str) -> Result<Option<veil_core::hub::ci::TestedTip>> {
        let (status, out) = self.call("GET", &self.url.project_path(&format!("/tested/{}", percent(branch))), None)?;
        match status {
            200 => Ok(Some(serde_json::from_slice(&out)?)),
            404 => Ok(None),
            s => Err(Self::error(s, &out)),
        }
    }
}

/// `s` percent-encoded for a query string.
fn percent(s: &str) -> String {
    let mut q = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            q.push(b as char);
        } else {
            q.push_str(&format!("%{b:02X}"));
        }
    }
    q
}

// ---- pull ---------------------------------------------------------------------------------

/// The server revision from which `history` answers pages
/// (`HistoryRequest::limit`), which thin clones need (BUG-1140: revision 3
/// is S5's read grants).
pub const HISTORY_PAGES: u32 = 4;

/// The branch a clone checks out (`hub_cmd::clone`): `main`, `trunk` or
/// `master`, else the first by name.
pub fn checkout_branch(tips: &Tips) -> Option<String> {
    ["main", "trunk", "master"]
        .into_iter()
        .find(|b| tips.branches.contains_key(*b))
        .map(str::to_string)
        .or_else(|| tips.branches.keys().find(|b| veil_core::embargo::embargo_id_of_branch(b).is_none()).cloned())
        .or_else(|| tips.branches.keys().next().cloned())
}

/// Is `path` inside the `only` directory, or a directory on the way to it?
fn in_scope(only: Option<&str>, path: &str) -> bool {
    let Some(o) = only else { return true };
    path.is_empty()
        || path == o
        || (path.len() > o.len() && path.starts_with(o) && path.as_bytes()[o.len()] == b'/')
        || (o.len() > path.len() && o.starts_with(path) && o.as_bytes()[path.len()] == b'/')
}

/// Pull from the server into `repo` as remote `remote`: new snapshots, the
/// trees and files they reach (within `only`), the key rings, then the
/// remote tags (with the checks of every pull).
pub fn pull(repo: &mut Repo, remote: &str, client: &Client, only: Option<&str>) -> Result<SyncReport> {
    pull_with(repo, remote, client, only, false)
}

/// [`pull`]; `widen`: in a thin clone, fetch every snapshot and every
/// object they reach into the main store (`vl partial full`), as a full
/// clone holds them.
pub fn pull_with(repo: &mut Repo, remote: &str, client: &Client, only: Option<&str>, widen: bool) -> Result<SyncReport> {
    Ok(pull_moving(repo, remote, client, only, widen, MoveView::No)?.0)
}

/// When a pull also moves a thin clone to its person's current view
/// (BUG-1509).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MoveView {
    No,
    /// When the server names a snapshot this clone met under another id
    /// (a tip it last pulled, or anything this process read).
    IfChanged,
    /// The command saw the view change: move whatever it finds.
    Always,
}

/// [`pull_with`], and in the same operation (one `vl undo` reverts both)
/// the move to the person's current view `mv` asks for.
pub fn pull_moving(
    repo: &mut Repo,
    remote: &str,
    client: &Client,
    only: Option<&str>,
    widen: bool,
    mv: MoveView,
) -> Result<(SyncReport, Option<veil_core::transaction::ViewMove>)> {
    let tips = client
        .tips()?
        .ok_or_else(|| anyhow!("no project '{}' that you can see on {}", client.url.project, client.url.authority))?;
    // Its grants serve this process's reads through the Veil daemon (S6).
    crate::thin::remember_grants(&client.url, &tips);
    // A thin clone (S3) takes the new snapshots (a page at most) and the
    // content of the branch it checks out only; the rest is fetched when
    // read.
    // A thin clone fetches on demand from its own remote's server only: a
    // pull from another remote is a full one, into the main store (BUG-1265).
    let own = repo.config().partial.as_ref().is_some_and(|p| p.remote == remote);
    let thin = own && !widen;
    // What that pull, and a widening one, takes as held: the main store's.
    let main_only = widen || (repo.is_partial() && !own);
    if thin && tips.revision < HISTORY_PAGES {
        bail!(
            "the server at {} is older than this vl and cannot serve a thin clone; `vl partial full` makes this a full clone",
            client.url.authority
        );
    }
    let full_clone = !repo.is_partial();
    let mut tx = repo.transaction(format!("pull from {remote}"))?;
    tx.repository_wide();
    let store: Arc<ObjectStore> = tx.repo().store().clone();
    let prefix = format!("{remote}/");
    let stop: Vec<ObjectId> = tx
        .view
        .remote_tags
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(_, v)| *v)
        .filter(|id| store.has(id) && !widen)
        .collect();
    // A pull into the main store (a widening one, or a full pull from
    // another remote) asks for every tip, held or not: what a held tip
    // reaches may be in the cache only, or nowhere (BUG-1318). `have` then
    // skips, object by object, what the main store holds.
    let mut want_tips: Vec<ObjectId> = tips
        .branches
        .values()
        .chain(tips.tested.values())
        .copied()
        .filter(|t| main_only || !store.has(t))
        .collect();
    want_tips.sort();
    want_tips.dedup();
    // A repository made for this clone holds only the root snapshot, its
    // empty tree and the empty change its workspace starts on (`vl clone`
    // makes the repository with its workspace): nothing to probe the disk
    // for, object by object. (Each probe of an object that is not there
    // looks for its file and lists the pack directory: 126,000 of them in a
    // clone of one directory of 10,000 snapshots, BUG-1945. The test was
    // "every head is the root", which no clone's repository passes.)
    let root = tx.repo().root_id();
    let empty_tree = tx.repo().snapshot(&root)?.tree;
    let starts_empty = |h: &ObjectId| *h == root || tx.repo().snapshot(h).is_ok_and(|s| s.parents == [root] && s.tree == empty_tree);
    let fresh = stop.is_empty() && tx.view.heads.iter().all(starts_empty);
    let fresh_heads: Vec<ObjectId> = tx.view.heads.iter().copied().collect();
    let have = |id: &ObjectId| match (fresh, main_only) {
        (true, _) => *id == root || *id == empty_tree || fresh_heads.contains(id),
        (false, true) => store.has_main(id),
        (false, false) => store.has(id),
    };
    let mut report = SyncReport::default();
    let mut incoming = Incoming::new(&store);
    // Where trees and files go: the cache area of a thin clone.
    let content_store: Arc<ObjectStore> = match thin {
        true => store.cache().expect("a thin clone has a cache").clone(),
        false => store.clone(),
    };
    let mut content = thin.then(|| Incoming::new(&content_store));
    let checked_out = checkout_branch(&tips).and_then(|b| tips.branches.get(&b).copied());
    // The cache's bound applies to what goes to the cache (not to `vl
    // partial full`, which fills the main store).
    let limit = store.cache_limit().filter(|_| thin).unwrap_or(u64::MAX);
    let mut content_bytes = 0u64;
    let mut new_snaps = Vec::new();
    // Whether a new snapshot names, as the version it replaces, something
    // a repository made for this clone holds (`supersede_landed`).
    let mut replaces_local = false;
    if !want_tips.is_empty() {
        // A thin clone takes the tips alone; a later pull, the new
        // snapshots down to what it has (a page at most).
        let first = !tx.view.remote_tags.keys().any(|k| k.starts_with(&prefix));
        let page = thin.then_some(if first { want_tips.len() } else { veil_core::promisor::HISTORY_PAGE });
        let history = client.history(want_tips, stop, page)?;
        let held: Vec<bool> = history.iter().map(|(id, _)| have(id)).collect();
        // Each snapshot decoded and its signature checked on every core:
        // 40 µs a snapshot, most of the first pull of a long history when
        // done one after another (BUG-1945). What follows is in order, as
        // before.
        let read = in_parallel(&history, &held, |(_, raw), held| -> Result<Option<(ObjectId, bool, bool)>> {
            // A widening pull, and a full pull from another remote, walk
            // what each snapshot reaches even when they hold the snapshot:
            // its trees and files may be in the cache, or not fetched
            // (BUG-1292).
            if *held && !main_only {
                return Ok(None);
            }
            let Object::Snapshot(s) = Object::decode(raw)? else {
                bail!("the server sent a non-snapshot in history");
            };
            let local = s.predecessors.iter().any(|p| *p == root || fresh_heads.contains(p));
            Ok(Some((s.tree, s.signature_valid() == Some(true), local)))
        });
        for (((id, raw), held), read) in history.into_iter().zip(held).zip(read) {
            let Some((tree, signed, local)) = read? else { continue };
            replaces_local |= local;
            if !signed && !held {
                report.warnings.push(format!("snapshot {} carries no valid signature", id.short()));
            }
            if !thin || Some(id) == checked_out || tips.tested.values().any(|t| *t == id) {
                new_snaps.push((id, tree));
            }
            if !held && incoming.put(id, raw, "")? {
                report.objects_copied += 1;
            }
        }
    }
    // Trees from the root down, then the files: one round per level, each
    // object written as its part of the level arrives (BUG-859). Sizes are
    // what tree entries say (0 for trees and other objects they don't size).
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut frontier: Vec<(ObjectId, String, ObjectId, u64)> = Vec::new();
    for (snap, tree) in &new_snaps {
        if seen.insert(*tree) && !have(tree) {
            frontier.push((*snap, String::new(), *tree, 0));
        }
    }
    // A server of revision 1 takes the wants of every snapshot in one
    // request per level; an older one, one request per snapshot.
    let across = tips.revision >= 1;
    // A thin clone reads through the Veil daemon first (S6): each object's
    // chain of trees from its snapshot's projected root is what the daemon
    // checks. Kept as each object's parent (the tree or conflict naming it;
    // an id is in the frontier once), the chain walked up when asked for.
    let daemon = thin && crate::thin::daemon_on();
    let roots: HashMap<ObjectId, ObjectId> = new_snaps.iter().copied().collect();
    let mut parents: HashMap<ObjectId, ObjectId> = HashMap::new();
    let chain_of = |parents: &HashMap<ObjectId, ObjectId>, id: &ObjectId| -> Vec<ObjectId> {
        let mut chain = Vec::new();
        let mut cur = *id;
        while let Some(p) = parents.get(&cur).filter(|_| chain.len() <= veil_core::hub::grant::MAX_CHAIN) {
            chain.push(*p);
            cur = *p;
        }
        chain.reverse();
        chain
    };
    while !frontier.is_empty() {
        let asked: Vec<(ObjectId, Vec<ObjectId>, ObjectId)> = match daemon {
            true => frontier.iter().filter_map(|(snap, _, id, _)| Some((*roots.get(snap)?, chain_of(&parents, id), *id))).collect(),
            false => Vec::new(),
        };
        let mut next = Vec::new();
        let mut handle = |snap: ObjectId, w: &Want, raw: Vec<u8>| -> Result<()> {
            let obj = Object::decode(&raw)?;
            let mut children = Vec::new();
            match &obj {
                Object::Tree(t) => {
                    for e in &t.entries {
                        let p = if w.path.is_empty() { e.name.clone() } else { format!("{}/{}", w.path, e.name) };
                        if !in_scope(only, &p) {
                            continue;
                        }
                        if e.kind == EntryKind::Dir && only.is_some_and(|o| o.len() > p.len()) {
                            // A directory on the way to `only`: its tree only.
                            children.push((e.id, p, 0));
                            continue;
                        }
                        let size = if e.kind == EntryKind::Dir { 0 } else { e.size };
                        children.push((e.id, p, size));
                    }
                }
                Object::Conflict(c) => children.extend(c.referenced_ids().into_iter().map(|i| (i, w.path.clone(), 0))),
                _ => {}
            }
            for (cid, p, size) in children {
                if seen.insert(cid) && !have(&cid) {
                    if daemon {
                        parents.insert(cid, w.id);
                    }
                    next.push((snap, p, cid, size));
                }
            }
            content_bytes += raw.len() as u64;
            if content_bytes > limit {
                bail!(
                    "what this thin clone checks out is larger than its object cache ({}); clone again with a larger \
                     `--cache-size`, or with `--full`",
                    veil_core::promisor::human(limit)
                );
            }
            let written = match content.as_mut() {
                Some(c) => c.put(w.id, raw, &w.path)?,
                None => incoming.put(w.id, raw, &w.path)?,
            };
            if written {
                report.objects_copied += 1;
            }
            Ok(())
        };
        if !asked.is_empty() {
            let mut got = crate::thin::via_daemon(&client.url, client.identity(), &asked);
            if !got.is_empty() {
                let mut rest = Vec::new();
                for (snap, path, id, size) in frontier.drain(..) {
                    match got.remove(&id) {
                        Some(raw) => handle(snap, &Want { path, id, snapshot: Some(snap) }, raw)?,
                        None => rest.push((snap, path, id, size)),
                    }
                }
                frontier = rest;
            }
        }
        // A snapshot's wants together: each request names few snapshots.
        frontier.sort_by_key(|f| f.0);
        let mut by_snap: HashMap<ObjectId, (Vec<Want>, Vec<u64>)> = HashMap::new();
        for (snap, path, id, size) in frontier.drain(..) {
            let key = match across {
                true => *by_snap.keys().next().unwrap_or(&snap),
                false => snap,
            };
            let (wants, sizes) = by_snap.entry(key).or_default();
            wants.push(Want { path, id, snapshot: (key != snap).then_some(snap) });
            sizes.push(size);
        }
        for (snap, (wants, sizes)) in by_snap {
            client.fetch_each(snap, &wants, &sizes, |w, raw| handle(w.snapshot.unwrap_or(snap), w, raw))?;
        }
        drop(handle);
        frontier = next;
    }
    report.packs_written = incoming.finish()?;
    if let Some(c) = content {
        report.packs_written += c.finish()?;
        store.recount_cache();
        // Down to the cache's bound: least recently written first, never
        // what the working copies hold.
        if store.trim_cache()?.full {
            report.warnings.push(format!(
                "the object cache is over its bound ({}) with what is checked out alone; raise it with `vl partial limit SIZE`",
                veil_core::promisor::human(limit)
            ));
        }
    }
    // Key rings of secret scopes: verified and fast-forwarded locally.
    if client.token.borrow().is_some() {
        if let Ok(rings) = client.rings() {
            report.warnings.extend(crate::hub_keys::merge_server_rings(tx.repo().keys(), &client.url, rings)?);
            tx.repo().keys().invalidate();
        }
    }
    for rec in &tips.embargoes {
        tx.repo().keys().merge_embargo(rec)?;
    }
    let tags: Vec<(String, Tag)> = tips
        .branches
        .iter()
        .map(|(n, id)| {
            (
                n.clone(),
                Tag { target: *id, annotation: None },
            )
        })
        .collect();
    let old_tips: Vec<ObjectId> = tx.view.remote_tags.iter().filter(|(k, _)| k.starts_with(&prefix)).map(|(_, v)| *v).collect();
    apply_remote_tags(&mut tx, remote, tags, None, &mut report)?;
    tx.view.remote_tags.retain(|k, _| !(k.starts_with(&prefix) && k.ends_with("@tested")));
    for (n, id) in &tips.tested {
        if store.has(id) {
            tx.view.remote_tags.insert(format!("{remote}/{n}@tested"), *id);
        }
    }
    // The person's view changed since this clone last pulled: a tip it had
    // is named under another id now (BUG-1509).
    let moving = match mv {
        MoveView::No => false,
        _ if thin => {
            let mut changed = mv == MoveView::Always || store.view_changed();
            for t in old_tips.iter().filter(|t| !tips.branches.values().any(|n| n == *t)) {
                if changed {
                    break;
                }
                changed = store.current_projection(t)?.is_some_and(|n| n != *t);
            }
            changed
        }
        // A full clone reads nothing on demand, so no read of its own shows
        // the view changed (BUG-1562): the server's history of the tips it
        // had that are tips no more (one request for all of them) names
        // each as the current view does, and one it names otherwise, or
        // not at all, is of a view its person no longer has.
        _ if full_clone && tips.revision >= HISTORY_PAGES => {
            let mut were: Vec<ObjectId> = old_tips.iter().copied().filter(|t| !tips.branches.values().any(|n| n == t)).collect();
            were.sort();
            were.dedup();
            match were.is_empty() {
                true => false,
                false => {
                    let named: HashSet<ObjectId> = client.history(were.clone(), Vec::new(), Some(were.len()))?.into_iter().map(|(id, _)| id).collect();
                    were.iter().any(|t| !named.contains(t))
                }
            }
        }
        _ => false,
    };
    let moved = match moving {
        true => {
            let m = match thin {
                true => tx.move_to_view()?,
                false => {
                    let now: Vec<ObjectId> = tips.branches.values().copied().collect();
                    let current = store.reached_by(&now);
                    let mut servers = store.reached_by(&old_tips);
                    servers.extend(current.iter().copied());
                    tx.move_to_view_from(&FullView { client, store: &store, servers, current, asked: Default::default() })?
                }
            };
            // Something moved: the warnings of tags the pull found diverged
            // and the move put on their remote tags are gone.
            if m.moved > 0 || m.mapped > 0 {
                tx.set_description(format!("pull from {remote}; your access changed: moved {} change(s) to your current view", m.moved));
                let now: Vec<String> = tx
                    .view
                    .tags
                    .iter()
                    .filter(|(n, t)| tx.view.remote_tags.get(&format!("{remote}/{n}")) == Some(&t.target))
                    .map(|(n, _)| format!("tag '{n}' has diverged from {remote}/{n}"))
                    .collect();
                report.warnings.retain(|w| !now.iter().any(|n| w.starts_with(n.as_str())));
            }
            Some(m).filter(|m| m.moved > 0 || m.mapped > 0)
        }
        false => None,
    };
    // A repository made for this clone holds the root and the empty change
    // its workspace starts on, and nothing else that could have landed:
    // unless a new snapshot replaces one of those, there is nothing to look
    // for (reading each new snapshot again to find that out was 80 ms of a
    // clone of 10,000).
    if moved.is_none() && !(fresh && !replaces_local) {
        supersede_landed(&mut tx, &new_snaps, &old_tips)?;
    }
    tx.commit()?;
    Ok((report, moved))
}

/// `f` of each of `items` with its `with`, in their order, on up to 16
/// threads when there are enough of them to share out.
fn in_parallel<T: Sync, W: Sync, R: Send>(items: &[T], with: &[W], f: impl Fn(&T, &W) -> R + Sync) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16).min(items.len() / 256);
    if threads < 2 {
        return items.iter().zip(with).map(|(i, w)| f(i, w)).collect();
    }
    let chunk = items.len().div_ceil(threads);
    let f = &f;
    std::thread::scope(|s| {
        let parts: Vec<_> = items
            .chunks(chunk)
            .zip(with.chunks(chunk))
            .map(|(i, w)| s.spawn(move || i.iter().zip(w).map(|(i, w)| f(i, w)).collect::<Vec<R>>()))
            .collect();
        parts.into_iter().flat_map(|p| p.join().expect("a worker reading history panicked")).collect()
    })
}

/// One row for a landed change (BUG-1910). The server lands a change as a
/// snapshot of its own (on the branch's newest tip, signed by the server),
/// which names the submitted snapshot as its predecessor. When a pull
/// brings such a snapshot, the version this clone made is superseded by
/// it, as by any rewrite: it leaves the log, and what stands on it (the
/// working copy, later changes, local tags) moves onto the landed one.
/// Only a version of this clone's own line counts: the same change id,
/// visible here, and under no remote tag, before this pull (`old_tips`) or
/// after it. A snapshot the server showed as part of a branch is never
/// superseded here (a branch someone rewrote and forced, a branch a pull
/// request landed from): it stays a row of its own.
fn supersede_landed(tx: &mut veil_core::transaction::Transaction, new_snaps: &[(ObjectId, ObjectId)], old_tips: &[ObjectId]) -> Result<()> {
    let under = |tx: &veil_core::transaction::Transaction, tips: &[ObjectId], id: &ObjectId| -> Result<bool> {
        for t in tips {
            if t == id || tx.repo().is_ancestor(id, t)? {
                return Ok(true);
            }
        }
        Ok(false)
    };
    // Only what this clone holds is read: a predecessor it does not hold
    // is no version of its own, and nothing is fetched to find out.
    let held = |tx: &veil_core::transaction::Transaction, ids: &mut dyn Iterator<Item = ObjectId>| -> Vec<ObjectId> {
        ids.filter(|t| tx.repo().held().snapshot(t).ok().flatten().is_some()).collect()
    };
    for (id, _) in new_snaps {
        let Some(s) = tx.repo().held().snapshot(id).ok().flatten() else { continue };
        for p in &s.predecessors {
            let Some(ps) = tx.repo().held().snapshot(p).ok().flatten() else { continue };
            if p == id || ps.change_id != s.change_id || ps.abandoned.is_some() {
                continue;
            }
            let heads = held(tx, &mut tx.view.heads.iter().copied());
            let now = held(tx, &mut tx.view.remote_tags.values().copied());
            let before = held(tx, &mut old_tips.iter().copied());
            if under(tx, &heads, p)? && !under(tx, &now, p)? && !under(tx, &before, p)? && under(tx, &now, id)? {
                tx.supersede(*p, *id)?;
            }
        }
    }
    Ok(())
}

/// What a full clone's move to its person's current view asks (BUG-1562).
/// It reads nothing from the server on demand: the server's snapshots are
/// what its remote tags reached before this pull and reach now, and a
/// snapshot's current projection is the server's history of it, when this
/// clone holds it whole (the pull just took the current view). One it does
/// not hold (of a branch deleted since) is left as it is, with what stands
/// on it.
struct FullView<'a> {
    client: &'a Client,
    store: &'a ObjectStore,
    servers: HashSet<ObjectId>,
    current: HashSet<ObjectId>,
    asked: std::cell::RefCell<HashMap<ObjectId, Option<ObjectId>>>,
}

impl veil_core::transaction::ViewSource for FullView<'_> {
    fn is_servers(&self, s: &ObjectId) -> veil_core::Result<bool> {
        Ok(self.servers.contains(s))
    }

    fn current_projection(&self, s: &ObjectId) -> veil_core::Result<Option<ObjectId>> {
        if self.current.contains(s) {
            return Ok(Some(*s));
        }
        if let Some(n) = self.asked.borrow().get(s) {
            return Ok(*n);
        }
        // A request that fails stops the move, nothing changed (BUG-1564).
        let page = self
            .client
            .history(vec![*s], Vec::new(), Some(1))
            .map_err(|e| veil_core::VeilError::Unavailable(format!("asking the server for your current view: {e:#}")))?;
        let n = page.into_iter().next().map(|(id, _)| id).filter(|id| self.current.contains(id) && self.store.has(id));
        self.asked.borrow_mut().insert(*s, n);
        Ok(n)
    }
}

/// For a clone of one directory: `tree` with only the path to `only` and
/// `only` itself, and the paths left out (never materialised, so every
/// snapshot keeps them as they are; `Materialised::hiding`).
pub fn restrict_to(store: &ObjectStore, tree: ObjectId, only: &str) -> Result<(ObjectId, Vec<veil_core::VPath>)> {
    let parts: Vec<&str> = only.split('/').collect();
    let mut hidden = Vec::new();
    fn go(
        store: &ObjectStore,
        tree: ObjectId,
        parts: &[&str],
        dir: &str,
        hidden: &mut Vec<veil_core::VPath>,
    ) -> Result<ObjectId> {
        let t = store.tree(&tree)?;
        let mut out = veil_core::Tree::default();
        for e in &t.entries {
            let p = if dir.is_empty() { e.name.clone() } else { format!("{dir}/{}", e.name) };
            if e.name != parts[0] {
                hidden.push(veil_core::VPath::new(&p)?);
                continue;
            }
            if parts.len() == 1 || e.kind != EntryKind::Dir {
                out.insert(e.clone());
            } else {
                let id = go(store, e.id, &parts[1..], &p, hidden)?;
                out.insert(veil_core::TreeEntry { id, ..e.clone() });
            }
        }
        Ok(store.put_tree(&out)?)
    }
    let id = go(store, tree, &parts, "", &mut hidden)?;
    Ok((id, hidden))
}

/// `tree` without the entry at `only` (a directory path): what stands for
/// everything a `--only` clone never writes. Only the trees on the way to
/// `only` are read.
pub fn without(store: &ObjectStore, tree: ObjectId, only: &str) -> Result<ObjectId> {
    let (name, rest) = only.split_once('/').map_or((only, None), |(a, b)| (a, Some(b)));
    let mut t = (*store.tree(&tree)?).clone();
    match rest {
        None => t.entries.retain(|e| e.name != name),
        Some(rest) => {
            for e in t.entries.iter_mut().filter(|e| e.name == name && e.kind == EntryKind::Dir) {
                e.id = without(store, e.id, rest)?;
            }
        }
    }
    Ok(store.put_tree(&t)?)
}

// ---- push ---------------------------------------------------------------------------------

/// Every object entry `e` names: its object and, for a conflict, its
/// terms' objects (the server's `named_ids`).
fn named_ids(store: &ObjectStore, e: &veil_core::TreeEntry) -> Result<Vec<ObjectId>> {
    let mut out = vec![e.id];
    if e.kind == EntryKind::Conflict {
        if let Object::Conflict(c) = store.get(&e.id)? {
            out.extend(c.referenced_ids());
        }
    }
    Ok(out)
}

/// The objects a push introduces, each handed to `emit` once: every new
/// snapshot and, at each path where its tree differs from all of its
/// parents' (the trees down to that path, and what the entry there names
/// that no parent's entry at that path names). That is what the server
/// asks an upload receipt for (`docs/HUB.md` §13, check 7; BUG-824), and
/// nothing more.
///
/// A tree is walked again for each set of parent trees it is compared with:
/// what it introduces depends on them (BUG-857: a tree walked once, against
/// a parent that already had a file, was never walked against the snapshot
/// that introduced the file, so the file was never sent).
pub struct Introduced<'a, F: FnMut(ObjectId, Vec<u8>) -> Result<()>> {
    store: &'a ObjectStore,
    emit: F,
    sent: HashSet<ObjectId>,
    walked: HashSet<(ObjectId, Vec<ObjectId>)>,
}

impl<'a, F: FnMut(ObjectId, Vec<u8>) -> Result<()>> Introduced<'a, F> {
    pub fn new(store: &'a ObjectStore, emit: F) -> Self {
        Introduced { store, emit, sent: HashSet::new(), walked: HashSet::new() }
    }

    fn send(&mut self, id: ObjectId, raw: Option<Vec<u8>>, path: &str) -> Result<()> {
        if self.sent.insert(id) {
            let raw = match raw {
                Some(r) => r,
                None => self.store.get_raw(&id).with_context(|| format!("reading {}", if path.is_empty() { "/" } else { path }))?,
            };
            (self.emit)(id, raw)?;
        }
        Ok(())
    }

    /// New snapshot `id`, whose parents' trees are `parents`.
    pub fn snapshot(&mut self, id: ObjectId, tree: ObjectId, mut parents: Vec<ObjectId>) -> Result<()> {
        self.send(id, None, "")?;
        parents.sort();
        parents.dedup();
        if !parents.contains(&tree) && !self.tree(tree, parents, "")? {
            self.send(tree, None, "")?;
        }
        Ok(())
    }

    /// Object `id` as a tree, if it is one as stored (a sealed directory is
    /// sent as it is, never walked).
    fn as_tree(&self, id: &ObjectId) -> Result<Option<(Arc<veil_core::Tree>, Vec<u8>)>> {
        let raw = self.store.get_raw(id)?;
        match Object::tree_encoding(&raw) {
            Some(_) => Ok(Some((self.store.tree_object(id)?, raw))),
            None => Ok(None),
        }
    }

    /// Walk tree `tree` at `path` against `parents` (the trees at `path` in
    /// the snapshot's parents, sorted; none of them is `tree`). False if
    /// `tree` is not a tree object.
    fn tree(&mut self, tree: ObjectId, parents: Vec<ObjectId>, path: &str) -> Result<bool> {
        let key = (tree, parents);
        if self.walked.contains(&key) {
            return Ok(true);
        }
        let Some((t, raw)) = self.as_tree(&tree).with_context(|| format!("reading {}", if path.is_empty() { "/" } else { path }))? else {
            return Ok(false);
        };
        let (tree, parents) = key.clone();
        self.walked.insert(key);
        self.send(tree, Some(raw), path)?;
        let mut ptrees = Vec::new();
        for p in &parents {
            ptrees.extend(self.as_tree(p)?.map(|(t, _)| t));
        }
        for e in &t.entries {
            let p = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
            let before: Vec<&veil_core::TreeEntry> = ptrees.iter().filter_map(|pt| pt.get(&e.name)).collect();
            let mut walked = false;
            if e.kind == EntryKind::Dir {
                // The same directory as in a parent: nothing below changed.
                if before.iter().any(|pe| pe.id == e.id) {
                    continue;
                }
                let mut sub: Vec<ObjectId> = before.iter().filter(|pe| pe.kind == EntryKind::Dir).map(|pe| pe.id).collect();
                sub.sort();
                sub.dedup();
                walked = self.tree(e.id, sub, &p)?;
            } else if before.iter().any(|pe| pe.id == e.id && pe.kind == e.kind) {
                // Names exactly what that parent's entry names.
                continue;
            } else if veil_core::secret_share::personal_key(&p) {
                bail!("'{}' is a personal private key: it never leaves your device", crate::render::safe(&p));
            }
            let mut known = HashSet::new();
            for pe in &before {
                known.extend(named_ids(self.store, pe)?);
            }
            for id in named_ids(self.store, e)? {
                if !(walked && id == e.id) && !known.contains(&id) {
                    self.send(id, None, &p)?;
                }
            }
        }
        Ok(true)
    }
}

/// Object frames on their way to the server, about 8 MiB per request, and
/// the server's receipt for each: the push shows them, so it names nothing
/// it did not send (BUG-824). To a server of revision 2 each object goes
/// compressed (S27), compressed as the walk finds it.
struct Uploads<'a> {
    client: &'a Client,
    compress: bool,
    frames: Vec<u8>,
    ids: Vec<ObjectId>,
    receipts: BTreeMap<ObjectId, String>,
}

impl Uploads<'_> {
    fn add(&mut self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        match self.compress {
            // Compressed within the ratio a server decodes (BUG-1009).
            true => put_frame(&mut self.frames, id, &encoding::encode_to_send(raw)),
            false => put_frame(&mut self.frames, id, raw),
        }
        self.ids.push(*id);
        if self.frames.len() > 8 << 20 {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.ids.is_empty() {
            return Ok(());
        }
        let r = self.client.upload(std::mem::take(&mut self.frames))?;
        let ids = std::mem::take(&mut self.ids);
        if r.len() != ids.len() {
            bail!("the server sent {} upload receipts for {} objects", r.len(), ids.len());
        }
        self.receipts.extend(ids.into_iter().zip(r));
        Ok(())
    }
}

/// The server refused (`403`) a push that deletes branches, with its reason.
#[derive(Debug)]
pub struct DeletionRefused(pub String);

impl std::fmt::Display for DeletionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DeletionRefused {}

pub struct PushOutcome {
    pub warnings: Vec<String>,
    pub moved: Vec<(String, ObjectId)>,
    /// Branches deleted on the server by this push.
    pub deleted: Vec<String>,
    /// Of `moved`: protected branches, where the server's landing service
    /// landed the pushed changes (`docs/HUB.md` §13.19).
    pub landed: Vec<String>,
    pub rejected: Vec<(String, String)>,
    pub uploaded: usize,
    pub created: bool,
}

/// Push local tags (all, or `only_tags`) to the server.
pub fn push(repo: &mut Repo, remote: &str, client: &Client, only_tags: &[String], force: bool) -> Result<PushOutcome> {
    let mut created = false;
    let revision = match client.tips()? {
        Some(tips) => tips.revision,
        None => {
            let tips = client.create_project()?;
            created = true;
            // This device made the project's `team` ring: the one it trusts.
            crate::hub_keys::anchor_created(repo.keys(), &client.url)?;
            tips.revision
        }
    };
    let release_warnings = repo.take_back_releases_out_of_force()?;
    let newly_released = repo.keys().publish_staged_releases()?;
    let mut attempt = 0;
    // Why the server refused this push's deletions: the rest is then pushed
    // without them, and they are shown as rejected.
    let mut refused_deletions: Option<String> = None;
    loop {
        attempt += 1;
        let deleted = veil_core::remote::deleted_tags(&**repo.backend())?;
        let view = repo.view().clone();
        let prefix = format!("{remote}/");
        let mut updates = Vec::new();
        for (name, tag) in &view.tags {
            if !only_tags.is_empty() && !only_tags.contains(name) {
                continue;
            }
            let expected = view.remote_tags.get(&format!("{prefix}{name}")).copied();
            if expected == Some(tag.target) {
                continue;
            }
            updates.push(BranchUpdate {
                branch: name.clone(),
                expected,
                new: Some(tag.target),
            });
        }
        // Tags deleted here (`vl tag delete`) are deleted on the server too,
        // while its tag is still where this one was deleted: never work
        // somebody pushed to it since. The server decides who may
        // (`docs/HUB.md`: a branch merged into the default branch, anyone
        // who may write; any other, admins).
        let deletions: Vec<String> = deleted
            .iter()
            .filter(|(name, at)| {
                !view.tags.contains_key(*name)
                    && (only_tags.is_empty() || only_tags.contains(*name))
                    && view.remote_tags.get(&format!("{prefix}{name}")) == Some(*at)
            })
            .map(|(name, _)| name.clone())
            .collect();
        if refused_deletions.is_none() {
            for name in &deletions {
                updates.push(BranchUpdate {
                    branch: name.clone(),
                    expected: Some(deleted[name]),
                    new: None,
                });
            }
        }
        let not_deleted = |rejected: &mut Vec<(String, String)>| {
            if let Some(why) = &refused_deletions {
                rejected.extend(deletions.iter().map(|name| (name.clone(), why.clone())));
            }
        };
        for t in only_tags {
            let deleted_remote = deleted.contains_key(t) && view.remote_tags.contains_key(&format!("{prefix}{t}"));
            if !view.tags.contains_key(t) && !deleted_remote {
                bail!("no tag '{t}' here");
            }
        }
        // Nothing an unreleased embargo withholds is uploaded on an unembargoed
        // branch (`fix`); an embargoed merge line itself (`carried_embargo`) goes
        // to the server's hidden `embargo/<id>` line with its signed record when
        // its groups exist on the server.
        let targets: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let mut blocks = veil_core::remote::embargo_blocks(repo, &targets)?.into_iter();
        let mut server_groups: Option<HashSet<String>> = None;
        let mut withheld = Vec::new();
        let mut kept = Vec::new();
        let mut embargoes: BTreeMap<String, veil_core::keychain::EmbargoRecord> = BTreeMap::new();
        let mut embargo_targets: BTreeMap<String, (String, ObjectId)> = BTreeMap::new();
        for u in updates {
            let why = if u.new.is_some() { blocks.next().unwrap_or(None) } else { None };
            match why {
                Some(why) => {
                    let carried = u.new.and_then(|t| repo.carried_embargo(&t).ok().flatten());
                    let rec = carried.and_then(|id| repo.keys().load_embargo(&id).ok().flatten());
                    if let (Some(target), Some(rec)) = (u.new, rec) {
                        // A local embargo for the default `team` scope stays local
                        // unless the server actually has a `team` group; named
                        // scopes (`--embargo-for`) go to the server to validate.
                        let send_to_server = if rec.scope == "team" {
                            let gs = match &server_groups {
                                Some(gs) => gs,
                                None => server_groups.insert(
                                    client
                                        .groups()
                                        .unwrap_or_default()
                                        .into_iter()
                                        .map(|g| g.name)
                                        .collect(),
                                ),
                            };
                            gs.contains("team")
                        } else {
                            true
                        };
                        if send_to_server {
                            embargo_targets.insert(rec.id.clone(), (u.branch.clone(), target));
                            embargoes.insert(rec.id.clone(), rec);
                            kept.push(u);
                            continue;
                        }
                    }
                    withheld.push((u.branch, why));
                }
                None => kept.push(u),
            }
        }
        let updates = kept;
        for id in &newly_released {
            if let Ok(Some(rec)) = repo.keys().load_embargo(id) {
                embargoes.insert(rec.id.clone(), rec);
            }
        }
        if let Ok(all) = repo.keys().embargoes() {
            for rec in all {
                if rec.released_at.is_some()
                    && view
                        .remote_tags
                        .contains_key(&format!("{prefix}{}", veil_core::embargo::embargo_branch(&rec.id)))
                {
                    embargoes.insert(rec.id.clone(), rec);
                }
            }
        }
        let sent: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let withdrawn: Vec<String> = release_warnings
            .iter()
            .cloned()
            .chain(veil_core::remote::withdrawn_warnings(repo, &sent)?)
            .collect();
        if updates.is_empty() && embargoes.is_empty() {
            not_deleted(&mut withheld);
            if refused_deletions.is_some() {
                let tx = repo.transaction(format!("push to {remote}"))?;
                for name in &deletions {
                    veil_core::remote::clear_tag_deletion(&**tx.repo().backend(), name)?;
                }
                tx.commit()?;
            }
            return Ok(PushOutcome {
                warnings: release_warnings,
                moved: vec![],
                deleted: vec![],
                landed: vec![],
                rejected: withheld,
                uploaded: 0,
                created,
            });
        }
        let targets: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let (uploaded, receipts) = if targets.is_empty() {
            (0, BTreeMap::new())
        } else {
            upload_new(repo, remote, client, &targets, revision >= 2)?
        };
        let pushed: HashMap<String, ObjectId> = updates.iter().filter_map(|u| Some((u.branch.clone(), u.new?))).collect();
        let req_embargoes: Vec<veil_core::keychain::EmbargoRecord> = embargoes.into_values().collect();
        let answer = match client.push(&PushRequest {
            updates,
            force,
            receipts,
            embargoes: req_embargoes,
        }) {
            // A deletion the server refuses never holds back the rest.
            Err(e) if refused_deletions.is_none() && e.downcast_ref::<DeletionRefused>().is_some() => {
                refused_deletions = Some(e.to_string());
                continue;
            }
            r => r?,
        };
        let Some(result) = answer else {
            if attempt < 5 {
                std::thread::sleep(Duration::from_millis(50 * attempt));
                continue;
            }
            bail!("a branch kept moving during the push; pull, then push again");
        };
        let mut out = PushOutcome {
            warnings: withdrawn.iter().cloned().chain(result.warnings.iter().cloned()).collect(),
            moved: vec![],
            deleted: vec![],
            landed: vec![],
            rejected: withheld,
            uploaded,
            created,
        };
        not_deleted(&mut out.rejected);
        // A release the server holds for approval is not a release
        // (BUG-1861): this clone's record says what the server's does, and
        // the embargo's line stays (BUG-1894).
        let mut held = Vec::new();
        for (id, why) in result.warnings.iter().filter_map(|w| veil_core::embargo::held_release(w)) {
            if repo.keys().hold_release(id, why)? {
                held.push(id.to_string());
            }
        }
        let mut tx = repo.transaction(format!("push to {remote}"))?;
        tx.repository_wide();
        let mut missing = false;
        let mut landed = Vec::new();
        for r in result.results {
            match (r.ok, r.tip) {
                (true, Some(tip)) => {
                    let diverted_eid = embargo_targets
                        .iter()
                        .find_map(|(eid, (b, _))| (b == &r.branch).then_some(eid.clone()));
                    if let Some(eid) = diverted_eid {
                        let ebranch = veil_core::embargo::embargo_branch(&eid);
                        if tx.repo().store().has(&tip) {
                            tx.view.remote_tags.insert(format!("{prefix}{ebranch}"), tip);
                            tx.view.tags.insert(ebranch, Tag { target: tip, annotation: None });
                        } else {
                            missing = true;
                        }
                        if let Some((orig_branch, orig_target)) = embargo_targets.get(&eid) {
                            if tx.view.tags.get(orig_branch).is_some_and(|t| t.target == *orig_target && t.annotation.is_none()) {
                                if let Some(pub_tip) = tx.view.remote_tags.get(&format!("{prefix}{orig_branch}")).copied() {
                                    tx.view.tags.insert(orig_branch.clone(), Tag { target: pub_tip, annotation: None });
                                }
                            }
                        }
                    } else {
                        if tx.repo().store().has(&tip) {
                            tx.view.remote_tags.insert(format!("{prefix}{}", r.branch), tip);
                        } else {
                            missing = true;
                        }
                        if veil_core::embargo::embargo_id_of_branch(&r.branch).is_some() && tx.repo().store().has(&tip) {
                            tx.view.tags.insert(r.branch.clone(), Tag { target: tip, annotation: None });
                        }
                    }
                    if r.ticket.is_some() {
                        out.landed.push(r.branch.clone());
                        if let Some(n) = pushed.get(&r.branch) {
                            landed.push((r.branch.clone(), *n, tip));
                        }
                    }
                    out.moved.push((r.branch, tip));
                }
                (true, None) => {
                    tx.view.remote_tags.remove(&format!("{prefix}{}", r.branch));
                    veil_core::remote::clear_tag_deletion(&**tx.repo().backend(), &r.branch)?;
                    out.deleted.push(r.branch);
                }
                (false, _) => out.rejected.push((r.branch, r.message.unwrap_or_default())),
            }
        }
        // A deletion the server refused is over: the server kept the tag,
        // and the next pull brings it back here (it is not asked again on
        // every push).
        for (name, _) in out.rejected.iter().filter(|(name, _)| deletions.contains(name)) {
            veil_core::remote::clear_tag_deletion(&**tx.repo().backend(), name)?;
        }
        for id in newly_released.iter().filter(|id| !held.contains(id)) {
            let eb = veil_core::embargo::embargo_branch(id);
            tx.view.remote_tags.remove(&format!("{prefix}{eb}"));
            if tx.view.tags.get(&eb).is_some_and(|t| t.annotation.is_none()) {
                tx.view.tags.remove(&eb);
            }
        }
        tx.commit()?;
        if missing {
            pull(repo, remote, client, None)?;
        }
        follow_landed(repo, remote, &landed)?;
        return Ok(out);
    }
}

/// Upload what the snapshots `targets` reach that the server lacks (what
/// the remote tags of `remote` do not reach), 8 MiB per request (BUG-858),
/// then the key rings (secret scopes), so new members can open what lands
/// (`team` first of them: it names the project the others belong to). The
/// objects sent, and their receipts.
/// `compress`: a server of revision 2 reads compressed objects.
fn upload_new(repo: &Repo, remote: &str, client: &Client, targets: &[ObjectId], compress: bool) -> Result<(usize, BTreeMap<ObjectId, String>)> {
    let prefix = format!("{remote}/");
    let view = repo.view().clone();
    // What the server has: everything the remote tags reach, as held
    // (beyond a thin clone's boundary it is the server's anyway).
    let store = repo.store().clone();
    let held = repo.held();
    let mut known: HashSet<ObjectId> = HashSet::new();
    let mut stack: Vec<ObjectId> = view
        .remote_tags
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(_, v)| *v)
        .collect();
    stack.push(repo.root_id());
    while let Some(id) = stack.pop() {
        if !known.insert(id) {
            continue;
        }
        if let Ok(Some(s)) = held.snapshot(&id) {
            // Attempts (format 10) go with their version.
            stack.extend(s.parents.iter().chain(&s.attempts).copied());
        }
    }
    let mut new = Vec::new();
    let mut stack: Vec<ObjectId> = targets.to_vec();
    let mut seen_snaps = HashSet::new();
    while let Some(id) = stack.pop() {
        if known.contains(&id) || !seen_snaps.insert(id) {
            continue;
        }
        let s = held.snapshot(&id)?.ok_or(veil_core::VeilError::Missing(id))?;
        // Its attempts (format 10) go with it.
        stack.extend(s.parents.iter().chain(&s.attempts).copied());
        new.push((id, s));
    }
    let tree_pairs: Vec<(ObjectId, Vec<ObjectId>)> = new
        .iter()
        .map(|(_, s)| {
            let parents = s.parents.iter().filter_map(|p| held.snapshot(p).ok().flatten().map(|ps| ps.tree)).collect();
            (s.tree, parents)
        })
        .collect();
    if let Err(why) = veil_core::remote::check_no_personal_keys(&store, &tree_pairs) {
        bail!("{why}");
    }
    // Upload what the push introduces as the walk finds it.
    let mut up = Uploads { client, compress, frames: Vec::new(), ids: Vec::new(), receipts: BTreeMap::new() };
    let mut walk = Introduced::new(&store, |id, raw| up.add(&id, &raw));
    for ((id, _), (tree, parents)) in new.iter().zip(tree_pairs) {
        walk.snapshot(*id, tree, parents)?;
    }
    drop(walk);
    up.flush()?;
    for ring in repo.keys().rings()? {
        if let Err(e) = client.post_ring(&ring) {
            crate::render::warn(&format!("key ring '{}' not sent: {e:#}", ring.scope));
        }
    }
    Ok((up.receipts.len(), up.receipts))
}

/// After a landing: a local tag still where the landed change was (`from`,
/// or below it) follows it to where it landed (`to`, pulled already). The
/// server may have made the change again on a newer tip.
fn follow_landed(repo: &mut Repo, remote: &str, landed: &[(String, ObjectId, ObjectId)]) -> Result<()> {
    if landed.is_empty() {
        return Ok(());
    }
    let mut tx = repo.transaction(format!("landed on {remote}"))?;
    tx.repository_wide();
    for (branch, from, to) in landed {
        if !tx.repo().store().has(to) {
            continue;
        }
        let follow = match tx.view.tags.get(branch) {
            None => true,
            Some(t) if t.annotation.is_some() => false,
            Some(t) => t.target == *from || tx.repo().is_ancestor(&t.target, from)?,
        };
        if follow {
            tx.view.tags.insert(branch.clone(), Tag { target: *to, annotation: None });
        }
    }
    tx.commit()?;
    Ok(())
}

/// What `vl land` came to.
pub struct LandOutcome {
    pub result: veil_core::hub::land::LandResult,
    pub uploaded: usize,
}

/// `vl land`: upload `rev` and the changes under it the server lacks, submit
/// them to land on `onto`, and (with `wait`) once they landed, pull and move
/// the local tag `onto` to where they landed when it was at `rev` or below.
pub fn land(repo: &mut Repo, remote: &str, client: &Client, rev: ObjectId, onto: &str, wait: bool) -> Result<LandOutcome> {
    if veil_core::remote::embargo_blocks(repo, &[rev])?.into_iter().flatten().next().is_some() {
        bail!("this change is under an embargo: it lands only at its release");
    }
    let revision = client.tips()?.map_or(0, |t| t.revision);
    let (uploaded, receipts) = upload_new(repo, remote, client, &[rev], revision >= 2)?;
    let result = client.land(&veil_core::hub::land::LandRequest {
        onto: onto.to_string(),
        snapshot: Some(rev),
        receipts,
        wait,
        ..Default::default()
    })?;
    if result.state == veil_core::hub::land::LandState::Landed {
        if let Some(tip) = result.landed.last() {
            pull(repo, remote, client, None)?;
            follow_landed(repo, remote, &[(onto.to_string(), rev, *tip)])?;
        }
    }
    Ok(LandOutcome { result, uploaded })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Property 4 of the S11 review (BUG-1390's class): every rewrite of
    /// `$VEIL_HOME/hub.json` (`update_entry`: `load_file`, a change,
    /// `save_file`) keeps the fields this `vl` does not know (a later
    /// release's, written by it on the same machine), or refuses. The file
    /// is outside every repository, so no repository format guards it.
    #[test]
    fn hub_json_keeps_the_fields_this_vl_does_not_know() {
        let before = br#"{"servers":{"hub.example:443":{"token":"t","expires_at":5,"anchors":{"p":"fp"},"later_trust":{"p":"MARKER-LATER-FIELD-1a"}}},"later_top":"MARKER-LATER-TOP-2b"}"#;
        let mut f: HubFile = serde_json::from_slice(before).expect("an older vl reads a newer hub.json");
        // What `update_entry` does: change one entry, write the whole file.
        f.servers.get_mut("hub.example:443").unwrap().token = Some("renewed".into());
        let after = String::from_utf8(serde_json::to_vec_pretty(&f).unwrap()).unwrap();
        assert!(after.contains("renewed"), "the change is written: {after}");
        assert!(after.contains("MARKER-LATER-FIELD-1a"), "a server entry's unknown field was dropped: {after}");
        assert!(after.contains("MARKER-LATER-TOP-2b"), "an unknown top-level field was dropped: {after}");
    }

    /// BUG-1913: `vl` waits out `503 warming` as it does an answer with
    /// `retry_after_ms` (BUG-1331), on every request ([`Client::send`] asks
    /// [`retry_after`]): half a second, doubling to 8 s, or what the server
    /// says. Any other answer is the request's.
    #[test]
    fn bug_1913_warming_is_waited_out_as_retry_after_is() {
        let warming = br#"{"code":"warming","message":"this history is being prepared for you; try again in a few seconds"}"#;
        let waits: Vec<Option<u64>> = (0..RETRIES).map(|tries| retry_after(503, warming, tries)).collect();
        assert_eq!(waits, [500, 1_000, 2_000, 4_000, 8_000, 8_000, 8_000, 8_000].map(Some));
        assert!(is_warming(503, warming));
        // The server's own time comes first, for `warming` too.
        assert_eq!(retry_after(503, br#"{"code":"warming","message":"m","retry_after_ms":1500}"#, 3), Some(1_500));
        assert_eq!(retry_after(503, br#"{"code":"busy","message":"m","retry_after_ms":700}"#, 0), Some(700));
        assert_eq!(retry_after(429, br#"{"code":"rate_limited","message":"m","retry_after_ms":1000}"#, 7), Some(1_000));
        assert_eq!(retry_after(429, br#"{"code":"rate_limited","message":"m","retry_after_ms":18446744073709551615}"#, 0), Some(u64::MAX));
        // Not asked to come back: a query past its deadline, an answer
        // that is not the server's, and `warming` under any other status.
        for (status, body) in [(503, &br#"{"code":"deadline","message":"m"}"#[..]), (503, b"<html>"), (200, warming), (404, warming), (500, warming)] {
            assert_eq!(retry_after(status, body, 0), None, "{status} {}", String::from_utf8_lossy(body));
            assert!(!is_warming(status, body) || status == 503);
        }
        assert!(!is_warming(503, br#"{"code":"deadline","message":"m"}"#) && !is_warming(200, warming));
    }

    /// `vl` says it reads encoded frames, and reads both kinds: plain
    /// frames (a server from before S27) and compressed ones.
    #[test]
    fn answers_of_plain_and_encoded_frames() {
        assert!(ACCEPT.split(", ").any(|t| t == encoding::FRAMES));
        let objs: Vec<(ObjectId, Vec<u8>)> = [&b"veil:blob\none"[..], &b"veil:blob\ntwo two two two two two two two two two two two two"[..]]
            .iter()
            .map(|r| (ObjectId::hash(r), r.to_vec()))
            .collect();
        let (mut plain, mut encoded) = (Vec::new(), Vec::new());
        for (id, raw) in &objs {
            put_frame(&mut plain, id, raw);
            put_frame(&mut encoded, id, &encoding::encode(raw));
        }
        assert_ne!(plain, encoded);
        assert_eq!(objects_of(&plain).unwrap(), objs);
        assert_eq!(objects_of(&encoded).unwrap(), objs);
        // Decoded on several threads (a large answer), in order.
        let many: Vec<(ObjectId, Vec<u8>)> = (0..2000)
            .map(|i| format!("veil:blob\nobject {i} {}", "text ".repeat(i % 50)).into_bytes())
            .map(|r| (ObjectId::hash(&r), r))
            .collect();
        let mut body = Vec::new();
        for (id, raw) in &many {
            put_frame(&mut body, id, &encoding::encode(raw));
        }
        let frames = encoding::split_frames(&body).unwrap();
        let parts = Decoded::parallel(&frames).unwrap();
        assert!(parts.len() > 1);
        let got: Vec<Vec<u8>> = parts.iter().flat_map(|d| d.objects.iter().map(|r| d.bytes[r.clone()].to_vec())).collect();
        assert_eq!(got, many.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>());
        let mut bad = body.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(Decoded::parallel(&encoding::split_frames(&bad).unwrap()).is_err());
    }

    #[test]
    fn urls() {
        let u = HubUrl::parse("veil://Hub.example:8443/acme").unwrap().unwrap();
        assert_eq!(u, HubUrl { authority: "hub.example:8443".into(), project: "acme".into() });
        assert_eq!(HubUrl::parse("https://h/p/").unwrap().unwrap().project, "p");
        assert!(HubUrl::parse("veil://h/a/b").unwrap().is_err());
        assert!(HubUrl::parse("veil://user@h/a").unwrap().is_err());
        assert!(HubUrl::parse("/some/path").is_none());
        assert!(HubUrl::parse("host:path").is_none());
    }

    #[test]
    fn only_scope() {
        assert!(in_scope(Some("src/api"), ""));
        assert!(in_scope(Some("src/api"), "src"));
        assert!(in_scope(Some("src/api"), "src/api/x.rs"));
        assert!(!in_scope(Some("src/api"), "src/apix"));
        assert!(!in_scope(Some("src/api"), "docs"));
    }

    /// What a push of `new` must send, computed path by path from whole
    /// flattened trees (the server's rule, `docs/HUB.md` §13 check 7): each
    /// new snapshot; at each path below no directory that equals a
    /// parent's directory there, the entry's directory tree, or what its
    /// leaf names that no parent's entry at that path names.
    fn required(store: &ObjectStore, new: &[(ObjectId, ObjectId, Vec<ObjectId>)]) -> HashSet<ObjectId> {
        fn flatten(store: &ObjectStore, tree: ObjectId, dir: &str, out: &mut BTreeMap<String, veil_core::TreeEntry>) {
            for e in &store.tree_object(&tree).unwrap().entries {
                let p = if dir.is_empty() { e.name.clone() } else { format!("{dir}/{}", e.name) };
                out.insert(p.clone(), e.clone());
                if e.kind == EntryKind::Dir {
                    flatten(store, e.id, &p, out);
                }
            }
        }
        let mut out = HashSet::new();
        for (id, tree, parents) in new {
            out.insert(*id);
            if !parents.contains(tree) {
                out.insert(*tree);
            }
            let mut mine = BTreeMap::new();
            flatten(store, *tree, "", &mut mine);
            let theirs: Vec<BTreeMap<String, veil_core::TreeEntry>> = parents
                .iter()
                .map(|t| {
                    let mut m = BTreeMap::new();
                    flatten(store, *t, "", &mut m);
                    m
                })
                .collect();
            let same_in_a_parent = |p: &str, e: &veil_core::TreeEntry| theirs.iter().any(|m| m.get(p).is_some_and(|pe| pe.id == e.id));
            for (p, e) in &mine {
                let mut up = p.as_str();
                let mut unchanged = e.kind == EntryKind::Dir && same_in_a_parent(p, e);
                while let Some((d, _)) = up.rsplit_once('/') {
                    unchanged |= same_in_a_parent(d, &mine[d]);
                    up = d;
                }
                if unchanged {
                    continue;
                }
                if e.kind == EntryKind::Dir {
                    out.insert(e.id);
                    continue;
                }
                let before: HashSet<ObjectId> =
                    theirs.iter().filter_map(|m| m.get(p)).flat_map(|pe| named_ids(store, pe).unwrap()).collect();
                out.extend(named_ids(store, e).unwrap().into_iter().filter(|id| !before.contains(id)));
            }
        }
        out
    }

    /// A leaf: absent, or (content, a conflict of contents).
    type Leaf = Option<(u8, bool)>;
    const PATHS: [&str; 8] = ["a", "b", "d/a", "d/b", "d/e/a", "d/e/b", "y", "y/a"];

    fn build(store: &ObjectStore, leaves: &[Leaf]) -> ObjectId {
        let mut files: BTreeMap<String, veil_core::TreeEntry> = BTreeMap::new();
        for (n, (path, leaf)) in PATHS.iter().zip(leaves).enumerate() {
            let Some((c, conflict)) = *leaf else { continue };
            // Contents 0 and 1 are the path's own; others are shared by all
            // paths (a file copied or moved).
            let blob = |c: u8| store.put(&Object::Blob(if c < 2 { vec![b'v', c, n as u8] } else { vec![b'v', c] })).unwrap();
            // `y` is a file or a directory, never both.
            if *path == "y/a" && files.contains_key("y") {
                continue;
            }
            let name = path.rsplit('/').next().unwrap().to_string();
            let file = |c: u8| veil_core::TreeEntry {
                name: name.clone(),
                kind: EntryKind::File,
                id: blob(c),
                size: 2,
                executable: false,
                visibility: Default::default(),
            };
            let e = if conflict {
                let t = |c: u8| Some(veil_core::object::ConflictTerm::of(&file(c)));
                let id = store.put(&Object::Conflict(veil_core::object::Conflict { adds: vec![t(c), t(c + 1)], removes: vec![t(c + 2)] })).unwrap();
                veil_core::TreeEntry { kind: EntryKind::Conflict, id, size: 0, ..file(c) }
            } else {
                file(c)
            };
            files.insert(path.to_string(), e);
        }
        fn dir(store: &ObjectStore, files: &BTreeMap<String, veil_core::TreeEntry>, at: &str) -> veil_core::Tree {
            let mut t = veil_core::Tree::default();
            let mut subdirs = BTreeMap::new();
            for (p, e) in files {
                let Some(rest) = (if at.is_empty() { Some(p.as_str()) } else { p.strip_prefix(&format!("{at}/")) }) else { continue };
                match rest.split_once('/') {
                    None => t.insert(e.clone()),
                    Some((d, _)) => {
                        subdirs.insert(d.to_string(), ());
                    }
                }
            }
            for d in subdirs.keys() {
                let sub = dir(store, files, &if at.is_empty() { d.clone() } else { format!("{at}/{d}") });
                let id = store.put_tree(&sub).unwrap();
                t.insert(veil_core::TreeEntry {
                    name: d.clone(),
                    kind: EntryKind::Dir,
                    id,
                    size: 0,
                    executable: false,
                    visibility: Default::default(),
                });
            }
            t
        }
        store.put_tree(&dir(store, &files, "")).unwrap()
    }

    fn leaf() -> impl proptest::strategy::Strategy<Value = Leaf> {
        use proptest::prelude::*;
        prop_oneof![
            3 => Just(None),
            6 => (0u8..3).prop_map(|c| Some((c, false))),
            1 => (0u8..3).prop_map(|c| Some((c, true))),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        /// BUG-857: a push sends exactly what the server asks a receipt
        /// for, whatever the history (trees reused across snapshots, a
        /// file turned directory, merges, conflicts), whatever
        /// the server already holds and in whatever order the snapshots
        /// are walked.
        #[test]
        fn a_push_sends_exactly_what_the_server_lacks(
            snaps in proptest::collection::vec(
                (proptest::collection::vec(leaf(), PATHS.len()), proptest::collection::vec(0usize..64, 1..3)),
                1..14,
            ),
            known_tips in proptest::collection::vec(0usize..64, 0..3),
            order in proptest::collection::vec(0usize..1000, 14),
        ) {
            let repo = Repo::init(Arc::new(veil_core::MemoryBackend::new()), None, "t").unwrap();
            let store = repo.store().clone();
            let root = repo.root_id();
            // Snapshot i's parents are earlier snapshots (or the root).
            let mut ids: Vec<ObjectId> = Vec::new();
            let mut info: HashMap<ObjectId, (ObjectId, Vec<ObjectId>)> = HashMap::new();
            info.insert(root, (repo.snapshot(&root).unwrap().tree, vec![]));
            for (i, (leaves, parents)) in snaps.iter().enumerate() {
                let tree = build(&store, leaves);
                let mut ps: Vec<ObjectId> = parents.iter().map(|p| if i == 0 || p % 4 == 0 { root } else { ids[p % i] }).collect();
                ps.dedup();
                let mut s = veil_core::object::Snapshot::root(tree);
                s.parents = ps.clone();
                s.timestamp = i as i64 + 1;
                let id = store.put(&Object::Snapshot(s)).unwrap();
                ids.push(id);
                info.insert(id, (tree, ps));
            }
            // What the server holds: everything some snapshots reach.
            let mut known = HashSet::from([root]);
            let mut stack: Vec<ObjectId> = known_tips.iter().filter(|_| !ids.is_empty()).map(|k| ids[k % ids.len()]).collect();
            while let Some(id) = stack.pop() {
                if known.insert(id) {
                    stack.extend(info[&id].1.iter().copied());
                }
            }
            let mut new: Vec<ObjectId> = ids.iter().copied().filter(|id| !known.contains(id)).collect();
            new.sort_by_key(|id| order[ids.iter().position(|x| x == id).unwrap()]);
            let new: Vec<(ObjectId, ObjectId, Vec<ObjectId>)> =
                new.iter().map(|id| (*id, info[id].0, info[id].1.iter().map(|p| info[p].0).collect())).collect();
            let mut sent = Vec::new();
            let mut walk = Introduced::new(&store, |id, raw| {
                assert_eq!(ObjectId::hash(&raw), id);
                sent.push(id);
                Ok(())
            });
            for (id, tree, parents) in &new {
                walk.snapshot(*id, *tree, parents.clone()).unwrap();
            }
            drop(walk);
            let set: HashSet<ObjectId> = sent.iter().copied().collect();
            proptest::prop_assert_eq!(set.len(), sent.len(), "an object sent twice");
            proptest::prop_assert_eq!(set, required(&store, &new));
        }
    }
}
