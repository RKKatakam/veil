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
    hub::wire::{
        device_fingerprint, put_frame, read_frames, vouch_message, AccessInfo, BranchUpdate, Challenge, ChallengeRequest, Devices, ErrorBody,
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
}

#[derive(Default, Serialize, Deserialize)]
struct HubFile {
    #[serde(default)]
    servers: BTreeMap<String, ServerEntry>,
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
pub fn signed_in_servers() -> Result<Vec<(String, String)>> {
    Ok(load_file()?.servers.into_iter().filter_map(|(a, e)| Some((a, e.person?))).collect())
}

// ---- the client -------------------------------------------------------------------------

pub struct Client {
    agent: ureq::Agent,
    pub url: HubUrl,
    identity: Identity,
    token: std::cell::RefCell<Option<String>>,
    /// Signed in before (an entry in hub.json): renew the session silently.
    known: bool,
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
    Ok(body.with_config().limit(4 << 30).read_to_vec()?)
}

impl Client {
    pub fn new(url: &HubUrl, identity: Identity) -> Result<Client> {
        let file = load_file()?;
        let entry = file.servers.get(&url.authority).cloned();
        let ca = match std::env::var_os("VEIL_HUB_CA") {
            Some(p) => Some(std::fs::read_to_string(&p).with_context(|| format!("reading VEIL_HUB_CA {}", Path::new(&p).display()))?),
            None => entry.as_ref().and_then(|e| e.ca.clone()),
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
        let agent = ureq::Agent::config_builder()
            .tls_config(tls.build())
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(600)))
            .build()
            .new_agent();
        let token = entry
            .as_ref()
            .filter(|e| e.expires_at > veil_core::now_millis() + 30_000)
            .and_then(|e| e.token.clone());
        Ok(Client {
            agent,
            url: url.clone(),
            identity,
            token: std::cell::RefCell::new(token),
            known: entry.is_some_and(|e| e.person.is_some()),
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

    fn send(&self, method: &str, path: &str, body: Option<(&str, Vec<u8>)>, auth: bool) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{path}", self.url.base());
        let token = if auth { self.token.borrow().clone() } else { None };
        let resp = match (method, body) {
            ("GET", _) => {
                let mut r = self.agent.get(&url);
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
                match body {
                    Some((ct, b)) => r.header("content-type", ct).send(&b[..]),
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
    pub fn login(&self, name: Option<&str>) -> Result<Session> {
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
        *self.token.borrow_mut() = Some(s.token.clone());
        update_entry(&self.url.authority, |e| {
            e.token = Some(s.token.clone());
            e.expires_at = s.expires_at;
            e.person = Some(s.person.clone());
            e.hub_key = Some(s.hub_key.clone());
        })?;
        Ok(s)
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

    pub fn create_project(&self) -> Result<Tips> {
        self.json("POST", &self.url.project_path(""), None::<&()>)
    }

    pub fn history(&self, tips: Vec<ObjectId>, stop: Vec<ObjectId>) -> Result<Vec<(ObjectId, Vec<u8>)>> {
        let out = self.ok(
            "POST",
            &self.url.project_path("/history"),
            Some(("application/json", serde_json::to_vec(&HistoryRequest { tips, stop })?)),
        )?;
        Ok(read_frames(&out)?.into_iter().map(|(id, raw)| (id, raw.to_vec())).collect())
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
    pub fn fetch_each(&self, snapshot: ObjectId, wants: &[Want], sizes: &[u64], mut f: impl FnMut(&Want, &[u8]) -> Result<()>) -> Result<()> {
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
        let mut check = |part: &[Want], body: &[u8]| -> Result<()> {
            let got = read_frames(body)?;
            if got.len() != part.len() {
                bail!("the server sent {} objects for {} asked", got.len(), part.len());
            }
            for (w, (id, raw)) in part.iter().zip(got) {
                if id != w.id {
                    bail!("the server sent another object than asked");
                }
                f(w, raw)?;
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
                        let mut r = agent.post(url).header("content-type", "application/json");
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

    /// Upload object frames; the server's receipt for each, in order.
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
            s => Err(Self::error(s, &out)),
        }
    }

    /// A commit through the API (`POST …/changes`).
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

    /// A person's devices and vouches, as the server lists them: never
    /// enough on its own to wrap a key (`docs/HUB.md` §13.11).
    pub fn devices(&self, person: &str) -> Result<Devices> {
        self.json("GET", &format!("/v1/people/{person}/devices"), None::<&()>)
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
}

// ---- pull ---------------------------------------------------------------------------------

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
    let tips = client
        .tips()?
        .ok_or_else(|| anyhow!("no project '{}' that you can see on {}", client.url.project, client.url.authority))?;
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
        .filter(|id| store.has(id))
        .collect();
    let mut want_tips: Vec<ObjectId> = tips.branches.values().copied().filter(|t| !store.has(t)).collect();
    want_tips.sort();
    want_tips.dedup();
    // A repository made for this clone holds only the root snapshot and
    // its empty tree: nothing to probe the disk for, object by object.
    let root = tx.repo().root_id();
    let fresh = stop.is_empty() && tx.view.heads.iter().all(|h| *h == root);
    let empty_tree = tx.repo().snapshot(&root)?.tree;
    let have = |id: &ObjectId| match fresh {
        true => *id == root || *id == empty_tree,
        false => store.has(id),
    };
    let mut report = SyncReport::default();
    let mut incoming = Incoming::new(&store);
    let mut new_snaps = Vec::new();
    if !want_tips.is_empty() {
        for (id, raw) in client.history(want_tips, stop)? {
            if have(&id) {
                continue;
            }
            let Object::Snapshot(s) = Object::decode(&raw)? else {
                bail!("the server sent a non-snapshot in history");
            };
            if s.signature_valid() != Some(true) {
                report.warnings.push(format!("snapshot {} carries no valid signature", id.short()));
            }
            new_snaps.push((id, s.tree));
            if incoming.put(id, raw, "")? {
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
        if !have(tree) && seen.insert(*tree) {
            frontier.push((*snap, String::new(), *tree, 0));
        }
    }
    // A server of revision 1 takes the wants of every snapshot in one
    // request per level; an older one, one request per snapshot.
    let across = tips.revision >= 1;
    while !frontier.is_empty() {
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
        let mut next = Vec::new();
        for (snap, (wants, sizes)) in by_snap {
            client.fetch_each(snap, &wants, &sizes, |w, raw| {
                let obj = Object::decode(raw)?;
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
                    if !have(&cid) && seen.insert(cid) {
                        next.push((w.snapshot.unwrap_or(snap), p, cid, size));
                    }
                }
                if incoming.put(w.id, raw.to_vec(), &w.path)? {
                    report.objects_copied += 1;
                }
                Ok(())
            })?;
        }
        frontier = next;
    }
    report.packs_written = incoming.finish()?;
    // Key rings of secret scopes: verified and fast-forwarded locally.
    if client.token.borrow().is_some() {
        if let Ok(rings) = client.rings() {
            report.warnings.extend(crate::hub_keys::merge_server_rings(tx.repo().keys(), &client.url, rings)?);
            tx.repo().keys().invalidate();
        }
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
    apply_remote_tags(&mut tx, remote, tags, None, &mut report)?;
    tx.commit()?;
    Ok(report)
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
/// it did not send (BUG-824).
struct Uploads<'a> {
    client: &'a Client,
    frames: Vec<u8>,
    ids: Vec<ObjectId>,
    receipts: BTreeMap<ObjectId, String>,
}

impl Uploads<'_> {
    fn add(&mut self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        put_frame(&mut self.frames, id, raw);
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

pub struct PushOutcome {
    pub warnings: Vec<String>,
    pub moved: Vec<(String, ObjectId)>,
    pub rejected: Vec<(String, String)>,
    pub uploaded: usize,
    pub created: bool,
}

/// Push local tags (all, or `only_tags`) to the server.
pub fn push(repo: &mut Repo, remote: &str, client: &Client, only_tags: &[String], force: bool) -> Result<PushOutcome> {
    let mut created = false;
    if client.tips()?.is_none() {
        client.create_project()?;
        created = true;
        // This device made the project's `team` ring: the one it trusts.
        crate::hub_keys::anchor_created(repo.keys(), &client.url)?;
    }
    let mut attempt = 0;
    loop {
        attempt += 1;
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
        for t in only_tags {
            if !view.tags.contains_key(t) {
                bail!("no tag '{t}' here");
            }
        }
        // Nothing an unreleased embargo withholds is uploaded: a tag that
        // would publish it is not pushed (it reaches no remote by any route).
        let targets: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let blocks = veil_core::remote::embargo_blocks(repo, &targets)?;
        let mut withheld = Vec::new();
        let mut kept = Vec::new();
        for (u, why) in updates.into_iter().zip(blocks) {
            match why {
                Some(why) => withheld.push((u.branch, why)),
                None => kept.push(u),
            }
        }
        let updates = kept;
        let sent: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let withdrawn = veil_core::remote::withdrawn_warnings(repo, &sent)?;
        if updates.is_empty() {
            return Ok(PushOutcome {
                warnings: vec![],
                moved: vec![],
                rejected: withheld,
                uploaded: 0,
                created,
            });
        }
        // What the server has: everything the remote tags reach.
        let store = repo.store().clone();
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
            if let Ok(s) = store.snapshot(&id) {
                stack.extend(s.parents.iter().copied());
            }
        }
        let mut new = Vec::new();
        let mut stack: Vec<ObjectId> = updates.iter().filter_map(|u| u.new).collect();
        let mut seen_snaps = HashSet::new();
        while let Some(id) = stack.pop() {
            if known.contains(&id) || !seen_snaps.insert(id) {
                continue;
            }
            let s = store.snapshot(&id)?;
            stack.extend(s.parents.iter().copied());
            new.push((id, s));
        }
        // Upload what the push introduces as the walk finds it, 8 MiB per
        // request (BUG-858).
        let mut up = Uploads { client, frames: Vec::new(), ids: Vec::new(), receipts: BTreeMap::new() };
        let mut walk = Introduced::new(&store, |id, raw| up.add(&id, &raw));
        for (id, s) in &new {
            let parents: Vec<ObjectId> = s.parents.iter().filter_map(|p| store.snapshot(p).ok().map(|ps| ps.tree)).collect();
            walk.snapshot(*id, s.tree, parents)?;
        }
        drop(walk);
        up.flush()?;
        let (uploaded, receipts) = (up.receipts.len(), up.receipts);
        // Key rings (secret scopes) first, so new members can open what lands
        // (`team` first of them: it names the project the others belong to).
        for ring in repo.keys().rings()? {
            if let Err(e) = client.post_ring(&ring) {
                crate::render::warn(&format!("key ring '{}' not sent: {e:#}", ring.scope));
            }
        }
        let Some(result) = client.push(&PushRequest { updates, force, receipts })? else {
            if attempt < 5 {
                std::thread::sleep(Duration::from_millis(50 * attempt));
                continue;
            }
            bail!("a branch kept moving during the push; pull, then push again");
        };
        let mut out = PushOutcome {
            warnings: withdrawn.iter().cloned().chain(result.warnings.iter().cloned()).collect(),
            moved: vec![],
            rejected: withheld,
            uploaded,
            created,
        };
        let mut tx = repo.transaction(format!("push to {remote}"))?;
        tx.repository_wide();
        let mut missing = false;
        for r in result.results {
            match (r.ok, r.tip) {
                (true, Some(tip)) => {
                    if tx.repo().store().has(&tip) {
                        tx.view.remote_tags.insert(format!("{prefix}{}", r.branch), tip);
                    } else {
                        missing = true;
                    }
                    out.moved.push((r.branch, tip));
                }
                (true, None) => {
                    tx.view.remote_tags.remove(&format!("{prefix}{}", r.branch));
                }
                (false, _) => out.rejected.push((r.branch, r.message.unwrap_or_default())),
            }
        }
        tx.commit()?;
        if missing {
            pull(repo, remote, client, None)?;
        }
        return Ok(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
