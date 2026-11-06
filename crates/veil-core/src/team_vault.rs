//! The team vault: secrets shared with the members of a scope
//! (`vl secret set|get|list|rm --scope S`), synced to team remotes.
//!
//! # Records
//!
//! Every write is one immutable **record**, a file
//! `.veil/meta/vault/<scope>/<id>.json` holding compact JSON
//! [`VaultRecord`]:
//!
//! * `sealed`: the entry's **name and value** (or, for a deletion, the name
//!   and no value) as JSON, padded with spaces to a multiple of
//!   [`PAD`] bytes, sealed with XChaCha20-Poly1305 under a random nonce
//!   (CRYPTO.md C2/C12) with the scope's *current* generation key at the
//!   time of the write. The label `vault:<scope>#<key-id>` names the
//!   generation and is authenticated. Names are sealed too: a team remote's
//!   operator sees opaque ids, sizes in [`PAD`]-byte steps, write times and
//!   who wrote.
//! * `timestamp`, `signature`: an Ed25519 signature (context `vault-entry`)
//!   by the writer over [`RecordBody`] (format, scope, the sealed envelope,
//!   timestamp, the writer's member id).
//! * The id is `BLAKE3` of the file's bytes, which must be exactly the
//!   compact JSON of the record (so a record has one id).
//!
//! # Who counts, and which write wins
//!
//! The vault's content is a pure function of the set of records and the
//! scope's verified ring, so replicas that hold the same records and ring
//! agree, whatever order they received them in:
//!
//! * A record **counts** if its signature verifies, it names a generation of
//!   the scope's ring, it opens with that generation's key, and its signer
//!   is a **current** member whose registered signing key made the
//!   signature. Writes of non-members, of revoked members (from the moment
//!   the revocation is in the ring, whenever they were written) and of
//!   members granted without a signing key never count.
//! * Per name, the counting record with the greatest `(timestamp, signing
//!   key, id)` wins. A winning deletion (no value) hides the name. A writer
//!   stamps `max(now, winner + 1)`, so a write always beats what its writer
//!   had seen, whatever the clocks say.
//!
//! **Compaction** deletes a record only when a newer record by the *same
//! signer* for the same name exists (both opened, both well signed).
//! Whatever any future ring says about that signer, the newer record
//! decides both or neither, so compaction never changes the vault's
//! content and replicas still converge. Records per name are bounded by
//! the number of members who ever wrote it.
//!
//! # Revocation
//!
//! [`Keychain::revoke_with_vault`] revokes a member and reports the entries
//! they could read (every live entry sealed under a generation they held:
//! the keys to rotate). The entries whose current version they wrote would
//! otherwise vanish (their writes stop counting); the revoking admin re-signs
//! those values under the new generation (they are in the report too).
//!
//! # Rotation
//!
//! After `vl scope rotate` (or a revocation) new writes are sealed under the
//! new generation; existing records keep their generation (members read
//! them through the ring's key chain) and are re-sealed when next written.
//!
//! # Sync
//!
//! Team remotes only ([`crate::remote`]): a record crosses if the receiver
//! lacks it and it passes the checks above against the receiver's ring
//! (merged first), except that records of *former* members are kept (they
//! count again if the member is granted again) with a warning on pull.
//! Push and pull both report the records they refuse (BUG-522).
//! Public remotes never receive the vault.
//!
//! # Stale rings, clocks and exposure (round 8)
//!
//! * A writer whose ring has not caught up with a revocation seals under a
//!   generation the revoked member holds (BUG-524). Push re-seals the
//!   pusher's own such records under the destination ring's current
//!   generation (on push, in `sync`); other records sealed under a generation after
//!   the scope had moved past it are flagged ([`Entry::stale_generation`]).
//! * A write replaces its writer's own records of the name stamped more than
//!   [`MAX_CLOCK_SKEW_MS`] ahead instead of being stamped after them
//!   (BUG-522).
//! * Each device remembers keyed hashes of the values it saw ([`HISTORY_DIR`]),
//!   so setting a name back to a value a revoked member read keeps its
//!   first generation as `since` (BUG-521).
//! * Names are shell identifiers, and a scope's live entries are capped at
//!   [`MAX_SCOPE_ENV_BYTES`] (BUG-520, BUG-523); `vl run` never sets
//!   [`is_execution_variable`] names from a team vault.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{domains, Envelope},
    error::{Result, VeilError},
    identity::{format_public_key, parse_public_key, Signature},
    keychain::{generation_label, split_label, validate_scope_name, KeyRing, Keychain, RingOp, RingState},
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// Where team-vault records live (one directory per scope).
pub const TEAM_VAULT_DIR: &str = ".veil/meta/vault";
/// Record format this build writes and reads; a newer one is skipped with a
/// warning (never rewritten: records are immutable).
pub const RECORD_FORMAT: u32 = 1;
/// Sealed payloads are padded to a multiple of this many bytes.
pub const PAD: usize = 128;
/// Longest entry name.
pub const MAX_NAME_LEN: usize = 128;
/// Largest entry value.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
/// Record files larger than this are not read.
const MAX_RECORD_FILE: u64 = 4 * MAX_VALUE_LEN as u64;
/// Records stamped further than this in the future are refused on sync.
pub const MAX_CLOCK_SKEW_MS: i64 = 24 * 3600 * 1000;

const SIG_CONTEXT: &str = domains::SIG_CONTEXT_VAULT_ENTRY;

/// One signed write of a team-vault entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecord {
    pub format: u32,
    pub scope: String,
    /// Name and value, sealed under `vault:<scope>#<key-id>`.
    pub sealed: Envelope,
    /// Milliseconds since the epoch (see the module documentation).
    pub timestamp: i64,
    pub signature: Signature,
}

/// What a record's signature covers. Never change it (FORMAT.md §2).
#[derive(Serialize)]
pub struct RecordBody<'a> {
    format: u32,
    scope: &'a str,
    sealed: &'a Envelope,
    timestamp: i64,
    signer: &'a str,
}

impl VaultRecord {
    /// The bytes the signature covers ([`RecordBody`]).
    pub fn signing_body(&self) -> Vec<u8> {
        serde_json::to_vec(&RecordBody {
            format: self.format,
            scope: &self.scope,
            sealed: &self.sealed,
            timestamp: self.timestamp,
            signer: &self.signature.signer,
        })
        .expect("serialisable")
    }

    /// The canonical file bytes (compact JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialisable")
    }

    /// The record id: BLAKE3 of [`VaultRecord::to_bytes`], hex.
    pub fn id(&self) -> String {
        blake3::hash(&self.to_bytes()).to_hex().to_string()
    }

    /// Build a record: `name` = `value` (`None`: a deletion), sealed with
    /// `keys`' current generation key of `scope` and signed by `signer`.
    /// Nothing is checked or written; [`Keychain::team_secret_write`] is the
    /// way to write one (tests use this to forge records).
    pub fn seal(
        keys: &Keychain,
        signer: &crate::identity::Identity,
        scope: &str,
        name: &str,
        value: Option<&str>,
        since: u32,
        timestamp: i64,
    ) -> Result<VaultRecord> {
        let (label, key) = keys.sealing_key(scope)?;
        let key = Zeroizing::new(key);
        if split_label(&label).1.is_none() {
            return Err(VeilError::repo(format!("scope '{scope}' has no key generation label; rotate it first")));
        }
        let mut pt = Zeroizing::new(serde_json::to_vec(&Payload {
            name: name.to_string(),
            value: value.map(str::to_string),
            since,
        })?);
        let padded = pt.len().div_ceil(PAD).max(1) * PAD;
        pt.resize(padded, b' ');
        let sealed = Envelope::seal_random(&key, &format!("{}{label}", domains::VAULT_LABEL_PREFIX), &pt)?;
        let mut rec = VaultRecord {
            format: RECORD_FORMAT,
            scope: scope.to_string(),
            sealed,
            timestamp,
            signature: Signature {
                signer: signer.public_hex(),
                key: signer.verifying_hex(),
                sig: String::new(),
            },
        };
        rec.signature = Signature::create(signer, SIG_CONTEXT, &rec.signing_body());
        Ok(rec)
    }

    /// Re-sign the record with `signer` (after editing a field).
    pub fn resign(&mut self, signer: &crate::identity::Identity) {
        self.signature = Signature::create(signer, SIG_CONTEXT, &self.signing_body());
    }

    /// Where the record is filed on a backend.
    pub fn path(&self) -> Result<VPath> {
        record_path(&self.scope, &self.id())
    }

    pub fn signature_valid(&self) -> bool {
        self.signature.verify(SIG_CONTEXT, &self.signing_body())
    }

    /// The generation key id the label names, if the label is
    /// `vault:<this scope>#<key-id>`.
    fn key_id(&self) -> Option<&str> {
        let label = self.sealed.scope.strip_prefix(domains::VAULT_LABEL_PREFIX)?;
        match split_label(label) {
            (s, Some(kid)) if s == self.scope && !kid.is_empty() => Some(kid),
            _ => None,
        }
    }
}

/// The sealed plaintext.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    name: String,
    /// `None`: the entry was deleted.
    value: Option<String>,
    /// The generation under which this exact value was first sealed: kept
    /// when the same value is written again (re-signed after a revocation,
    /// re-sealed after a rotation), so the revocation report still knows
    /// who could read it. At most the record's own generation.
    since: u32,
}

/// Is `name` a shell identifier, `[A-Za-z_][A-Za-z0-9_]*`, of at most
/// [`MAX_NAME_LEN`] bytes? Only such names are written, and only they reach
/// `vl run`'s environment (BUG-520).
pub fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The names records written before BUG-520 may hold (`.` and `-` were
/// allowed too). They are still read, so those records keep counting and
/// replicas keep agreeing, but `vl run` skips them.
fn readable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Check the name of a new write: a shell identifier ([`is_identifier`]),
/// so it is a usable environment variable name (no `=`, no NUL) and safe to
/// print.
pub fn validate_name(name: &str) -> Result<()> {
    if is_identifier(name) {
        Ok(())
    } else {
        Err(VeilError::repo(format!(
            "invalid secret name {name:?}: use letters, digits and '_', starting with a letter or '_' \
             (at most {MAX_NAME_LEN} characters), since it becomes an environment variable"
        )))
    }
}

/// Environment variables (compared in upper case) that decide which code a
/// command runs, which libraries or modules it loads, which configuration
/// files it reads, or where its traffic and credentials go. `vl run` never
/// takes them from a team vault (BUG-520): otherwise any member of any
/// loaded scope would run code of their choosing, on every teammate's
/// machine, with the secrets of every other loaded scope in its
/// environment. Sources: the loader (`ld.so(8)`, `dyld(1)`), glibc's
/// unsecure-environment list, the shells' startup and prompt variables,
/// language runtimes' option and path variables, and the configuration,
/// proxy and CA overrides of common tools.
pub const EXECUTION_VARIABLES: &[&str] = &[
    // shells and the system
    "PATH", "CDPATH", "ENV", "BASH_ENV", "SHELL", "SHELLOPTS", "BASHOPTS", "IFS", "PS1", "PS2", "PS3", "PS4",
    "PROMPT_COMMAND", "BASH_XTRACEFD", "BASH_LOADABLES_PATH", "ZDOTDIR", "FPATH", "GLOBIGNORE", "INPUTRC",
    "HISTFILE", "HOME", "TMPDIR", "TMP", "TEMP", "EDITOR", "VISUAL", "PAGER", "MANPAGER", "BROWSER",
    "LESSOPEN", "LESSCLOSE", "SUDO_ASKPASS", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "SSH_AUTH_SOCK", "GNUPGHOME",
    // the loader and libc
    "LIBPATH", "SHLIB_PATH", "GCONV_PATH", "GLIBC_TUNABLES", "LOCPATH", "NLSPATH", "HOSTALIASES", "RES_OPTIONS",
    "LOCALDOMAIN", "MALLOC_TRACE",
    // language runtimes and build tools
    "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_REPL_EXTERNAL_MODULE",
    "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS",
    "JAVA_HOME", "CLASSPATH", "MAVEN_OPTS", "GRADLE_OPTS", "GRADLE_USER_HOME", "PHPRC", "PHP_INI_SCAN_DIR",
    "LUA_PATH", "LUA_CPATH", "LUA_INIT", "TCLLIBPATH", "GOFLAGS", "GOPATH", "GOROOT", "GOPROXY", "GOTOOLCHAIN",
    "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GOINSECURE", "GOENV", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "CC",
    "CXX", "CPP", "LD", "AR", "AS", "MAKE", "MAKEFLAGS", "MFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
    "PKG_CONFIG_PATH", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "UV_INDEX_URL",
    "UV_EXTRA_INDEX_URL", "UV_CONFIG_FILE",
    // where traffic goes, which certificates are trusted, which config is read
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "CURL_HOME", "WGETRC", "KUBECONFIG", "DOCKER_HOST", "DOCKER_CONFIG",
    "DOCKER_CONTEXT", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR",
];

/// Prefixes of [`EXECUTION_VARIABLES`] families (compared in upper case):
/// the dynamic loaders, Git (`GIT_SSH_COMMAND`, `GIT_EXEC_PATH`,
/// `GIT_CONFIG_*`), exported Bash functions, Python, Perl and Ruby options
/// and paths, npm configuration, the XDG configuration directories, Cargo's
/// build and runner settings, and vl's own (`VEIL_HOME` names the identity).
pub const EXECUTION_PREFIXES: &[&str] = &[
    "LD_", "DYLD_", "GIT_", "BASH_FUNC_", "PYTHON", "PERL", "RUBY", "NPM_CONFIG_", "XDG_", "CARGO_BUILD_",
    "CARGO_TARGET_", "VEIL_",
];

/// Does `name` decide what a command executes or loads (see
/// [`EXECUTION_VARIABLES`])? Such names may be stored in a team vault, but
/// `vl run` never sets them from one.
pub fn is_execution_variable(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    EXECUTION_VARIABLES.contains(&up.as_str()) || EXECUTION_PREFIXES.iter().any(|p| up.starts_with(p))
}

/// Largest total [`env_cost`] of a scope's live entries. `vl run` hands
/// them to a command in its environment, and `execve` refuses arguments and
/// environment over `ARG_MAX` together (2 MiB on a default Linux, 1 MiB on
/// macOS) with `E2BIG` (BUG-523). A write that would take the scope over
/// this is refused (one that shrinks it is not).
pub const MAX_SCOPE_ENV_BYTES: usize = 256 * 1024;

/// What an entry costs in a command's environment, as `execve` counts it:
/// `NAME=VALUE` and its NUL, plus the pointer to it.
pub fn env_cost(name: &str, value: &str) -> usize {
    name.len() + 1 + value.len() + 1 + std::mem::size_of::<usize>()
}

/// Check an entry value: no NUL (it becomes an environment variable), at
/// most [`MAX_VALUE_LEN`] bytes.
pub fn validate_value(value: &str) -> Result<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(VeilError::repo(format!(
            "secret value is {} bytes; the team vault holds at most {MAX_VALUE_LEN}",
            value.len()
        )));
    }
    if value.contains('\0') {
        return Err(VeilError::repo("secret value contains a NUL byte, which no environment variable can hold"));
    }
    Ok(())
}

fn scope_dir(scope: &str) -> Result<VPath> {
    validate_scope_name(scope)?;
    VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}"))
}

fn record_path(scope: &str, id: &str) -> Result<VPath> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(VeilError::NotFound(format!("vault record '{id}'")));
    }
    VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}/{id}.json"))
}

/// Read and decode one record file. `Err` describes what is wrong.
fn parse_record(scope: &str, id: &str, raw: &[u8]) -> std::result::Result<VaultRecord, String> {
    if raw.len() as u64 > MAX_RECORD_FILE {
        return Err(format!("{} bytes, more than a record can hold", raw.len()));
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) {
        if let Some(f) = v.get("format").and_then(|f| f.as_u64()) {
            if f > u64::from(RECORD_FORMAT) {
                return Err(format!("record format {f} needs a newer vl"));
            }
        }
    }
    let rec: VaultRecord = serde_json::from_slice(raw).map_err(|e| format!("cannot be parsed: {e}"))?;
    if rec.format != RECORD_FORMAT {
        return Err(format!("record format {}", rec.format));
    }
    if rec.scope != scope {
        return Err(format!("filed under scope '{scope}' but is for '{}'", rec.scope));
    }
    if rec.to_bytes() != raw {
        return Err("not in canonical form".into());
    }
    if rec.id() != id {
        return Err("its name is not its id".into());
    }
    Ok(rec)
}

/// The ids of the records of `scope` on `backend` (file names only, nothing
/// is read).
fn list_ids(backend: &dyn StorageBackend, scope: &str) -> Result<BTreeSet<String>> {
    let dir = scope_dir(scope)?;
    if !backend.exists(&dir)? {
        return Ok(BTreeSet::new());
    }
    Ok(backend
        .list_dir(&dir)?
        .into_iter()
        .filter(|e| e.kind == NodeKind::File)
        .filter_map(|e| e.name.strip_suffix(".json").map(str::to_string))
        .filter(|id| record_path(scope, id).is_ok())
        .collect())
}

/// Read one record by id: `Ok(None)` if absent, `Err` text if it is not a
/// readable record.
fn read_record(backend: &dyn StorageBackend, scope: &str, id: &str) -> Result<Option<std::result::Result<VaultRecord, String>>> {
    let path = record_path(scope, id)?;
    if backend.metadata(&path)?.is_some_and(|m| m.len > MAX_RECORD_FILE) {
        return Ok(Some(Err(format!("vault record {path}: too large"))));
    }
    Ok(backend
        .read_opt(&path)?
        .map(|raw| parse_record(scope, id, &raw).map_err(|why| format!("vault record {path}: {why}"))))
}

/// Every record of `scope` on `backend`, by id, plus a description of each
/// file that is not a readable record.
pub fn load_records(backend: &dyn StorageBackend, scope: &str) -> Result<(BTreeMap<String, VaultRecord>, Vec<String>)> {
    let dir = scope_dir(scope)?;
    let mut out = BTreeMap::new();
    let mut bad = Vec::new();
    if !backend.exists(&dir)? {
        return Ok((out, bad));
    }
    for e in backend.list_dir(&dir)? {
        if e.name.starts_with('.') && e.name.contains(".vltmp") {
            continue;
        }
        let Some(id) = e.name.strip_suffix(".json").filter(|_| e.kind == NodeKind::File) else {
            bad.push(format!("unexpected entry {TEAM_VAULT_DIR}/{scope}/{}", e.name));
            continue;
        };
        if record_path(scope, id).is_err() {
            bad.push(format!("unexpected entry {TEAM_VAULT_DIR}/{scope}/{}", e.name));
            continue;
        }
        match read_record(backend, scope, id)? {
            Some(Ok(r)) => {
                out.insert(id.to_string(), r);
            }
            Some(Err(why)) => bad.push(why),
            None => {}
        }
    }
    Ok((out, bad))
}

/// Scopes that have a team-vault directory on `backend`.
pub fn vault_scopes(backend: &dyn StorageBackend) -> Result<Vec<String>> {
    let dir = VPath::new(TEAM_VAULT_DIR)?;
    if !backend.exists(&dir)? {
        return Ok(vec![]);
    }
    Ok(backend
        .list_dir(&dir)?
        .into_iter()
        .filter(|e| e.kind == NodeKind::Dir && validate_scope_name(&e.name).is_ok())
        .map(|e| e.name)
        .collect())
}

/// How many records `backend` holds, over all scopes (for warnings about
/// public remotes).
pub fn record_count(backend: &dyn StorageBackend) -> Result<usize> {
    let mut n = 0;
    for s in vault_scopes(backend)? {
        n += backend.list_dir(&scope_dir(&s)?)?.len();
    }
    Ok(n)
}

/// One entry as the vault shows it: the winning write for its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// `None`: deleted.
    pub value: Option<String>,
    pub timestamp: i64,
    /// Member id of the writer.
    pub signer: String,
    /// Their name in the ring.
    pub signer_name: String,
    /// Generation the value is sealed under, and its key id.
    pub generation: u32,
    pub key_id: String,
    /// The generation under which this value was first sealed (see
    /// [`last_generation_held`]): it was readable to everyone who held that
    /// generation or a later one before the value changed.
    pub since: u32,
    /// The record's id.
    pub record: String,
    /// Sealed under a generation the scope had already moved on from when
    /// it was written (by its timestamp), by a writer whose key ring was
    /// stale, so a member revoked in between can read it (BUG-524). Set it
    /// again to re-seal it under the current generation (and rotate it at
    /// its source).
    pub stale_generation: bool,
}

/// A record that does not count, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub record: String,
    pub reason: IgnoredReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgnoredReason {
    /// Signed by someone who was a member of the scope and no longer is (or
    /// whose registered signing key changed): name from the ring.
    FormerMember(String),
    /// Signed by a key the scope's ring never registered.
    NotAMember,
    BadSignature,
    /// Names no generation of the ring.
    UnknownGeneration,
    /// The AEAD (or the payload) does not check out.
    Unreadable,
    /// The file is not a readable record (see the text).
    Malformed(String),
}

impl IgnoredReason {
    pub fn describe(&self) -> String {
        match self {
            IgnoredReason::FormerMember(n) => format!("written by {n}, no longer a member"),
            IgnoredReason::NotAMember => "signed by someone who was never a member".into(),
            IgnoredReason::BadSignature => "bad signature".into(),
            IgnoredReason::UnknownGeneration => "sealed under a key generation the scope's ring does not have".into(),
            IgnoredReason::Unreadable => "does not decrypt to a valid entry".into(),
            IgnoredReason::Malformed(w) => w.clone(),
        }
    }
}

/// The state of one scope's team vault, as this identity reads it.
#[derive(Clone, Debug, Default)]
pub struct TeamVault {
    /// Winning write per name, deletions included.
    pub entries: BTreeMap<String, Entry>,
    pub ignored: Vec<Ignored>,
}

impl TeamVault {
    /// Entries that hold a value (not deleted).
    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values().filter(|e| e.value.is_some())
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name).filter(|e| e.value.is_some())
    }
}

/// Checks that need no key: signature, generation, signer. `Ok` gives the
/// generation; `Err(FormerMember)` is a well-formed record of a former
/// member.
fn check_record(rec: &VaultRecord, state: &RingState) -> std::result::Result<u32, IgnoredReason> {
    if !rec.signature_valid() {
        return Err(IgnoredReason::BadSignature);
    }
    let Some(kid) = rec.key_id() else {
        return Err(IgnoredReason::UnknownGeneration);
    };
    let Some(generation) = state.generations.iter().position(|g| g == kid) else {
        return Err(IgnoredReason::UnknownGeneration);
    };
    let sig = &rec.signature;
    let current = state
        .members
        .get(&sig.signer)
        .is_some_and(|m| m.signing_key.as_deref() == Some(sig.key.as_str()));
    if !current {
        // A former member: the ring once registered this key for this
        // signer. Anything else (an unknown key, or a key claiming someone
        // else's member id) was never a member's write.
        return Err(match state.ever_signers.get(&sig.key) {
            Some((member, name)) if *member == sig.signer => IgnoredReason::FormerMember(name.clone()),
            _ => IgnoredReason::NotAMember,
        });
    }
    Ok(generation as u32)
}

/// Open a record with `keys` (any generation it can derive). `None` if it
/// has no key for the generation; `Some(Err)` if the record does not open
/// or holds an invalid entry.
/// An opened entry: name, value (`None`: deleted), first generation.
type Opened = (String, Option<String>, u32);

fn open_record(keys: &Keychain, rec: &VaultRecord) -> Option<std::result::Result<Opened, ()>> {
    let kid = rec.key_id()?;
    let key = Zeroizing::new(keys.key(&generation_label(&rec.scope, kid))?);
    let parsed = rec
        .sealed
        .open(&key)
        .ok()
        .map(Zeroizing::new)
        .and_then(|pt| serde_json::from_slice::<Payload>(&pt).ok())
        .filter(|p| readable_name(&p.name) && p.value.as_deref().is_none_or(|v| validate_value(v).is_ok()));
    Some(parsed.map(|p| (p.name, p.value, p.since)).ok_or(()))
}

/// Sort key of a write: greater wins.
fn rank<'a>(rec: &'a VaultRecord, id: &'a str) -> (i64, &'a str, &'a str) {
    (rec.timestamp, rec.signature.key.as_str(), id)
}

fn verified_state(keys: &Keychain, scope: &str) -> Result<(KeyRing, RingState)> {
    let ring = keys
        .load_ring(scope)?
        .ok_or_else(|| VeilError::NotFound(format!("scope '{scope}'")))?;
    let state = ring
        .verify()
        .map_err(|e| VeilError::repo(format!("the key ring of scope '{scope}' does not verify: {e}")))?;
    if state.legacy || ring.is_legacy() {
        return Err(VeilError::repo(format!(
            "scope '{scope}' still has an unsigned legacy key ring, which cannot say who may write its team vault; \
             an admin change (`vl scope rotate {scope}`) upgrades it"
        )));
    }
    Ok((ring, state))
}

/// When each generation of `ring` started: the timestamp of the change that
/// introduced it (index = generation; the genesis change for 0).
fn generation_starts(ring: &KeyRing) -> BTreeMap<u32, i64> {
    let mut out = BTreeMap::new();
    for c in &ring.log {
        let g = match &c.op {
            RingOp::Genesis { .. } => 0,
            RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => rotation.generation,
            RingOp::Grant { .. } | RingOp::Share { .. } | RingOp::Invite { .. } | RingOp::Uninvite { .. } => continue,
        };
        out.entry(g).or_insert(c.timestamp);
    }
    out
}

/// Every member id `ring` ever listed (genesis and grants).
fn ever_members(ring: &KeyRing) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for c in &ring.log {
        match &c.op {
            RingOp::Genesis { members, .. } => out.extend(members.iter().map(|m| m.id.clone())),
            RingOp::Grant { member } | RingOp::Share { member, .. } => {
                out.insert(member.id.clone());
            }
            _ => {}
        }
    }
    out
}

/// What decides whether a record was sealed under a stale generation
/// ([`Entry::stale_generation`]).
pub(crate) struct Staleness {
    current: u32,
    starts: BTreeMap<u32, i64>,
    /// The last generation each former member held.
    former: Vec<u32>,
}

impl Staleness {
    pub(crate) fn new(ring: &KeyRing, state: &RingState) -> Staleness {
        let former = ever_members(ring)
            .into_iter()
            .filter(|m| !state.members.contains_key(m))
            .filter_map(|m| last_generation_held(ring, state, &m))
            .collect();
        Staleness {
            current: state.generation,
            starts: generation_starts(ring),
            former,
        }
    }

    /// Was a record sealed under `generation` at `timestamp` written after
    /// the scope had moved past `generation`, and is it readable by a
    /// former member who could not have read a record sealed at that time
    /// under the generation then current? Timestamps are self-asserted:
    /// this flags an honest writer whose ring was stale, not a member who
    /// backdates a record on purpose (they could hand the value over
    /// directly anyway).
    /// Was a record sealed under `generation` stamped after the next
    /// generation started (written with a ring that had not caught up)?
    pub(crate) fn written_late(&self, generation: u32, timestamp: i64) -> bool {
        self.starts.get(&(generation + 1)).is_some_and(|start| timestamp > *start)
    }

    pub(crate) fn stale(&self, generation: u32, timestamp: i64) -> bool {
        if generation >= self.current {
            return false;
        }
        // The generation current when the record says it was written.
        let then = self
            .starts
            .iter()
            .filter(|(_, t)| **t <= timestamp)
            .map(|(g, _)| *g)
            .max()
            .unwrap_or(0);
        then > generation && self.former.iter().any(|last| generation <= *last && *last < then)
    }
}

/// The vault of `scope` read from `backend` with `keys` (rings and keys).
fn read_vault(keys: &Keychain, backend: &dyn StorageBackend, scope: &str, ring: &KeyRing, state: &RingState) -> Result<TeamVault> {
    let staleness = Staleness::new(ring, state);
    let (records, bad) = load_records(backend, scope)?;
    let mut out = TeamVault {
        ignored: bad
            .into_iter()
            .map(|w| Ignored {
                record: String::new(),
                reason: IgnoredReason::Malformed(w),
            })
            .collect(),
        ..Default::default()
    };
    let mut best: BTreeMap<String, (&str, &VaultRecord, u32, Option<String>, u32)> = BTreeMap::new();
    let mut former = Vec::new();
    for (id, rec) in &records {
        let generation = match check_record(rec, state) {
            Ok(g) => g,
            Err(reason @ IgnoredReason::FormerMember(_)) => {
                former.push((id.as_str(), rec, reason));
                continue;
            }
            Err(reason) => {
                out.ignored.push(Ignored { record: id.clone(), reason });
                continue;
            }
        };
        let (name, value, since) = match open_record(keys, rec) {
            Some(Ok(nv)) => nv,
            _ => {
                out.ignored.push(Ignored {
                    record: id.clone(),
                    reason: IgnoredReason::Unreadable,
                });
                continue;
            }
        };
        let better = best.get(&name).is_none_or(|(bid, brec, ..)| rank(rec, id) > rank(brec, bid));
        if better {
            best.insert(name, (id.as_str(), rec, generation, value, since.min(generation)));
        }
    }
    // A former member's write is worth reporting only where it would have
    // won: one that a counting write outranks changed nothing.
    for (id, rec, reason) in former {
        let outranked = match open_record(keys, rec) {
            Some(Ok((name, ..))) => best.get(&name).is_some_and(|(bid, brec, ..)| rank(brec, bid) > rank(rec, id)),
            _ => false,
        };
        if !outranked {
            out.ignored.push(Ignored {
                record: id.to_string(),
                reason,
            });
        }
    }
    for (name, (id, rec, generation, value, since)) in best {
        let signer_name = state
            .members
            .get(&rec.signature.signer)
            .map_or_else(String::new, |m| m.name.clone());
        out.entries.insert(
            name.clone(),
            Entry {
                name,
                value,
                timestamp: rec.timestamp,
                signer: rec.signature.signer.clone(),
                signer_name,
                generation,
                since,
                key_id: state.generations[generation as usize].clone(),
                record: id.to_string(),
                stale_generation: staleness.stale(generation, rec.timestamp),
            },
        );
    }
    Ok(out)
}

/// Delete, on `backend`, every record superseded by a newer record of the
/// same signer for the same name (both well signed and opened with
/// `keys`). Never changes what the vault holds (module documentation).
/// Returns how many records were deleted.
pub(crate) fn compact(keys: &Keychain, backend: &dyn StorageBackend, scope: &str) -> Result<usize> {
    let (records, _) = load_records(backend, scope)?;
    // (name, signer id, signing key) → newest (rank, id)
    type Newest<'a> = BTreeMap<(String, &'a str, &'a str), ((i64, &'a str, &'a str), &'a str)>;
    let mut newest: Newest = BTreeMap::new();
    let mut opened = Vec::new();
    for (id, rec) in &records {
        if !rec.signature_valid() {
            continue;
        }
        let Some(Ok((name, ..))) = open_record(keys, rec) else { continue };
        let k = (name, rec.signature.signer.as_str(), rec.signature.key.as_str());
        let r = rank(rec, id);
        if newest.get(&k).is_none_or(|(br, _)| r > *br) {
            newest.insert(k.clone(), (r, id.as_str()));
        }
        opened.push((k, id.as_str()));
    }
    let mut removed = 0;
    for (k, id) in opened {
        if newest.get(&k).is_some_and(|(_, keep)| *keep != id) {
            backend.remove_file(&record_path(scope, id)?)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The last key generation `member` (a member id) received in `ring`:
/// the current one while they are a member. `None` if they never were.
/// Every generation up to it is readable to them (each rotation carries
/// the previous key).
pub fn last_generation_held(ring: &KeyRing, state: &RingState, member: &str) -> Option<u32> {
    if state.members.contains_key(member) {
        return Some(state.generation);
    }
    let mut last = None;
    for c in &ring.log {
        let g = match &c.op {
            RingOp::Genesis { members, .. } => members.iter().any(|m| m.id == member).then_some(0),
            RingOp::Grant { member: m } | RingOp::Share { member: m, .. } => (m.id == member).then_some(m.generation),
            RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => {
                rotation.wrapped.contains_key(member).then_some(rotation.generation)
            }
            RingOp::Invite { .. } | RingOp::Uninvite { .. } => None,
        };
        if g.is_some() {
            last = last.max(g);
        }
    }
    last
}

/// Find a member (current or former) of `ring` by public key, member id or
/// name. Returns `(member id, name)`.
pub fn resolve_member(ring: &KeyRing, state: &RingState, who: &str) -> Result<(String, String)> {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for c in &ring.log {
        match &c.op {
            RingOp::Genesis { members, .. } => names.extend(members.iter().map(|m| (m.id.clone(), m.name.clone()))),
            RingOp::Grant { member } | RingOp::Share { member, .. } => {
                names.insert(member.id.clone(), member.name.clone());
            }
            _ => {}
        }
    }
    for (id, m) in &state.members {
        names.insert(id.clone(), m.name.clone());
    }
    if let Ok(pk) = parse_public_key(who) {
        let id = format_public_key(&pk);
        return match names.get(&id) {
            Some(n) => Ok((id, n.clone())),
            None => Err(VeilError::NotFound(format!("{id} was never a member of scope '{}'", ring.scope))),
        };
    }
    let found: Vec<(&String, &String)> = names.iter().filter(|(_, n)| n.as_str() == who).collect();
    match found.as_slice() {
        [(id, n)] => Ok(((*id).clone(), (*n).clone())),
        [] => Err(VeilError::NotFound(format!("no member named '{who}' in scope '{}'", ring.scope))),
        _ => Err(VeilError::repo(format!(
            "{} members of scope '{}' are named '{who}'; give the public key instead",
            found.len(),
            ring.scope
        ))),
    }
}

/// What [`Keychain::team_secret_write`] replaced.
#[derive(Clone, Debug, Default)]
pub struct WriteOutcome {
    /// The entry before the write (a deletion included).
    pub previous: Option<Entry>,
    /// The new record's id.
    pub record: String,
    /// What the writer should be told: earlier writes of theirs this one
    /// replaced (stamped too far ahead), a value revoked members could read.
    pub notes: Vec<String>,
}

/// What [`Keychain::revoke_with_vault`] found.
#[derive(Clone, Debug, Default)]
pub struct RevokeReport {
    /// Live entries the revoked member could read: rotate them.
    pub exposed: Vec<String>,
    /// Entries whose current version the revoked member wrote, re-signed by
    /// this identity under the new generation so they do not vanish.
    pub adopted: Vec<String>,
    /// Set when the vault could not be read or adopted (the revocation
    /// itself happened).
    pub warning: Option<String>,
}

// ---- the value history (device-local) ---------------------------------------

/// Where this device remembers, per scope, a keyed hash of every value each
/// name held and the first generation it was sealed under (BUG-521):
/// `<dir>/<scope>.json`. Compaction deletes superseded records, so without
/// it a name set back to a value a revoked member read (after a rotation,
/// or a deletion) would no longer count as exposed. Never synced; what it
/// learns travels in the `since` of the records this device writes.
pub const HISTORY_DIR: &str = ".veil/local/vault-history";
/// Values remembered per name; beyond it, those first sealed under the
/// latest generations are forgotten first.
const HISTORY_PER_NAME: usize = 256;

#[derive(Default, Serialize, Deserialize)]
struct HistoryFile {
    /// Keyed hash of a name → keyed hash of a value → the first generation
    /// it was sealed under. Names are hashed too: like the records, the
    /// file holds neither names nor values.
    #[serde(default)]
    names: BTreeMap<String, BTreeMap<String, u32>>,
}

/// The value history of one scope, open for reading and noting.
struct History {
    key: [u8; 32],
    scope: String,
    data: HistoryFile,
    dirty: bool,
}

impl History {
    /// `None` without an identity (nothing to key the hashes with).
    fn open(keys: &Keychain, scope: &str) -> Result<Option<History>> {
        let Some(local) = keys.key(domains::LOCAL_LABEL).map(Zeroizing::new) else {
            return Ok(None);
        };
        let key = blake3::derive_key(domains::TEAM_VAULT_HISTORY, &*local);
        let data = keys
            .backend()
            .read_opt(&history_path(scope)?)?
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        Ok(Some(History {
            key,
            scope: scope.to_string(),
            data,
            dirty: false,
        }))
    }

    fn mac(&self, name: &str, value: Option<&str>) -> String {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&[u8::from(value.is_some())]);
        for part in [self.scope.as_str(), name, value.unwrap_or_default()] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
        h.finalize().to_hex()[..32].to_string()
    }

    /// The first generation `value` of `name` is known to have been sealed
    /// under.
    fn since(&self, name: &str, value: &str) -> Option<u32> {
        self.data.names.get(&self.mac(name, None))?.get(&self.mac(name, Some(value))).copied()
    }

    fn note(&mut self, name: &str, value: &str, since: u32) {
        let mac = self.mac(name, Some(value));
        let values = self.data.names.entry(self.mac(name, None)).or_default();
        let slot = values.entry(mac).or_insert(u32::MAX);
        if since < *slot {
            *slot = since;
            self.dirty = true;
        }
        while values.len() > HISTORY_PER_NAME {
            let latest = values.iter().max_by_key(|(_, g)| **g).map(|(m, _)| m.clone()).expect("not empty");
            values.remove(&latest);
        }
    }

    /// Note every value of the opened, well-signed records of `records`
    /// that names a generation of `state`.
    fn note_records<'a>(&mut self, keys: &Keychain, state: &RingState, records: impl Iterator<Item = &'a VaultRecord>) {
        for rec in records {
            let Some(generation) = record_generation(rec, state).filter(|_| rec.signature_valid()) else { continue };
            if let Some(Ok((name, Some(value), since))) = open_record(keys, rec) {
                self.note(&name, &value, since.min(generation));
            }
        }
    }

    fn save(&self, keys: &Keychain) -> Result<()> {
        if self.dirty {
            keys.backend()
                .write(&history_path(&self.scope)?, &serde_json::to_vec(&self.data)?)?;
        }
        Ok(())
    }
}

fn history_path(scope: &str) -> Result<VPath> {
    validate_scope_name(scope)?;
    VPath::new(&format!("{HISTORY_DIR}/{scope}.json"))
}

/// The generation a record's label names in `state`.
fn record_generation(rec: &VaultRecord, state: &RingState) -> Option<u32> {
    let kid = rec.key_id()?;
    state.generations.iter().position(|g| g == kid).map(|g| g as u32)
}

/// `ms` as a short duration ("2 days", "5 hours").
fn human_ms(ms: i64) -> String {
    let h = ms / 3_600_000;
    if h >= 48 {
        format!("{} days", h / 24)
    } else if h >= 1 {
        format!("{h} hours")
    } else {
        format!("{} minutes", (ms / 60_000).max(1))
    }
}

impl Keychain {
    /// The team vault of `scope`, for a current member.
    pub fn team_vault(&self, scope: &str) -> Result<TeamVault> {
        let (ring, state) = verified_state(self, scope)?;
        if !self.is_member(scope) {
            return Err(VeilError::repo(format!(
                "you are not a member of scope '{scope}', so you cannot read its team vault"
            )));
        }
        read_vault(self, &**self.backend(), scope, &ring, &state)
    }

    /// The live secrets of `scope` (name → value), for `vl run`.
    pub fn team_secrets(&self, scope: &str) -> Result<BTreeMap<String, String>> {
        Ok(self
            .team_vault(scope)?
            .entries
            .into_values()
            .filter_map(|e| Some((e.name, e.value?)))
            .collect())
    }

    /// Scopes that have a team-vault directory here.
    pub fn team_vault_scopes(&self) -> Result<Vec<String>> {
        vault_scopes(&**self.backend())
    }

    /// Scopes this identity is a current member of (whether or not their
    /// vault holds anything).
    pub fn member_scopes(&self) -> Result<Vec<String>> {
        Ok(self
            .rings()?
            .into_iter()
            .map(|r| r.scope)
            .filter(|s| self.is_member(s))
            .collect())
    }

    /// Set (`Some`) or delete (`None`) the entry `name` of `scope`'s team
    /// vault: a new record sealed under the current generation and signed
    /// by this identity, which must be a current member with its signing
    /// key registered. Deleting a name that holds no value is `NotFound`.
    ///
    /// The name must be a shell identifier, and the scope's live entries
    /// must stay within [`MAX_SCOPE_ENV_BYTES`]. Earlier writes of the same
    /// name by this identity stamped more than [`MAX_CLOCK_SKEW_MS`] ahead
    /// (a clock that was wrong) are deleted and replaced by this one, which
    /// is stamped by the clock (BUG-522); a winning write of someone else's
    /// that far ahead is an error. A value this device saw before keeps the
    /// generation it was first sealed under (`since`, BUG-521).
    pub fn team_secret_write(&self, scope: &str, name: &str, value: Option<&str>) -> Result<WriteOutcome> {
        let _lock = self.lock_meta()?;
        validate_name(name)?;
        if let Some(v) = value {
            validate_value(v)?;
        }
        let (ring, state) = verified_state(self, scope)?;
        let me = self
            .identity()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))?;
        let my_id = me.public_hex();
        let my_key = me.verifying_hex();
        match state.members.get(&my_id) {
            None => {
                return Err(VeilError::repo(format!(
                    "you are not a member of scope '{scope}', so you cannot write its team vault"
                )))
            }
            Some(m) if m.signing_key.as_deref() != Some(my_key.as_str()) => {
                return Err(VeilError::repo(format!(
                    "scope '{scope}' does not register your signing key (you were granted with the short member id, \
                     or before your identity changed), so teammates would ignore your writes; ask an admin to grant \
                     the full key from `vl identity show` again"
                )))
            }
            Some(_) => {}
        }
        let backend = &**self.backend();
        let now = crate::now_millis();
        let ahead = now.saturating_add(MAX_CLOCK_SKEW_MS);
        let mut notes = Vec::new();
        let (records, _) = load_records(backend, scope)?;
        let mut history = History::open(self, scope)?;
        if let Some(h) = history.as_mut() {
            h.note_records(self, &state, records.values());
        }
        // BUG-522: this identity's own writes of `name` stamped beyond the
        // skew window. Teammates refuse them, and they would pin every
        // later write (stamped after them) out of the window too.
        let mut replaced = Vec::new();
        for (id, rec) in &records {
            if rec.timestamp > ahead && rec.signature.signer == my_id && rec.signature.key == my_key && rec.signature_valid() {
                if let Some(Ok((n, ..))) = open_record(self, rec) {
                    if n == name {
                        replaced.push((id.clone(), rec.timestamp));
                    }
                }
            }
        }
        if let Some(furthest) = replaced.iter().map(|(_, t)| *t).max() {
            for (id, _) in &replaced {
                backend.remove_file(&record_path(scope, id)?)?;
            }
            notes.push(format!(
                "{} earlier write(s) of {name} by you were stamped up to {} ahead of this device's clock (was the \
                 clock wrong?); teammates refuse such records, so this write replaces them",
                replaced.len(),
                human_ms(furthest - now)
            ));
        }
        let vault = read_vault(self, backend, scope, &ring, &state)?;
        let previous = vault.entries.get(name).cloned();
        if value.is_none() && previous.as_ref().is_none_or(|p| p.value.is_none()) {
            return Err(VeilError::NotFound(format!("secret '{name}' in the team vault of scope '{scope}'")));
        }
        if let Some(p) = previous.as_ref().filter(|p| p.timestamp > ahead) {
            return Err(VeilError::repo(format!(
                "the current write of {name} in scope '{scope}' (by {}) is stamped {} ahead of this device's clock, \
                 so no write made now would win over it, and teammates refuse records that far ahead; check this \
                 device's clock, and ask {} to check theirs",
                p.signer_name,
                human_ms(p.timestamp - now),
                p.signer_name
            )));
        }
        if let Some(v) = value {
            let cost = |e: &Entry| env_cost(&e.name, e.value.as_deref().unwrap_or_default());
            let before: usize = vault.live().map(cost).sum();
            let after = before - vault.get(name).map_or(0, cost) + env_cost(name, v);
            if after > MAX_SCOPE_ENV_BYTES && after > before {
                return Err(VeilError::repo(format!(
                    "the team vault of scope '{scope}' would hold {} KiB, more than the {} KiB a scope may hold: \
                     `vl run` passes every entry to a command in its environment, which the system limits to about \
                     1 to 2 MiB in all, arguments included. Store large values (certificates, key files) as cloaked \
                     files instead, or remove entries no longer needed",
                    after.div_ceil(1024),
                    MAX_SCOPE_ENV_BYTES / 1024
                )));
            }
        }
        let floor = previous.as_ref().map_or(i64::MIN, |p| p.timestamp.saturating_add(1));
        // The same value written again keeps its first generation, whether
        // it is the current one or one this device saw earlier.
        let mut since = state.generation;
        if let Some(v) = value {
            if let Some(p) = previous.as_ref().filter(|p| p.value.as_deref() == Some(v)) {
                since = since.min(p.since);
            }
            if let Some(s) = history.as_ref().and_then(|h| h.since(name, v)) {
                since = since.min(s);
            }
            let staleness = Staleness::new(&ring, &state);
            if staleness.former.iter().any(|last| since <= *last) {
                notes.push(format!(
                    "this value of {name} was first sealed under key generation {since}, which a member revoked \
                     since holds: `vl secret list --scope {scope} --exposed-to <them>` keeps listing it until it \
                     holds a new value"
                ));
            }
        }
        let record = self.write_record(scope, name, value, since, now.max(floor))?;
        if let (Some(h), Some(v)) = (history.as_mut(), value) {
            h.note(name, v, since);
        }
        if let Some(h) = &history {
            h.save(self)?;
        }
        compact(self, backend, scope)?;
        Ok(WriteOutcome { previous, record, notes })
    }

    fn write_record(&self, scope: &str, name: &str, value: Option<&str>, since: u32, timestamp: i64) -> Result<String> {
        let me = self
            .identity()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))?;
        let rec = VaultRecord::seal(self, me, scope, name, value, since, timestamp)?;
        let id = rec.id();
        self.backend().write(&record_path(scope, &id)?, &rec.to_bytes())?;
        Ok(id)
    }

    /// Live entries of `scope` that `member` (public key, member id or
    /// name; current or former) could read: those whose value was sealed
    /// under a generation they held, by the record's `since` or by what
    /// this device remembers of the value (BUG-521). For a current member,
    /// all of them.
    pub fn team_vault_exposed_to(&self, scope: &str, member: &str) -> Result<(String, String, Vec<Entry>)> {
        let (ring, state) = verified_state(self, scope)?;
        let (id, name) = resolve_member(&ring, &state, member)?;
        let vault = self.team_vault(scope)?;
        let history = History::open(self, scope)?;
        let last = last_generation_held(&ring, &state, &id);
        let exposed = vault
            .live()
            .filter(|e| {
                let remembered = history.as_ref().and_then(|h| h.since(&e.name, e.value.as_deref().unwrap_or_default()));
                last.is_some_and(|g| e.since.min(remembered.unwrap_or(u32::MAX)) <= g)
            })
            .cloned()
            .collect();
        Ok((id, name, exposed))
    }

    /// Revoke `public_key` from `scope` ([`Keychain::revoke`]) and report
    /// the team-vault entries they could read. Entries whose current version
    /// they wrote are re-signed by this identity (sealed under the new
    /// generation), so they do not vanish when the revoked member's writes
    /// stop counting. `Ok(None)`: not a member, nothing changed.
    pub fn revoke_with_vault(&self, scope: &str, public_key: &str) -> Result<Option<RevokeReport>> {
        let _lock = self.lock_meta()?;
        let member = format_public_key(&parse_public_key(public_key)?);
        let before = self.team_vault(scope).ok();
        if let Ok((_, state)) = verified_state(self, scope) {
            if let Some(mut h) = History::open(self, scope)? {
                h.note_records(self, &state, load_records(&**self.backend(), scope)?.0.values());
                h.save(self)?;
            }
        }
        if !self.revoke(scope, public_key)? {
            return Ok(None);
        }
        let mut report = RevokeReport::default();
        let Some(before) = before else {
            report.warning = Some(format!(
                "the team vault of scope '{scope}' could not be read; check it with `vl secret list --scope {scope} \
                 --exposed-to {member}`"
            ));
            return Ok(Some(report));
        };
        let mut adopt_failed = Vec::new();
        for e in before.entries.values().filter(|e| e.signer == member) {
            let ts = crate::now_millis().max(e.timestamp.saturating_add(1));
            match self.write_record(scope, &e.name, e.value.as_deref(), e.since, ts) {
                Ok(_) if e.value.is_some() => report.adopted.push(e.name.clone()),
                Ok(_) => {}
                Err(err) => adopt_failed.push(format!("{} ({err})", e.name)),
            }
        }
        if !adopt_failed.is_empty() {
            report.warning = Some(format!(
                "could not re-sign the entries the revoked member wrote: {}; set them again with `vl secret set --scope {scope}`",
                adopt_failed.join(", ")
            ));
        }
        compact(self, &**self.backend(), scope)?;
        let (ring, state) = verified_state(self, scope)?;
        let last = last_generation_held(&ring, &state, &member);
        // Their pre-revocation view: every live entry sealed under a
        // generation they held (all of them, before the revocation).
        report.exposed = before
            .live()
            .filter(|e| last.is_some_and(|g| e.since <= g))
            .map(|e| e.name.clone())
            .collect();
        Ok(Some(report))
    }
}

/// Copy the team-vault records of `src` that `dst` lacks into `dst`, for
/// every scope (team remotes only; `crate::remote::sync_meta`). Each
/// record is checked against `dst`'s ring (already merged): a record with a
/// bad signature, an unknown generation, a signer who was never a member,
/// a timestamp more than [`MAX_CLOCK_SKEW_MS`] ahead, or (where `local`
/// can open it) content that does not decrypt to a valid entry, is not
/// copied, and both push and pull say so (BUG-522). Records of former
/// members are copied but do not count (reported on pull). Then `dst` is
/// compacted with `local`'s keys. `local` is the keychain with this
/// identity (the source on push, the destination on pull).
///
/// Stale key generations (BUG-524): on push, a record of this identity's
/// sealed under a generation older than the current one of `dst`'s ring,
/// and stamped after the next generation started (written before this
/// device had pulled a rotation), is not sent as it is. This device's ring is fast-forwarded to `dst`'s, the entry is
/// re-sealed under the current generation (same name, value and `since`,
/// stamped one millisecond later, so it replaces the old record), and the
/// push says so. Any other record that was sealed under a generation after
/// the scope had moved on, readable by a member revoked in between
/// ([`Staleness`]), is copied and reported by name, to be set again.
///
/// On push, this identity's own records on `dst` stamped beyond the skew
/// window that this device no longer holds (replaced by a later write,
/// [`Keychain::team_secret_write`]) are deleted from `dst`, so they cannot
/// win over later writes once their time comes.
pub(crate) fn sync(src: &Keychain, dst: &Keychain, local: &Keychain, pulling: bool, warnings: &mut Vec<String>) -> Result<()> {
    let now = crate::now_millis();
    let ahead = now.saturating_add(MAX_CLOCK_SKEW_MS);
    let src_backend = &**src.backend();
    let dst_backend = &**dst.backend();
    let me = local.identity().map(|i| (i.public_hex(), i.verifying_hex()));
    let mine = |rec: &VaultRecord| {
        me.as_ref()
            .is_some_and(|(id, key)| rec.signature.signer == *id && rec.signature.key == *key && rec.signature_valid())
    };
    for scope in vault_scopes(src_backend)? {
        let have = list_ids(dst_backend, &scope)?;
        let src_ids = list_ids(src_backend, &scope)?;
        if !pulling {
            defuse_future_records(local, dst_backend, &scope, &have, &src_ids, ahead, &mine, warnings)?;
        }
        let mut incoming = Vec::new();
        let mut problems: BTreeMap<String, usize> = BTreeMap::new();
        for id in src_ids.difference(&have) {
            match read_record(src_backend, &scope, id)? {
                Some(Ok(rec)) => incoming.push((id.clone(), rec)),
                Some(Err(_)) => *problems.entry("not copied (not a readable record)".into()).or_default() += 1,
                None => {}
            }
        }
        let flush = |problems: BTreeMap<String, usize>, warnings: &mut Vec<String>| {
            for (why, n) in problems {
                warnings.push(format!("team vault of scope '{scope}': {n} record(s) {why}"));
            }
        };
        if incoming.is_empty() {
            flush(problems, warnings);
            continue;
        }
        let (ring, state) = match verified_state(dst, &scope) {
            Ok(rs) => rs,
            Err(e) => {
                warnings.push(format!(
                    "team vault of scope '{scope}': {} record(s) not copied: {e}",
                    incoming.len()
                ));
                continue;
            }
        };
        let staleness = Staleness::new(&ring, &state);
        let mut history = match pulling && local.is_member(&scope) {
            true => History::open(local, &scope)?,
            false => None,
        };
        let mut copied = 0usize;
        let mut reseal = Vec::new();
        let mut late: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        let mut late_unnamed = 0usize;
        for (id, rec) in &incoming {
            let checked = check_record(rec, &state);
            let verdict = match &checked {
                Ok(_) | Err(IgnoredReason::FormerMember(_)) if rec.timestamp > ahead || rec.timestamp < 0 => Err(if rec.timestamp < 0 {
                    "timestamp out of range".to_string()
                } else {
                    "timestamp out of range: stamped more than a day ahead of this device's clock; check the clock \
                     of whoever wrote them"
                        .to_string()
                }),
                Ok(_) => match open_record(local, rec) {
                    Some(Err(())) => Err(IgnoredReason::Unreadable.describe()),
                    _ => Ok(None),
                },
                Err(IgnoredReason::FormerMember(n)) => match open_record(local, rec) {
                    Some(Err(())) => Err(IgnoredReason::Unreadable.describe()),
                    _ => Ok(Some(IgnoredReason::FormerMember(n.clone()).describe())),
                },
                Err(r) => Err(r.describe()),
            };
            let note = match verdict {
                Ok(note) => note,
                Err(why) => {
                    *problems.entry(format!("not copied ({why})")).or_default() += 1;
                    continue;
                }
            };
            let generation = record_generation(rec, &state).unwrap_or_default();
            // Records written before the scope moved on (pushed to a new
            // remote, say) are sent as they are.
            if !pulling && checked.is_ok() && mine(rec) && generation < state.generation && staleness.written_late(generation, rec.timestamp) {
                reseal.push(rec.clone());
                continue;
            }
            dst_backend.write(&record_path(&scope, id)?, &rec.to_bytes())?;
            copied += 1;
            if let Some(n) = note.filter(|_| pulling) {
                *problems.entry(format!("kept but ignored ({n})")).or_default() += 1;
            }
            let opened = open_record(local, rec);
            if let (Some(h), Some(Ok((name, Some(value), since)))) = (history.as_mut(), &opened) {
                h.note(name, value, (*since).min(generation));
            }
            if checked.is_ok() && staleness.stale(generation, rec.timestamp) {
                match opened {
                    Some(Ok((name, ..))) => late.entry(generation).or_default().push(name),
                    _ => late_unnamed += 1,
                }
            }
        }
        if !reseal.is_empty() {
            copied += reseal_for_push(local, dst_backend, &scope, &ring, state.generation, &reseal, warnings)?;
        }
        for (g, mut names) in late {
            names.sort();
            names.dedup();
            warnings.push(format!(
                "team vault of scope '{scope}': {} secret(s) were sealed under key generation {g} after the scope had \
                 moved past it (written by a teammate whose key ring was out of date), so members revoked in between \
                 can read them: {}. Set each again with `vl secret set --scope {scope} NAME` to re-seal it, and \
                 rotate it at its source",
                names.len(),
                names.join(", ")
            ));
        }
        if late_unnamed > 0 {
            warnings.push(format!(
                "team vault of scope '{scope}': {late_unnamed} record(s) were sealed under a key generation after the \
                 scope had moved past it, so members revoked in between can read them; a member should set them again"
            ));
        }
        flush(problems, warnings);
        if let Some(h) = &history {
            h.save(local)?;
        }
        if copied > 0 && local.is_member(&scope) {
            compact(local, dst_backend, &scope)?;
        }
    }
    Ok(())
}

/// BUG-524, on push: re-seal `stale` (records of this identity sealed
/// under a generation older than `current`) under the current generation of
/// `ring` (the destination's), on this device and on `dst`. Returns how many
/// records were written to `dst`.
fn reseal_for_push(
    local: &Keychain,
    dst: &dyn StorageBackend,
    scope: &str,
    ring: &KeyRing,
    current: u32,
    stale: &[VaultRecord],
    warnings: &mut Vec<String>,
) -> Result<usize> {
    let Some(me) = local.identity() else { return Ok(0) };
    // As a pull would: fast-forward this device's ring, so the current
    // generation's key is at hand (and later writes use it).
    if let crate::keychain::RingMerge::Rejected(w) = local.merge_ring(ring)? {
        warnings.push(format!(
            "team vault of scope '{scope}': {} record(s) you wrote under an old key generation not pushed: {w}",
            stale.len()
        ));
        return Ok(0);
    }
    local.invalidate();
    let mut names = Vec::new();
    let mut old = BTreeSet::new();
    for rec in stale {
        let Some(Ok((name, value, since))) = open_record(local, rec) else { continue };
        let new = VaultRecord::seal(local, me, scope, &name, value.as_deref(), since, rec.timestamp.saturating_add(1))?;
        local.backend().write(&new.path()?, &new.to_bytes())?;
        dst.write(&new.path()?, &new.to_bytes())?;
        if let Some(kid) = rec.key_id() {
            old.insert(kid.to_string());
        }
        names.push(name);
    }
    compact(local, &**local.backend(), scope)?;
    if !names.is_empty() {
        names.sort();
        names.dedup();
        warnings.push(format!(
            "team vault of scope '{scope}': you wrote {} secret(s) under an old key generation, before this device had \
             pulled the scope's move to generation {current}: {}. They were re-sealed under generation {current} before \
             being sent, so members revoked in between do not get them from this push (your key ring is updated too)",
            names.len(),
            names.join(", ")
        ));
    }
    Ok(names.len())
}

/// BUG-522, on push: delete from `dst` this identity's records stamped
/// beyond `ahead` that `src` no longer holds, for names `src` holds a later
/// write of this identity's for (it replaced them,
/// [`Keychain::team_secret_write`]).
#[allow(clippy::too_many_arguments)]
fn defuse_future_records(
    local: &Keychain,
    dst: &dyn StorageBackend,
    scope: &str,
    have: &BTreeSet<String>,
    src_ids: &BTreeSet<String>,
    ahead: i64,
    mine: &dyn Fn(&VaultRecord) -> bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut future = Vec::new();
    for id in have.difference(src_ids) {
        if let Some(Ok(rec)) = read_record(dst, scope, id)? {
            if rec.timestamp > ahead && mine(&rec) {
                if let Some(Ok((name, ..))) = open_record(local, &rec) {
                    future.push((id.clone(), name));
                }
            }
        }
    }
    if future.is_empty() {
        return Ok(());
    }
    let (records, _) = load_records(&**local.backend(), scope)?;
    let written: BTreeSet<String> = records
        .values()
        .filter(|r| mine(r) && r.timestamp <= ahead)
        .filter_map(|r| match open_record(local, r) {
            Some(Ok((name, ..))) => Some(name),
            _ => None,
        })
        .collect();
    let mut removed = 0;
    for (id, name) in future {
        if written.contains(&name) {
            dst.remove_file(&record_path(scope, &id)?)?;
            removed += 1;
        }
    }
    if removed > 0 {
        warnings.push(format!(
            "team vault of scope '{scope}': removed {removed} of your own record(s) stamped more than a day ahead from \
             the remote (later writes replaced them), so they cannot win over newer values once their time comes"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Suite;

    fn fixed_record() -> VaultRecord {
        VaultRecord {
            format: 1,
            scope: "team".into(),
            sealed: Envelope {
                scope: "vault:team#0011223344556677".into(),
                suite: Suite::XChaCha20Poly1305 { nonce: [7; 24] },
                ciphertext: vec![1, 2, 3],
            },
            timestamp: 1_700_000_000_000,
            signature: Signature {
                signer: "veil1aa".into(),
                key: "bb".into(),
                sig: "cc".into(),
            },
        }
    }

    /// The signed body and the file encoding are fixed (FORMAT.md §2):
    /// changing either breaks every record already written.
    #[test]
    fn signing_body_and_encoding_never_change() {
        let r = fixed_record();
        assert_eq!(
            String::from_utf8(r.signing_body()).unwrap(),
            r#"{"format":1,"scope":"team","sealed":{"scope":"vault:team#0011223344556677","nonce":"070707070707070707070707070707070707070707070707","ciphertext":"010203"},"timestamp":1700000000000,"signer":"veil1aa"}"#
        );
        assert_eq!(
            String::from_utf8(r.to_bytes()).unwrap(),
            r#"{"format":1,"scope":"team","sealed":{"scope":"vault:team#0011223344556677","nonce":"070707070707070707070707070707070707070707070707","ciphertext":"010203"},"timestamp":1700000000000,"signature":{"signer":"veil1aa","key":"bb","sig":"cc"}}"#
        );
        assert_eq!(r.key_id(), Some("0011223344556677"));
        assert_eq!(parse_record("team", &r.id(), &r.to_bytes()).unwrap(), r);
    }

    #[test]
    fn labels_must_name_this_scope_and_a_generation() {
        let mut r = fixed_record();
        for bad in ["team#0011", "vault:ops#0011", "vault:team", "vault:team#", "embargo/x"] {
            r.sealed.scope = bad.into();
            assert_eq!(r.key_id(), None, "{bad}");
        }
    }

    #[test]
    fn unknown_fields_and_wrong_files_are_refused() {
        let r = fixed_record();
        let id = r.id();
        let mut v: serde_json::Value = serde_json::from_slice(&r.to_bytes()).unwrap();
        v["extra"] = 1.into();
        assert!(parse_record("team", &id, &serde_json::to_vec(&v).unwrap()).is_err());
        assert!(parse_record("ops", &id, &r.to_bytes()).is_err());
        assert!(parse_record("team", &"0".repeat(64), &r.to_bytes()).is_err());
        assert!(record_path("team", "../../x").is_err());
        assert!(record_path("team", &"A".repeat(64)).is_err());
        assert!(scope_dir("../keyrings").is_err());
    }

    #[test]
    fn name_rules() {
        for ok in ["A", "_x", "STRIPE_LIVE_KEY", "a_b_9"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        // New writes take shell identifiers only (BUG-520); records written
        // before with '.' or '-' are still read.
        for bad in ["", "9A", "-a", "a b", "a=b", "a/b", "é", "a.b-c_9", "A\0B"] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
        assert!(readable_name("a.b-c_9") && !readable_name("a=b"));
    }

    #[test]
    fn execution_variables_are_recognised() {
        for v in ["PATH", "path", "BASH_ENV", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONPATH",
            "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT", "JAVA_TOOL_OPTIONS", "GIT_SSH_COMMAND", "SHELL", "IFS", "HOME",
            "TMPDIR", "ENV", "PROMPT_COMMAND", "KUBECONFIG", "HTTPS_PROXY", "https_proxy", "VEIL_HOME", "XDG_CONFIG_HOME",
            "NPM_CONFIG_USERCONFIG", "GCONV_PATH"]
        {
            assert!(is_execution_variable(v), "{v}");
        }
        for v in ["DATABASE_URL", "STRIPE_LIVE_KEY", "NPM_TOKEN", "GITHUB_TOKEN", "NODE_ENV", "PATHNAME", "AWS_SECRET_ACCESS_KEY"] {
            assert!(!is_execution_variable(v), "{v}");
        }
    }

    #[test]
    fn staleness_needs_a_revoked_holder_who_missed_the_newer_generation() {
        let st = Staleness {
            current: 2,
            starts: [(0, 0), (1, 100), (2, 200)].into_iter().collect(),
            former: vec![0],
        };
        assert!(st.stale(0, 150), "after generation 1 started, readable by the member revoked at 1");
        assert!(!st.stale(0, 50), "written while generation 0 was current");
        assert!(!st.stale(1, 250), "the former member never held generation 1");
        assert!(!st.stale(2, 250), "current generation");
        let plain_rotation = Staleness { former: vec![], ..st };
        assert!(!plain_rotation.stale(0, 150), "nobody revoked: nobody new can read it");
    }
}
