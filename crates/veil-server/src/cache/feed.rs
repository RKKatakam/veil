//! The server's side of the regional caches: `POST /v1/cache/epochs`, the
//! access-epoch feed they poll (`docs/HUB.md` §13.18).
//!
//! A cache serves an object under a read grant only while the grant's two
//! epochs (its project's, and the person's of the device it names) are the
//! current ones (`veil_core::hub::grant`). It learns them here, about once a
//! second, for every project and device whose grants it has seen: the
//! answer holds each one's current epoch, the same values
//! `grant::Grants::current` reads for the server's own check, and leaves out
//! a project that does not exist and a device that is removed or not yet
//! confirmed, which voids their grants alike. It also names the grant key.
//!
//! **Only the server's own caches may ask** (they are inside its trust
//! boundary, `phase-2-thin-clients.md` §6): the request carries the token in
//! `<data>/hub-cache-token` (made at the first start, 0600), which the
//! operator gives each cache. Epochs are random values compared only for
//! equality (BUG-1081), but they still tell who had an access change, so
//! nobody else reads them for other people: a person's session reads only
//! their own (`GET /v1/epochs`).

use std::collections::BTreeMap;

use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    HubState,
};

/// The header that carries the caches' token.
pub const TOKEN_HEADER: &str = "veil-cache-token";
/// Most keys (projects and devices together) one request names; a cache
/// with more asks in several requests.
pub const FEED_KEYS: usize = 50_000;

/// `POST /v1/cache/epochs`: the keys whose epochs the cache relies on.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedRequest {
    /// Project names, as grants name them.
    #[serde(default)]
    pub projects: Vec<String>,
    /// Devices' Ed25519 keys (hex), as grants name them.
    #[serde(default)]
    pub devices: Vec<String>,
}

/// The answer: each project's epoch, and each device's person's epoch. A
/// key left out has no grant that holds (no such project; a device removed
/// or pending).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FeedAnswer {
    /// The server's grant key (hex).
    pub grant_key: String,
    pub projects: BTreeMap<String, i64>,
    pub devices: BTreeMap<String, i64>,
}

/// Load or create the caches' token in `data_dir` (`hub-cache-token`, 32
/// random bytes in hex, 0600); its hash. Servers sharing the data directory
/// accept the same token.
pub fn load_token(data_dir: &std::path::Path) -> anyhow::Result<blake3::Hash> {
    let path = data_dir.join("hub-cache-token");
    if !path.exists() {
        let _ = crate::tls::write_private(&path, hex::encode(veil_core::crypto::random_bytes::<32>()).as_bytes());
    }
    let token = std::fs::read_to_string(&path)?;
    let token = token.trim();
    anyhow::ensure!(token.len() >= 32, "hub-cache-token must hold at least 32 characters");
    Ok(blake3::hash(token.as_bytes()))
}

/// `POST /v1/cache/epochs` (the caches' token only): the current epochs of
/// the projects and devices named. Two statements of index lookups,
/// whatever the number of keys.
pub async fn epochs(State(hub): State<HubState>, headers: HeaderMap, body: Bytes) -> Result<Json<FeedAnswer>> {
    // `blake3::Hash` compares in constant time.
    let token = headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()).map(|t| blake3::hash(t.trim().as_bytes()));
    if token != Some(hub.cache_token) {
        return Err(Error::unauthorized("this route is for the server's regional caches"));
    }
    let req: FeedRequest = serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("invalid feed request: {e}")))?;
    if req.projects.len() + req.devices.len() > FEED_KEYS {
        return Err(Error::bad_request(format!("at most {FEED_KEYS} keys per request")));
    }
    let projects: Vec<(String, i64)> = sqlx::query_as(
        "SELECT p.name, COALESCE(e.epoch, 0) FROM projects p \
         LEFT JOIN access_epochs e ON e.project_id = p.id AND e.person_id = 0 WHERE p.name = ANY($1)",
    )
    .bind(&req.projects)
    .fetch_all(&hub.db)
    .await?;
    let devices: Vec<(String, i64)> = sqlx::query_as(
        "SELECT d.signing_key, COALESCE(e.epoch, 0) FROM devices d \
         LEFT JOIN access_epochs e ON e.project_id = 0 AND e.person_id = d.person_id \
         WHERE d.signing_key = ANY($1) AND d.removed_at IS NULL AND NOT d.pending",
    )
    .bind(&req.devices)
    .fetch_all(&hub.db)
    .await?;
    Ok(Json(FeedAnswer {
        grant_key: hub.grants.key_hex().to_string(),
        projects: projects.into_iter().collect(),
        devices: devices.into_iter().collect(),
    }))
}
