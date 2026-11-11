//! The Veil server's tests against real databases and object storage, in
//! Docker containers started by `scripts/verify-server.sh`:
//!
//! * `VEIL_TEST_DATABASE_URL`: PostgreSQL or YugabyteDB;
//! * `VEIL_TEST_S3_ENDPOINT` (+ `_BUCKET`, `_KEY`, `_SECRET`): MinIO; without
//!   it, objects go to a temporary directory;
//! * `VEIL_TEST_VL`: the `vl` binary.
//!
//! Built only with `--features containers`, so `verify-fast.sh` (no
//! Docker) never runs them.
#![cfg(feature = "containers")]

mod support;

mod auth;
mod changes;
mod concurrency;
mod escalation;
mod leaks;
mod sync;
mod adversarial;
mod secrets2;
mod adversarial_s2;
mod adversarial_s10;
mod projects;
mod shares;
mod derived;
mod query;
mod blame;
mod search;
mod startup;
mod grants;
mod caches;
mod adversarial_s4;
mod landing;
mod prs;
mod thin;
mod cache;
mod agents;
mod daemon;
mod limits;
mod packs;
mod workspaces;
mod ci;
mod embargo;
mod embargo_prs;
mod bisect;
mod pack_gc;
mod phase2_review;
mod web;
mod rv_access;
