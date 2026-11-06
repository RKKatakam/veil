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
mod concurrency;
mod escalation;
mod leaks;
mod sync;
mod adversarial;
mod derived;
mod startup;
