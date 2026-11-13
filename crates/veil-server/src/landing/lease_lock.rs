//! The landing lease's liveness lock (BUG-1970, cause 2; `docs/HUB.md`
//! §13.32 item 13).
//!
//! A branch's lease (`landing_leases`) is taken over when it expires,
//! `LEASE_MS` after its holder last renewed it; after a crash that alone
//! paused landings more than 2 s. So the holder of a lease at epoch `e`
//! also holds a **session** advisory lock keyed by the branch and `e`, on a
//! connection of its own (`Session`) that it takes before the lease (so
//! a lease row whose `lock_epoch` is its `epoch` always had its lock
//! first). When the holder's process dies its connections close and the database frees the
//! lock at once (by hand: under 15 ms on PostgreSQL 17, under 150 ms on
//! YugabyteDB 2025.2); another server that finds the lease unexpired but
//! its lock free knows its holder is gone and takes the lease at the next
//! epoch then, by a compare-and-swap on `e`. Nothing else changes: the
//! commit transaction's fencing on the epoch is what keeps a holder that
//! lost its lease from landing, whichever way it lost it.
//!
//! * A holder never locks its epoch's key again, so a key found free stays
//!   free: what was taken over is exactly the epoch whose lock was free.
//! * A holder is taken over before its lease expires only if its lock
//!   session ended: its process died, or the database ended that session
//!   (a dropped connection, a partition the database noticed). A live
//!   holder whose session ended is fenced as one whose lease expired is.
//! * A machine that vanishes sends nothing: the database keeps its session
//!   (and lock) until TCP keepalive gives up, with the tightest settings
//!   about 2 s, no sooner than the lease's expiry, so that case is still
//!   the lease's.
//! * The probe (`take_lease`) takes the lock and lets it go in one
//!   statement, on any connection: nothing is kept by whoever looked.
//! * A lease taken without the lock (the session could not be opened, its
//!   key held by another session: a take in progress, two branches' keys
//!   alike; a server of an older release, a row written otherwise) has no
//!   `lock_epoch` equal to its epoch and is only ever taken over on expiry.

use sqlx::{Connection, PgConnection, PgPool};

/// The lease lock's key: the branch's (a hash) and the epoch's low 31 bits.
/// Two-integer advisory keys are a space apart from every one-`bigint` key
/// the server takes (derive, pack GC, migrations, the review gate).
pub(super) fn key(project: i64, branch: &str, epoch: i64) -> (i32, i32) {
    (branch_key(project, branch), epoch_key(epoch))
}

/// The branch's half of the key: stable across releases and processes
/// (a hash that changed would take every live holder's lease over).
pub(super) fn branch_key(project: i64, branch: &str) -> i32 {
    let mut h = blake3::Hasher::new();
    h.update(b"veil landing lease lock\0");
    h.update(&project.to_le_bytes());
    h.update(branch.as_bytes());
    i32::from_le_bytes(h.finalize().as_bytes()[..4].try_into().expect("4 bytes"))
}

/// The epoch's half of the key; SQL computes the same: `(epoch & 2147483647)::int4`.
fn epoch_key(epoch: i64) -> i32 {
    (epoch & 0x7fff_ffff) as i32
}

/// This server's connection that holds the locks of the leases it holds.
pub(crate) struct Session {
    conn: tokio::sync::Mutex<Option<PgConnection>>,
    /// Its `application_name`: `APPLICATION_NAME` and the lease holder.
    name: String,
}

/// The lock session's `application_name`, before the holder's name.
pub const APPLICATION_NAME: &str = "veil-landing-leases";

impl Session {
    pub(super) fn new(holder: &str) -> Session {
        Session { conn: Default::default(), name: format!("{APPLICATION_NAME} {holder}") }
    }

    /// Take the lock of `epoch` of the branch's lease, without waiting:
    /// whether it is held now. A failed statement closes the session (its
    /// locks go with it, and the leases they kept may be taken over).
    pub(super) async fn lock(&self, db: &PgPool, project: i64, branch: &str, epoch: i64) -> bool {
        self.run(db, "SELECT pg_try_advisory_lock($1, $2)", key(project, branch, epoch)).await
    }

    /// Let the lock of `epoch` go (the lease is given up or was lost).
    pub(super) async fn unlock(&self, db: &PgPool, project: i64, branch: &str, epoch: i64) {
        self.run(db, "SELECT pg_advisory_unlock($1, $2)", key(project, branch, epoch)).await;
    }

    async fn run(&self, db: &PgPool, sql: &str, (k1, k2): (i32, i32)) -> bool {
        let mut s = self.conn.lock().await;
        // Bounded: a session that hangs (a network gone quiet) must not hold
        // up every take of this server; it is dropped, and with it whatever
        // it held, which leaves those leases to their expiry at worst.
        let r = tokio::time::timeout(SESSION_WAIT, async {
            if s.is_none() {
                let opts = (*db.connect_options()).clone().application_name(&self.name);
                *s = Some(PgConnection::connect_with(&opts).await?);
            }
            sqlx::query_scalar::<_, bool>(sql).bind(k1).bind(k2).fetch_one(s.as_mut().expect("opened")).await
        })
        .await;
        match r {
            Ok(Ok(v)) => v,
            failed => {
                eprintln!("veil-server: the landing leases' lock session failed: {failed:?}");
                // Dropped, not closed: closing waits on the connection.
                *s = None;
                false
            }
        }
    }
}

/// Most a lock session's statement (or its opening) takes: as long as a
/// statement waits for a lock (`db::LOCK_TIMEOUT`). Its statements never
/// wait, so only a database or a network in trouble reaches it, and a
/// session dropped frees every lock it held: this server's leases are then
/// taken over as if it had stopped (and fenced).
const SESSION_WAIT: std::time::Duration = crate::db::LOCK_TIMEOUT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_and_per_branch_and_epoch() {
        // A key that changed between releases would make every server of
        // one release take over the live leases of the other's.
        assert_eq!(key(7, "main", 3), (branch_key(7, "main"), 3));
        assert_eq!(branch_key(7, "main"), branch_key(7, "main"));
        assert_ne!(branch_key(7, "main"), branch_key(8, "main"));
        assert_ne!(branch_key(7, "main"), branch_key(7, "dev"));
        assert_eq!(epoch_key(1 << 31), 0);
        assert_eq!(epoch_key((1 << 31) + 5), 5);
        assert_eq!(epoch_key(i64::MAX), i32::MAX);
        // Pinned: every release computes the same key.
        assert_eq!(branch_key(7, "main"), 397_569_646);
    }
}
