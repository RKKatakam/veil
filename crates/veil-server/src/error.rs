//! API errors: an HTTP status, a stable code and a message. Messages never
//! name anything the caller may not see (`docs/VISIBILITY.md`).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use veil_core::hub::wire::ErrorBody;

#[derive(Debug)]
pub enum Error {
    Api { status: StatusCode, code: &'static str, message: String },
    Db(sqlx::Error),
    Other(anyhow::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Error {
        Error::Api {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn unauthorized(m: impl Into<String>) -> Error {
        Error::new(StatusCode::UNAUTHORIZED, "unauthorized", m)
    }
    pub fn forbidden(m: impl Into<String>) -> Error {
        Error::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    /// Also what someone without access gets for something that exists.
    pub fn not_found(m: impl Into<String>) -> Error {
        Error::new(StatusCode::NOT_FOUND, "not_found", m)
    }
    pub fn bad_request(m: impl Into<String>) -> Error {
        Error::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }
    /// A transaction could not finish within its deadline (contention).
    pub fn busy() -> Error {
        Error::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "the database is busy (a transaction kept losing races or waiting); try again",
        )
    }
    pub fn conflict(m: impl Into<String>) -> Error {
        Error::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn rate_limited(m: impl Into<String>, _retry_after_ms: u64) -> Error {
        Error::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", m)
    }

    /// A transaction that lost a serialisation race (PostgreSQL and
    /// YugabyteDB report 40001; deadlocks 40P01): run it again.
    /// A database error that reached here through `anyhow` (the object
    /// store's statements, `pack::Packs` and `store::Objects`) is judged as
    /// one (BUG-2340: their lost races answered "internal error").
    pub fn is_retryable(&self) -> bool {
        let e = match self {
            Error::Db(e) => e,
            Error::Other(e) => {
                if caused_by::<RetryableDb>(e) {
                    return true;
                }
                match find_cause::<sqlx::Error>(e) {
                    Some(e) => e,
                    None => return false,
                }
            }
            Error::Api { .. } => return false,
        };
        match e.as_database_error() {
            Some(d) => {
                // Serialisation failure, deadlock, lock or statement
                // timeout; on YugabyteDB, a read to restart, a catalog
                // changed by DDL (BUG-838) or a stalled tablet RPC (BUG-890;
                // never run again after a commit, `db::transaction`).
                let m = d.message();
                matches!(d.code().as_deref(), Some("40001" | "40P01" | "55P03" | "57014"))
                    || is_rpc_timeout(m)
                    || m.contains("Restart read required")
                    || m.contains("Try again")
                    || m.contains("catalog snapshot")
                    || m.contains("catalog version")
                    || m.contains("schema version mismatch")
            }
            None => false,
        }
    }

    /// Classify and log `self` once, returning a cheap-to-clone [`Answer`]
    /// shared across waiters (blame jobs, viewer-graph fills: BUG-2680).
    pub fn answer(self) -> Answer {
        const BUSY_DB: &str = "the database is busy (a transaction kept losing races or waiting); try again";
        match self {
            Error::Api { status, code, message } => Answer { status, code, message, retry: Retry::None },
            // Every connection busy: the caller may try again.
            Error::Db(sqlx::Error::PoolTimedOut) => {
                eprintln!("veil-server: no database connection free");
                Answer { status: StatusCode::SERVICE_UNAVAILABLE, code: "busy", message: BUSY_DB.into(), retry: Retry::None }
            }
            // Lost a race, outside a transaction: `db::retry_requests` runs
            // the request again, or answers "busy" at its deadline.
            e @ Error::Db(_) if e.is_retryable() => {
                Answer { status: StatusCode::SERVICE_UNAVAILABLE, code: "busy", message: BUSY_DB.into(), retry: Retry::Db }
            }
            // Internal details go to the server's log, not to the caller.
            Error::Db(e) => {
                let code = e.as_database_error().and_then(|d| d.code().map(|c| c.into_owned())).unwrap_or_default();
                eprintln!("veil-server: database error [{code}]: {e}");
                Answer { status: StatusCode::INTERNAL_SERVER_ERROR, code: "internal", message: "internal error".into(), retry: Retry::None }
            }
            // No share of the server's bound on pack indexes came free in
            // time (BUG-1496, BUG-1622): the caller may try again.
            Error::Other(e) if crate::pack::indexes_full(&e) => {
                eprintln!("veil-server: {e:#}");
                Answer { status: StatusCode::SERVICE_UNAVAILABLE, code: "busy", message: crate::pack::IndexesFull.to_string(), retry: Retry::None }
            }
            // The object store stayed busy (429, 503) or unreachable for all
            // of its retries (BUG-2430: a MinIO restarting under load gave
            // clients "internal error"): the caller may try again.
            Error::Other(e) if crate::error::caused_by::<crate::store::StoreUnavailable>(&e) => {
                eprintln!("veil-server: {e:#}");
                Answer {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    code: "busy",
                    message: "the object store is busy; try again".into(),
                    retry: Retry::None,
                }
            }
            Error::Other(e) if crate::error::caused_by::<crate::sync::StagedUploadDiscarded>(&e) => Answer {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message: crate::sync::DISCARDED_UPLOAD.into(),
                retry: Retry::None,
            },
            // A lost race of the object store's statements (BUG-2340), as
            // any other: run again, or "busy" at the deadline.
            e @ Error::Other(_) if e.is_retryable() => {
                Answer { status: StatusCode::SERVICE_UNAVAILABLE, code: "busy", message: BUSY_DB.into(), retry: Retry::Db }
            }
            Error::Other(e) => {
                eprintln!("veil-server: error: {e:#}");
                Answer { status: StatusCode::INTERNAL_SERVER_ERROR, code: "internal", message: "internal error".into(), retry: Retry::None }
            }
        }
    }

    /// Carry `self` across a [`veil_core::VeilError`] boundary (`Trees::node`)
    /// so `From<VeilError> for Error` recovers the original [`Error`].
    pub(crate) fn into_veil(self) -> veil_core::VeilError {
        veil_core::VeilError::Io {
            path: "query".into(),
            source: std::io::Error::other(CarriedError(self)),
        }
    }

    /// Map [`veil_core::VeilError`] from validating or decoding an object a
    /// client uploaded or named in a write (`upload`, `push`, `changes`);
    /// server-side reads of already-stored objects convert through `From`,
    /// which treats `Missing` and `Corrupt` as `500 internal` (BUG-2681).
    pub(crate) fn client_object(e: veil_core::VeilError) -> Error {
        match e {
            veil_core::VeilError::Corrupt(_, m) => Error::bad_request(format!("invalid object: {m}")),
            veil_core::VeilError::Missing(id) => Error::bad_request(format!("missing object {}", id.short())),
            other => Error::from(other),
        }
    }
}

/// How [`Answer`] participates in server-side retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    None,
    /// A retryable database error (`Error::is_retryable`).
    Db,
}

/// The client-safe HTTP answer of an [`Error`] after logging internal detail
/// once (BUG-2680): cheap to clone across waiters on a shared job or fill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub retry: Retry,
}

impl Answer {
    pub fn into_error(self) -> Error {
        match self.retry {
            Retry::None => Error::Api {
                status: self.status,
                code: self.code,
                message: self.message,
            },
            Retry::Db => Error::Other(anyhow::Error::new(RetryableDb)),
        }
    }
}

impl IntoResponse for Answer {
    fn into_response(self) -> Response {
        let Answer { status, code, message, retry } = self;
        let mut resp = if status == StatusCode::SERVICE_UNAVAILABLE && code == "busy" {
            crate::limits::refuse(status, code, &message, Some(crate::limits::shed_wait()), false)
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            let mut r = (
                status,
                Json(serde_json::json!({
                    "code": code,
                    "message": message,
                    "retry_after_ms": 1_000u64,
                })),
            )
                .into_response();
            r.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
            r
        } else {
            (status, Json(ErrorBody { code: code.into(), message })).into_response()
        };
        if retry != Retry::None {
            resp.extensions_mut().insert(crate::db::Retryable);
        }
        resp
    }
}

#[derive(Debug)]
struct RetryableDb;

impl std::fmt::Display for RetryableDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("retryable database contention")
    }
}

impl std::error::Error for RetryableDb {}

#[derive(Debug)]
struct CarriedError(Error);

impl std::fmt::Display for CarriedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("carried server error")
    }
}

impl std::error::Error for CarriedError {}

#[derive(Debug)]
pub(crate) struct AnyhowCause(pub anyhow::Error);

impl std::fmt::Display for AnyhowCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for AnyhowCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Find a `T` in `e` or what it wraps (an I/O error's inner chain included).
pub fn find_cause<T: std::error::Error + 'static>(e: &anyhow::Error) -> Option<&T> {
    e.chain().find_map(|c| {
        c.downcast_ref::<T>().or_else(|| {
            c.downcast_ref::<std::io::Error>().and_then(|io| io.get_ref()).and_then(|i| {
                let mut cur: &(dyn std::error::Error + 'static) = i;
                loop {
                    if let Some(t) = cur.downcast_ref::<T>() {
                        return Some(t);
                    }
                    if let Some(a) = cur.downcast_ref::<AnyhowCause>() {
                        if let Some(t) = find_cause::<T>(&a.0) {
                            return Some(t);
                        }
                    }
                    cur = cur.source()?;
                }
            })
        })
    })
}

/// Is `e`, or what it wraps (an I/O error's inner chain included), a `T`?
/// A store's errors reach a route through `anyhow` and, from a body being
/// read, inside an I/O error.
pub fn caused_by<T: std::error::Error + 'static>(e: &anyhow::Error) -> bool {
    find_cause::<T>(e).is_some()
}

/// YugabyteDB's `XX000 … Rpc timeout`: a tablet RPC that did not answer in
/// time. Before a commit nothing took effect; on the commit itself the
/// outcome is unknown.
pub fn is_rpc_timeout(message: &str) -> bool {
    message.contains("Rpc timeout")
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Error {
        Error::Db(e)
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Error {
        if caused_by::<crate::sync::StagedUploadDiscarded>(&e) {
            return Error::conflict(crate::sync::DISCARDED_UPLOAD);
        }
        Error::Other(e)
    }
}

impl From<veil_core::VeilError> for Error {
    fn from(e: veil_core::VeilError) -> Error {
        match e {
            veil_core::VeilError::Policy(m) => Error::forbidden(m),
            veil_core::VeilError::Io { source, .. } if source.get_ref().is_some_and(|i| i.is::<CarriedError>()) => {
                source.into_inner().unwrap().downcast::<CarriedError>().unwrap().0
            }
            veil_core::VeilError::Io { source, .. } if crate::sync::staged_upload_discarded(&source) => {
                Error::conflict(crate::sync::DISCARDED_UPLOAD)
            }
            // Server-side reads and decodes of stored objects go through `?`:
            // `Missing` and `Corrupt` here are server storage faults (logged,
            // 500 internal, naming no object id: BUG-2681). Client uploads use
            // `Error::client_object`.
            other => Error::Other(other.into()),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.answer().into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database error with YugabyteDB's code and message.
    #[derive(Debug)]
    struct YbError(&'static str);
    impl std::fmt::Display for YbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for YbError {}
    impl sqlx::error::DatabaseError for YbError {
        fn message(&self) -> &str {
            self.0
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some("XX000".into())
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// BUG-890: a stalled tablet RPC is run again; other internal errors are not.
    #[test]
    fn bug_890_a_yugabytedb_rpc_timeout_is_retryable() {
        let db = |m| Error::Db(sqlx::Error::Database(Box::new(YbError(m))));
        assert!(db("Timed out: Perform RPC (request call id 81) to 127.0.0.1:9100 timed out after 15.000s; Rpc timeout, passed: 15.0s, timeout: 15.000s").is_retryable());
        assert!(!db("internal error: tablet not found").is_retryable());
    }

    /// BUG-2340: a database error through `anyhow` (the object store's
    /// statements), with context or not, is judged as one; a commit whose
    /// outcome is unknown (`db::transaction`) is never run again.
    #[test]
    fn bug_2340_a_database_error_through_anyhow_is_judged_as_one() {
        const RPC: &str = "Timed out: Perform RPC (request call id 81) to 127.0.0.1:9100 timed out after 15.000s; Rpc timeout";
        let sqlx_err = |m| sqlx::Error::Database(Box::new(YbError(m)));
        assert!(Error::Other(anyhow::Error::from(sqlx_err(RPC))).is_retryable());
        assert!(Error::Other(anyhow::Error::from(sqlx_err(RPC)).context("1 of 2 packs")).is_retryable());
        assert!(!Error::Other(anyhow::Error::from(sqlx_err("internal error: tablet not found"))).is_retryable());
        assert!(!Error::Other(anyhow::anyhow!("the commit timed out; its outcome is unknown: {}", sqlx_err(RPC))).is_retryable());
        assert!(!Error::busy().is_retryable());
    }

    /// BUG-2680: `Error::answer` masks internal detail, preserves retryable
    /// and busy classifications, and round-trips through `Answer::into_error`.
    #[test]
    fn bug_2680_answer_round_trips_every_error_kind_without_leaking_detail() {
        let internal = Error::Other(anyhow::anyhow!("CANARY-INTERNAL-2680")).answer();
        assert_eq!(
            internal,
            Answer {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal",
                message: "internal error".into(),
                retry: Retry::None,
            }
        );

        let store = Error::Other(crate::store::StoreUnavailable::new("S3 503 CANARY").into()).answer();
        assert_eq!(store.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(store.code, "busy");
        assert_eq!(store.message, "the object store is busy; try again");
        assert_eq!(store.retry, Retry::None);

        let wrapped_idx = Error::from(veil_core::VeilError::Io {
            path: "object store".into(),
            source: std::io::Error::other(AnyhowCause(
                anyhow::Error::new(crate::pack::IndexesFull).context("CANARY-INDEXES-CONTEXT-2680"),
            )),
        })
        .answer();
        assert_eq!(wrapped_idx.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(wrapped_idx.code, "busy");
        assert_eq!(wrapped_idx.message, crate::pack::IndexesFull.to_string());
        assert_eq!(wrapped_idx.retry, Retry::None);

        const RPC: &str = "Timed out; Rpc timeout";
        let db_ans = Error::Db(sqlx::Error::Database(Box::new(YbError(RPC)))).answer();
        assert_eq!(db_ans.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(db_ans.code, "busy");
        assert_eq!(db_ans.retry, Retry::Db);
        let db_err = db_ans.clone().into_error();
        assert!(db_err.is_retryable());
        assert!(db_ans.into_response().extensions().get::<crate::db::Retryable>().is_some());

        let deadline = Error::new(StatusCode::SERVICE_UNAVAILABLE, "deadline", "too slow");
        match Error::from(deadline.into_veil()) {
            Error::Api { status, code, message } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(code, "deadline");
                assert_eq!(message, "too slow");
            }
            other => panic!("expected Error::Api deadline, got {other:?}"),
        }
    }

    /// BUG-2681: `VeilError::Missing` and `VeilError::Corrupt` default through
    /// `From` to `500 internal` without object ids, while `Error::client_object`
    /// preserves the `400 bad_request` answers for client uploads and writes.
    #[test]
    fn bug_2681_stored_veil_errors_default_to_internal_while_client_object_maps_to_400() {
        let id = veil_core::ObjectId::hash(b"hidden-stored-object");
        for stored in [
            Error::from(veil_core::VeilError::Missing(id)).answer(),
            Error::from(veil_core::VeilError::Corrupt(id.hex(), "bad header".into())).answer(),
        ] {
            assert_eq!(stored.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(stored.code, "internal");
            assert_eq!(stored.message, "internal error");
            assert!(!stored.message.contains(&id.short()));
        }

        let client_missing = Error::client_object(veil_core::VeilError::Missing(id)).answer();
        assert_eq!(client_missing.status, StatusCode::BAD_REQUEST);
        assert_eq!(client_missing.code, "bad_request");
        assert_eq!(client_missing.message, format!("missing object {}", id.short()));

        let client_corrupt = Error::client_object(veil_core::VeilError::Corrupt(id.hex(), "bad tree".into())).answer();
        assert_eq!(client_corrupt.status, StatusCode::BAD_REQUEST);
        assert_eq!(client_corrupt.code, "bad_request");
        assert_eq!(client_corrupt.message, "invalid object: bad tree");
    }

    /// BUG-2661 + BUG-2681: a vanished staged upload (`staged_gone`) answers
    /// `409 conflict` through `From<VeilError>`, `Error::client_object`, and
    /// `anyhow` chains, never `500` or `400`.
    #[test]
    fn bug_2661_staged_upload_discarded_answers_409_under_both_from_and_client_object() {
        for err in [
            Error::from(crate::sync::staged_gone()),
            Error::client_object(crate::sync::staged_gone()),
            Error::from(anyhow::Error::from(crate::sync::staged_gone()).context("push")),
            Error::Other(anyhow::Error::from(crate::sync::staged_gone())),
        ] {
            let ans = err.answer();
            assert_eq!(ans.status, StatusCode::CONFLICT);
            assert_eq!(ans.code, "conflict");
            assert_eq!(ans.message, crate::sync::DISCARDED_UPLOAD);
            assert_eq!(ans.retry, Retry::None);
        }
    }
}
