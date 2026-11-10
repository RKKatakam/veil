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

    /// A transaction that lost a serialisation race (PostgreSQL and
    /// YugabyteDB report 40001; deadlocks 40P01): run it again.
    pub fn is_retryable(&self) -> bool {
        let Error::Db(e) = self else { return false };
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
        Error::Other(e)
    }
}

impl From<veil_core::VeilError> for Error {
    fn from(e: veil_core::VeilError) -> Error {
        match e {
            veil_core::VeilError::Policy(m) => Error::forbidden(m),
            veil_core::VeilError::Corrupt(_, m) => Error::bad_request(format!("invalid object: {m}")),
            veil_core::VeilError::Missing(id) => Error::bad_request(format!("missing object {}", id.short())),
            other => Error::Other(other.into()),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Error::Api { status, code, message } => (status, code, message),
            // Every connection busy: the caller may try again.
            Error::Db(sqlx::Error::PoolTimedOut) => {
                eprintln!("veil-server: no database connection free");
                return Error::busy().into_response();
            }
            // Lost a race, outside a transaction: `db::retry_requests` runs
            // the request again, or answers "busy" at its deadline.
            e @ Error::Db(_) if e.is_retryable() => {
                let mut r = Error::busy().into_response();
                r.extensions_mut().insert(crate::db::Retryable);
                return r;
            }
            // Internal details go to the server's log, not to the caller.
            Error::Db(e) => {
                let code = e.as_database_error().and_then(|d| d.code().map(|c| c.into_owned())).unwrap_or_default();
                eprintln!("veil-server: database error [{code}]: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".to_string())
            }
            // No share of the server's bound on pack indexes came free in
            // time (BUG-1496, BUG-1622): the caller may try again.
            Error::Other(e) if crate::pack::indexes_full(&e) => {
                eprintln!("veil-server: {e:#}");
                return crate::limits::refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "busy",
                    &e.to_string(),
                    Some(crate::limits::shed_wait()),
                    false,
                );
            }
            Error::Other(e) => {
                eprintln!("veil-server: error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".to_string())
            }
        };
        if status == StatusCode::SERVICE_UNAVAILABLE && code == "busy" {
            return crate::limits::refuse(status, code, &message, Some(crate::limits::shed_wait()), false);
        }
        (status, Json(ErrorBody { code: code.into(), message })).into_response()
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
}
