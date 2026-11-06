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
                // timeout; on YugabyteDB, a read to restart or a catalog
                // changed by DDL (BUG-838).
                let m = d.message();
                matches!(d.code().as_deref(), Some("40001" | "40P01" | "55P03" | "57014"))
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
            Error::Other(e) => {
                eprintln!("veil-server: error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error".to_string())
            }
        };
        (status, Json(ErrorBody { code: code.into(), message })).into_response()
    }
}
