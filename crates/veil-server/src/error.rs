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
    pub fn conflict(m: impl Into<String>) -> Error {
        Error::new(StatusCode::CONFLICT, "conflict", m)
    }

    /// A transaction that lost a serialisation race (PostgreSQL and
    /// YugabyteDB report 40001; deadlocks 40P01): run it again.
    pub fn is_retryable(&self) -> bool {
        let Error::Db(e) = self else { return false };
        match e.as_database_error() {
            Some(d) => {
                matches!(d.code().as_deref(), Some("40001" | "40P01"))
                    || d.message().contains("Restart read required")
                    || d.message().contains("Try again")
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
            // Internal details go to the server's log, not to the caller.
            Error::Db(e) => {
                eprintln!("veil-server: database error: {e}");
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
