use crate::id::ObjectId;

/// Every fallible engine operation returns this error type.
#[derive(Debug, thiserror::Error)]
pub enum VeilError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("storage backend is read-only")]
    ReadOnly,
    #[error("object {0} is not present in this store")]
    Missing(ObjectId),
    #[error("corrupt object {0}: {1}")]
    Corrupt(String, String),
    #[error("content is cloaked under scope '{scope}' and no key is available")]
    Redacted { scope: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("{0}")]
    Revset(String),
    #[error("{0}")]
    Repo(String),
    #[error("repository is locked by another process (remove .veil/lock if stale)")]
    Locked,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl VeilError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, VeilError::NotFound(_))
    }

    /// True when content exists in the graph but this reader cannot see it
    /// (missing key or object stripped by a public remote).
    pub fn is_unreadable(&self) -> bool {
        matches!(self, VeilError::Redacted { .. } | VeilError::Missing(_))
    }

    pub fn repo(msg: impl Into<String>) -> Self {
        VeilError::Repo(msg.into())
    }
}

pub type Result<T, E = VeilError> = std::result::Result<T, E>;
