use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    error::{Result, VeilError},
    now_millis,
    vfs::StorageBackend,
    vpath::VPath,
};

const STALE_AFTER_MS: i64 = 120_000;
const WAIT_FOR: Duration = Duration::from_secs(15);

/// Advisory repository lock built only on `StorageBackend::create_new`, so it
/// works identically on disk and in memory. Held for the duration of a
/// transaction; released on drop.
#[derive(Debug)]
pub struct RepoLock {
    backend: Arc<dyn StorageBackend>,
    path: VPath,
}

impl RepoLock {
    pub fn acquire(backend: Arc<dyn StorageBackend>) -> Result<RepoLock> {
        let path = VPath::new(".veil/lock")?;
        let start = Instant::now();
        loop {
            let stamp = format!("{} {}", std::process::id(), now_millis());
            if backend.create_new(&path, stamp.as_bytes())? {
                return Ok(RepoLock { backend, path });
            }
            if let Some(content) = backend.read_opt(&path)? {
                let ts = String::from_utf8_lossy(&content)
                    .split_whitespace()
                    .nth(1)
                    .and_then(|t| t.parse::<i64>().ok())
                    .unwrap_or(0);
                if now_millis() - ts > STALE_AFTER_MS {
                    backend.remove_file(&path)?;
                    continue;
                }
            }
            if start.elapsed() > WAIT_FOR {
                return Err(VeilError::Locked);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        let _ = self.backend.remove_file(&self.path);
    }
}
