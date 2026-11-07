//! BUG-120: concurrent first pushes to an empty remote. Initialisation
//! happens under the remote's lock, so one pusher creates the repository
//! and the others push to it normally (they used to fail with "a Veil
//! repository already exists", or reset `op_head` behind the winner).

use crate::adversarial_support;

use std::{
    sync::{Arc, Barrier},
    time::Duration,
};

use adversarial_support::{commit_files, new_repo};
use veil_core::{
    vfs::{DirEntry, Metadata},
    remote, DiskBackend, Repo, Result, StorageBackend, VPath,
};

/// A disk backend whose writes take a few milliseconds, as over SFTP: it
/// widens the window between "is it a repository?" and the end of
/// initialisation enough to hit the race every round.
#[derive(Debug)]
struct Slow(DiskBackend);

impl StorageBackend for Slow {
    fn kind(&self) -> &'static str {
        "slow"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        std::thread::sleep(Duration::from_millis(3));
        self.0.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.0.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.0.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.0.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        // A round trip, as every `stat` over SFTP.
        std::thread::sleep(Duration::from_millis(1));
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.0.set_executable(path, executable)
    }
}

#[test]
fn concurrent_first_pushes_to_an_empty_remote_all_succeed() {
    const PUSHERS: usize = 8;
    for round in 0..15 {
        let dir = tempfile::tempdir().unwrap();
        let mut repos: Vec<Repo> = (0..PUSHERS)
            .map(|i| {
                let (mut r, fs, _) = new_repo(&format!("dev{i}"));
                let c = commit_files(&mut r, &*fs, &[(&format!("dev{i}.txt"), "x\n")], "work");
                r.set_tag(&format!("t{i}"), c, true).unwrap();
                r
            })
            .collect();
        let barrier = Arc::new(Barrier::new(PUSHERS));
        let results: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = repos
                .iter_mut()
                .enumerate()
                .map(|(i, r)| {
                    let (barrier, path) = (barrier.clone(), dir.path().to_path_buf());
                    s.spawn(move || {
                        let backend: Arc<dyn StorageBackend> = Arc::new(Slow(DiskBackend::new(&path)));
                        barrier.wait();
                        // Staggered, so that some pushers check the remote
                        // while others are initialising or already pushing.
                        std::thread::sleep(Duration::from_micros(((i * 7919 + round * 104_729) % 25_000) as u64));
                        remote::push(r, backend, false, &[], false).map(|_| ())
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "round {round}: pusher {i} failed: {:?}", r.as_ref().err());
        }
        // Every pusher's tag landed: nobody's push was undone by a late
        // initialisation.
        let remote = Repo::open(Arc::new(DiskBackend::new(dir.path())), None, "check").unwrap();
        for (i, repo) in repos.iter().enumerate() {
            assert_eq!(
                remote.view().tags.get(&format!("t{i}")).map(|t| t.target),
                Some(repo.view().tags[&format!("t{i}")].target),
                "round {round}: t{i} missing on the remote"
            );
        }
    }
}
