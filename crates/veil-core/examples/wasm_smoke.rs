//! The portable engine end to end, with no operating system and no disk:
//! everything runs over `MemoryBackend`, on a clock the program installs.
//!
//! ```text
//! # natively, with exactly the feature set of the WASM build
//! cargo run -p veil-core --example wasm_smoke --no-default-features --features wasm
//!
//! # on wasm32-unknown-unknown, run under node (scripts/check-wasm.sh)
//! RUSTFLAGS='--cfg getrandom_backend="custom"' cargo rustc -p veil-core --release \
//!     --example wasm_smoke --target wasm32-unknown-unknown \
//!     --no-default-features --features wasm --crate-type cdylib
//! node scripts/wasm-smoke.mjs target/wasm32-unknown-unknown/release/examples/wasm_smoke.wasm
//! ```
//!
//! Steps: init a repository with an identity created in memory, write
//! files, snapshot, read them back, show the log, diff two snapshots, seal
//! a secret file under a scope and read it back, check that another
//! identity cannot, merge two lines of work, clone into a second
//! repository by pull, garbage-collect into a pack and read everything back
//! from it.
//!
//! On WASM the module exports `veil_smoke_run() -> i32` (0: success) and
//! `veil_smoke_report_ptr()` / `veil_smoke_report_len()` (the report, UTF-8),
//! and imports `env.veil_now_ms() -> f64` (the clock) and, built with
//! `--cfg getrandom_backend="custom"`, `env.veil_random_fill(ptr, len)`.
//! A browser build would use getrandom's WebCrypto backend (the `wasm`
//! feature) through wasm-bindgen instead; the custom backend lets a plain
//! `WebAssembly.instantiate` run the module.

use std::{fmt::Write as _, sync::Arc, time::Duration};

use veil_core::{
    clock,
    gc::{gc, GcOptions},
    object::{Object, Visibility},
    remote,
    tree::{diff_trees, lookup, walk_files},
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).expect("valid path")
}

fn read_at(repo: &Repo, snapshot: &ObjectId, path: &str) -> Result<Option<Vec<u8>>, String> {
    let tree = repo.snapshot(snapshot).map_err(|e| e.to_string())?.tree;
    match lookup(repo.store(), &tree, &p(path)).map_err(|e| e.to_string())? {
        Some(e) => repo.store().read_entry(&e).map(Some).map_err(|e| e.to_string()),
        None => Ok(None),
    }
}

/// Snapshot the working copy (the repository's own backend), then commit it.
fn commit(repo: &mut Repo, fs: &MemoryBackend, message: &str) -> Result<ObjectId, String> {
    repo.snapshot_workspace(WS, fs).map_err(|e| e.to_string())?;
    Ok(repo.commit_working_copy(WS, message).map_err(|e| e.to_string())?.0)
}

fn check(cond: bool, what: &str) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(format!("check failed: {what}"))
    }
}

/// The whole scenario; returns a human-readable report.
pub fn smoke() -> Result<String, String> {
    let e = |e: veil_core::VeilError| e.to_string();
    let mut out = String::new();

    // ---- init, write, snapshot ------------------------------------------
    let fs = Arc::new(MemoryBackend::new());
    let alice = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(alice.clone()), "alice").map_err(e)?;
    writeln!(out, "init: repository {} (format {})", repo.repo_id(), repo.format()).unwrap();

    fs.write(&p("README.md"), b"# Hello from WASM\n").map_err(e)?;
    fs.write(&p("src/lib.rs"), b"pub fn answer() -> u32 {\n    41\n}\n").map_err(e)?;
    let first = commit(&mut repo, &fs, "first: readme and lib")?;
    writeln!(out, "snapshot: {} first", first.short()).unwrap();

    // ---- read back --------------------------------------------------------
    let lib = read_at(&repo, &first, "src/lib.rs")?.ok_or("src/lib.rs missing")?;
    check(lib == b"pub fn answer() -> u32 {\n    41\n}\n", "src/lib.rs reads back")?;
    let files: Vec<String> = walk_files(repo.store(), &repo.snapshot(&first).map_err(e)?.tree)
        .map_err(e)?
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect();
    check(files == ["README.md", "src/lib.rs"], "file list")?;
    writeln!(out, "read back: {}", files.join(", ")).unwrap();

    // ---- a second snapshot, log and diff ---------------------------------
    fs.write(&p("src/lib.rs"), b"pub fn answer() -> u32 {\n    42\n}\n").map_err(e)?;
    fs.write(&p("NOTES.txt"), b"fixed the answer\n").map_err(e)?;
    let second = commit(&mut repo, &fs, "second: fix the answer")?;

    writeln!(out, "log:").unwrap();
    let mut cur = Some(second);
    let mut seen = 0;
    while let Some(id) = cur {
        let s = repo.snapshot(&id).map_err(e)?;
        writeln!(out, "  {} {} {}", id.short(), s.timestamp, repo.description(&s)).unwrap();
        check(s.timestamp >= 1_700_000_000_000 || s.parents.is_empty(), "timestamps come from the installed clock")?;
        seen += 1;
        cur = s.parents.first().copied();
    }
    check(seen == 3, "log has root, first, second")?;

    let (t1, t2) = (repo.snapshot(&first).map_err(e)?.tree, repo.snapshot(&second).map_err(e)?.tree);
    let changes = diff_trees(repo.store(), Some(&t1), Some(&t2)).map_err(e)?;
    let summary: Vec<String> = changes.iter().map(|c| format!("{} {}", c.status(), c.path)).collect();
    check(summary == ["A NOTES.txt", "M src/lib.rs"], "diff summary")?;
    writeln!(out, "diff: {}", summary.join(", ")).unwrap();
    let old = String::from_utf8(lib).map_err(|e| e.to_string())?;
    let new = String::from_utf8(read_at(&repo, &second, "src/lib.rs")?.ok_or("missing")?).map_err(|e| e.to_string())?;
    let patch = diffy::create_patch(&old, &new).to_string();
    check(patch.contains("-    41") && patch.contains("+    42"), "text diff")?;
    for line in patch.lines() {
        writeln!(out, "  {line}").unwrap();
    }

    // ---- scopes: seal, unseal, and an outsider --------------------------
    // `Repo::init` with an identity already made the default scope `team`.
    check(repo.keys().is_member("team"), "alice holds the team key")?;
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").map_err(e)?;
    fs.write(&p("secrets/.env.plan"), b"team-only plan\n").map_err(e)?;
    let sealed = commit(&mut repo, &fs, "team plan")?;
    let tree = repo.snapshot(&sealed).map_err(e)?.tree;
    let entry = lookup(repo.store(), &tree, &p("secrets/.env.plan")).map_err(e)?.ok_or("plan missing")?;
    check(entry.visibility == Visibility::Cloaked { scope: "team".into() }, "cloaked by policy")?;
    let raw = repo.store().get_raw(&entry.id).map_err(e)?;
    check(Object::sealed_scope(&raw).is_some(), "stored sealed")?;
    check(!raw.windows(9).any(|w| w == b"team-only"), "no plaintext in the stored object")?;
    check(repo.store().read_entry(&entry).map_err(e)? == b"team-only plan\n", "a member unseals it")?;
    writeln!(out, "seal: secrets/.env.plan sealed under scope team ({} bytes), unsealed by alice", raw.len()).unwrap();

    let outsider = Repo::open(fs.clone(), Some(Identity::generate("mallory")), "mallory").map_err(e)?;
    check(outsider.store().read_entry(&entry).is_err(), "an outsider cannot unseal it")?;
    check(read_at(&outsider, &sealed, "src/lib.rs")?.is_some(), "an outsider reads public files")?;
    writeln!(out, "seal: another identity cannot read it, but reads the public files").unwrap();

    // ---- merge ------------------------------------------------------------
    let a = repo.ephemeral_workspace(sealed).map_err(e)?;
    a.write("src/a.rs", "pub fn a() {}\n").map_err(e)?;
    let (line_a, _) = repo.commit_ephemeral(&a, "line a").map_err(e)?;
    let b = repo.ephemeral_workspace(sealed).map_err(e)?;
    b.write("src/b.rs", "pub fn b() {}\n").map_err(e)?;
    let (line_b, _) = repo.commit_ephemeral(&b, "line b").map_err(e)?;
    let merged = repo.merge(WS, line_a, vec![line_b], "merge a and b", None).map_err(e)?;
    check(merged.conflicts.is_empty(), "no conflicts")?;
    check(repo.snapshot(&merged.snapshot).map_err(e)?.parents == vec![line_a, line_b], "merge parents")?;
    for f in ["src/a.rs", "src/b.rs", "secrets/.env.plan"] {
        check(read_at(&repo, &merged.snapshot, f)?.is_some(), &format!("merge has {f}"))?;
    }
    writeln!(out, "merge: {} = {} + {}", merged.snapshot.short(), line_a.short(), line_b.short()).unwrap();
    repo.set_tag("main", merged.snapshot, false).map_err(e)?;

    // ---- sync: clone by pull into a second repository ----------------------
    let bob_fs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bob_fs, Some(Identity::generate("bob")), "bob").map_err(e)?;
    remote::pull(&mut bob, "origin", fs.clone()).map_err(e)?;
    let main = bob.view().tags.get("main").ok_or("main not pulled")?.target;
    check(read_at(&bob, &main, "src/b.rs")?.as_deref() == Some(b"pub fn b() {}\n"), "pulled content")?;
    writeln!(out, "pull: bob has main at {}", main.short()).unwrap();

    // ---- gc into a pack, read back from it --------------------------------
    let report = gc(
        &mut repo,
        &GcOptions {
            keep_ops: None,
            grace: Duration::ZERO,
            ..GcOptions::default()
        },
    )
    .map_err(e)?;
    let stats = repo.store().stats().map_err(e)?;
    check(stats.packs >= 1 && stats.packed_objects > 0, "gc wrote a pack")?;
    check(repo.store().verify_packs().map_err(e)?.is_empty(), "packs verify")?;
    check(read_at(&repo, &second, "src/lib.rs")?.as_deref() == Some(new.as_bytes()), "reads back from the pack")?;
    check(repo.store().read_entry(&entry).map_err(e)? == b"team-only plan\n", "sealed object from the pack")?;
    let ps = &report.pack_stats;
    writeln!(
        out,
        "gc: {} objects packed ({} stored, {} compressed, {} deltas), {} loose left",
        stats.packed_objects, ps.stored, ps.compressed, ps.deltas, stats.loose_objects
    )
    .unwrap();

    Ok(out)
}

/// Install a clock: the host's on WASM, the system clock otherwise (through
/// [`clock::set_clock`] all the same, so the injected path is what runs).
fn install_clock() {
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    {
        #[link(wasm_import_module = "env")]
        unsafe extern "C" {
            fn veil_now_ms() -> f64;
        }
        clock::set_clock(Arc::new(|| unsafe { veil_now_ms() } as i64));
    }
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    {
        use veil_core::clock::Clock as _;
        clock::set_clock(Arc::new(|| clock::SystemClock.now_millis().max(1_700_000_000_000)));
    }
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod wasm_exports {
    use std::sync::Mutex;

    static REPORT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    /// Run the scenario. 0: success; 1: a check failed; 2: a panic.
    #[unsafe(no_mangle)]
    pub extern "C" fn veil_smoke_run() -> i32 {
        super::install_clock();
        let (code, text) = match std::panic::catch_unwind(super::smoke) {
            Ok(Ok(r)) => (0, r),
            Ok(Err(m)) => (1, m),
            Err(_) => (2, "panicked".to_string()),
        };
        *REPORT.lock().unwrap() = text.into_bytes();
        code
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn veil_smoke_report_ptr() -> *const u8 {
        REPORT.lock().unwrap().as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn veil_smoke_report_len() -> usize {
        REPORT.lock().unwrap().len()
    }

    /// Randomness from the host (`crypto.getRandomValues`), for builds with
    /// `--cfg getrandom_backend="custom"`.
    #[cfg(getrandom_backend = "custom")]
    #[unsafe(no_mangle)]
    unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
        #[link(wasm_import_module = "env")]
        unsafe extern "C" {
            fn veil_random_fill(ptr: *mut u8, len: usize) -> i32;
        }
        match unsafe { veil_random_fill(dest, len) } {
            0 => Ok(()),
            _ => Err(getrandom::Error::UNSUPPORTED),
        }
    }
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), allow(dead_code))]
fn main() {
    install_clock();
    match smoke() {
        Ok(report) => print!("{report}"),
        Err(m) => {
            eprintln!("wasm_smoke: {m}");
            std::process::exit(1);
        }
    }
}
