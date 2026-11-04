//! `vl status` benchmark on a ~20,000-file working copy (ignored by default).
//!
//! ```sh
//! cargo test --release -p vl --test bench_status -- --ignored --nocapture
//! # compare against another build of the binary:
//! VL_BENCH_BIN=/path/to/old/vl cargo test --release -p vl --test bench_status -- --ignored --nocapture
//! ```
//!
//! Layout: `src/mNNN/sK/fJJ.rs` (200 × 5 × 20 = 20,000 files). The first ten
//! modules are cloaked by `.veilpolicy` (1,000 encrypted files), and an
//! ignored `target/` holds another 500 files that are never read.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const MODULES: usize = 200;
const SUBDIRS: usize = 5;
const FILES: usize = 20;
const RUNS: usize = 10;

fn bin() -> PathBuf {
    std::env::var_os("VL_BENCH_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_vl")))
}

fn vl(home: &Path, cwd: &Path, args: &[&str]) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "bench")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "vl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn timed(home: &Path, cwd: &Path, args: &[&str]) -> Duration {
    let t = Instant::now();
    vl(home, cwd, args);
    t.elapsed()
}

fn file_body(m: usize, s: usize, f: usize, rev: usize) -> String {
    let mut body = format!("// module {m} sub {s} file {f} rev {rev}\n");
    for line in 0..(8 + (m * 7 + s * 3 + f) % 40) {
        body.push_str(&format!(
            "pub fn item_{m}_{s}_{f}_{line}(x: u64) -> u64 {{ x * {line} + {f} }}\n"
        ));
    }
    body
}

fn stats(mut v: Vec<Duration>) -> String {
    v.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    format!(
        "median {:8.1} ms   min {:8.1} ms   max {:8.1} ms",
        ms(v[v.len() / 2]),
        ms(v[0]),
        ms(v[v.len() - 1])
    )
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture (use --release)"]
fn status_on_20k_files() {
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let home = tmp.path().join("home");
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();

    let t = Instant::now();
    for m in 0..MODULES {
        for s in 0..SUBDIRS {
            let dir = root.join(format!("src/m{m:03}/s{s}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..FILES {
                std::fs::write(dir.join(format!("f{f:02}.rs")), file_body(m, s, f, 0)).unwrap();
            }
        }
    }
    for i in 0..500 {
        let dir = root.join(format!("target/debug/d{}", i / 50));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("o{i}.o")), vec![b'x'; 256]).unwrap();
    }
    let mut policy = String::from("target/ ignore\n");
    for m in 0..10 {
        policy.push_str(&format!("src/m{m:03}/ cloak team\n"));
    }
    std::fs::write(root.join(".veilpolicy"), policy).unwrap();
    eprintln!(
        "generated {} files in {:?}",
        MODULES * SUBDIRS * FILES + 500,
        t.elapsed()
    );
    eprintln!("binary: {}", bin().display());

    let init = timed(&home, &root, &["init"]);
    // Commit, so `status` measures snapshotting a clean working copy rather
    // than listing 20,000 added files.
    let commit = timed(&home, &root, &["commit", "-m", "base"]);
    let first = timed(&home, &root, &["status"]);
    // Let the files written above age past any racy-mtime window.
    std::thread::sleep(Duration::from_millis(2500));
    let second = timed(&home, &root, &["status"]);

    let unchanged: Vec<Duration> = (0..RUNS).map(|_| timed(&home, &root, &["status"])).collect();

    let mut touched = Vec::new();
    for rev in 1..=RUNS {
        let p = root.join("src/m100/s2/f07.rs");
        std::fs::write(&p, file_body(100, 2, 7, rev)).unwrap();
        touched.push(timed(&home, &root, &["status"]));
    }
    let mut touched_cloaked = Vec::new();
    for rev in 1..=RUNS {
        let p = root.join("src/m003/s1/f11.rs");
        std::fs::write(&p, file_body(3, 1, 11, rev)).unwrap();
        touched_cloaked.push(timed(&home, &root, &["status"]));
    }

    eprintln!();
    eprintln!("vl init (first snapshot)        {:8.1} ms", init.as_secs_f64() * 1000.0);
    eprintln!(
        "vl commit -m base               {:8.1} ms",
        commit.as_secs_f64() * 1000.0
    );
    eprintln!(
        "first vl status after commit    {:8.1} ms",
        first.as_secs_f64() * 1000.0
    );
    eprintln!(
        "second vl status (files aged)   {:8.1} ms",
        second.as_secs_f64() * 1000.0
    );
    eprintln!("status, unchanged tree          {}", stats(unchanged));
    eprintln!("status, 1 public file edited    {}", stats(touched));
    eprintln!("status, 1 cloaked file edited   {}", stats(touched_cloaked));
}
