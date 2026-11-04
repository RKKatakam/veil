//! `vl ws exec` benchmark on a ~20,000-file, ~500 MB workspace (ignored by
//! default).
//!
//! ```sh
//! cargo test --release -p vl --test bench_ws_exec -- --ignored --nocapture
//! # compare against another build of the binary:
//! VL_BENCH_BIN=/path/to/old/vl cargo test --release -p vl --test bench_ws_exec -- --ignored --nocapture
//! ```
//!
//! Everything (repository, `$TMPDIR`, `$VEIL_HOME`) lives under the cargo
//! target directory (or `$VL_BENCH_DIR`), so on a typical Linux machine it measures ext4 rather
//! than a tmpfs `/tmp`. Layout: `src/mNNN/sK/fJJ.rs` (200 × 5 × 20 = 20,000
//! files of ~25 KB each).
//!
//! Measured: the first and the following runs of `true`, a run whose
//! command edits 10 files, a run after 10 files were changed in the
//! workspace from outside (`vl ws write`), and the disk the sandboxes use
//! between runs.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MODULES: usize = 200;
const SUBDIRS: usize = 5;
const FILES: usize = 20;
/// ~25 KB per file: 20,000 files ≈ 500 MB.
const LINES: usize = 460;

fn bin() -> PathBuf {
    std::env::var_os("VL_BENCH_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_vl")))
}

struct Bench {
    home: PathBuf,
    tmp: PathBuf,
    root: PathBuf,
}

impl Bench {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args)
            .current_dir(&self.root)
            .env("VEIL_HOME", &self.home)
            .env("VEIL_USER", "bench")
            .env("TMPDIR", &self.tmp)
            .env("NO_COLOR", "1");
        c
    }

    fn vl(&self, args: &[&str]) {
        let out = self.cmd(args).output().unwrap();
        assert!(
            out.status.success(),
            "vl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn timed(&self, args: &[&str]) -> Duration {
        let t = Instant::now();
        self.vl(args);
        t.elapsed()
    }

    fn ws_write(&self, ws: &str, path: &str, data: &str) {
        let mut c = self
            .cmd(&["ws", "write", ws, path])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(data.as_bytes()).unwrap();
        let out = c.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}

fn file_body(m: usize, s: usize, f: usize, rev: usize) -> String {
    let mut body = format!("// module {m} sub {s} file {f} rev {rev}\n");
    for line in 0..LINES {
        body.push_str(&format!(
            "pub fn item_{m}_{s}_{f}_{line}(x: u64) -> u64 {{ x * {line} + {f} }}\n"
        ));
    }
    body
}

fn du_kib(p: &Path) -> u64 {
    if !p.exists() {
        return 0;
    }
    let out = Command::new("du").arg("-sk").arg(p).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture (use --release)"]
fn ws_exec_on_20k_files() {
    let base = std::env::var_os("VL_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::tempdir_in(&base).unwrap();
    let b = Bench {
        home: dir.path().join("home"),
        tmp: dir.path().join("tmp"),
        root: dir.path().join("repo"),
    };
    std::fs::create_dir_all(&b.root).unwrap();
    std::fs::create_dir_all(&b.tmp).unwrap();

    let t = Instant::now();
    let mut bytes = 0;
    for m in 0..MODULES {
        for s in 0..SUBDIRS {
            let d = b.root.join(format!("src/m{m:03}/s{s}"));
            std::fs::create_dir_all(&d).unwrap();
            for f in 0..FILES {
                let body = file_body(m, s, f, 0);
                bytes += body.len();
                std::fs::write(d.join(format!("f{f:02}.rs")), body).unwrap();
            }
        }
    }
    eprintln!(
        "generated {} files, {} MB in {:?}",
        MODULES * SUBDIRS * FILES,
        bytes / 1_000_000,
        t.elapsed()
    );
    eprintln!("binary: {}", bin().display());
    let fs_type = Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "--target"])
        .arg(&b.root)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    eprintln!("filesystem: {fs_type}");

    b.vl(&["init"]);
    b.vl(&["commit", "-m", "base"]);
    b.vl(&["ws", "new", "agent"]);
    // Let the files written above age past any racy-mtime window.
    std::thread::sleep(Duration::from_millis(2500));

    let first = b.timed(&["ws", "exec", "agent", "--", "true"]);
    let second = b.timed(&["ws", "exec", "agent", "--", "true"]);
    let mut more: Vec<Duration> = (0..3).map(|_| b.timed(&["ws", "exec", "agent", "--", "true"])).collect();
    more.sort();
    let steady = more[1];
    let disk_after = du_kib(&b.root.join(".veil/local/sandboxes"));
    let tmp_after = du_kib(&b.tmp);

    let mut edit = String::new();
    for i in 0..10 {
        edit.push_str(&format!("echo edit >> src/m{:03}/s1/f03.rs; ", 20 + i * 7));
    }
    let edit10_in_cmd = b.timed(&["ws", "exec", "agent", "--", "sh", "-c", &edit]);
    let after_cmd_edit = b.timed(&["ws", "exec", "agent", "--", "true"]);

    for i in 0..10 {
        let m = 30 + i * 11;
        b.ws_write("agent", &format!("src/m{m:03}/s2/f05.rs"), &file_body(m, 2, 5, 9));
    }
    let after_ws_write10 = b.timed(&["ws", "exec", "agent", "--", "true"]);
    let steady_again = b.timed(&["ws", "exec", "agent", "--", "true"]);

    eprintln!();
    eprintln!("ws exec -- true, first run               {:9.1} ms", ms(first));
    eprintln!("ws exec -- true, second run              {:9.1} ms", ms(second));
    eprintln!("ws exec -- true, later runs (median of 3){:9.1} ms", ms(steady));
    eprintln!("ws exec, command edits 10 files          {:9.1} ms", ms(edit10_in_cmd));
    eprintln!("ws exec -- true after that               {:9.1} ms", ms(after_cmd_edit));
    eprintln!("ws exec -- true after 10 `ws write`s      {:9.1} ms", ms(after_ws_write10));
    eprintln!("ws exec -- true again                    {:9.1} ms", ms(steady_again));
    eprintln!("disk kept between runs: sandboxes {} MiB, $TMPDIR {} MiB", disk_after / 1024, tmp_after / 1024);
}
