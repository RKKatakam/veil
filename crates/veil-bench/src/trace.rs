//! The walk and lock detector, without a hook in the product: `vl` runs
//! under `strace -f -ttt -y` (see `proc.rs`), and this reads the trace.
//!
//! * **Snapshot reads.** A loose object is a file `.veil/objects/ab/cdef…`,
//!   opened once per read that misses the in-process cache. The generator
//!   lists every snapshot id (`snapshots.txt`), so an open of one of them
//!   is a snapshot decode. On a packed store (after `gc`) objects are read
//!   from the pack without an open each, so counts are only meaningful
//!   before `gc`; the harness only traces then.
//! * **Locks.** `.veil/lock` is created with `linkat(tmp, "lock")` (or
//!   `O_CREAT|O_EXCL`), which fails with `EEXIST` while someone holds it,
//!   and released with `unlinkat(…, "lock")`. A command's wait is the time
//!   from its first failed attempt to its successful one; its hold is the
//!   time from acquisition to release.
//!
//! strace slows each traced syscall, so traced runs are never the timed
//! ones: they give counts, and lock times relative to each other.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LockStats {
    pub acquisitions: u64,
    pub failed_attempts: u64,
    pub wait_ms: f64,
    pub hold_ms: f64,
    pub max_hold_ms: f64,
}

#[derive(Clone, Debug, Default)]
pub struct TraceSummary {
    /// Distinct snapshots opened (decoded from disk).
    pub snapshots_distinct: u64,
    /// Snapshot opens (a snapshot may be decoded more than once if it fell
    /// out of the cache).
    pub snapshot_opens: u64,
    /// Every other loose object opened for reading.
    pub other_object_opens: u64,
    /// Lock statistics by role (`local`, `remote`) and lock file.
    pub locks: BTreeMap<String, LockStats>,
}

impl TraceSummary {
    pub fn merge(&mut self, o: &TraceSummary) {
        self.snapshots_distinct += o.snapshots_distinct;
        self.snapshot_opens += o.snapshot_opens;
        self.other_object_opens += o.other_object_opens;
        for (k, v) in &o.locks {
            let e = self.locks.entry(k.clone()).or_default();
            e.acquisitions += v.acquisitions;
            e.failed_attempts += v.failed_attempts;
            e.wait_ms += v.wait_ms;
            e.hold_ms += v.hold_ms;
            e.max_hold_ms = e.max_hold_ms.max(v.max_hold_ms);
        }
    }

    pub fn lock(&self, role: &str) -> LockStats {
        let mut s = LockStats::default();
        for (k, v) in &self.locks {
            if k == role {
                s = v.clone();
            }
        }
        s
    }
}

#[derive(Debug, PartialEq)]
struct Call {
    pid: u32,
    t: f64,
    name: String,
    args: Vec<String>,
    result: String,
}

/// Split strace's argument list at top-level commas.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut quoted, mut esc) = (0i32, false, false);
    for c in s.chars() {
        if quoted {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                quoted = false;
            }
            continue;
        }
        match c {
            '"' => {
                quoted = true;
                cur.push(c);
            }
            '<' | '{' | '[' | '(' => {
                depth += 1;
                cur.push(c);
            }
            '>' | '}' | ']' | ')' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Joins `<unfinished ...>` / `resumed` pairs, one line at a time.
#[derive(Default)]
struct Parser {
    pending: HashMap<u32, String>,
}

impl Parser {
    fn line(&mut self, line: &str) -> Option<Call> {
        let mut it = line.splitn(3, ' ');
        let (pid, t, rest) = (it.next()?, it.next()?, it.next()?);
        let (Ok(pid), Ok(t)) = (pid.parse::<u32>(), t.parse::<f64>()) else { return None };
        let body = if let Some(head) = rest.strip_suffix(" <unfinished ...>") {
            self.pending.insert(pid, head.to_string());
            return None;
        } else if rest.starts_with("<... ") {
            let i = rest.find(" resumed>")?;
            let head = self.pending.remove(&pid)?;
            format!("{head}{}", &rest[i + " resumed>".len()..])
        } else {
            rest.to_string()
        };
        let open = body.find('(')?;
        let name = body[..open].to_string();
        let eq = body.rfind(") = ")?;
        let args = split_args(&body[open + 1..eq]);
        let result = body[eq + 4..].trim().to_string();
        Some(Call { pid, t, name, args, result })
    }
}

/// `3</a/b>` → `/a/b`; `AT_FDCWD</cwd>` → `/cwd`.
fn fd_path(a: &str) -> Option<&str> {
    let i = a.find('<')?;
    a[i + 1..].strip_suffix('>')
}

fn string_arg(a: &str) -> Option<&str> {
    a.strip_prefix('"')?.strip_suffix('"')
}

fn join(dir: Option<&str>, name: &str) -> String {
    if name.starts_with('/') {
        return name.to_string();
    }
    match dir {
        Some(d) => format!("{d}/{name}"),
        None => name.to_string(),
    }
}

fn ok(result: &str) -> bool {
    !result.starts_with("-1")
}

fn eexist(result: &str) -> bool {
    result.starts_with("-1 EEXIST")
}

enum Ev {
    Read(String),
    LockTry(String, bool),
    LockRelease(String),
}

fn event(c: &Call) -> Option<(f64, Ev)> {
    let mut out = Vec::new();
    {
        match c.name.as_str() {
            "openat" | "openat2" | "open" => {
                let (dir, name, flags) = if c.name == "open" {
                    (None, c.args.first().and_then(|a| string_arg(a)), c.args.get(1))
                } else {
                    (c.args.first().and_then(|a| fd_path(a)), c.args.get(1).and_then(|a| string_arg(a)), c.args.get(2))
                };
                let (Some(name), Some(flags)) = (name, flags) else { return None };
                let path = join(dir, name);
                let excl = flags.contains("O_EXCL") && flags.contains("O_CREAT");
                if path.ends_with("/.veil/lock") && excl {
                    if ok(&c.result) {
                        out.push((c.t, Ev::LockTry(path, true)));
                    } else if eexist(&c.result) {
                        out.push((c.t, Ev::LockTry(path, false)));
                    }
                } else if ok(&c.result) && !flags.contains("O_WRONLY") && !flags.contains("O_RDWR") && !flags.contains("O_CREAT") && !flags.contains("O_PATH") {
                    out.push((c.t, Ev::Read(path)));
                }
            }
            "linkat" | "link" => {
                let path = if c.name == "link" {
                    c.args.get(1).and_then(|a| string_arg(a)).map(|n| n.to_string())
                } else {
                    let dir = c.args.get(2).and_then(|a| fd_path(a));
                    c.args.get(3).and_then(|a| string_arg(a)).map(|n| join(dir, n))
                };
                let path = path?;
                if path.ends_with("/.veil/lock") {
                    if ok(&c.result) {
                        out.push((c.t, Ev::LockTry(path, true)));
                    } else if eexist(&c.result) {
                        out.push((c.t, Ev::LockTry(path, false)));
                    }
                }
            }
            "unlinkat" | "unlink" => {
                let path = if c.name == "unlink" {
                    c.args.first().and_then(|a| string_arg(a)).map(|n| n.to_string())
                } else {
                    let dir = c.args.first().and_then(|a| fd_path(a));
                    c.args.get(1).and_then(|a| string_arg(a)).map(|n| join(dir, n))
                };
                let path = path?;
                if path.ends_with("/.veil/lock") && ok(&c.result) {
                    out.push((c.t, Ev::LockRelease(path)));
                }
            }
            _ => {}
        }
    }
    out.pop()
}

/// The loose object id in `path`, if it is one under `.veil/objects/`.
fn loose_id(path: &str) -> Option<String> {
    let i = path.find("/.veil/objects/")?;
    let rest = &path[i + "/.veil/objects/".len()..];
    let (a, b) = rest.split_once('/')?;
    if a.len() == 2 && b.len() >= 40 && !b.contains('/') && a.chars().chain(b.chars()).all(|c| c.is_ascii_hexdigit()) {
        Some(format!("{a}{b}"))
    } else {
        None
    }
}

/// Summarise one trace. Lock files under `local_root` are `local`, the
/// rest `remote`.
#[cfg(test)]
pub fn summarise(text: &str, snapshots: &HashSet<String>, local_root: &Path) -> TraceSummary {
    summarise_lines(text.lines().map(str::to_string), snapshots, local_root)
}

/// Summarise a trace from a stream of lines (traces of whole-history commands
/// run to gigabytes: never held in memory, which would also raise the
/// harness's own peak RSS, the floor of every child's `ru_maxrss`).
pub fn summarise_lines(lines: impl Iterator<Item = String>, snapshots: &HashSet<String>, local_root: &Path) -> TraceSummary {
    let mut parser = Parser::default();
    let local = format!("{}/.veil/lock", local_root.display());
    let mut s = TraceSummary::default();
    let mut seen: HashSet<String> = HashSet::new();
    struct St {
        waiting: Option<f64>,
        held: Option<f64>,
    }
    let mut state: HashMap<String, St> = HashMap::new();
    let mut last_t = 0.0;
    let local_objects = format!("{}/.veil/objects/", local_root.display());
    for (t, ev) in lines.filter_map(|l| parser.line(&l)).filter_map(|c| event(&c)) {
        last_t = t;
        match ev {
            Ev::Read(p) => {
                if !p.starts_with(&local_objects) {
                    continue;
                }
                if let Some(id) = loose_id(&p) {
                    if snapshots.contains(&id) {
                        s.snapshot_opens += 1;
                        if seen.insert(id) {
                            s.snapshots_distinct += 1;
                        }
                    } else {
                        s.other_object_opens += 1;
                    }
                }
            }
            Ev::LockTry(p, success) => {
                let role = if p == local { "local" } else { "remote" };
                let st = state.entry(p).or_insert(St { waiting: None, held: None });
                let l = s.locks.entry(role.to_string()).or_default();
                if success {
                    l.acquisitions += 1;
                    if let Some(w) = st.waiting.take() {
                        l.wait_ms += (t - w) * 1e3;
                    }
                    st.held = Some(t);
                } else {
                    l.failed_attempts += 1;
                    st.waiting.get_or_insert(t);
                }
            }
            Ev::LockRelease(p) => {
                let role = if p == local { "local" } else { "remote" };
                if let Some(st) = state.get_mut(&p) {
                    if let Some(h) = st.held.take() {
                        let l = s.locks.entry(role.to_string()).or_default();
                        let d = (t - h) * 1e3;
                        l.hold_ms += d;
                        l.max_hold_ms = l.max_hold_ms.max(d);
                    }
                }
            }
        }
    }
    // A lock still held when the trace ends (killed, or released by
    // another route) counts up to the last event.
    for (p, st) in state {
        let role = if p == local { "local" } else { "remote" };
        let l = s.locks.entry(role.to_string()).or_default();
        if let Some(h) = st.held {
            let d = (last_t - h) * 1e3;
            l.hold_ms += d;
            l.max_hold_ms = l.max_hold_ms.max(d);
        }
        if let Some(w) = st.waiting {
            l.wait_ms += (last_t - w) * 1e3;
        }
    }
    s
}

/// Summarise `trace`, then delete it.
pub fn summarise_files(trace: &Path, snapshots: &HashSet<String>, local_root: &Path) -> TraceSummary {
    let mut s = TraceSummary::default();
    if let Ok(file) = std::fs::File::open(trace) {
        use std::io::BufRead;
        let lines = std::io::BufReader::new(file).lines().map_while(|l| l.ok());
        s.merge(&summarise_lines(lines, snapshots, local_root));
    }
    let _ = std::fs::remove_file(trace);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID1: &str = "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

    #[test]
    fn counts_snapshots_and_lock_times() {
        let snaps: HashSet<String> = [ID1.to_string()].into_iter().collect();
        let text = format!(
            "10 100.000000 openat(AT_FDCWD</r>, \"/r/.veil/objects/ab/{}\", O_RDONLY|O_CLOEXEC) = 5</r/.veil/objects/ab/x>\n\
             10 100.100000 linkat(4</r/.veil>, \"lock.tmp1\", 4</r/.veil>, \"lock\", 0) = -1 EEXIST (File exists)\n\
             11 100.150000 openat(7</r/.veil/objects/cd>, \"ef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab\", O_RDONLY|O_CLOEXEC <unfinished ...>\n\
             10 100.200000 linkat(4</r/.veil>, \"lock.tmp2\", 4</r/.veil>, \"lock\", 0) = -1 EEXIST (File exists)\n\
             11 100.210000 <... openat resumed>) = 8</r/.veil/objects/cd/ef>\n\
             10 100.300000 linkat(4</r/.veil>, \"lock.tmp3\", 4</r/.veil>, \"lock\", 0) = 0\n\
             10 100.350000 openat(AT_FDCWD</r>, \"/r/.veil/objects/ab/{}\", O_RDONLY|O_CLOEXEC) = 5</x>\n\
             10 100.800000 unlinkat(4</r/.veil>, \"lock\", 0) = 0\n\
             10 101.000000 openat(AT_FDCWD</>, \"/srv/remote/.veil/lock\", O_WRONLY|O_CREAT|O_EXCL, 0644) = 3</srv/remote/.veil/lock>\n\
             10 101.250000 unlink(\"/srv/remote/.veil/lock\") = 0\n",
            &ID1[2..],
            &ID1[2..]
        );
        let s = summarise(&text, &snaps, Path::new("/r"));
        assert_eq!(s.snapshots_distinct, 1);
        assert_eq!(s.snapshot_opens, 2);
        assert_eq!(s.other_object_opens, 1);
        let l = s.lock("local");
        assert_eq!(l.acquisitions, 1);
        assert_eq!(l.failed_attempts, 2);
        assert!((l.wait_ms - 200.0).abs() < 0.01, "{l:?}");
        assert!((l.hold_ms - 500.0).abs() < 0.01, "{l:?}");
        let r = s.lock("remote");
        assert_eq!(r.acquisitions, 1);
        assert!((r.hold_ms - 250.0).abs() < 0.01, "{r:?}");
    }

    #[test]
    fn splits_quoted_commas() {
        assert_eq!(split_args(r#"3</a,b>, "x, \"y\"", O_RDONLY"#), vec!["3</a,b>", r#""x, \"y\"""#, "O_RDONLY"]);
    }
}
