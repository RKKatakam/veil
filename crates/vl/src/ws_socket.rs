//! The workspace socket: a `vl` inside a `vl ws exec` sandbox talks to the
//! `vl` outside (milestone S8; `docs/design/server/phase-2-thin-clients.md`
//! §4.6).
//!
//! Inside the sandbox there is no device key, no session and no Veil home,
//! so a `vl` there cannot sign in or open the repository. `vl ws exec` gives
//! the sandbox one Unix socket, named by [`ENV`] (at [`INSIDE`] in a
//! confined run), served by the `vl ws exec` outside for as long as the
//! command runs. A `vl` that finds [`ENV`] set sends its arguments there and
//! prints what comes back; it runs nothing itself.
//!
//! **What the socket runs.** The `vl` outside parses the arguments as the
//! command line would, and runs only the workspace commands of the design:
//! `status`, `diff`, `log`, `show`, `blame` (reading), and `commit`,
//! `describe` and `new` on the sandbox's own workspace ([`allowed`]):
//! `describe` only of its working-copy change, `new` only on top of it.
//! Everything else (access, groups, identity, other workspaces, pushes,
//! `-R`) is refused, before anything is opened. A command runs as the
//! person running `vl ws exec`, with that `vl`'s environment and identity
//! (never the caller's), on that workspace only ([`crate::ctx::Ctx::open_for_workspace`]):
//! the project directory is never touched. Hooks never run for it (they
//! would run outside the sandbox). So the sandbox's `vl` can do only what
//! its person may, and less.
//!
//! **What it sees.** Before each command, what the sandbox holds is
//! recorded into the workspace (a mount's overlay, or the checked-out
//! sandbox's files), so `vl status` and `vl commit` see the command's edits.
//!
//! **Access.** The socket is created `0600` in a `0700` directory of the
//! user's; every connection's peer must be the same user (`SO_PEERCRED`).
//! Only the run's own sandbox has it bound. Requests are at most
//! [`MAX_REQUEST`] bytes, one at a time.
//!
//! **Protocol.** One JSON line, `{"argv": […], "cwd": "…"}`; then frames
//! back, each a tag byte (`o` stdout, `e` stderr, `x` the exit status), a
//! big-endian `u32` length, and that many bytes.

use std::{
    ffi::OsString,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::{
    cli::{Cli, Cmd},
    ctx::Ctx,
    render::safe,
};

/// The variable naming the socket, for a `vl` inside the sandbox.
pub const ENV: &str = "VEIL_WORKSPACE_SOCKET";
/// Where the socket is inside a confined run.
pub const INSIDE: &str = "/run/veil/workspace.sock";
/// Hidden first argument: the `vl` the socket server runs for a request
/// (`COMMAND_ARG ROOT WS -- ARGS…`).
pub const COMMAND_ARG: &str = "__veil-workspace-command";
/// The largest request line, in bytes.
pub const MAX_REQUEST: usize = 1 << 20;

/// The workspace commands, as a refusal names them.
const ALLOWED: &str = "status, diff, log, show, blame, commit, describe (of @) and new (on top of @)";

#[derive(Serialize, Deserialize, Debug)]
struct Request {
    argv: Vec<String>,
    cwd: String,
}

/// May `cli` run through the socket? (Revisions are checked once the
/// repository is open: [`check_revisions`].)
pub fn allowed(cli: &Cli) -> Result<()> {
    if cli.repository.is_some() {
        bail!("-R is not available inside a sandbox: the workspace socket runs commands of this workspace only");
    }
    let name = match &cli.cmd {
        Cmd::Status { .. } | Cmd::Log { .. } | Cmd::Show { .. } | Cmd::Diff { .. } | Cmd::Blame(_) => return Ok(()),
        Cmd::Commit { .. } | Cmd::Describe { .. } | Cmd::New { .. } => return Ok(()),
        other => command_name(other),
    };
    bail!("`vl {name}` is not available inside a sandbox: through the workspace socket, vl runs only {ALLOWED}")
}

/// The command's name, as typed.
fn command_name(cmd: &Cmd) -> String {
    let dbg = format!("{cmd:?}");
    let word: String = dbg.chars().take_while(|c| c.is_alphanumeric()).collect();
    let mut out = String::new();
    for (i, ch) in word.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            out.push('-');
        }
        out.extend(ch.to_lowercase());
    }
    out
}

/// Every revision a socket command takes is the workspace's working-copy
/// change (`@`) or one of its ancestors: the sandbox reads only its own
/// workspace's history, never another workspace's files or the project
/// directory's (BUG-1361). `describe` only of `@`, `new` only on top of it:
/// neither moves the workspace to another tree, nor rewrites a change some
/// other workspace may hold. One exhaustive match, for every command the
/// socket runs; anything else is refused here too.
/// The check reads only what this replica holds (BUG-1803): a thin clone
/// never asks its server to place a revision a sandboxed command named, so
/// a name it cannot place locally is refused, and `--no-network` holds for
/// the check too. Another workspace's revisions (`name@`) are refused by
/// name, whatever their place in the history.
fn check_revisions(ctx: &Ctx, ws: &str, cli: &Cli) -> Result<()> {
    let store = ctx.repo.store().clone();
    store.without_fetching(|| check_revisions_here(ctx, ws, cli))
}

/// Names another workspace's revision (`name@`, `name@-`, …): any `@`
/// preceded by a name other than `ws`.
fn names_other_workspace(spec: &str, ws: &str) -> bool {
    let b = spec.as_bytes();
    (0..b.len()).filter(|&i| b[i] == b'@').any(|i| {
        let start = spec[..i].rfind(|c: char| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))).map_or(0, |j| j + 1);
        let name = &spec[start..i];
        !name.is_empty() && name != ws
    })
}

fn check_revisions_here(ctx: &Ctx, ws: &str, cli: &Cli) -> Result<()> {
    let wc = ctx.wc()?;
    let within = |spec: &str, what: &str| -> Result<()> {
        if names_other_workspace(spec, ws) {
            bail!("inside a sandbox, `vl {what}` reads this workspace's own history only: {} names another workspace", safe(spec));
        }
        let id = ctx.rev(spec)?;
        if id == wc || ctx.repo.is_ancestor(&id, &wc)? {
            return Ok(());
        }
        bail!(
            "inside a sandbox, `vl {what}` reads the workspace's own history only: {} is not @ or one of its ancestors",
            safe(spec)
        )
    };
    match &cli.cmd {
        Cmd::Status { .. } | Cmd::Commit { .. } => Ok(()),
        Cmd::Show { rev, .. } => within(rev, "show"),
        Cmd::Blame(a) => within(&a.rev, "blame"),
        Cmd::Diff { rev, from, to, .. } => {
            for r in [rev, from, to].into_iter().flatten() {
                within(r, "diff")?;
            }
            Ok(())
        }
        // `::B`, `A..B`, `..B`: ancestors of B (and A, when given); `X`: X.
        // (`parse_command` makes a plain `vl log` `::@`; `agent(…)` walks all
        // refs and is refused in favour of `--agent`.)
        Cmd::Log { filter, .. } => {
            let spec = filter.revset.as_deref().unwrap_or("::@").trim();
            if spec.strip_prefix("agent(").and_then(|r| r.strip_suffix(')')).is_some() {
                bail!(
                    "inside a sandbox, `vl log -r agent(…)` is not available (it searches outside the workspace's history): use `vl log --agent PATTERN`"
                );
            }
            if let Some(b) = spec.strip_prefix("::") {
                return within(b, "log");
            }
            match spec.split_once("..") {
                None => within(spec, "log"),
                Some((_, b)) if b.contains("..") => bail!("'{}': one `..` per range", safe(spec)),
                Some((_, b)) if b.trim().is_empty() => bail!(
                    "inside a sandbox, `vl log -r A..` is not available (it names snapshots outside the workspace's history): use `A..@` or `::@`"
                ),
                Some((a, b)) => {
                    if !a.trim().is_empty() {
                        within(a, "log")?;
                    }
                    within(b, "log")
                }
            }
        }
        Cmd::Describe { rev, .. } => match ctx.rev(rev)? == wc {
            true => Ok(()),
            false => bail!("inside a sandbox, `vl describe` describes the workspace's working-copy change (@) only"),
        },
        Cmd::New { revs, .. } => {
            for r in revs {
                if ctx.rev(r)? != wc {
                    bail!("inside a sandbox, `vl new` starts a change on top of the workspace's working-copy change (@) only");
                }
            }
            Ok(())
        }
        other => bail!("`vl {}` is not available inside a sandbox", command_name(other)),
    }
}

/// Every description the socket accepts (`commit`, `describe`, `new`) is
/// checked against the sandbox's secret-value guard (isolated files injected
/// with `--with-isolated` and sealed files checked out or mounted), so no
/// secret value enters history in plain text (BUG-1841). The refusal names
/// the source file only, never echoing the value.
fn check_description(ctx: &Ctx, root: &Path, ws: &str, cli: &Cli) -> Result<()> {
    let (what, message) = match &cli.cmd {
        Cmd::Commit { message, .. } => ("commit", message.as_str()),
        Cmd::Describe { message, .. } => ("describe", message.as_str()),
        Cmd::New { message, .. } => ("new", message.as_str()),
        Cmd::Status { .. } | Cmd::Log { .. } | Cmd::Show { .. } | Cmd::Diff { .. } | Cmd::Blame(_) => return Ok(()),
        other => bail!("`vl {}` is not available inside a sandbox", command_name(other)),
    };
    if message.is_empty() {
        return Ok(());
    }
    let paths = veil_core::sandbox::SandboxPaths::new(root, ws);
    let mut guard = paths.load_guard(&ctx.repo)?.unwrap_or_default();
    if let Some(mg) = crate::mount::Paths::new(root, ws).load_guard(&ctx.repo)? {
        guard.merge(&mg);
    }
    let only = match paths.load_manifest() {
        veil_core::sandbox::Loaded::Found(m) => m.only_set()?,
        _ => None,
    };
    let wc = ctx.wc()?;
    let store = ctx.repo.store().clone();
    store.without_fetching(|| -> Result<()> {
        if let Ok(snap) = ctx.repo.snapshot(&wc) {
            for id in std::iter::once(wc).chain(snap.parents.iter().copied()) {
                if let Ok(s) = ctx.repo.snapshot(&id) {
                    let slice = match &only {
                        Some(set) => veil_core::vfs::restrict(&store, &s.tree, set)?,
                        None => s.tree,
                    };
                    guard.add(&veil_core::sandbox::sealed_files_in_tree(&store, &slice, None));
                }
            }
        }
        Ok(())
    })?;
    if !guard.files.is_empty() {
        if let Some(f) = guard.secrets().find(message.as_bytes()) {
            bail!(
                "`vl {what}` refused: the change description holds {} ({}); change descriptions are recorded in plain text",
                safe(&f.excerpt),
                f.rule,
            );
        }
    }
    Ok(())
}

// ---- inside the sandbox --------------------------------------------------------------

/// The `vl` inside a sandbox: send the arguments to the socket and print
/// what comes back.
pub fn client_main(socket: &std::ffi::OsStr, args: Vec<OsString>) -> ExitCode {
    let out = (|| -> Result<u8> {
        let argv = args
            .into_iter()
            .map(|a| a.into_string().map_err(|_| anyhow!("an argument is not valid UTF-8")))
            .collect::<Result<Vec<_>>>()?;
        let cwd = std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
        let mut stream = UnixStream::connect(socket)
            .with_context(|| format!("the workspace socket {} does not answer (has the `vl ws exec` outside ended?)", Path::new(socket).display()))?;
        let mut line = serde_json::to_vec(&Request { argv, cwd })?;
        line.push(b'\n');
        stream.write_all(&line)?;
        let mut out = std::io::stdout().lock();
        let mut err = std::io::stderr().lock();
        loop {
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).context("the workspace socket closed the connection")?;
            let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
            let mut body = vec![0; len];
            stream.read_exact(&mut body)?;
            match head[0] {
                b'o' => out.write_all(&body)?,
                b'e' => err.write_all(&body)?,
                b'x' if len == 4 => return Ok(i32::from_be_bytes([body[0], body[1], body[2], body[3]]).clamp(0, 255) as u8),
                _ => bail!("the workspace socket sent something unexpected"),
            }
        }
    })();
    match out {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", safe(&format!("{e:#}")));
            ExitCode::FAILURE
        }
    }
}

// ---- outside: the server -----------------------------------------------------------

/// What the server does around each command: record what the sandbox
/// holds first, and keep the sandbox's record in step after.
pub trait Around: Send + Sync {
    fn before(&self) -> Result<()>;
    fn after(&self);
}

/// No recording of its own: a mount's overlay is recorded by every command
/// (`Ctx::open_for_workspace`).
pub struct Mounted;

impl Around for Mounted {
    fn before(&self) -> Result<()> {
        Ok(())
    }
    fn after(&self) {}
}

/// The prefix of a socket server's private directory, `PREFIX<pid>-<random>`.
const PREFIX: &str = "veil-ws-";

/// Remove the socket directories of `vl` processes that are gone (killed
/// before they could remove their own).
fn sweep(base: &Path) {
    let Ok(rd) = std::fs::read_dir(base) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.strip_prefix(PREFIX).and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        let ours = e.path().join("sock").exists() || e.path().join("bin").exists();
        if ours && veil_core::lock::process_alive(pid) == Some(false) {
            let _ = veil_core::vfs::remove_tree(&e.path());
        }
    }
}

/// A running socket server; stopped when dropped.
pub struct Server {
    path: PathBuf,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Serve workspace `ws` of the project at `root`, whose sandbox is the
    /// directory `sandbox` (where an unconfined command runs).
    pub fn start(root: &Path, ws: &str, sandbox: &Path, around: Box<dyn Around>) -> Result<Server> {
        // A socket's path must fit `sun_path` (104 bytes on macOS, whose
        // `$TMPDIR` alone is long): the first of these where it does.
        let name_len = PREFIX.len() + 10 + 1 + 12 + "/sock".len();
        let base = [std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from), Some(std::env::temp_dir()), Some(PathBuf::from("/tmp"))]
            .into_iter()
            .flatten()
            .find(|d| d.is_absolute() && d.is_dir() && d.as_os_str().len() + 1 + name_len < 100)
            .ok_or_else(|| anyhow!("no directory for the workspace socket: $XDG_RUNTIME_DIR, $TMPDIR and /tmp are too long or missing"))?;
        sweep(&base);
        let dir = base.join(format!(
            "{PREFIX}{}-{}",
            std::process::id(),
            hex::encode(veil_core::crypto::random_bytes::<6>())
        ));
        veil_core::vfs::private_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // This `vl`, for an unconfined command's `PATH` (a confined one
        // gets it bound at `/run/veil/bin`).
        let bin = dir.join("bin");
        veil_core::vfs::private_dir(&bin)?;
        if let Ok(exe) = std::env::current_exe() {
            std::os::unix::fs::symlink(exe, bin.join("vl")).with_context(|| format!("linking vl into {}", bin.display()))?;
        }
        let path = dir.join("sock");
        let listener = UnixListener::bind(&path).with_context(|| format!("creating the workspace socket {}", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Served {
            root: root.to_path_buf(),
            ws: ws.to_string(),
            sandbox: sandbox.to_path_buf(),
            around,
        };
        let s = stop.clone();
        let thread = std::thread::Builder::new()
            .name("veil-ws-socket".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if s.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(conn) = conn else { continue };
                    if !same_user(&conn) {
                        continue;
                    }
                    let _ = ctx.serve(conn);
                }
            })?;
        Ok(Server { path, dir, stop, thread: Some(thread) })
    }

    /// The socket, outside the sandbox.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `PATH` for an unconfined command: this `vl` first.
    pub fn path_env(&self) -> OsString {
        let mut p = self.dir.join("bin").into_os_string();
        if let Some(old) = std::env::var_os("PATH").filter(|o| !o.is_empty()) {
            p.push(":");
            p.push(old);
        }
        p
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
        let _ = veil_core::vfs::remove_tree(&self.dir);
    }
}

/// Is the peer of `conn` this user?
fn same_user(conn: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: u32::MAX, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt fills `cred`, of the size given.
    let r = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    // SAFETY: getuid has no preconditions.
    r == 0 && cred.uid == unsafe { libc::getuid() }
}

struct Served {
    root: PathBuf,
    ws: String,
    sandbox: PathBuf,
    around: Box<dyn Around>,
}

fn frame(conn: &mut UnixStream, tag: u8, body: &[u8]) -> std::io::Result<()> {
    let mut head = [tag, 0, 0, 0, 0];
    head[1..].copy_from_slice(&(body.len() as u32).to_be_bytes());
    conn.write_all(&head)?;
    conn.write_all(body)
}

impl Served {
    fn serve(&self, mut conn: UnixStream) -> Result<()> {
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut line = Vec::new();
        BufReader::new(&conn).take(MAX_REQUEST as u64 + 1).read_until(b'\n', &mut line)?;
        conn.set_read_timeout(None)?;
        let refuse = |conn: &mut UnixStream, msg: String, code: i32| -> Result<()> {
            frame(conn, b'e', format!("error: {}\n", safe(&msg)).as_bytes())?;
            frame(conn, b'x', &code.to_be_bytes())?;
            Ok(())
        };
        if line.len() > MAX_REQUEST || line.last() != Some(&b'\n') {
            return refuse(&mut conn, "the request is too large or incomplete".into(), 2);
        }
        let req: Request = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => return refuse(&mut conn, format!("a malformed request: {e}"), 2),
        };
        if req.argv.iter().any(|a| a.contains('\0')) {
            return refuse(&mut conn, "an argument holds a NUL".into(), 2);
        }
        let cli = match Cli::try_parse_from(std::iter::once("vl".to_string()).chain(req.argv.iter().cloned())) {
            Ok(c) => c,
            // `--help`, `--version` and usage errors, as the command line
            // prints them.
            Err(e) => {
                let code = e.exit_code();
                let text = e.render().to_string();
                let tag = if code == 0 { b'o' } else { b'e' };
                frame(&mut conn, tag, text.as_bytes())?;
                return Ok(frame(&mut conn, b'x', &code.to_be_bytes())?);
            }
        };
        if let Err(e) = allowed(&cli) {
            return refuse(&mut conn, format!("{e:#}"), 2);
        }
        if let Err(e) = self.around.before() {
            return refuse(&mut conn, format!("could not record the sandbox first: {e:#}"), 1);
        }
        // Where the command was run, as a folder of the project.
        let cwd = Path::new(&req.cwd);
        // The sandbox first: an unconfined command's lies inside the
        // project (`.veil/local/sandboxes`), a mount's outside it.
        let rel = [&self.sandbox, &self.root]
            .iter()
            .find_map(|base| cwd.strip_prefix(base).ok())
            .filter(|r| r.components().all(|c| matches!(c, Component::Normal(_))))
            .filter(|r| !r.components().next().is_some_and(|c| c.as_os_str().to_str().is_some_and(veil_core::object::is_reserved_name)))
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let dir = Some(self.root.join(&rel)).filter(|d| d.is_dir()).unwrap_or_else(|| self.root.clone());
        let mut child = Command::new(std::env::current_exe()?)
            .arg(COMMAND_ARG)
            .arg(&self.root)
            .arg(&self.ws)
            .arg("--")
            .args(&req.argv)
            .current_dir(&dir)
            .env_remove(ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running the command")?;
        let (tx, rx) = mpsc::channel::<(u8, Vec<u8>)>();
        let mut readers = Vec::new();
        for (tag, pipe) in [(b'o', child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>)), (b'e', child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>))] {
            let Some(mut pipe) = pipe else { continue };
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || {
                let mut buf = vec![0; 64 << 10];
                while let Ok(n) = pipe.read(&mut buf) {
                    if n == 0 || tx.send((tag, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);
        let mut gone = false;
        for (tag, chunk) in rx {
            if !gone && frame(&mut conn, tag, &chunk).is_err() {
                // The caller went away: stop the command.
                gone = true;
                let _ = child.kill();
            }
        }
        for r in readers {
            let _ = r.join();
        }
        let status = child.wait()?;
        self.around.after();
        let code = {
            use std::os::unix::process::ExitStatusExt;
            status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
        };
        if !gone {
            frame(&mut conn, b'x', &code.to_be_bytes())?;
        }
        Ok(())
    }
}

/// The `vl` a request runs (`COMMAND_ARG ROOT WS -- ARGS…`): the command,
/// checked again, on workspace `WS` only, with hooks off.
pub fn parse_command(args: Vec<OsString>) -> Result<(PathBuf, String, Cli)> {
    let mut it = args.into_iter();
    let (Some(root), Some(ws), Some(sep)) = (it.next(), it.next(), it.next()) else {
        bail!("usage: {COMMAND_ARG} ROOT WS -- ARGS");
    };
    if sep != "--" {
        bail!("usage: {COMMAND_ARG} ROOT WS -- ARGS");
    }
    let ws = ws.into_string().map_err(|_| anyhow!("the workspace name is not valid UTF-8"))?;
    let mut cli = Cli::try_parse_from(std::iter::once(OsString::from("vl")).chain(it))?;
    allowed(&cli)?;
    // Hooks would run outside the sandbox; a commit moves no tag (the
    // person's next push would send it: BUG-1362); a plain `vl log` shows
    // the workspace's own history, not every workspace's (BUG-1361).
    match &mut cli.cmd {
        Cmd::Commit { hooks, no_advance, .. } => {
            hooks.no_verify = true;
            *no_advance = true;
        }
        Cmd::Describe { hooks, .. } => hooks.no_verify = true,
        Cmd::Log { filter, .. } if filter.revset.is_none() => filter.revset = Some("::@".into()),
        _ => {}
    }
    Ok((PathBuf::from(root), ws, cli))
}

/// Open the repository for `cli` through the socket: workspace `ws` only.
pub fn open(root: &Path, ws: &str, cli: &Cli) -> Result<Ctx> {
    let ctx = Ctx::open_for_workspace(root, ws)?;
    check_revisions(&ctx, ws, cli)?;
    check_description(&ctx, root, ws, cli)?;
    Ok(ctx)
}
