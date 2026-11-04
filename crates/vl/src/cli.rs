use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `vl -V`: version, the commit it was built from and the repository format
/// it reads and writes.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("VL_GIT_COMMIT"),
    ", repository format ",
    // Kept in step with `veil_core::repo::REPO_FORMAT_VERSION` by a test.
    "4",
    ")"
);

/// `vl --version`.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit: ",
    env!("VL_GIT_COMMIT"),
    "\nrepository format: 4",
    "\ntarget: ",
    env!("VL_TARGET"),
);

/// Veil — snapshot-first version control with cloaking, engine-level secret
/// protection and virtual workspaces.
///
/// There is no staging area: every `vl` invocation first records the working
/// copy as a snapshot of the current change. Use `vl commit -m` to finish a
/// change, `vl undo` to step back through the operation log.
#[derive(Parser, Debug)]
#[command(name = "vl", version = VERSION, long_version = LONG_VERSION, propagate_version = true, max_term_width = 100)]
pub struct Cli {
    /// Path to the repository (defaults to searching upward from the cwd).
    #[arg(short = 'R', long, global = true, value_name = "PATH")]
    pub repository: Option<PathBuf>,

    /// Do not auto-snapshot the working copy before running the command.
    #[arg(long, global = true)]
    pub no_snapshot: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    // ---- setup ------------------------------------------------------------
    /// Create a repository in PATH (default: current directory).
    Init {
        /// Directory to create the repository in (created if missing).
        path: Option<PathBuf>,
    },
    /// Copy a repository (and every tag you can see) into a new directory.
    ///
    /// SOURCE is a path, `ssh://[user@]host[:port]/path` or scp-style
    /// `[user@]host:path` (through your own `ssh`; the server needs only
    /// SSH with SFTP).
    Clone {
        /// Repository to clone: a path or an SSH URL.
        source: String,
        /// Directory to clone into (default: the source's last path component).
        dest: Option<PathBuf>,
    },

    // ---- inspecting -------------------------------------------------------
    /// Show working-copy changes, local-only files and conflicts.
    #[command(visible_alias = "st")]
    Status {
        #[command(flatten)]
        out: JsonOut,
    },
    /// Show the snapshot graph.
    Log {
        /// Maximum number of snapshots to show.
        #[arg(short = 'n', long)]
        limit: Option<usize>,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Show a snapshot's metadata and diff.
    Show {
        /// Snapshot to show.
        #[arg(default_value = "@")]
        rev: String,
        /// Only list changed paths.
        #[arg(long)]
        stat: bool,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Show changes in a snapshot, or between two snapshots.
    Diff {
        /// Snapshot whose changes to show (default: @). Not together with
        /// `--from` / `--to`, which compare two snapshots instead.
        #[arg(short, long, conflicts_with_all = ["from", "to"])]
        rev: Option<String>,
        /// Compare from this snapshot (default: @).
        #[arg(long)]
        from: Option<String>,
        /// Compare to this snapshot (default: @).
        #[arg(long)]
        to: Option<String>,
        /// Only list changed paths.
        #[arg(long)]
        stat: bool,
        #[command(flatten)]
        out: JsonOut,
    },
    /// List the files of a snapshot with their visibility.
    ///
    /// The plain listing of recorded files, kept unchanged for scripts.
    /// `vl ls` shows more: tiers as this reader sees them, and the working
    /// copy's local-only files.
    Files {
        /// Snapshot to list.
        #[arg(short, long, default_value = "@")]
        rev: String,
    },
    /// List a snapshot's files with their tier: who can read each one, and
    /// what never leaves this machine.
    ///
    /// One line per file: tier, size in bytes, path (`*` marks an
    /// executable), and a note in parentheses. Tiers: `public`;
    /// `cloaked:<scope>` (encrypted for a scope you are in);
    /// `embargoed:<id>` (under an unreleased embargo whose key you hold);
    /// `redacted` (sealed for someone else, or withheld from this
    /// repository: the note says for whom). For the working copy (`-r @`,
    /// the default) the local-only files are listed too: `isolated` (never
    /// snapshotted or pushed), `quarantined` (a secret was found in it) and,
    /// with `--all`, `ignored`. No content is ever printed.
    Ls {
        /// Files or directories to list (default: all).
        paths: Vec<String>,
        /// Snapshot to list.
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// Also list ignored files and directories (working copy only).
        #[arg(short, long)]
        all: bool,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Print a file's content at a snapshot.
    Cat {
        /// File to print.
        path: String,
        /// Snapshot to read it from.
        #[arg(short, long, default_value = "@")]
        rev: String,
    },
    /// Verify repository integrity: object hashes, reachability, key rings,
    /// embargo records and the operation log. Exits 1 on corruption.
    Fsck {
        /// Also list redacted (expected) objects and notes one by one.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Upgrade the repository (or a remote) to the newest format.
    ///
    /// Existing repositories keep working at their format without this;
    /// upgrading enables what the newer format adds (format 2: binary
    /// trees, which make `vl status` faster). Old objects keep their ids,
    /// nothing is rewritten, and older vl releases can no longer read the
    /// repository afterwards. Runs `fsck` first; resumable after a crash.
    Upgrade {
        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Upgrade this remote instead of the local repository.
        #[arg(long, value_name = "NAME")]
        remote: Option<String>,
        /// Upgrade even if fsck reports corruption.
        #[arg(long)]
        force: bool,
    },
    /// Show how a change evolved (amends, rewrites, rebases).
    Evolog {
        /// Change whose evolution to show.
        #[arg(short, long, default_value = "@")]
        rev: String,
    },

    // ---- shaping history --------------------------------------------------
    /// Set the description of a change.
    Describe {
        /// Change to describe.
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// The new description.
        #[arg(short, long)]
        message: String,
    },
    /// Start a new change on top of REVS (default: @). Several = merge.
    New {
        /// Parents of the new change.
        revs: Vec<String>,
        /// Description of the new change.
        #[arg(short, long, default_value = "")]
        message: String,
    },
    /// Describe the working-copy change and start a new one on top.
    ///
    /// Tags that pointed at the change's parent move to it (`main` follows
    /// your commits), except on a cloaked line: there only tags cloaked
    /// under the same scope move, so cloaked work never reaches `main` by
    /// accident (publish it with `vl merge`).
    Commit {
        /// Description of the change being committed.
        #[arg(short, long)]
        message: String,
        /// Move no tag, not even those at the parent.
        #[arg(long)]
        no_advance: bool,
    },
    /// Make REV the working-copy change.
    Edit {
        /// Change to edit.
        rev: String,
    },
    /// Discard a change; descendants are rebased onto its parent.
    Abandon {
        /// Change to abandon.
        #[arg(default_value = "@")]
        rev: String,
    },
    /// Move a change (and its descendants) onto new parents.
    Rebase {
        /// Change to move; its descendants follow.
        #[arg(short, long, visible_short_alias = 'r', default_value = "@")]
        source: String,
        /// New parent (repeat for a merge).
        #[arg(short, long, required = true)]
        destination: Vec<String>,
    },
    /// List unresolved conflicts, or resolve one by keeping one of its
    /// versions.
    ///
    /// With no `--ours`/`--theirs`/`--base`/`--side`, lists the conflicts
    /// of the working copy (or `-r REV`): each version with who can read
    /// it. Otherwise each conflict at or below PATHS in the working copy is
    /// replaced by the version named, exactly as it is recorded: a version
    /// sealed for a scope stays sealed for that scope, and a version with
    /// no file removes the path. To combine the versions instead, edit the
    /// file: a conflict is resolved once its markers are gone.
    #[command(group(clap::ArgGroup::new("pick").args(["ours", "theirs", "base", "side"])))]
    Resolve {
        /// Conflicted files (or directories) to resolve.
        paths: Vec<String>,
        /// List the conflicts (the default without a version to keep).
        #[arg(short, long, conflicts_with = "pick")]
        list: bool,
        /// Keep the first side: the change merged into (for a rebase, the
        /// new parent).
        #[arg(long)]
        ours: bool,
        /// Keep the other side of a two-sided conflict.
        #[arg(long)]
        theirs: bool,
        /// Keep the base of a two-sided conflict.
        #[arg(long)]
        base: bool,
        /// Keep side N (1-based) of a conflict with any number of sides.
        #[arg(long, value_name = "N")]
        side: Option<usize>,
        /// Snapshot whose conflicts to list.
        #[arg(short, long, default_value = "@", conflicts_with = "pick")]
        rev: String,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Split a change in two: what you choose, then the rest.
    ///
    /// The first change, on the original's parents, holds what you choose:
    /// the changes at PATHS, the hunks named by `--hunks` or `--plan`, or
    /// the hunks you pick with `-i`. It gets a new change id and the
    /// description given with `-m` (none by default). The second change,
    /// its child, holds the rest and stays the change you split: the same
    /// change id, description and files, so its descendants, tags and the
    /// working copy follow it with nothing to rebase. No file changes
    /// visibility: a cloaked file's hunks stay sealed for its scope in both
    /// halves. Hunks of a file you cannot read, of a binary or conflicted
    /// file, or of a file whose visibility this change alters cannot be
    /// chosen one by one: such a file moves whole. A split that would leave
    /// either change empty is refused.
    Split {
        /// Files or directories whose changes go in the first change (with
        /// `-i`: the files to ask about).
        paths: Vec<String>,
        /// Change to split.
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// Description of the first change.
        #[arg(short, long)]
        message: Option<String>,
        #[command(flatten)]
        pick: PickArgs,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Move a change, or part of it, into its parent or another change.
    ///
    /// With no PATHS and no `-i`, `--hunks` or `--plan`, the whole change
    /// moves and is abandoned, its description joined to the destination's.
    /// Otherwise only what you choose moves; the change keeps the rest (and
    /// its description), and is abandoned only if nothing is left.
    /// Descendants are rebased. Squashing into a cloaked change seals what
    /// it brings for that change's scope.
    Squash {
        /// Files or directories whose changes move (with `-i`: the files to
        /// ask about).
        paths: Vec<String>,
        /// Change to fold into its parent (or into `--into`).
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// Move into this change instead of the parent (an ancestor, a
        /// descendant or an unrelated change).
        #[arg(long, value_name = "REV")]
        into: Option<String>,
        #[command(flatten)]
        pick: PickArgs,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Restore paths in the working copy from another snapshot.
    Restore {
        /// Paths to restore (default: every path).
        paths: Vec<String>,
        /// Source snapshot (default: the parent of @; for a merge, its
        /// merged parents, which is what `vl status` compares with).
        #[arg(long)]
        from: Option<String>,
    },
    /// Merge REVS into the current line of work.
    Merge {
        /// Snapshots to merge in.
        #[arg(required = true)]
        revs: Vec<String>,
        /// Merge into this snapshot (default: @, or @- if @ is empty).
        #[arg(long)]
        into: Option<String>,
        /// Description of the merge (default: "merge REVS").
        #[arg(short, long)]
        message: Option<String>,
        /// Delayed-visibility merge: hide the merged changes from anyone
        /// outside SCOPE until released.
        #[arg(long)]
        embargo: bool,
        /// Release automatically at TIME (RFC 3339, YYYY-MM-DD, or +7d/+12h/+30m).
        #[arg(long, value_name = "TIME")]
        until: Option<String>,
        /// Scope that can see the embargoed changes before release.
        #[arg(long, default_value = "team")]
        scope: String,
    },
    /// Manage embargoes created by delayed-visibility merges.
    #[command(subcommand)]
    Embargo(EmbargoCmd),
    /// Manage tags (named pointers into the snapshot graph).
    #[command(subcommand)]
    Tag(TagCmd),

    // ---- visibility ---------------------------------------------------------
    /// Encrypt matching paths for a scope (default: team).
    Cloak {
        /// Paths or glob patterns.
        #[arg(required = true)]
        patterns: Vec<String>,
        /// Scope to encrypt for (you must hold its key).
        #[arg(long, default_value = "team")]
        scope: String,
    },
    /// Keep matching paths local-only: never snapshotted, never synced.
    Isolate {
        /// Paths or glob patterns.
        #[arg(required = true)]
        patterns: Vec<String>,
    },
    /// Make matching paths public.
    Expose {
        /// Paths or glob patterns.
        #[arg(required = true)]
        patterns: Vec<String>,
        /// Also allow built-in secret paths and disable secret scanning.
        #[arg(long)]
        force: bool,
    },
    /// Do not track matching paths at all.
    Ignore {
        /// Paths or glob patterns.
        #[arg(required = true)]
        patterns: Vec<String>,
    },
    /// Inspect the visibility policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Scan the working copy for secrets that would become public.
    ///
    /// With `--policy-from`, scan as a CI gate on a checkout (no Veil
    /// repository needed): every file counts as public, because a Git
    /// checkout publishes all of them, except what FILE marks `public!`.
    Scan {
        /// CI gate: take the rules from FILE (the base branch's
        /// `.veilpolicy`, e.g. from `git show`; an empty file for the
        /// built-in rules only) and disregard the scanned directory's own
        /// `.veilpolicy`, so a pull request cannot switch the scan off.
        #[arg(long, value_name = "FILE")]
        policy_from: Option<PathBuf>,
        #[command(flatten)]
        out: JsonOut,
    },

    // ---- secrets & identities ---------------------------------------------
    /// Encrypted secrets: the device-local vault, or a scope's team vault
    /// (`--scope`), shared with the scope's members through team remotes.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Run a command with vault secrets injected as environment variables.
    ///
    /// Loads the team vaults of the chosen scopes first, then the local
    /// vault, whose secrets override a team secret of the same name.
    /// Variables already in the environment are overridden by both. A team
    /// vault never sets variables that decide what the command runs or loads
    /// (PATH, LD_*, BASH_ENV, NODE_OPTIONS, GIT_*, …): any member of the
    /// scope could set them.
    Run {
        /// Load these scopes' team vaults (repeatable). Default: the scopes
        /// chosen with `--remember` on this device, none until then. A name
        /// set in two loaded scopes is an error unless the local vault
        /// overrides it.
        #[arg(long = "scope", value_name = "SCOPE")]
        scopes: Vec<String>,
        /// Load only the local vault, no team vault.
        #[arg(long, conflicts_with = "scopes")]
        local_only: bool,
        /// Make the given `--scope`s (or, with `--local-only`, no team
        /// vault) this device's default; the command is optional.
        #[arg(long)]
        remember: bool,
        /// Command and arguments (put them after `--`).
        #[arg(trailing_var_arg = true, required_unless_present = "remember", allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Your public-key identity.
    #[command(subcommand)]
    Identity(IdentityCmd),
    /// Key scopes and their members (identity rings).
    #[command(subcommand)]
    Scope(ScopeCmd),

    // ---- workspaces -------------------------------------------------------
    /// Virtual workspaces (replacing worktrees).
    #[command(subcommand, visible_alias = "ws")]
    Workspace(WsCmd),

    // ---- operation log ----------------------------------------------------
    /// Inspect or restore the operation log.
    #[command(subcommand)]
    Op(OpCmd),
    /// Undo the last operation; run again to go further back.
    ///
    /// Automatic snapshots (your unrecorded edits) and earlier undos are
    /// skipped, and the edits on disk are kept. `vl redo` re-applies what
    /// the latest undos took back.
    Undo,
    /// Re-apply what the latest `vl undo` took back.
    ///
    /// Successive redos take back successive undos, newest first. Any other
    /// command after an undo leaves nothing to redo.
    Redo,
    /// Snapshot continuously as files change.
    Watch {
        /// How often to snapshot, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },

    /// Serve this repository to editors and agents over a local socket.
    ///
    /// `vl serve --local` listens on `.veil/local/sock`, a Unix socket only
    /// you can connect to, and answers newline-delimited JSON-RPC 2.0: one
    /// request per line, one response per line. The read methods (`status`,
    /// `log`, `diff`, `show`, `ws.list`, `tag.list`, `op.log`, `scan`,
    /// `secret.list`) answer with exactly the document their command prints
    /// with `--json`; `snapshot`, `describe`, `new` and `commit` record
    /// operations as the commands do (`vl undo` takes them back); `watch`
    /// sends a notification whenever the operation log moves. The
    /// repository is read afresh for every request, and its lock is taken
    /// only while a request writes. Stop it with Ctrl-C or SIGTERM: the
    /// socket is removed. See docs/reference/json-rpc.md.
    Serve {
        /// Listen on the repository's local socket.
        #[arg(long, required_unless_present = "call", conflicts_with = "call")]
        local: bool,
        /// Client: send one request to the running server and print its
        /// result (for `watch`, then every notification, one per line).
        #[arg(long, value_name = "METHOD")]
        call: Option<String>,
        /// The request's parameters with `--call`: a JSON object, e.g.
        /// '{"limit": 5}'.
        #[arg(value_name = "PARAMS", requires = "call")]
        params: Option<String>,
    },

    // ---- sync -------------------------------------------------------------
    /// Manage remotes.
    #[command(subcommand)]
    Remote(RemoteCmd),
    /// Send tags and their history to a remote (visibility-filtered).
    ///
    /// `--dry-run` shows what the push would send, writing nothing to the
    /// remote (it only reads the remote's tags): which tags it creates,
    /// moves or would have rejected, how many snapshots and objects it
    /// sends and their size, and what stays here (embargoed history). For a
    /// public remote it also lists every file whose content would become
    /// public there, and the files it withholds, with the reason.
    Push {
        /// Remote to push to (default: origin; with --dry-run, every
        /// configured remote).
        remote: Option<String>,
        /// Only push these tags.
        #[arg(short, long)]
        tag: Vec<String>,
        /// Overwrite tags that diverged on the remote.
        #[arg(long)]
        force: bool,
        /// Walk and verify every object instead of skipping what the remote
        /// provably has (repairs damaged or missing objects on the remote).
        #[arg(long)]
        full: bool,
        /// Delete this tag on the remote (repeatable). Delete it here first
        /// with `vl tag delete`. Refused if someone moved it there since
        /// (unless --force). With no --tag, nothing else is pushed.
        #[arg(short, long, value_name = "TAG")]
        delete: Vec<String>,
        /// Show what would be sent, and send nothing.
        #[arg(long, conflicts_with_all = ["full", "delete"])]
        dry_run: bool,
        /// With --dry-run: print one JSON document (`veil.push.plan/1`; see
        /// docs/reference/json.md) instead of text. Errors then also print
        /// a `veil.error/1` document.
        #[arg(long, requires = "dry_run")]
        json: bool,
    },
    /// Fetch tags and history from a remote.
    Pull {
        /// Remote to pull from.
        #[arg(default_value = "origin")]
        remote: String,
        /// Walk and verify every object instead of skipping what this
        /// repository provably has (repairs damaged local objects).
        #[arg(long)]
        full: bool,
    },

    /// Two-way Git interop: import Git history, push and fetch Git remotes.
    ///
    /// Git sees exactly what a public Veil remote sees: no cloaked or
    /// isolated files, no cloaked descriptions, and the pre-merge tree of an
    /// unreleased embargo. Tags map to branches.
    #[command(subcommand)]
    Git(GitCmd),

    // ---- maintenance ------------------------------------------------------
    /// Pack objects and delete those no retained operation can reach.
    ///
    /// Unreachable objects are deleted only once they have stayed unreachable
    /// for the grace period (seen by an earlier `vl gc`), so running `vl`
    /// commands are never affected.
    Gc {
        /// Prune operations older than this many days (the current operation
        /// and its parents are always kept). Default: keep the whole op log.
        #[arg(long, value_name = "DAYS")]
        keep_ops_days: Option<f64>,
        /// Minutes an object must have been unreachable before deletion.
        #[arg(long, value_name = "MINUTES", default_value_t = 60.0)]
        grace_minutes: f64,
        /// Delete unreachable objects now (grace period 0). Unsafe while
        /// another `vl` process is running.
        #[arg(long)]
        prune_now: bool,
        /// zstd compression level for packed objects.
        #[arg(long, default_value_t = 3)]
        level: i32,
        /// Do not delta-compress successive versions of a file.
        #[arg(long)]
        no_deltas: bool,
    },
    /// Check this machine's setup and explain every problem found: identity,
    /// VEIL_HOME, the repository and its lock, the stat cache, the
    /// filesystem (case sensitivity, fsync, network mounts), the clock, the
    /// vault and leftover sandboxes. Exits 1 if anything is broken.
    Doctor {
        /// Also check that every remote can be reached.
        #[arg(long)]
        remotes: bool,
    },
    /// Print a shell completion script, e.g. `vl completions zsh > ~/.zfunc/_vl`.
    Completions {
        /// Shell to generate the script for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page (`vl man | man -l -`), or write one page per
    /// command into DIR.
    Man {
        /// Write `vl.1` and one `vl-<command>.1` page per command here.
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
}

/// How `vl split` and `vl squash` choose hunks.
#[derive(Args, Debug, Clone, Default)]
pub struct PickArgs {
    /// Choose hunk by hunk: each hunk is shown with a question (y, n, s to
    /// split it, q, a, d, ? for help). Answers are read from standard input,
    /// one per line, so they can be piped in; questions go to standard
    /// error.
    #[arg(short, long)]
    pub interactive: bool,
    /// Choose hunks without asking: PATH:LIST, where LIST is hunk numbers
    /// as `vl diff -r REV --json` lists them (from 1), `N.M` for the M-th
    /// edit of hunk N, or `mode` for the executable bit, separated by
    /// commas (`--hunks src/main.rs:1,3.2`). Repeat for more files.
    #[arg(long, value_name = "PATH:LIST", conflicts_with = "interactive")]
    pub hunks: Vec<String>,
    /// Choose from a JSON plan in FILE (`-` for standard input):
    /// `{"files": [{"path": "src/main.rs", "hunks": [1, "3.2"]}, {"path": "docs"}]}`
    /// with paths relative to the repository root; a file without `hunks`
    /// is taken whole.
    #[arg(long, value_name = "FILE", conflicts_with = "interactive")]
    pub plan: Option<PathBuf>,
}

/// `--json`, on every read command.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct JsonOut {
    /// Print one JSON document instead of text (its schema is named in its
    /// `schema` field; see docs/reference/json.md). Errors then also print a
    /// `veil.error/1` document.
    #[arg(long)]
    pub json: bool,
}

impl Cmd {
    /// Did the command ask for JSON output?
    pub fn wants_json(&self) -> bool {
        let out = match self {
            Cmd::Status { out }
            | Cmd::Log { out, .. }
            | Cmd::Show { out, .. }
            | Cmd::Diff { out, .. }
            | Cmd::Scan { out, .. }
            | Cmd::Tag(TagCmd::List { out })
            | Cmd::Secret(SecretCmd::List { out, .. })
            | Cmd::Workspace(WsCmd::List { out })
            | Cmd::Op(OpCmd::Log { out, .. })
            | Cmd::Ls { out, .. }
            | Cmd::Resolve { out, .. }
            | Cmd::Split { out, .. }
            | Cmd::Squash { out, .. } => out,
            Cmd::Push { json, .. } => return *json,
            _ => return false,
        };
        out.json
    }
}

#[derive(Subcommand, Debug)]
pub enum TagCmd {
    /// List tags.
    List {
        #[command(flatten)]
        out: JsonOut,
    },
    /// Create or move a tag.
    Set {
        /// Tag name.
        name: String,
        /// Snapshot the tag points at.
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// Cloak the tag (default scope: team): never pushed to public remotes.
        #[arg(long, value_name = "SCOPE", num_args = 0..=1, default_missing_value = "team")]
        cloak: Option<String>,
        /// Allow moving the tag to a snapshot that is not a descendant.
        #[arg(long)]
        allow_backwards: bool,
    },
    /// Delete a tag.
    Delete {
        /// Tag name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum EmbargoCmd {
    /// List embargoes.
    List,
    /// Release an embargo: show what becomes public, ask, and release it in
    /// this repository. The next push (or Git export) publishes the key;
    /// until then `vl undo` takes the release back.
    Release {
        /// Embargo id, from `vl embargo list`.
        id: String,
        /// Do not ask for confirmation (required when stdin is not a terminal).
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Show all rules, built-in first, and any change not yet accepted.
    Show,
    /// Explain how paths are classified.
    Check {
        /// Paths to classify.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Apply the working copy's .veilpolicy in full, including changes that
    /// arrived by merge, pull or checkout and weaken the protection of
    /// local files (until now held back on this device).
    Accept {
        /// Record instead the edit of .veilpolicy a command made in this
        /// virtual workspace's `vl ws exec` sandbox or mount, held back
        /// because it weakens the workspace's recorded policy.
        #[arg(long, value_name = "NAME")]
        workspace: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    /// Store a secret (reads VALUE from stdin if omitted).
    Set {
        /// Secret name (the environment variable `vl run` sets).
        name: String,
        /// Secret value (default: read from stdin, which keeps it out of
        /// your shell history).
        value: Option<String>,
        /// Store it in this scope's team vault (sealed for its members,
        /// pushed to team remotes) instead of the local vault.
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
    },
    /// Print a secret's value to stdout.
    Get {
        /// Secret name.
        name: String,
        /// Read it from this scope's team vault.
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
    },
    /// List secret names (never values).
    List {
        /// List this scope's team vault, with who last set each name and when.
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
        /// Only the names MEMBER (public key, member id or name; current or
        /// revoked) could read: the secrets to rotate when they leave.
        #[arg(long, value_name = "MEMBER", requires = "scope")]
        exposed_to: Option<String>,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Delete a secret (in a team vault: a signed deletion that syncs).
    Rm {
        /// Secret name.
        name: String,
        /// Delete it from this scope's team vault.
        #[arg(long, value_name = "SCOPE")]
        scope: Option<String>,
    },
    /// List the vault's backups of isolated files (`.env` & co), including
    /// those of files gone from the working copy (kept 30 days).
    Files,
    /// Write the vault's backup of an isolated file back into the working
    /// copy (never over an existing file).
    Recover {
        /// Path of the isolated file.
        path: String,
    },
    /// Import KEY=VALUE lines from a dotenv file.
    Import {
        /// Dotenv file to read.
        file: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum IdentityCmd {
    /// Show your identity and public key.
    Show,
    /// Create a new identity (replaces the existing one with --force; the
    /// replaced one is kept so local vaults can be re-keyed).
    New {
        /// Your name (default: $VEIL_USER, then $USER).
        #[arg(long)]
        name: Option<String>,
        /// Replace the existing identity.
        #[arg(long)]
        force: bool,
    },
    /// Re-key this repository's local vault, sealed by an identity that was
    /// replaced, to the current identity.
    RecoverVault {
        /// Identity file to recover from (default: every identity replaced
        /// by `vl identity new --force`).
        #[arg(long)]
        from: Option<std::path::PathBuf>,
    },
    /// Hand the scope admin rights of a replaced identity over to the
    /// current one, in this repository: the replaced identity signs a grant
    /// that makes the current identity an admin. Push to share it.
    RecoverAdmin {
        /// Identity file to recover from (default: every identity replaced
        /// by `vl identity new --force`, newest first).
        #[arg(long)]
        from: Option<std::path::PathBuf>,
        /// Then revoke the replaced identity from those scopes (rotates
        /// their keys). Leave it out while another device still uses it.
        #[arg(long)]
        revoke_old: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ScopeCmd {
    /// List scopes and members.
    List,
    /// Create a scope with you as the only member.
    Create {
        /// Scope name.
        name: String,
    },
    /// Give an identity access to a scope (admins only). Use the full public
    /// key from `vl identity show` so the member's signatures are recognised.
    Grant {
        /// Scope name.
        scope: String,
        /// The member's full public key, from their `vl identity show`.
        public_key: String,
        /// Display name for the member.
        #[arg(long, default_value = "member")]
        name: String,
        /// Make the member an admin (may grant, revoke and rotate).
        #[arg(long)]
        admin: bool,
    },
    /// Remove an identity from a scope and rotate its key (admins only).
    /// Lists the scope's team-vault secrets they could read: rotate them.
    Revoke {
        /// Scope name.
        scope: String,
        /// The member's public key or member id.
        public_key: String,
    },
    /// Start a new key generation for the current members (admins only).
    Rotate {
        /// Scope name.
        scope: String,
    },
    /// Show the signed membership log of a scope.
    Log {
        /// Scope name.
        scope: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum WsCmd {
    /// List workspaces.
    List {
        #[command(flatten)]
        out: JsonOut,
    },
    /// Create a virtual workspace (no directory is created).
    New {
        /// Workspace name.
        name: String,
        /// Base revision (default: the parents of @, like a fresh checkout).
        #[arg(short, long)]
        rev: Option<String>,
        /// Cloak everything recorded in this workspace (default scope: team).
        #[arg(long, value_name = "SCOPE", num_args = 0..=1, default_missing_value = "team")]
        cloak: Option<String>,
    },
    /// Attach the project directory to another workspace.
    Switch {
        /// Workspace name.
        name: String,
    },
    /// Delete a workspace, and its `ws exec` sandbox.
    Rm {
        /// Workspace name.
        name: String,
        /// Also when its sandbox holds quarantined files, which are in no snapshot.
        #[arg(long)]
        force: bool,
    },
    /// Run a command in a workspace's sandbox and record the result.
    ///
    /// Each workspace keeps one sandbox, .veil/local/sandboxes/NAME/files,
    /// between runs: a run rewrites only what changed since the last one
    /// (copy-on-write clones where the filesystem has them), and files the
    /// command leaves that are not recorded (ignored build output) stay for
    /// the next run. A second run in the same workspace waits for the first.
    /// With --ephemeral, a one-shot workspace on REV runs in a throwaway
    /// directory instead.
    ///
    /// With --only, the sandbox holds just the given files and directories
    /// (and .veilpolicy): everything else is recorded exactly as the
    /// workspace has it, and files the command writes elsewhere are not
    /// recorded (a warning lists them) and are removed from the sandbox.
    ///
    /// The command's output is never deleted when something fails: if vl
    /// is killed or the result cannot be recorded (the repository is busy),
    /// it stays in the sandbox, and the next run (or --record-only)
    /// records it first. SIGTERM and SIGHUP are forwarded to the command,
    /// as Ctrl-C is, and vl records what it left.
    Exec {
        /// Workspace to run in (or use --ephemeral).
        name: Option<String>,
        /// Run in a one-shot workspace on REV and record the result as a new change on top of it.
        #[arg(long)]
        ephemeral: bool,
        /// Base revision for --ephemeral.
        #[arg(short, long, default_value = "@-")]
        rev: String,
        /// Description to record.
        #[arg(short, long, default_value = "")]
        message: String,
        /// Copy local-only (isolated) files such as .env into the sandbox for this run (they are taken out again afterwards).
        #[arg(long)]
        with_isolated: bool,
        /// Sparse sandbox: hold only these paths (files or directories of the workspace, relative to the current directory).
        #[arg(long, value_name = "PATH", num_args = 1..)]
        only: Vec<String>,
        /// Run nothing: record what an earlier run left unrecorded (vl was killed, or recording failed).
        #[arg(long, conflicts_with_all = ["ephemeral", "with_isolated", "only", "command"])]
        record_only: bool,
        /// Command and arguments.
        #[arg(last = true, required_unless_present = "record_only")]
        command: Vec<String>,
    },
    /// Print a file from a workspace.
    Cat {
        /// Workspace name.
        name: String,
        /// File to print.
        path: String,
    },
    /// Write stdin to a file in a workspace (in memory, no checkout).
    Write {
        /// Workspace name.
        name: String,
        /// File to write.
        path: String,
    },
    /// Mount a workspace as a directory (FUSE), without checking it out.
    ///
    /// Reads come from the workspace's tree, as this identity may see it
    /// (cloaked files it cannot read are absent or show their public
    /// version, as in a checkout). Writes go to an overlay kept in
    /// .veil/local/mounts/NAME and are recorded into the workspace, through
    /// the policy and the secret scanner: by `vl ws unmount`, before every
    /// other vl command, every --record-every seconds, and when the
    /// directory is unmounted from outside. Isolated, ignored and
    /// quarantined files stay in the mount and are never recorded. Without
    /// --foreground a background process serves the mount. Needs FUSE
    /// (/dev/fuse and fusermount3 on Linux; macFUSE and a `--features
    /// macfuse` build on macOS).
    Mount {
        /// Workspace name.
        name: String,
        /// Directory to mount it at: empty, outside the project directory (created if missing).
        dir: PathBuf,
        /// Serve the mount from this process until it is unmounted (Ctrl-C unmounts).
        #[arg(long)]
        foreground: bool,
        /// Also record the mount every SECS seconds while it has changes (0: never on a timer).
        #[arg(long, value_name = "SECS", default_value_t = 60)]
        record_every: u64,
    },
    /// Record a mounted workspace and unmount it (also recovers a mount whose process died).
    Unmount {
        /// Workspace name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum OpCmd {
    /// Show the operation log.
    Log {
        /// Number of operations to show.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        #[command(flatten)]
        out: JsonOut,
    },
    /// Restore the repository to the state after operation ID.
    Restore {
        /// Operation id (or prefix), from `vl op log`.
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RemoteCmd {
    /// Add a remote: a path to another Veil repository, or an SSH remote
    /// (`ssh://[user@]host[:port]/path` or `[user@]host:path`), reached
    /// through your own `ssh` and its SFTP subsystem (`VEIL_SSH` overrides
    /// the command). Nothing but SSH is needed on the server.
    Add {
        /// Remote name.
        name: String,
        /// Path or SSH URL.
        url: String,
        /// Public remote: cloaked content, cloaked tags and unreleased
        /// embargoes are never sent.
        #[arg(long)]
        public: bool,
    },
    /// List remotes.
    List,
    /// Remove a remote.
    Rm {
        /// Remote name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum GitCmd {
    /// Import a Git repository's history (path or URL): adds it as a Git
    /// remote and creates a tag for every branch.
    Import {
        /// Git repository: a path or any URL `git` understands.
        source: String,
        /// Name of the Git remote to create.
        #[arg(long, default_value = "origin")]
        remote: String,
    },
    /// Manage Git remotes.
    #[command(subcommand)]
    Remote(GitRemoteCmd),
    /// Fetch a Git remote's branches as `<remote>/<branch>` (local tags stay).
    Fetch {
        /// Git remote.
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Fetch, then create or fast-forward local tags from the branches.
    Pull {
        /// Git remote.
        #[arg(default_value = "origin")]
        remote: String,
    },
    /// Export tags (all by default) as branches and push them.
    Push {
        /// Git remote.
        #[arg(default_value = "origin")]
        remote: String,
        /// Only push these tags.
        #[arg(short, long)]
        tag: Vec<String>,
        /// Overwrite branches that moved on the Git side (only if they still
        /// hold what was last fetched).
        #[arg(long)]
        force: bool,
        /// Delete this branch on the Git remote (repeatable). Delete its tag
        /// here first with `vl tag delete`. Refused if the branch moved since
        /// the last fetch (unless --force). With no --tag, nothing else is
        /// pushed.
        #[arg(short, long, value_name = "BRANCH")]
        delete: Vec<String>,
    },
    /// Export tags into the local bridge repository without pushing, and
    /// print the commit of each.
    Export {
        /// Only export these tags.
        #[arg(short, long)]
        tag: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum GitRemoteCmd {
    /// Add a Git remote (any URL `git` understands, or a path).
    Add {
        /// Git remote name.
        name: String,
        /// Any URL `git` understands, or a path.
        url: String,
    },
    /// List Git remotes.
    List,
    /// Remove a Git remote.
    Rm {
        /// Git remote name.
        name: String,
    },
}
