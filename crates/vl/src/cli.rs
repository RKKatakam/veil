use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `vl -V`: version, the commit it was built from and the repository format
/// it reads and writes.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("VL_GIT_COMMIT"),
    ", repository format ",
    // Kept in step with `veil_core::repo::REPO_FORMAT_VERSION` by a test.
    "1",
    ")"
);

/// `vl --version`.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit: ",
    env!("VL_GIT_COMMIT"),
    "\nrepository format: 1",
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
    Init { path: Option<PathBuf> },
    /// Copy a repository (and every tag you can see) into a new directory.
    Clone { source: PathBuf, dest: Option<PathBuf> },

    // ---- inspecting -------------------------------------------------------
    /// Show working-copy changes, local-only files and conflicts.
    #[command(visible_alias = "st")]
    Status,
    /// Show the snapshot graph.
    Log {
        /// Maximum number of snapshots to show.
        #[arg(short = 'n', long)]
        limit: Option<usize>,
    },
    /// Show a snapshot's metadata and diff.
    Show {
        #[arg(default_value = "@")]
        rev: String,
        #[arg(long)]
        stat: bool,
    },
    /// Show changes in a snapshot, or between two snapshots.
    Diff {
        /// Snapshot whose changes to show (default: @).
        #[arg(short, long)]
        rev: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        /// Only list changed paths.
        #[arg(long)]
        stat: bool,
    },
    /// List the files of a snapshot with their visibility.
    Files {
        #[arg(short, long, default_value = "@")]
        rev: String,
    },
    /// Print a file's content at a snapshot.
    Cat {
        path: String,
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
    /// Show how a change evolved (amends, rewrites, rebases).
    Evolog {
        #[arg(short, long, default_value = "@")]
        rev: String,
    },

    // ---- shaping history --------------------------------------------------
    /// Set the description of a change.
    Describe {
        #[arg(short, long, default_value = "@")]
        rev: String,
        #[arg(short, long)]
        message: String,
    },
    /// Start a new change on top of REVS (default: @). Several = merge.
    New {
        revs: Vec<String>,
        #[arg(short, long, default_value = "")]
        message: String,
    },
    /// Describe the working-copy change and start a new one on top.
    Commit {
        #[arg(short, long)]
        message: String,
    },
    /// Make REV the working-copy change.
    Edit { rev: String },
    /// Discard a change; descendants are rebased onto its parent.
    Abandon {
        #[arg(default_value = "@")]
        rev: String,
    },
    /// Move a change (and its descendants) onto new parents.
    Rebase {
        #[arg(short, long, visible_short_alias = 'r', default_value = "@")]
        source: String,
        #[arg(short, long, required = true)]
        destination: Vec<String>,
    },
    /// Fold a change into its parent.
    Squash {
        #[arg(short, long, default_value = "@")]
        rev: String,
    },
    /// Restore paths in the working copy from another snapshot.
    Restore {
        paths: Vec<String>,
        /// Source snapshot (default: @-).
        #[arg(long, default_value = "@-")]
        from: String,
    },
    /// Merge REVS into the current line of work.
    Merge {
        #[arg(required = true)]
        revs: Vec<String>,
        /// Merge into this snapshot (default: @, or @- if @ is empty).
        #[arg(long)]
        into: Option<String>,
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
        #[arg(required = true)]
        patterns: Vec<String>,
        #[arg(long, default_value = "team")]
        scope: String,
    },
    /// Keep matching paths local-only: never snapshotted, never synced.
    Isolate {
        #[arg(required = true)]
        patterns: Vec<String>,
    },
    /// Make matching paths public.
    Expose {
        #[arg(required = true)]
        patterns: Vec<String>,
        /// Also allow built-in secret paths and disable secret scanning.
        #[arg(long)]
        force: bool,
    },
    /// Do not track matching paths at all.
    Ignore {
        #[arg(required = true)]
        patterns: Vec<String>,
    },
    /// Inspect the visibility policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Scan the working copy for secrets that would become public.
    Scan,

    // ---- secrets & identities ---------------------------------------------
    /// Device-local encrypted secret vault.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Run a command with vault secrets injected as environment variables.
    Run {
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
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
    /// Undo the last operation.
    Undo,
    /// Snapshot continuously as files change.
    Watch {
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },

    // ---- sync -------------------------------------------------------------
    /// Manage remotes.
    #[command(subcommand)]
    Remote(RemoteCmd),
    /// Send tags and their history to a remote (visibility-filtered).
    Push {
        #[arg(default_value = "origin")]
        remote: String,
        /// Only push these tags.
        #[arg(short, long)]
        tag: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Fetch tags and history from a remote.
    Pull {
        #[arg(default_value = "origin")]
        remote: String,
    },

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
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page (`vl man | man -l -`), or write one page per
    /// command into DIR.
    Man {
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TagCmd {
    /// List tags.
    List,
    /// Create or move a tag.
    Set {
        name: String,
        #[arg(short, long, default_value = "@")]
        rev: String,
        /// Cloak the tag: never pushed to public remotes.
        #[arg(long, value_name = "SCOPE", num_args = 0..=1, default_missing_value = "team")]
        cloak: Option<String>,
        #[arg(long)]
        allow_backwards: bool,
    },
    /// Delete a tag.
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum EmbargoCmd {
    /// List embargoes.
    List,
    /// Publish an embargo key now.
    Release { id: String },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Show all rules, built-in first.
    Show,
    /// Explain how paths are classified.
    Check {
        #[arg(required = true)]
        paths: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    /// Store a secret (reads VALUE from stdin if omitted).
    Set { name: String, value: Option<String> },
    /// Print a secret.
    Get { name: String },
    /// List secret names.
    List,
    /// Delete a secret.
    Rm { name: String },
    /// Import KEY=VALUE lines from a dotenv file.
    Import { file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum IdentityCmd {
    /// Show your identity and public key.
    Show,
    /// Create a new identity (replaces the existing one with --force; the
    /// replaced one is kept so local vaults can be re-keyed).
    New {
        #[arg(long)]
        name: Option<String>,
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
}

#[derive(Subcommand, Debug)]
pub enum ScopeCmd {
    /// List scopes and members.
    List,
    /// Create a scope with you as the only member.
    Create { name: String },
    /// Give an identity access to a scope (admins only). Use the full public
    /// key from `vl identity show` so the member's signatures are recognised.
    Grant {
        scope: String,
        public_key: String,
        #[arg(long, default_value = "member")]
        name: String,
        /// Make the member an admin (may grant, revoke and rotate).
        #[arg(long)]
        admin: bool,
    },
    /// Remove an identity from a scope and rotate its key (admins only).
    Revoke { scope: String, public_key: String },
    /// Start a new key generation for the current members (admins only).
    Rotate { scope: String },
    /// Show the signed membership log of a scope.
    Log { scope: String },
}

#[derive(Subcommand, Debug)]
pub enum WsCmd {
    /// List workspaces.
    List,
    /// Create a virtual workspace (no directory is created).
    New {
        name: String,
        /// Base revision (default: the parents of @, like a fresh checkout).
        #[arg(short, long)]
        rev: Option<String>,
        /// Cloak everything recorded in this workspace (default scope: team).
        #[arg(long, value_name = "SCOPE", num_args = 0..=1, default_missing_value = "team")]
        cloak: Option<String>,
    },
    /// Attach the project directory to another workspace.
    Switch { name: String },
    /// Delete a workspace.
    Rm { name: String },
    /// Run a command inside a workspace in a throwaway directory and record
    /// the result. With --ephemeral, a one-shot workspace on REV is used.
    Exec {
        name: Option<String>,
        #[arg(long)]
        ephemeral: bool,
        /// Base revision for --ephemeral.
        #[arg(short, long, default_value = "@-")]
        rev: String,
        #[arg(short, long, default_value = "")]
        message: String,
        /// Copy local-only (isolated) files such as .env into the sandbox.
        #[arg(long)]
        with_isolated: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print a file from a workspace.
    Cat { name: String, path: String },
    /// Write stdin to a file in a workspace (in memory, no checkout).
    Write { name: String, path: String },
}

#[derive(Subcommand, Debug)]
pub enum OpCmd {
    /// Show the operation log.
    Log {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Restore the repository to the state after operation ID.
    Restore { id: String },
}

#[derive(Subcommand, Debug)]
pub enum RemoteCmd {
    /// Add a remote (a path to another Veil repository).
    Add {
        name: String,
        url: String,
        /// Public remote: cloaked content, cloaked tags and unreleased
        /// embargoes are never sent.
        #[arg(long)]
        public: bool,
    },
    /// List remotes.
    List,
    /// Remove a remote.
    Rm { name: String },
}
