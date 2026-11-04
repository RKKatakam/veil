<img src="assets/icon.svg" width="64" height="64" alt="">

# Veil (`vl`)

**Snapshot-first version control with per-file cloaking, engine-level secret
protection, virtual workspaces, and a storage engine that never needs a disk.**

Git assumes every byte is public, every branch is a mutable pointer, and the
working tree *is* the host filesystem. Veil drops all three assumptions:

| Git pain | Veil |
|---|---|
| `.env` leaks when `.gitignore` is wrong | `.env`, `*.pem`, SSH keys… are **isolated by the engine**; every public file is secret-scanned and **quarantined** on a hit |
| Private files need separate repos or submodules | **Cloaked** paths are encrypted per scope inside one repo; public remotes never receive them |
| Security fixes leak the moment they're merged | **Embargoed merges**: outsiders see the pre-merge tree, and none of the fix's history, until release |
| `git add` / index / detached HEAD | Every command **auto-snapshots** the working copy; stable **change ids**; undoable **op log** |
| Worktrees lock directories hostage | **Virtual workspaces** live in the DAG; agents get **in-memory overlays** in microseconds |
| Tied to the OS filesystem | Engine runs on any `StorageBackend`: disk, memory, overlay, SFTP |

## Quick start

```sh
cargo build --release          # binary at target/release/vl

cd my-project
vl init                        # creates .veil/, a default .veilpolicy, your identity and a `team` scope
vl status                      # no `add`: the working copy is already snapshotted
vl commit -m "first change"    # describe @ and start a new change on top
vl log
```

```text
@  tnkzpxlp alice 2026-11-03 23:14:49 default@ 9359028f (empty)
│  (no description set)
○  nsuvxswx alice 2026-11-03 23:14:49 main f0b52e3c
│  first change
◆  zzzzzzzz 72edc798
   root()
```

Change ids (`tnkzpxlp`, letters k–z) are stable across rewrites; snapshot ids
(`f0b52e3c`, hex) are BLAKE3 content addresses.

## A tour

```sh
# Secrets: nothing to configure.
echo "DB_URL=postgres://…" > .env              # isolated: never snapshotted, never pushed
echo 'k = "AKIAIOSFODNN7EXAMPLE"' > cfg.js      # quarantined with a warning
vl scan                                          # CI-friendly: exit 1 if a public file holds a secret
vl secret import .env && vl run -- ./server      # encrypted device-local vault → env vars

# Cloaking: encrypted for a scope, inside the same repository.
vl cloak secrets/ --scope team
vl scope grant team veil1<bob's public key> --name bob   # from bob's `vl identity show`
vl scope revoke team veil1<…>   # rotates the key: new content is unreadable to them
vl remote add origin alice@build.example.com:repos/proj   # any SSH server: no vl needed there
vl remote add mirror ../public-mirror --public
vl push origin        # team members receive ciphertext + key rings
vl push mirror        # cloaked blobs and cloaked tags are withheld

# Delayed-visibility merge (e.g. a security fix), developed out of sight.
vl ws new fix-cve -r main --cloak team            # or any change not on `main`
vl merge fix-cve@ --into main --embargo --until +7d -m "Fix CVE-…"
vl push mirror        # the mirror shows main's pre-merge tree: no new names, sizes or message,
                      # and the fix's own history is withheld (the merge's extra parent is redacted)
vl embargo release <id>   # (or automatically after 7 days)
vl push mirror        # same snapshot ids, now readable, and the fix's history follows
# Until release, outsiders keep seeing the pre-merge tree, even for commits made on
# top of the merge, and cannot commit on top of it; a tag that would publish the fix
# by another route is skipped by `vl push`.

# Visibility never widens by accident: rebase, `vl new`, squash and policy edits that
# arrive by merge keep sealed files sealed. Publishing is explicit: `vl merge` of a
# cloaked line (secret-scanned; it lists what it published) or `vl expose`.

# Virtual workspaces: no directories, no collisions.
vl ws new agent                                   # exists only in the DAG
vl ws exec agent -m "lint fixes" -- cargo fmt     # runs in a throwaway sandbox, records the result
vl ws exec --ephemeral -r main -- ./codegen.sh    # one-shot agent task on main
vl ws switch agent                                # attach the project dir to another workspace

# Everything is an operation.
vl op log
vl undo
```

## CLI grammar

```text
vl <command> [args]     global: -R <repo>  --no-snapshot

Setup        init [path] · clone <src> [dest] · identity show|new
             (<src>, remotes: a path, ssh://[user@]host[:port]/path or [user@]host:path)
Inspect      status|st · log [-n N] · show [rev] · diff [-r rev | --from a --to b] [--stat]
             files [-r rev] · cat <path> [-r rev] · evolog [-r rev]
History      new [revs…] [-m] · commit -m · describe [-r rev] -m · edit <rev>
             abandon [rev] · rebase -s <rev> -d <dest…> · squash [-r rev]
             restore [paths…] [--from rev]
             merge <revs…> [--into rev] [-m] [--embargo] [--until TIME] [--scope S]
             embargo list|release <id> · tag list|set <name> [-r rev] [--cloak [S]]|delete
Visibility   cloak <pat…> [--scope S] · isolate <pat…> · expose <pat…> [--force] · ignore <pat…>
             policy show|check <paths…> · scan
Secrets      secret set|get|list|rm|import · run -- <cmd…>
Access       scope list|create <S>|grant <S> <pubkey> [--name] [--admin]|revoke <S> <pubkey>
             scope rotate <S> · scope log <S>
Workspaces   ws list|new <name> [-r rev] [--cloak [S]]|switch <name>|rm <name>
             ws exec <name>|--ephemeral [-r rev] [-m] [--with-isolated] -- <cmd…>
             ws cat <name> <path> · ws write <name> <path> < stdin
Op log       op log [-n N] · op restore <id> · undo · watch [--interval-ms N]
Sync         remote add <name> <path|ssh-url> [--public]|list|rm
             push [remote] [-t tag…] [--force] [--full] · pull [remote] [--full]
Maintenance  gc [--keep-ops-days N] [--grace-minutes M | --prune-now] [--level L] [--no-deltas]
```

Revisions: `@` (working copy), `name@` (another workspace), `root`, tags,
`origin/main`, change-id or snapshot-id prefixes, and `X-` / `X--` for parents.

### `.veilpolicy`

```text
# <pattern>        <tier> [scope]     — last matching rule wins
secrets/            cloak team
config/prod/**      cloak ops
*.local.json        isolate
target/             ignore
tests/fixtures/     public!           # deliberate exposure, secret scanning off
```

Built-in rules (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `*.tfstate`, …)
come first and **cannot be overridden by a plain `public` rule**, only by
`cloak` (encrypted sharing) or an explicit `public!`.

Patterns are globs; `\` escapes a character (`config\[prod\].yml`,
`my\ notes.txt`). `vl cloak|isolate|expose|ignore <path>` on an existing path
writes it escaped, so `app/[id]/` means that directory. Built-in secret rules
and `cloak`/`isolate` rules ignore case (`.ENV`, `Secrets/`). `public`,
`public!` and `ignore` rules are case-sensitive. A rule with an invalid scope
(`local`, `embargo/…`, `UPPER`), an unknown tier or no tier is treated as
`isolate`, with a warning.

## Repository layout

```text
crates/
  veil-core/   the engine library (no direct std::fs use outside DiskBackend)
    src/vfs/          StorageBackend + Disk / Memory / Overlay / SFTP backends
    src/crypto.rs     VeilEnvelope (XChaCha20-Poly1305, SIV-style nonces)
    src/identity.rs   X25519 + Ed25519 identities, key wrapping, signatures
    src/keychain.rs   signed key-ring logs, key generations, embargo records, `local`
    src/object.rs     Blob / Tree / Snapshot / Sealed objects
    src/store.rs      BLAKE3 CAS with transparent decryption, bounded caches
    src/pack.rs       packfiles (zstd, deltas, fan-out index)   src/gc.rs  garbage collection
    src/policy.rs     visibility tiers   src/secrets.rs  secret scanner
    src/builder.rs    working copy → tree (policy enforcement point)
    src/checkout.rs   tree → working copy    src/merge.rs  3-way tree merge
    src/oplog.rs      views + operation log  src/transaction.rs  auto-rebase
    src/workspace.rs  workspaces, ephemeral overlays
    src/embargo.rs    delayed-visibility merges
    src/remote.rs     visibility-filtered, incremental push / pull (packs on the wire)
    src/vault.rs      device-local encrypted vault
    tests/engine.rs   end-to-end tests, entirely in memory
  vl/          the CLI (clap)
docs/ARCHITECTURE.md  design, data model, threat model, roadmap
```

## Embedding the engine (in-memory, e.g. for agents)

```rust
use std::sync::Arc;
use veil_core::{Identity, MemoryBackend, Repo};

let backend = Arc::new(MemoryBackend::new());
let mut repo = Repo::init(backend, Some(Identity::generate("agent")), "agent")?;
let base = repo.root_id();

let ws = repo.ephemeral_workspace(base)?;       // O(1): overlay over a tree view
ws.write("src/lib.rs", "pub fn hello() {}")?;
let (snapshot, _report) = repo.commit_ephemeral(&ws, "agent: add hello")?;
drop(ws);                                       // vanishes; the snapshot remains
```

## Status

This is an MVP of the architecture: the full engine and CLI work end-to-end
and are covered by tests (`cargo test`). See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#limitations-and-roadmap) for
known limitations and what comes next (Git interop, sealed tree names,
FUSE/WASM front-ends).

### SSH remotes

A remote can live on any machine you can `ssh` to; the server needs SSH
with its SFTP subsystem and nothing else. `vl` runs your own `ssh`, so
`~/.ssh/config` host aliases, the agent, `known_hosts` and ProxyJump work as
they do for Git (`VEIL_SSH` replaces the command). Cloaked content is
encrypted before it leaves your machine. Pushes send one pack of what the
remote lacks; pulls download what they lack in a few round trips. A client
that crashes mid-push leaves a lease-based lock that the next push takes
over after at most about 45 seconds.
