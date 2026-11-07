# Embedding the engine: in memory and in WebAssembly

`vl` is a thin command line over `veil-core`, the engine crate. Version
control in Veil does not need a real operating system or file system: a
repository, its working copy and its remotes are all *storage backends*,
and one of them, `MemoryBackend`, is a plain in-memory tree. The engine
also builds for `wasm32-unknown-unknown`, so it can run in a browser tab, a
Web Worker or any WebAssembly host, with no disk, threads or system clock.

Read this page if you are writing a tool, a test harness, an agent sandbox
or a web front-end that talks to `veil-core` directly. For the design, see
[ARCHITECTURE.md §13](../ARCHITECTURE.md#13-builds-without-an-operating-system-wasm).

## Two builds of one engine

| | Native (`vl`, the default) | Portable (`--no-default-features --features wasm`) |
|---|---|---|
| Targets | Linux, macOS | `wasm32-unknown-unknown`; any host, for tests |
| Storage | `DiskBackend`, `MemoryBackend`, overlays | `MemoryBackend`, overlays, or a `StorageBackend` you write (IndexedDB, OPFS, a server API) |
| Clock | system clock | the one you install with `veil_core::clock::set_clock` |
| Randomness | the OS | WebCrypto (`crypto.getRandomValues`), through getrandom's `wasm_js` backend |
| Packs (`gc`, sync) | read and written with zstd: compressed and delta entries | read with a pure-Rust decoder (every pack `vl` writes); written with *stored* entries only |
| Repository lock | waits up to 15 s, a heartbeat renews it, dead holders are detected by pid | fails at once if held; never renewed; never taken from another instance |

Both builds read and write the same repository format. A repository built
in memory by the portable engine and copied to disk opens in `vl`, and a
repository written by `vl` (packs included) opens in the portable engine.

## Using it from Rust

```toml
[dependencies]
veil-core = { version = "0.1", default-features = false, features = ["wasm"] }
```

```rust
use std::sync::Arc;
use veil_core::{clock, tree::lookup, Identity, MemoryBackend, Repo, StorageBackend, VPath};

// Time: install a clock before recording anything (in a browser, Date.now()).
clock::set_clock(Arc::new(|| js_now_millis()));

let fs = Arc::new(MemoryBackend::new());
let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice")?;

fs.write(&VPath::new("src/lib.rs")?, b"pub fn answer() -> u32 { 42 }\n")?;
repo.snapshot_workspace("default", &*fs)?;
let (commit, _) = repo.commit_working_copy("default", "first")?;

let tree = repo.snapshot(&commit)?.tree;
let entry = lookup(repo.store(), &tree, &VPath::new("src/lib.rs")?)?.unwrap();
assert_eq!(repo.store().read_entry(&entry)?, b"pub fn answer() -> u32 { 42 }\n");
```

[`crates/veil-core/examples/wasm_smoke.rs`](../../crates/veil-core/examples/wasm_smoke.rs)
goes further: log, diff, a secret file sealed under a scope and read
back, an outsider who cannot read it, a merge, a clone by pull into a
second in-memory repository, and `gc`. Run it on your machine with exactly
the portable feature set:

```sh
cargo run -p veil-core --example wasm_smoke --no-default-features --features wasm
```

`scripts/check-wasm.sh` builds the same example for `wasm32-unknown-unknown`
and runs it under node, with nothing but a clock and a randomness function
as imports.

## What works without an operating system

Everything in the engine that is not about the host:

* init, snapshots of a working copy in any backend, ephemeral workspaces,
  commit, describe, new, edit, abandon, rebase, squash, undo and redo, the
  operation log, revsets, tags;
* trees, diffs and three-way merges, including conflicts;
* identities created in memory, scopes, sealing and unsealing, key rings
  and grants, embargoes, the vault, snapshot signatures;
* `.veilpolicy` tiers and the secret scanner, which runs on every snapshot
  as it does in `vl`;
* sync between backends (push, pull, clone), `fsck` and `gc`.

Not available: `DiskBackend` and `vl` itself.

## Things to know

* **Install a clock.** On `wasm32-unknown-unknown` there is no system
  clock. Until you call `clock::set_clock`, the engine's time is 0 (1 January 1970).
  That is safe (no embargo deadline passes, no grace period ends, nothing
  expires early) but every snapshot is stamped 1970.
* **One writer per repository.** Without an operating system the lock
  cannot tell whether another instance (another tab, another worker) is
  alive, so it never takes over a lock held by someone else. If an
  instance dies while holding the lock of a *shared, persistent* backend,
  the lock file `.veil/lock` stays behind until you remove it; the same
  goes for a lock file copied in with a repository from disk. Within one
  instance, a lock it leaked is reclaimed at once.
* **Packs written without zstd are bigger.** `gc` and sync still work and
  write ordinary packs, but every entry is stored uncompressed. Running
  `vl gc` on the repository later recompresses everything.
* **Randomness in a browser** comes from WebCrypto through the `wasm_js`
  backend of the `getrandom` crate, which needs `wasm-bindgen` for its
  JavaScript glue (wasm-pack or `wasm-bindgen-cli` provide it). For a
  plain WebAssembly host without JavaScript glue, build with
  `RUSTFLAGS='--cfg getrandom_backend="custom"'` and the `ruzstd`
  feature instead of `wasm`, and supply randomness yourself, as the example
  does.
* **Size.** The example compiles to about 4 MB of WebAssembly in a release
  build (1.2 MB gzipped), and 2.2 MB (0.85 MB gzipped) with
  `opt-level = "z"`, fat LTO and stripped symbols.
