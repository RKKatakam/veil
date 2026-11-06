# 5. Hooks and signed tags

> **Access model:** written for today's client, which restricts paths by cloaking them for a *scope*. With the server, access is the ordinary model in `docs/VISIBILITY.md` (admins, private by default, groups and managers, folder access, `public`): cloaked paths become private folders, and only secrets and embargoed changes are encrypted.

Status: design and threat review. Hooks need no format change. Annotated/signed tags are part of **format 5** (see `PLAN.md`).

## 5a. Hooks

### Design sketch

- **Hook points**, each run by `vl`, never by the engine (`crates/vl/src/hooks.rs`, new; process execution needs `os`):

  | hook | when | stdin / env | effect of non-zero exit |
  |---|---|---|---|
  | `pre-commit` | `vl commit`, `vl describe` of `@`, `serve` `commit` | env `VEIL_HOOK`, `VEIL_SNAPSHOT` (the `@` about to be committed), `VEIL_WORKSPACE`; cwd = project root | aborts the commit |
  | `commit-msg` | same, after `pre-commit` | `$1` = a temp file holding the message (`0600`, under `.veil/local/tmp/`) | aborts; an edited message is used |
  | `pre-push` | `vl push` | argv: remote name, URL (redacted by `redact_url`), `public` or `team`; stdin: one line per tag, `<tag> <snapshot> <remote-tag-or-0>` | aborts the push |
  | `post-checkout` | after `vl new`, `edit`, `ws switch` | old and new snapshot ids | none (warning only) |

- **Where hooks come from.**
  1. **Device-local hooks:** `.veil/hooks/<name>` (never synced; `.veil` is never a tree entry, BUG-002) and `$VEIL_HOME/hooks/<name>` (global). These run without asking, like `.git/hooks`: the user put them there.
  2. **Repository-suggested hooks:** a tracked file `.veilhooks` (TOML), e.g. `[pre-commit] run = ["scripts/lint.sh"]`. These run **only after a per-device trust step**:
     - `vl hooks trust` prints the file and the BLAKE3 of `.veilhooks` and of every script it names, then records them in `.veil/local/hooks-trust.json` `{version:1, trusted:[{hook, command, digests}]}`.
     - Any change to the file or a script means the hook is **untrusted again**: it does not run, and every command that would run it warns "`.veilhooks` changed since you trusted it (by change X); review with `vl hooks show`, then `vl hooks trust`".
- **Execution:**
  - `std::process::Command` with no shell; `.veilhooks` commands are argv arrays, not strings.
  - The environment is scrubbed of `VEIL_*` secrets and `GIT_*` variables. No vault variables are injected, and `vl run` is the explicit way to get them.
  - There is a timeout (`VEIL_HOOK_TIMEOUT`, default 10 min).
  - **No repository lock is held while a hook runs**, and the transaction re-checks the state afterwards (as `commands::check_current` does for split).
- `--no-verify` skips hooks for a command (Git's flag).

### Threat review

1. **Code execution from a teammate's push.** `.veilhooks` and the scripts it names arrive through `pull` or `merge`.
   - *Invariant:* a repository-suggested hook runs only if the digests of `.veilhooks` *and* of every file it names match the device's trust record. A trust record is never synced; a sandbox, a mount or `vl serve` cannot write it (only `vl hooks trust` on a terminal, or with `--yes`).
   - *Test:* a teammate changes `scripts/lint.sh` and the victim pulls and commits; the hook does not run, there is a warning, and a marker file is not created.
2. **Time-of-check to time-of-use.** The script is trusted by digest, then swapped between the hash check and `exec`.
   - *Invariant:* the hash is taken over the bytes Veil then executes: the script is copied into `.veil/local/hooks-run/<digest>` (`0700`) and that copy runs (with the interpreter given in `.veilhooks`, for example `["sh", "scripts/lint.sh"]`, run as `sh <copy>`).
   - *Test:* a race harness that rewrites the script in a loop; only the trusted bytes ever run (the script writes its own hash).
3. **Indirect execution through trusted interpreters.** `run = ["make", "lint"]` trusts `make` but not the `Makefile`.
   - *Invariant:* the trust record must name **every** repository file the command reads. `vl hooks trust` refuses commands whose argv[0] is a known build tool (`make`, `npm`, `cargo`, `just`, `pre-commit`, …) unless `--i-understand-indirect` is given, and it lists the extra files to pin (`Makefile`, `package.json`, `.pre-commit-config.yaml`).
   - This is documented as a limit: trusting `npm run lint` trusts `package.json` scripts.
   - *Revised (Git-parity fix wave 3, BUG-700–702):* "every file it names" covers every spelling (`./a`, `a//b`, `--opt=a`, `VAR=a` name `a`), and a directory the program may run (`python3 tools`, `node dir`) or that `files` lists is pinned with every file below it (capped) and copied like a script; other directories are the command's data, as the working directory is. Build tools are recognised behind launchers (`nice make`, `timeout 60 make`, `sudo -u x make`). Commands whose code is text (`sh -c`, `python3 -c`, `node -e`, …), that pass their arguments through a shell or take them from their input (`xargs`, `watch`, `parallel`), or name the project in a way no trust can pin (through `..`, by absolute path or `/proc`) are refused, `--i-understand-indirect` or not. A property test over generated argv shapes checks that every repository file a trusted command runs is pinned or makes trust refuse.
4. **Hook input leaking sealed content.** A `pre-push` hook to a public remote should see what the remote receives.
   - *Invariant:* stdin lists snapshot ids. It never lists cloaked tags for a public remote, or withheld snapshots.
   - A hook can still run `vl cat` as the user: the hook is trusted code. This is documented.
   - *Test (conformance t5401/t5571):* a public push with a cloaked tag; the hook's stdin has no cloaked tag name and no withheld id.
5. **Hook environment leaks.** An `.env` value or vault secret must not be in the hook's environment. *Invariant:* the environment is scrubbed, with an allowlist (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TMPDIR`, `VEIL_HOOK*`). *Test:* `env` in the hook, with `vl run`-style variables set in the parent, prints none of them.
6. **Deadlock and lost operations.** A hook that runs `vl status` must not deadlock on the repository lock or lose the outer command's state (BUG-361/362).
   - *Invariant:* hooks run before the transaction takes the lock. After the hook, `@` is snapshotted again; a changed tree aborts the commit with "the pre-commit hook changed files; review and commit again".
   - *Test:* a hook that runs `vl describe -m x` and edits a file; the commit is refused and nothing is lost.
7. **`vl serve` and agents.** `commit` over JSON-RPC runs the same hooks, and their output goes to the server's stderr, never into the JSON reply (a hook could print secrets). *Test:* the serve commit hook prints a canary; the JSON reply lacks it.
8. **Denial of service.** A hook that never exits is killed after the timeout with its process group, and the command fails. *Test:* `sleep 1000` with `VEIL_HOOK_TIMEOUT=1`.
9. **Sandboxes and mounts.** `ws exec` and FUSE-mounted workspaces never run hooks of their own. `vl commit` inside a sandbox runs the project's hooks only if trusted, in the sandbox directory. *Test:* an untrusted `.veilhooks` in a sandbox does not run.

## 5c. Annotated and signed tags

### Design sketch

- **Format 5:** a new object `veil:atag\n` ‖ canonical JSON `{name, target, kind:"annotated", message: Text, tagger, timestamp, signature?}`, and `oplog::Tag` gains `annotation: Option<ObjectId>`. The new field is in the view, so a format bump is needed (FORMAT.md rule 1: an old vl rewriting a remote view would drop it).
- The signature is `Ed25519(identity signing key, SIG_PREFIX ‖ "tag" ‖ 0 ‖ unsigned-id)`. The new context `SIG_CONTEXT_TAG = "tag"` goes in `crypto/domains.rs`, pinned by its unit test.
- **CLI:** `vl tag set NAME -r REV -a -m MSG` (annotated, signed when an identity exists) and `vl tag verify NAME`. `vl tag list` and `api::tag_list` gain `annotated`, `signer` and `verified` (additive).
  - An annotated tag is **immutable**: `tag set` over it is refused without `--force`, which writes a new atag. That is Git's release-tag semantics.
- **Message sealing:** a cloaked tag (`--cloak S`) seals the message under `S` (`Text::Sealed`), and the atag is never pushed to public remotes (cloaked tags never are).

### Threat review

17. **Replay or transplant of a signature.** An atag signed for `v1.0 → X` is re-used for `v1.0 → Y`, or under another name.
    - *Invariant:* the signature covers the unsigned id of the canonical JSON, including `name` and `target`. The view's tag name must equal `atag.name`, or the tag is shown "unverified (name mismatch)".
    - *Test:* a forged view entry pointing at an atag of another name.
18. **A cloaked tag message on a public remote.** *Invariant:* push excludes cloaked tags and their atags, and an atag object is withheld from public remotes when `cloak` is set (`push_closure`). *Test:* a public mirror's object dump has no atag with a sealed message, and none of its plaintext.
20. **Format 4 readers.** A format-4 vl must refuse the view of a format-5 remote (FORMAT rule), not drop `annotation`. This is covered by the format-5 bump, and the test is in `format_compat.rs`.
21. **Terminal escapes in tag messages.** These go through `render::safe` and `to_json`.

## Open decisions

- **Should repository hooks ever run automatically?** *Recommendation:* never without a per-device trust step pinned by content digest. Device-local `.veil/hooks` run like Git's. Reason: hooks are code execution from anyone with push access, and Veil's threat model already treats a teammate's push as hostile input (BUG-103/122).
- **Nested Veil repositories (a Veil repository inside another).** *Recommendation:* not this round; nested Veil repositories stay unrecorded (BUG-200).
