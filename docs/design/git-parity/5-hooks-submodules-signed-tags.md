# 5. Hooks, submodules and signed tags

Status: design and threat review. Hooks need no format change. Submodules (gitlink entries) and annotated/signed tags are part of **format 5** (see `PLAN.md`).

## 5a. Hooks

### Design sketch

- **Hook points**, each run by `vl`, never by the engine (`crates/vl/src/hooks.rs`, new; process execution needs `os`):

  | hook | when | stdin / env | effect of non-zero exit |
  |---|---|---|---|
  | `pre-commit` | `vl commit`, `vl describe` of `@`, `serve` `commit` | env `VEIL_HOOK`, `VEIL_SNAPSHOT` (the `@` about to be committed), `VEIL_WORKSPACE`; cwd = project root | aborts the commit |
  | `commit-msg` | same, after `pre-commit` | `$1` = a temp file holding the message (`0600`, under `.veil/local/tmp/`) | aborts; an edited message is used |
  | `pre-push` | `vl push`, `vl git push` | argv: remote name, URL (redacted by `redact_url`), `public` or `team` or `git`; stdin: one line per tag, `<tag> <snapshot> <remote-tag-or-0> <public-commit?>`; for `vl git push`, then the Git tags it sends in Git's format, `refs/tags/<n> <object> refs/tags/<n> <remote-or-zeros>` (BUG-641) | aborts the push |
  | `post-checkout` | after `vl new`, `edit`, `ws switch` | old and new snapshot ids | none (warning only) |

- **Where hooks come from.**
  1. **Device-local hooks:** `.veil/hooks/<name>` (never synced; `.veil` is never a tree entry, BUG-002) and `$VEIL_HOME/hooks/<name>` (global). These run without asking, like `.git/hooks`: the user put them there.
  2. **Repository-suggested hooks:** a tracked file `.veilhooks` (TOML), e.g. `[pre-commit] run = ["scripts/lint.sh"]`. These run **only after a per-device trust step**:
     - `vl hooks trust` prints the file and the BLAKE3 of `.veilhooks` and of every script it names, then records them in `.veil/local/hooks-trust.json` `{version:1, trusted:[{hook, command, digests}]}`.
     - Any change to the file or a script means the hook is **untrusted again**: it does not run, and every command that would run it warns "`.veilhooks` changed since you trusted it (by change X); review with `vl hooks show`, then `vl hooks trust`".
  3. In colocated mode (feature 9), `vl hooks` can delegate `pre-commit` and `pre-push` to `.git/hooks/*` (device-local, so trusted), for the pre-commit framework.
- **Execution:**
  - `std::process::Command` with no shell; `.veilhooks` commands are argv arrays, not strings.
  - The environment is scrubbed of `VEIL_*` secrets and `GIT_*` variables (as `git/transport.rs` does). No vault variables are injected, and `vl run` is the explicit way to get them.
  - There is a timeout (`VEIL_HOOK_TIMEOUT`, default 10 min).
  - **No repository lock is held while a hook runs**, and the transaction re-checks the state afterwards (as `commands::check_current` does for split).
- `--no-verify` skips hooks for a command (Git's flag).

### Threat review

1. **Code execution from a teammate's push.** `.veilhooks` and the scripts it names arrive through `pull`, `merge`, Git import or `am`.
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
   - *Invariant:* stdin lists snapshot ids and, for public and Git remotes, the Git bridge commit of the public projection (`public-commit`). It never lists cloaked tags for a public remote, or withheld snapshots.
   - A hook can still run `vl cat` as the user: the hook is trusted code. This is documented.
   - *Test (conformance t5401/t5571):* a public push with a cloaked tag; the hook's stdin has no cloaked tag name and no withheld id.
5. **Hook environment leaks.** An `.env` value or vault secret must not be in the hook's environment. *Invariant:* the environment is scrubbed, with an allowlist (`PATH`, `HOME`, `USER`, `LANG`, `TERM`, `TMPDIR`, `VEIL_HOOK*`). *Test:* `env` in the hook, with `vl run`-style variables set in the parent, prints none of them.
6. **Deadlock and lost operations.** A hook that runs `vl status` must not deadlock on the repository lock or lose the outer command's state (BUG-361/362).
   - *Invariant:* hooks run before the transaction takes the lock. After the hook, `@` is snapshotted again; a changed tree aborts the commit with "the pre-commit hook changed files; review and commit again".
   - *Test:* a hook that runs `vl describe -m x` and edits a file; the commit is refused and nothing is lost.
7. **`vl serve` and agents.** `commit` over JSON-RPC runs the same hooks, and their output goes to the server's stderr, never into the JSON reply (a hook could print secrets). *Test:* the serve commit hook prints a canary; the JSON reply lacks it.
8. **Denial of service.** A hook that never exits is killed after the timeout with its process group, and the command fails. *Test:* `sleep 1000` with `VEIL_HOOK_TIMEOUT=1`.
9. **Sandboxes and mounts.** `ws exec` and FUSE-mounted workspaces never run hooks of their own. `vl commit` inside a sandbox runs the project's hooks only if trusted, in the sandbox directory. *Test:* an untrusted `.veilhooks` in a sandbox does not run.

## 5b. Submodules

### Design sketch

- **Format 5:** a tree entry kind `gitlink` (see `PLAN.md`). `id` names a blob whose bytes are `"<hex git commit id>\n"` (40 or 64 hex digits), plaintext or sealed like any file under the policy.
  - `EntryKind::Gitlink` lives in `object.rs`.
  - The builder never descends into a directory recorded as a gitlink; it *carries* the entry.
  - Checkout creates an empty directory, as Git does without `--recurse-submodules`.
- **Changing the pinned commit** is explicit only: `vl submodule set PATH COMMIT` or a Git import. The builder never reads the inner `.git` to follow its HEAD.
- **`vl submodule update [PATH…]`** clones or fetches with the system `git` into PATH and checks out the pinned commit.
  - The URL comes from `.gitmodules` at `@`, parsed by gix's config parser.
  - `vl submodule status` shows pinned versus checked-out commits.
- **Git bridge:** import maps mode `160000` to a gitlink entry (format 5; below format 5, today's carry-over). Export maps a *public* gitlink to `160000`; a sealed one is omitted, like any sealed entry.

### Threat review

10. **Hostile `.gitmodules` URLs** (CVE-2017-1000117, CVE-2018-17456, CVE-2020-27955 class). `url = --upload-pack=touch /tmp/x`, `ext::sh -c …`, `file:///home/u/private-repo`, `fd::`, and `url` with newlines.
    - *Invariant:* URLs go through `git::transport::validate_url` (refusing option-like values) plus a protocol allowlist passed as `GIT_ALLOW_PROTOCOL=https:ssh:git` and `-c protocol.file.allow=never` (local paths only with `--allow-local`).
    - `git` runs as `git clone --no-checkout -- <url> <dir>` with `--` and never with `--recurse-submodules`.
    - *Test:* each URL above; nothing is executed and the error names the submodule.
11. **Hostile submodule names and paths** (CVE-2018-11235: name `../../modules/x` writing into `.git/modules`, then hooks).
    - *Invariant:* a submodule *path* must equal a gitlink entry's path (a `VPath`, never `.veil`, `.git` or outside the root). The name is validated as Git's `check_submodule_name` does: no `..` component.
    - The clone goes into `.veil/local/submodules/<hash-of-name>/` with `--separate-git-dir`, never into `.git/modules`. The work tree at PATH gets a `.git` *file*.
    - *Test:* name `../../../.veil/hooks`; it is refused.
12. **The submodule's working tree is not Veil's.** Policy rules under a gitlink path cannot protect files there, because Veil does not record them and Git publishes them.
    - *Invariant:* the builder never records below a gitlink, whatever the policy says. `vl policy check vendor/sdk/secret.txt` reports "inside submodule `vendor/sdk`: not recorded by Veil; its own repository decides where it is published". `vl status` warns once if a policy rule targets a path below a gitlink.
    - *Test:* a cloak rule inside a submodule path; `policy check` warns, and nothing below it is in the tree.
13. **A nested Git repository that is not a submodule.** Today a directory holding `.git` (a vendored clone) has its files recorded (only `.git` is skipped).
    - *Recommendation:* keep that behaviour, which is Git's for an untracked nested repository (it is recorded as a gitlink only on `git add`), but warn once ("`vendor/x` is a Git repository; record it as a submodule with `vl submodule add`").
    - *Test:* the warning appears, and nothing changes in the recorded content.
14. **A sealed gitlink.** A cloaked private submodule: its commit id is sealed, export omits it, and `.gitmodules` (public) still names its URL.
    - *Invariant:* export warns when a public `.gitmodules` names a path whose gitlink is not exported ("`.gitmodules` names `vendor/private` which Git does not receive"). Veil never rewrites file content to hide it.
    - The scanner already catches tokens in `.gitmodules` URLs (URL passwords).
    - *Test:* export a sealed gitlink; there is a warning and no `160000` entry.
15. **Format and upgrade.** A gitlink entry in a format-4 repository is refused by `put_raw` (`Unsupported`), and a push of one to a format-4 remote fails with the upgrade hint. *Test:* in `format_compat.rs`.
16. **Checkout and data loss.** Checkout creates the empty directory and never removes a non-empty one that the user populated with `vl submodule update` (the "never remove what it did not materialise" rule). Switching to a tree without the gitlink leaves the directory and reports `kept`. *Test:* populate it, then `vl new root()`; the directory is still there.

## 5c. Annotated and signed tags

### Design sketch

- **Format 5:** a new object `veil:atag\n` ‖ canonical JSON `{name, target, kind:"annotated"|"lightweight-git", message: Text, tagger, timestamp, signature?, git?: {oid, raw}}`, and `oplog::Tag` gains `annotation: Option<ObjectId>`. The new field is in the view, so a format bump is needed (FORMAT.md rule 1: an old vl rewriting a remote view would drop it).
- The signature is `Ed25519(identity signing key, SIG_PREFIX ‖ "tag" ‖ 0 ‖ unsigned-id)`. The new context `SIG_CONTEXT_TAG = "tag"` goes in `crypto/domains.rs`, pinned by its unit test.
- **CLI:** `vl tag set NAME -r REV -a -m MSG` (annotated, signed when an identity exists) and `vl tag verify NAME`. `vl tag list` and `api::tag_list` gain `annotated`, `signer` and `verified` (additive).
  - An annotated tag is **immutable**: `tag set` over it is refused without `--force`, which writes a new atag. That is Git's release-tag semantics, and what feature 8 exports as `refs/tags`.
- **Message sealing:** a cloaked tag (`--cloak S`) seals the message under `S` (`Text::Sealed`), and the atag is never pushed to public remotes (cloaked tags never are).

### Threat review

17. **Replay or transplant of a signature.** An atag signed for `v1.0 → X` is re-used for `v1.0 → Y`, or under another name.
    - *Invariant:* the signature covers the unsigned id of the canonical JSON, including `name` and `target`. The view's tag name must equal `atag.name`, or the tag is shown "unverified (name mismatch)".
    - *Test:* a forged view entry pointing at an atag of another name.
18. **A cloaked tag message on a public remote.** *Invariant:* push excludes cloaked tags and their atags, and an atag object is withheld from public remotes when `cloak` is set (`push_closure`). *Test:* a public mirror's object dump has no atag with a sealed message, and none of its plaintext.
19. **Trust in Git signatures.** An imported Git tag's GPG/SSH signature is kept verbatim in `git.raw` for exact re-export but **never shown as verified**. *Invariant:* `verified` is true only for a Veil Ed25519 signature by a key the ring knows. *Test:* import a Git tag signed with a junk key; `tag verify` reports "Git signature, not verified by Veil".
20. **Format 4 readers.** A format-4 vl must refuse the view of a format-5 remote (FORMAT rule), not drop `annotation`. This is covered by the format-5 bump, and the test is in `format_compat.rs`.
21. **Terminal escapes in tag messages.** These go through `render::safe` and `to_json`.

## Open decisions

- **Should repository hooks ever run automatically?** *Recommendation:* never without a per-device trust step pinned by content digest. Device-local `.veil/hooks` run like Git's. Reason: hooks are code execution from anyone with push access, and Veil's threat model already treats a teammate's push as hostile input (BUG-103/122).
- **Submodule pointer updates from the inner HEAD.** *Recommendation:* explicit only (`vl submodule set`), since Veil has no `git add` moment and following the inner HEAD on every snapshot would read a `.git` the user may not trust.
- **Veil-native submodules (a Veil repository inside another).** *Recommendation:* not this round; nested Veil repositories stay unrecorded (BUG-200).
- **Signing Git tags so GitHub shows "Verified".** *Recommendation:* not this round. Export annotated tags unsigned (feature 8). Using the Veil Ed25519 key for SSHSIG is key reuse across protocols; if wanted later, use a separate key and an explicit `vl identity git-signing-key`.
