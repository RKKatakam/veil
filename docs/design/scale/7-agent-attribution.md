# 7. Agent attribution

Status: design and threat review (Scion 4.6). **Requires format 6:** a new snapshot field. `Snapshot` is decoded without `deny_unknown_fields`, so an older vl would silently drop the field when it rewrites a snapshot (`FORMAT.md` §4 rule 1), and its signature would no longer verify.

## Design sketch

### The field

```rust
// object.rs
pub struct Snapshot {
    …,
    /// Who produced this change's content: an agent, its task and a
    /// reference to its prompt (format 6). Covered by `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<Attribution>,
    pub signature: Option<Signature>,
}

pub struct Attribution {
    pub agent: String,            // "claude-code/2.3 opus-5.5"; 1–128 chars, printable, no control chars
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<Text>,       // a task id or title; Plain or Sealed (as `description`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<Text>,     // a prompt reference (URL, transcript id, digest); sealed by default
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,      // harness run or session id; [A-Za-z0-9._:-], ≤ 64
}
```

- **Encoding.** Canonical JSON, with `agent` placed before `signature`. Snapshots without it keep their bytes and ids.
- **Format gate.** `Object::min_repo_format` returns 6 for a snapshot with `agent`, and `check_storable` and the pack sink refuse it below format 6.
- **Validation** (`Attribution::validate`) runs on decode:
  - lengths: `task` and `prompt` at most 4 KiB once opened, the other fields as above;
  - characters as above;
  - otherwise the object is `Corrupt`, as a hostile tree name is (threat 4).

### Who sets it

- **`vl ws exec NAME --agent A [--task T] [--prompt-ref R] [--run ID] -- CMD`**: the recorded snapshot (`ws exec` step 7) carries it.
- **Environment read by `vl` itself:** `VEIL_AGENT`, `VEIL_AGENT_TASK`, `VEIL_AGENT_PROMPT_REF` and `VEIL_AGENT_RUN`, for agents that drive `vl` directly. Every snapshot a command *creates* gets the attribution: `commit`, `new`, `describe`, `squash`'s result, a working-copy snapshot of a new change.
- **`vl ws mount … --agent A`** stores the flags in `state.json`, and every recording is stamped.
- **The hook.** `Transaction::write_snapshot` and `rewrite` call `attribution::stamp(&mut snap, repo)` (stubbed by stream 0), which uses `Repo::set_attribution` (set once per process by the CLI).
- **What a command run inside a sandbox can do:** nothing. `vl` never resolves a repository from inside `.veil/` (`find_root`), and attribution is read only from `vl`'s own arguments and environment.

### Sealing

- **`task` and `prompt` use exactly the description's scope:** `embargo::description_scope(store, tree, cloak)`, as `Transaction::new_change` does. On a cloaked line they are sealed for the cloak's scope; under an unreleased embargo, for the embargo key.
- **`prompt` on a public change** is sealed for the **attribution scope**, set per device with `vl agent config --prompt-scope S` (`.veil/local/attribution.json`) or `VEIL_AGENT_PROMPT_SCOPE`.
  - With none configured, the prompt reference is **not put in the snapshot**. It goes to a device-local side record, `.veil/local/attribution/<snapshot id>` (sealed under `local`, 0600), and the first time `vl` prints "prompt references stay on this device; set `vl agent config --prompt-scope <scope>` to share them with a scope".
  - `--prompt-public` stores it plaintext, for open-source projects whose prompts are public.
- **`task` on a public change** is plaintext by default, like a public description; `--task-sealed` seals it for the attribution scope.

### Signatures

- The attribution is inside the snapshot, so `Snapshot::signature` (over `unsigned_id`, context `snapshot`) covers it. The signer is the identity running `vl`, so **the attribution is that member's claim** about which agent produced the change.
- No new signing context is needed. `unsigned_id` is the BLAKE3 of the canonical encoding without `signature`, so it already commits to the field set: a snapshot with an `agent` field can never share an unsigned id with one without it. `CRYPTO.md` records this argument (open decision 2).

### Rewrites

- **Kept** on rebase, auto-rebase, describe and `restore` (as `author` is kept).
- **Squash keeps the destination's attribution.** The sources stay in `predecessors`, so `vl evolog` shows each one's attribution.
- **`vl describe --agent none`** clears it; `--agent A …` sets it.
- **Git import never invents an attribution**, and the Git export does not write one (open decision 3).

### Reading it

- `vl log` and `vl show` print `agent: <name> · task: <task or "sealed"> · run: <id>`. The prompt is shown only by `vl show --prompt`, and only if readable.
- **`--json`**: `veil.log`/`veil.show` gain an optional `agent` object (`{agent, task?, prompt?, run?}`; a sealed field the reader cannot open is `{"sealed": true}`). This is an addition, so the schema's version number follows `docs/reference/json.md`'s rule for added fields.
- **The revset function `agent(PATTERN)`** matches the `agent` field exactly or as a glob. **`vl log --agent PATTERN`** is shorthand for it.
- **`vl blame --agent`** adds the agent column.

## Threat review

1. **The prompt or task reaches a public remote or Git in plaintext.**
   - *Invariant:* a sealed attribution `Text` is never plaintext outside its scope. Remotes receive the snapshot with the envelope, as for descriptions, and the Git export never includes attribution.
   - *Test:* a property test (extend `adversarial7` rewrites): random histories with agent-stamped changes on public, cloaked and embargoed lines are pushed to a public remote and exported to Git. Grep every decoded object and commit for each task and prompt string: none outside readers of the scope.
2. **Leaking through a task title on an embargoed line** (the BUG-016 class: "embargo messages published in plaintext before release").
   - *Invariant:* `task` and `prompt` are sealed exactly when and as the description is (`description_scope`).
   - *Test:* an embargoed fix made by an agent with the task "fix CVE-2026-1234 in auth". The public remote and Git hold no "CVE-2026-1234" before release, and do after (for `task`).
3. **Spoofing or stripping from inside the sandbox.** The command sets `VEIL_AGENT`, writes a file that looks like attribution, or runs `vl describe`.
   - *Invariant:* attribution comes only from the recording `vl` process's own arguments and environment; a command inside `ws exec` cannot reach the repository (`find_root` refuses `.veil/` and the ceiling is set).
   - *Test:* a sandbox command that exports `VEIL_AGENT=evil`, writes `.veil-agent` and runs `vl describe` (which fails). The recorded snapshot's attribution is the harness's.
4. **Hostile attribution from a remote.** ANSI escapes (`\x1b]8;;…`, `\x1b[2J`), overlong fields, or invalid UTF-8 in `agent` or `run` corrupt the terminal and logs.
   - *Invariant:* `Attribution::validate` refuses them at decode (the snapshot is `Corrupt`, as for hostile tree names); rendering escapes anything unprintable in opened `Text` too.
   - *Test:* `hostile_objects.rs`: a pulled snapshot with each hostile value. The pull skips it with a warning, and `vl log` output contains no escape byte.
5. **Signatures and format.**
   - *Invariant:* the attribution is covered by the signature, any change to it changes the id, and a format-5 store refuses it.
   - *Test:* flip one byte of `agent` in a signed snapshot: the id changes. A forged re-encoding with the original signature fails verification. `format_compat.rs`: a format-5 store's `put_raw` refuses an attributed snapshot with the upgrade hint.
6. **Silent loss in rewrites or round trips.**
   - *Invariant:* every rewrite keeps the attribution unless the user changes it; squash keeps the destination's and the evolution log keeps the rest.
   - *Test:* a property test of rebase, squash, split, duplicate, `am` and auto-rebase on attributed changes: the field equals the expected one after each.
7. **The device-local prompt record.**
   - *Invariant:* `.veil/local/attribution/` is 0700, its files 0600 and sealed under `local`; it is never synced, never in a sandbox, never exported.
   - *Test:* permissions and `vl push`/`vl git push` contents.
8. **Size abuse.** A 4 GiB prompt reference.
   - *Invariant:* 4 KiB cap on the opened text, enforced when stamping and when decoding.
   - *Test:* `--prompt-ref` of 5 KiB is refused with a message, and a pulled snapshot with one is skipped.
9. **Revset parsing.** `agent(PATTERN)` is a new surface for hostile input.
   - *Invariant:* glob only (no regex), length capped, with the same error path as other revset functions.
   - *Test:* the `adversarial_fuzz.rs` revset fuzzer gains `agent(…)`.
10. **Interactions:**
    - **colocated Git:** not exported;
    - **the team vault:** none;
    - **the history index:** not indexed (`agent()` reads snapshots; it is a filtered walk, exempt from the gate like `log -S`);
    - **mounts and sandboxes:** the flags are stored in device-local state only.

    - *Test:* a colocated repository with an attributed commit: `git log --format=%B` shows no attribution.

## Open decisions

1. **Agent sub-keys:** an identity-signed delegation for an agent's own Ed25519 key, so that snapshots are signed by the agent and the member's grant can be revoked.
   - *Recommendation:* defer to the Hub (Scion 4.5 needs per-agent credentials anyway). This round, the member's signature covers the claim.
2. **A new signing context for attributed snapshots.**
   - *Recommendation:* no (the argument above); the crypto reviewer confirms it in `CRYPTO.md`.
3. **Git trailers** (`Veil-Agent: …`).
   - *Recommendation:* not this round. It is easy to add for public changes later; plaintext rules for sealed fields would need care.
4. **The default for prompts without an attribution scope.**
   - *Recommendation:* the device-local side record (above), not a `local`-sealed envelope inside the snapshot: ciphertext nobody else can open would only leak its length.
