# 7. Agent attribution

> **Owner, 2026-11-06:** attribution (`agent`, `task`, `prompt`) is **never encrypted**. It's plain text behind the server's permissions, visible to exactly the people who can see the change. The `Sealed` variants below describe older plans and are dropped.

Status: design and threat review, **not built** (Scion 4.6). It is built with the server's agent work (`docs/design/scion-for-developers.md`, phase 2). Where this document seals text "for a scope" or "for a cloaked line", it describes today's client; on the server, see "Sealing" below. **Requires format 6:** a new snapshot field. `Snapshot` is decoded without `deny_unknown_fields`, so an older vl would silently drop the field when it rewrites a snapshot (`FORMAT.md` §4 rule 1), and its signature would no longer verify.

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
    pub prompt: Option<Text>,     // a prompt reference (URL, transcript id, digest); Plain or Sealed (as `description`)
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

- **`task` and `prompt` follow the description:** `embargo::description_scope(store, tree, cloak)`, as `Transaction::new_change` does. On the server, that means plain text, visible to exactly the people who can see the change (`docs/VISIBILITY.md`); under an unreleased embargo, sealed with the embargo key.
- **Prompt references can stay on the device.** With `--prompt-local` (or by device setting, `.veil/local/attribution.json`), the prompt reference is **not put in the snapshot**. It goes to a device-local side record, `.veil/local/attribution/<snapshot id>` (0600).
- In today's client, which still restricts paths by cloaking, `task` and `prompt` on a cloaked line are sealed for the cloak's scope, exactly as the description is.

### Signatures

- The attribution is inside the snapshot, so `Snapshot::signature` (over `unsigned_id`, context `snapshot`) covers it. The signer is the identity running `vl`, so **the attribution is that member's claim** about which agent produced the change.
- No new signing context is needed. `unsigned_id` is the BLAKE3 of the canonical encoding without `signature`, so it already commits to the field set: a snapshot with an `agent` field can never share an unsigned id with one without it. `CRYPTO.md` records this argument (open decision 2).

### Rewrites

- **Kept** on rebase, auto-rebase, describe and `restore` (as `author` is kept).
- **Squash keeps the destination's attribution.** The sources stay in `predecessors`, so `vl evolog` shows each one's attribution.
- **`vl describe --agent none`** clears it; `--agent A …` sets it.

### Reading it

- `vl log` and `vl show` print `agent: <name> · task: <task or "sealed"> · run: <id>`. The prompt is shown only by `vl show --prompt`, and only if readable.
- **`--json`**: `veil.log`/`veil.show` gain an optional `agent` object (`{agent, task?, prompt?, run?}`; a sealed field the reader cannot open is `{"sealed": true}`). This is an addition, so the schema's version number follows `docs/reference/json.md`'s rule for added fields.
- **The revset function `agent(PATTERN)`** matches the `agent` field exactly or as a glob. **`vl log --agent PATTERN`** is shorthand for it.
- **`vl blame --agent`** adds the agent column.

## Threat review

1. **The prompt or task reaches people who can't see the change.**
   - *Invariant:* `task` and `prompt` reach exactly the people who can see the change, as its description does.
   - *Test:* a property test (extend `adversarial7` rewrites): random histories with agent-stamped changes on public, private and embargoed lines. Grep everything a person without access receives for each task and prompt string: none.
2. **Leaking through a task title on an embargoed line** (the BUG-016 class: "embargo messages published in plaintext before release").
   - *Invariant:* `task` and `prompt` are sealed exactly when and as the description is (`description_scope`).
   - *Test:* an embargoed fix made by an agent with the task "fix CVE-2026-1234 in auth". Nobody outside the embargo's groups receives "CVE-2026-1234" before release; everyone with access does after (for `task`).
3. **Spoofing or stripping from inside the sandbox.** The command sets `VEIL_AGENT`, writes a file that looks like attribution, or runs `vl describe`.
   - *Invariant:* attribution comes only from the recording `vl` process's own arguments and environment; a command inside `ws exec` cannot reach the repository (`find_root` refuses `.veil/` and the ceiling is set).
   - *Test:* a sandbox command that exports `VEIL_AGENT=evil`, writes `.veil-agent` and runs `vl describe` (which fails). The recorded snapshot's attribution is the harness's.
4. **Hostile attribution in a pulled snapshot.** ANSI escapes (`\x1b]8;;…`, `\x1b[2J`), overlong fields, or invalid UTF-8 in `agent` or `run` corrupt the terminal and logs.
   - *Invariant:* `Attribution::validate` refuses them at decode (the snapshot is `Corrupt`, as for hostile tree names); rendering escapes anything unprintable in opened `Text` too.
   - *Test:* `hostile_objects.rs`: a pulled snapshot with each hostile value. The pull skips it with a warning, and `vl log` output contains no escape byte.
5. **Signatures and format.**
   - *Invariant:* the attribution is covered by the signature, any change to it changes the id, and a format-5 store refuses it.
   - *Test:* flip one byte of `agent` in a signed snapshot: the id changes. A forged re-encoding with the original signature fails verification. `format_compat.rs`: a format-5 store's `put_raw` refuses an attributed snapshot with the upgrade hint.
6. **Silent loss in rewrites or round trips.**
   - *Invariant:* every rewrite keeps the attribution unless the user changes it; squash keeps the destination's and the evolution log keeps the rest.
   - *Test:* a property test of rebase, squash, split, duplicate and auto-rebase on attributed changes: the field equals the expected one after each.
7. **The device-local prompt record.**
   - *Invariant:* `.veil/local/attribution/` is 0700, its files 0600; it is never synced and never in a sandbox.
   - *Test:* permissions and `vl push` contents.
8. **Size abuse.** A 4 GiB prompt reference.
   - *Invariant:* 4 KiB cap on the opened text, enforced when stamping and when decoding.
   - *Test:* `--prompt-ref` of 5 KiB is refused with a message, and a pulled snapshot with one is skipped.
9. **Revset parsing.** `agent(PATTERN)` is a new surface for hostile input.
   - *Invariant:* glob only (no regex), length capped, with the same error path as other revset functions.
   - *Test:* the `adversarial_fuzz.rs` revset fuzzer gains `agent(…)`.
10. **Interactions:**
    - **secrets:** none;
    - **the history index:** not indexed (`agent()` reads snapshots; it is a filtered walk, exempt from the gate like `log -S`);
    - **mounts and sandboxes:** the flags are stored in device-local state only.


## Open decisions

1. **Agent sub-keys:** an identity-signed delegation for an agent's own Ed25519 key, so that snapshots are signed by the agent and the member's grant can be revoked.
   - *Recommendation:* no. An agent acts with its person's device identity, and nobody makes new keys for agents (`docs/VISIBILITY.md`). The person's signature covers the claim.
2. **A new signing context for attributed snapshots.**
   - *Recommendation:* no (the argument above); the crypto reviewer confirms it in `CRYPTO.md`.
4. **The default for prompt references.**
   - *Recommendation:* in the snapshot, visible to whoever can see the change; `--prompt-local` for the device-local side record (above), not an envelope inside the snapshot that nobody else can open (it would only leak its length).
