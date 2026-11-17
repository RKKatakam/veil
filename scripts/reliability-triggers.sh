#!/usr/bin/env bash
# Diff-triggered reliability checklist matcher for Veil.
#
# Usage:
#   scripts/reliability-triggers.sh [<git-range>]
#   scripts/reliability-triggers.sh --stdin < patch.diff
#   scripts/reliability-triggers.sh --self-test
#
# Default <git-range> is integration...HEAD. Prints the ID and title of each
# item in docs/RELIABILITY.md whose trigger matches the diff.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  scripts/reliability-triggers.sh [<git-range>]
  scripts/reliability-triggers.sh --stdin
  scripts/reliability-triggers.sh --self-test

Given a git diff range (default: integration...HEAD), prints the IDs and titles
of docs/RELIABILITY.md checklist items whose triggers match the diff.
EOF
}

# Extract touched file paths (CHANGED_FILES) and "<path>\t<added-line>" records
# (ADDED_LINES) from unified-0 diff text on stdin. Skips generated/log/review
# files and pure // comment lines in Rust sources so prose in docs/BUGS.md or
# comments does not cause false-positive trigger noise.
parse_unified_diff() {
    awk '
        function skipped(p) {
            return p == "" ||
                   p == "/dev/null" ||
                   p == "Cargo.lock" ||
                   p == "docs/BUGS.md" ||
                   p == "docs/RELIABILITY.md" ||
                   p == "docs/review-evals.md" ||
                   p == "scripts/reliability-triggers.sh" ||
                   p ~ /^docs\/reference\// ||
                   p ~ /^\.claude\/skills\//
        }
        /^diff --git a\// {
            line = $0
            sub(/^diff --git a\/.* b\//, "", line)
            cur = line
            if (!skipped(cur) && !seen[cur]++) {
                printf "F\t%s\n", cur
            }
            next
        }
        /^\+\+\+ b\// {
            cur = substr($0, 7)
            if (!skipped(cur) && !seen[cur]++) {
                printf "F\t%s\n", cur
            }
            next
        }
        /^\+\+\+ \/dev\/null$/ {
            cur = ""
            next
        }
        /^\+/ {
            if (skipped(cur)) next
            code = substr($0, 2)
            if (cur ~ /\.rs$/ && code ~ /^[[:space:]]*\/\//) next
            if (code ~ /^[[:space:]]*$/) next
            printf "A\t%s\t%s\n", cur, code
        }
    '
}

CHANGED_FILES=""
ADDED_LINES=""

load_parsed_diff() {
    local parsed
    parsed="$(parse_unified_diff)"
    CHANGED_FILES="$(awk -F'\t' '$1 == "F" { print $2 }' <<< "$parsed")"
    ADDED_LINES="$(awk -F'\t' '$1 == "A" { print $2 "\t" substr($0, index($0, "\t") + 1 + length($2) + 1) }' <<< "$parsed")"
}

# True when any touched non-skipped file path matches ERE $1.
file_matches() {
    local path_re="$1"
    [[ -n "$CHANGED_FILES" ]] && grep -Eq "^(${path_re})$" <<< "$CHANGED_FILES"
}

# True when an added line in a file matching ERE $1 matches ERE $2.
added_in() {
    local path_re="$1"
    local line_re="$2"
    [[ -n "$ADDED_LINES" ]] && grep -Eq "^(${path_re})	.*(${line_re})" <<< "$ADDED_LINES"
}

emit() {
    printf '%s\t%s\n' "$1" "$2"
}

# Evaluate all 36 triggers in docs/RELIABILITY.md against CHANGED_FILES and
# ADDED_LINES. Keep one readable block per item in ID order.
evaluate_triggers() {
    # --- Area 1: Core Invariants & Confidentiality ---

    # R-01: No Git interop, offline mode, or plain-file/SFTP remotes
    if added_in 'crates/(veil-core|vl|veil-server)/src/.*\.rs' \
       '(\.git(/|")|\b(git2|gix|git_interop|ssh2|PathRemote)\b|file://|sftp://|RemoteUrl::Path)' || \
       file_matches 'crates/vl/src/test_remotes\.rs'; then
        emit "R-01" "No Git interop, offline mode, or file/SFTP remotes"
    fi

    # R-02: Secret-only encryption, accepted-policy pin, and personal-key boundary
    if added_in 'crates/(veil-core|vl|veil-server)/src/.*\.rs' \
       '(\beffective_policy\b|\baccepted_policy\b|\.veilpolicy|\bpersonal_key\b|identity\.json|\bdevice_vouches\b|\bSealedObject\b|\bRingKey\b|\bweb_secrets\b|\bteam_secret\b)'; then
        emit "R-02" "Only secret files encrypted; accepted-policy pin and personal-key refusal"
    fi

    # R-03: Refusals, logs, and conflict reports never leak hidden paths or content
    if added_in 'crates/(veil-core|vl|veil-server)/src/(landing/.*|prs/.*|sync|error|conflict|merge|repo)\.rs' \
       '(\bAccessDenied\b|\bConflictReport\b|\bconflict_paths\b|\bconflicting_files\b|tracing::(info|warn|error)!|\beprintln!\()'; then
        emit "R-03" "Refusals, logs, and conflict reports omit hidden paths and content"
    fi

    # R-04: Upload receipts and keyed/filtered scope hashes prevent existence oracles
    if added_in 'crates/veil-server/src/(sync|grant|shares|perm|api)\.rs' \
       '(\bupload_receipt\b|\buploaded_ids\b|\breceipt\b|\bgrant_token\b|rule-|\bsecret_shares\b|blake3::keyed_hash|/rings\b)'; then
        emit "R-04" "Upload receipts on all referenced IDs and keyed/filtered scope hashes"
    fi

    # R-05: Visibility and sealing derive from objects and lineage, never entry labels alone
    if added_in 'crates/(veil-core|vl)/src/(repo|builder|merge|checkout|tree|secrets|render|history|confinement)\.rs' \
       '(\bverify_sealing\b|\bverified_visibility\b|\breconcile_sealing\b|\bdiff_trees\b|\bdiff_trees_hiding\b|\bEntryVisibility\b|Visibility::Public)'; then
        emit "R-05" "Sealing and visibility derived from objects and lineage, never labels alone"
    fi

    # R-06: Client embargo withholding keys on ChangeId and replacements across rewrites
    if added_in 'crates/(veil-core|vl)/src/(embargo|remote|blame|commands|repo|rewrite_cmd)\.rs' \
       '(\bembargo\b|\bwithheld\b|\bEmbargoRecord\b|\bembargoed_changes\b|--public|\bis_embargoed\b)'; then
        emit "R-06" "Client embargo withholding keyed on ChangeId and rewrite descent"
    fi

    # --- Area 2: Permissions, Agent Sessions & Server Embargoes ---

    # R-07: Branch moves, merges, and landings check write access across full tip-to-tip diff
    if added_in 'crates/veil-server/src/(sync|branches|changes|perm|landing/.*|prs/.*)\.rs' \
       '(\bcheck_write\b|\bcan_write\b|\bwritable\b|\bwrites_anything\b|\.veilrules|\.veilpolicy|rules\.protected|\bprotected_branch\b|\bdefault_tip\b|\bcheck_access_files\b)'; then
        emit "R-07" "Full tip-to-tip write checks and default-tip comparison on access files"
    fi

    # R-08: Route visibility and CI check footprints match caller read/write scope
    if added_in 'crates/veil-server/src/(api|ci|perm|auth|query/.*|search/.*)\.rs' \
       '(Router::new|\.route\(|\breadable_footprint\b|\brequire_read\b|\brequire_write\b|\bCheckReport\b)'; then
        emit "R-08" "Route permissions and CI check footprints scoped to caller access"
    fi

    # R-09: Narrowed agent sessions (viewer.only) cannot mutate access files, clobber change_refs, or read global /health
    if added_in 'crates/veil-server/src/(auth|perm|sync|branches|changes|api|limits/health)\.rs' \
       '(viewer\.only|\bagent_sessions\b|\bAgentTip\b|\bagent_may_\w+|\bonly_paths\b|\bchange_refs\b|\bnarrowed\b)'; then
        emit "R-09" "Narrowed agent sessions isolated on access files, change_refs, and /health"
    fi

    # R-10: Rate limits, memory pools, queue caps, and check slots aggregate per person
    if added_in 'crates/veil-server/src/(limits/.*|ci|landing/service)\.rs' \
       '(Key::Person|\badmit_queue\b|\bMAX_CHECKS\b|\bcounts_for_gate\b|body::acquire|answers::prepay|\brate_limit\b)'; then
        emit "R-10" "Per-person rate/memory accounting, merging-aware queue cap, and counting check slots"
    fi

    # R-11: Server embargoes enforce hidden_for_embargo IS NULL, stored group_names, review gates, and per-project release_due
    if added_in 'crates/veil-server/src/(embargo|prs/embargo|derive/.*|search/.*|query/.*|ci|limits/health)\.rs' \
       '(\bhidden_for_embargo\b|\bembargo_ancestry\b|\brelease_due\b|\bgroup_names\b|\bembargo_id\b)'; then
        emit "R-11" "Server embargo filtering, stored group_names, review gates, and isolated release_due"
    fi

    # --- Area 3: Database, Migrations & YugabyteDB ---

    # R-12: Index DDL runs in '-- veil: online indexes' outside transactions and checks indislive/indisready/indisvalid
    if added_in 'crates/veil-server/(migrations/.*\.sql|src/(db|main)\.rs|tests/server_hub/startup\.rs)' \
       '(CREATE[[:space:]]+(UNIQUE[[:space:]]+)?INDEX|DROP[[:space:]]+INDEX|veil:[[:space:]]*online[[:space:]]+indexes|\bpg_index\b|\bindis(live|ready|valid)\b)'; then
        emit "R-12" "Online index DDL outside transactions with indislive/indisready/indisvalid check"
    fi

    # R-13: Migration transactional DDL/DML is re-runnable after partial YugabyteDB failure
    if added_in 'crates/veil-server/(migrations/.*\.sql|src/db\.rs|tests/server_hub/startup\.rs)' \
       '(CREATE[[:space:]]+TABLE|ALTER[[:space:]]+TABLE|DROP[[:space:]]+(TABLE|COLUMN|CONSTRAINT)|ADD[[:space:]]+(COLUMN|CONSTRAINT)|not_safe_to_run_again)' || \
       added_in 'crates/veil-server/migrations/.*\.sql' \
       '(INSERT[[:space:]]+INTO|UPDATE[[:space:]]+[a-z_]+[[:space:]]+SET|DELETE[[:space:]]+FROM)'; then
        emit "R-13" "Migration DDL/DML idempotent on re-run after YugabyteDB partial failure"
    fi

    # R-14: Skewed-column queries disable generic plans (.persistent(false)) and bound ordered scans
    if added_in 'crates/veil-server/src/.*\.rs' \
       '(\.persistent\(false\)|FROM[[:space:]]+(projections|view_commits|view_fills|branch_changes)|WHERE[[:space:]]+[^"]*projected_id|ORDER[[:space:]]+BY[[:space:]]+[^"]*(projected_at|seq))'; then
        emit "R-14" "Skewed-column queries use .persistent(false) and bounded indexed ORDER BY"
    fi

    # R-15: Review-gate ordering, YugabyteDB review_writers, FOR NO KEY UPDATE hierarchy, negative writer keys, READ COMMITTED
    if added_in 'crates/veil-server/src/(prs/.*|landing/.*|perm|sync|branches|db)\.rs' \
       '(\bpg_advisory_xact_lock\b|\breview_writers\b|\breview_gate\b|FOR[[:space:]]+(NO[[:space:]]+KEY[[:space:]]+)?(UPDATE|SHARE)|\bdefault_transaction_isolation\b)'; then
        emit "R-15" "Review-gate ordering, YB review_writers, lock hierarchy, and READ COMMITTED check"
    fi

    # R-16: One DB commit per push, post-commit pg_notify (Caches::tips_moved), and unwrapped retryable sqlx::Error
    if added_in 'crates/veil-server/src/(sync|caches|events|db|derive/.*|search/.*|landing/.*)\.rs' \
       '(\bpg_notify\b|\btips_moved\b|\.commit\(\)\.await|\bis_retryable\b|40001|40P01|downcast_ref::<sqlx::Error>)'; then
        emit "R-16" "Single DB commit per push, post-commit pg_notify, and retryable sqlx::Error unwrap"
    fi

    # R-17: Database and S3 TLS parameters fail closed on unknown flags or plain HTTP
    if added_in 'crates/veil-server/src/(db|tls|store|main)\.rs' \
       '(\bsslmode\b|\bsslrootcert\b|\bPgConnectOptions\b|\bhttps_only\b|\ballow_http\b|\bdatabase_url\b|\bVEIL_S3_CA\b|verify-(ca|full))' || \
       file_matches 'vendor/sqlx-core/src/net/tls/.*\.rs'; then
        emit "R-17" "Database and S3 TLS configuration fails closed on unknown flags or HTTP"
    fi

    # --- Area 4: Object Store, Packs & Garbage Collection ---

    # R-18: GC switches and gated loose-object chunk deletes coordinate via guard_root_write, FOR UPDATE, and STAMP_TABLES
    if added_in 'crates/veil-server/(migrations/.*\.sql|src/(pack_gc|sync|bisect|changes|search/.*|embargo|prs/.*|landing/.*)\.rs)' \
       '(\bguard_root_write\b|\bSTAMP_TABLES\b|\bmark_and_sweep\b|\bgc_epoch\b|store\.delete\(|\bdelete_object\b|\bLOOSE_DELETE_CHUNK\b|\broots_at_switch\b|\bcollect_roots\b|\bGcEpochChanged\b)'; then
        emit "R-18" "GC root-writer gate (guard_root_write), STAMP_TABLES coverage, and gated S3 deletes"
    fi

    # R-19: Tree entries and tags verify target ObjectKind, canonical entry names, and separate leaf/tree GC marks
    if added_in 'crates/(veil-core/src/(tree|tag_object|fsck|gc|object)\.rs|veil-server/src/(sync|pack_gc|changes)\.rs)' \
       '(\bEntryKind\b|\bObjectKind\b|\bTreeEntry\b|\bwalk_from_roots\b|\bvalidate_entry_name\b|\bTagObject\b)'; then
        emit "R-19" "Entry/tag target ObjectKind verified, safe entry names, and separate leaf/tree GC marks"
    fi

    # R-20: Pack lookups rescan until pack_gen / forgotten count settles, and compaction locks STAGED rows
    if added_in 'crates/(veil-core/src/(store|pack|maintenance)\.rs|veil-server/src/(pack|pack_gc|store)\.rs)' \
       '(\bpack_gen\b|\bread_packed\b|\bhas_main\b|\brefresh_in\b|\brescan\b|\bSTAGED\b|\breplaced_by\b)'; then
        emit "R-20" "Pack lookups rescan until pack_gen settles and compaction locks STAGED rows"
    fi

    # R-21: Background pack merges and post-grace sweeps stay bounded under busy pushes and quiet periods
    if added_in 'crates/veil-server/src/(pack|pack_gc|sync)\.rs' \
       '(\bmaybe_schedule\b|\bmerge_tier\b|\bsweep_replaced\b|\bsweep_due\b|\bpacks_listed\b|\bpack_merge\b|\bread_whole\b|FROM[[:space:]]+packs\b|Map::weight|\bgrace\b)'; then
        emit "R-21" "Background pack merges keep up under load and sweep replaced/crashed packs after grace"
    fi

    # R-22: In-memory caches hash full scopes with BLAKE3 (never XOR) and invalidate on GC sweeps
    if added_in 'crates/veil-server/src/(caches|grant|subtree|query/.*|cache/.*|pack_gc)\.rs' \
       '(\bCaches\b|\bevict\b|\binvalidate\b|committed\.|grants\.stored|\bCacheKey\b|blake3::Hasher)'; then
        emit "R-22" "In-memory caches hash full scopes with BLAKE3 and evict on GC sweep"
    fi

    # --- Area 5: Server Concurrency, HTTP & Resource Bounds ---

    # R-23: Multi-server races on embargo::release_one, branch leases, bisect_leases, and fenced merging claims
    if added_in 'crates/veil-server/src/(embargo|bisect|landing/lease_lock|landing/service|landing/merge)\.rs' \
       '(\brelease_one\b|\bembargo_lines\b|\breleased_at\b|"not_ready"|\blease_lock\b|\bbisect_leases\b|\blease_until\b|\bmerging\b|\balready_released\b|\bNotReady\b)'; then
        emit "R-23" "Multi-server races on embargo release, branch/bisect leases, and fenced merging claims"
    fi

    # R-24: HTTP/1.1 early responses set Connection: close when body unread; idle/body/write deadlines and ALPN match
    if added_in 'crates/veil-server/src/(lib|main|api|tls|cache/.*|limits/body)\.rs' \
       '((connection|CONNECTION).*close|Connection::close|Version::HTTP_|\bis_end_stream\b|\bhttp1\b|\bhttp2\b|\balpn_protocols\b|\baccept_timeout\b|\bheader_read_timeout\b|\bConnectionLimits\b|\binto_body\b)'; then
        emit "R-24" "HTTP/1.1 unread-body Connection: close, stream deadlines, and matching ALPN"
    fi

    # R-25: Buffers, web pages, and Range reads fit longest valid input (HTTP_BUFFER >= MAX_CHAIN) and budget memory
    if added_in 'crates/veil-server/src/(cache/.*|limits/.*|web/.*|api|sync|store)\.rs' \
       '(\bHTTP_BUFFER\b|\bMAX_CHAIN\b|\bMAX_HEADER\b|\bWEB_FILE_BYTES\b|header::RANGE|\bRange\b|\bprepay\b|\bMAX_BODY\b)'; then
        emit "R-25" "Buffers fit longest valid input (HTTP_BUFFER >= MAX_CHAIN) and Range/page answers prepay budget"
    fi

    # R-26: Spawned tasks carry limits::in_request (RequestLocals), WEB_CTX fails closed, and check_same_origin requires https://
    if added_in 'crates/veil-server/src/.*\.rs' \
       '(tokio::spawn|\bspawn_blocking\b|\bin_request\b|\bRequestLocals\b|task_local!|\bWEB_CTX\b|\bcheck_same_origin\b)'; then
        emit "R-26" "Spawned tasks carry RequestLocals, WEB_CTX fails closed, and Origin requires https://"
    fi

    # R-27: Client (512 MiB) and server (1,024 MiB) 1 GB memory gates, first-entry BATCH_BYTES flush, allocator, daemon prefetch
    if added_in 'crates/(veil-core/src/(prefetch|pack|remote|blob_stream)\.rs|vl/src/(hub|thin|daemon/.*)\.rs|veil-server/src/(main|subtree|pack|landing/.*)\.rs)' \
       '(\btikv_jemallocator\b|\bMALLOC_CONF\b|\bBATCH_BYTES\b|\bMAX_BATCH\b|\bprefetch\b|\bsubtree\b|\bSUBTREE_REVISION\b|\bdirty_decay_ms\b)' || \
       file_matches 'scripts/bench-(scale|server)\.sh'; then
        emit "R-27" "1 GB memory gates (client 512 MiB, server 1,024 MiB), first-entry batch flush, and daemon prefetch"
    fi

    # --- Area 6: Client Engine, Sandboxes, Portability & Formats ---

    # R-28: Op-log merges treat settler rebases as derived effects (not re-recorded command rewrites), and undo scopes to ChangeId
    if added_in 'crates/(veil-core/src/(oplog|settled|repo|commands)\.rs|vl/src/(history|rewrite_cmd)\.rs)' \
       '(\bshared_base\b|\bmerge_plan\b|\badd_rebases\b|\bsettler\b|\bOpRecord\b|\brewritten_from\b|\bundo\b)'; then
        emit "R-28" "Op-log merges separate settler rebases from re-recorded command rewrites; undo scopes to ChangeId"
    fi

    # R-29: Crash-safe publish order (.pack -> .idx -> op head), live-tx GC protection, clone journal, O_NOFOLLOW barriers
    if added_in 'crates/(veil-core/src/(transaction|gc|maintenance|checkout|working_copy|store|vfs/.*)\.rs|vl/src/(auto_gc|hub_cmd)\.rs)' \
       '(\bsync_all\b|\bbarrier_sync_dir\b|\bO_NOFOLLOW\b|\bO_DIRECTORY\b|\bprune_now\b|\blive_transactions\b|\bclone_journal\b|\.idx\b)'; then
        emit "R-29" "Crash-safe publish order (.pack -> .idx -> op), live-tx GC lock, clone journal, O_NOFOLLOW barriers"
    fi

    # R-30: Workspace confinement (vl ws exec) writable tool overlays, full revset endpoint checks, non-Linux warnings
    if added_in 'crates/(veil-core/src/(sandbox|workspace|vfs/sandbox)\.rs|vl/src/(sandbox|confine|ws_socket)\.rs)' \
       '(\bbwrap\b|sandbox|ws_socket|\bephemeral\b|\bunconfined\b|revset|\boverlay\b|target_os = "linux")'; then
        emit "R-30" "Workspace sandbox overlays, full revset endpoint checks in ws_socket, and non-Linux warnings"
    fi

    # R-31: Quarantined secret files exit status 3 across commit, new, push, land, and ws exec, and survive --ephemeral
    if added_in 'crates/(veil-core/src/(secrets|wc_policy|workspace)\.rs|vl/src/(main|cli|api|api/.*|doctor|mount|sandbox|hub_cmd|confine|rewrite_cmd)\.rs)' \
       '(\bquarantine\b|\bQuarantined\b|\bquarantine_kept\b|\bEXIT_QUARANTINE\b|ephemeral-kept|\bephemeral_kept\b|\bLeftOut\b|exit\(3\))'; then
        emit "R-31" "Quarantined secret files exit 3 across all commands and survive --ephemeral"
    fi

    # R-32: Format/JSON schema bumps (vl upgrade), veil-core WASM #[cfg(feature = "os")], MSRV 1.88, and blessed CLI docs
    if added_in 'crates/(veil-core/src/.*|vl/src/(cli|docgen))\.rs' \
       '(\bREPO_FORMAT_VERSION\b|\bFORMAT_VERSION\b|\bupgrade_repo\b|std::(fs|process|net|os::unix)|#\[command\(|#\[arg\()' || \
       added_in 'crates/.*\.rs' \
       '(\.try_update\(|\.extract_if\()' || \
       added_in '(Cargo\.toml|crates/.*/Cargo\.toml)' \
       '(\brust-version\b|^\[dependencies\])'; then
        emit "R-32" "Format upgrades, veil-core WASM #[cfg(feature = \"os\")], MSRV 1.88, and blessed CLI docs"
    fi

    # --- Area 7: Tests & Harness Isolation ---

    # R-33: Tests never substring-match random hex or [k-z] IDs, short (<8-byte) leak needles, or [k-z]-only tag names
    if added_in 'crates/.*/tests/.*\.rs' \
       '(\.contains\("[0-9a-f]{2,7}"\)|\.contains\("[a-z]{2,5}"\)|"tag",[[:space:]]*"set",[[:space:]]*"[k-z]{2,}"|tag_set\([^)]*"[k-z]{2,}")'; then
        emit "R-33" "Tests avoid substring checks on random hex/[k-z] IDs, short leak needles, and [k-z] tags"
    fi

    # R-34: Server tests isolate DDL, SERIALIZABLE loads, custom stores (start_own/own_database), shared deletes, and fixed IDs
    if added_in 'crates/veil-server/tests/.*\.rs' \
       '(ALTER[[:space:]]+TABLE|DROP[[:space:]]+(INDEX|TABLE)|CREATE[[:space:]]+(INDEX|TABLE)|SERIALIZABLE|DELETE[[:space:]]+FROM[[:space:]]+[a-z_]+|TRUNCATE[[:space:]]+|\b(LocalStore|S3Store|start_with_store|own_database|start_own|setval|pg_get_serial_sequence)\b|INSERT[[:space:]]+INTO[[:space:]]+(groups|users|projects)[[:space:]]*\([^)]*\bid\b)'; then
        emit "R-34" "Server tests isolate DDL, SERIALIZABLE tx, custom stores, shared-table deletes, and row IDs"
    fi

    # R-35: Tests unconditionally assert their primary action succeeded/refused before checking side effects
    if added_in 'crates/.*/tests/.*\.rs' \
       '(if[[:space:]]+let[[:space:]]+Ok\(|if[[:space:]]+[a-z0-9_.]+\.status\(\)[[:space:]]*==|if[[:space:]]+[a-z0-9_.]+\.status\.success\(\)|if[[:space:]]+ok[[:space:]]*\{)'; then
        emit "R-35" "Tests assert primary action outcome unconditionally (never guarded by if ok / if status == 200)"
    fi

    # R-36: Load-sensitive tests retry transient 503 warming/deadline/busy and stamp-aborted GC passes, and avoid timing ratios
    if added_in 'crates/.*/tests/.*\.rs' \
       '(\bmark_and_sweep\b|\bgc_pass\b|\.elapsed\(\)[[:space:]]*[<>]|as_(millis|micros|secs_f64)\(\)[[:space:]]*[*/<>]|\b503\b|"warming"|"deadline")'; then
        emit "R-36" "Tests retry transient 503/stamp-aborted GC passes and avoid wall-clock timing ratios"
    fi
}

run_on_diff_text() {
    load_parsed_diff
    evaluate_triggers
}

run_self_test() {
    local failures=0
    local out

    # 1. Neutral diff (ordinary calculation + BUGS.md prose + Rust comment) must match nothing.
    out="$(run_on_diff_text <<'EOF'
diff --git a/crates/veil-core/src/hunks.rs b/crates/veil-core/src/hunks.rs
+++ b/crates/veil-core/src/hunks.rs
@@ -10,0 +11,2 @@
+    // CREATE INDEX CONCURRENTLY and effective_policy mentioned in a comment only
+    let total_lines = before.len() + after.len();
diff --git a/docs/BUGS.md b/docs/BUGS.md
+++ b/docs/BUGS.md
@@ -1,0 +2,1 @@
+| BUG-9999 | high | server | CREATE INDEX in transaction and .persistent(false) and Viewer.only |
EOF
)"
    if [[ -n "$out" ]]; then
        printf 'SELF-TEST FAIL: neutral diff matched:\n%s\n' "$out" >&2
        failures=$((failures + 1))
    fi

    check_sample() {
        local expected="$1"
        local got
        got="$(run_on_diff_text)"
        if ! grep -Eq "^${expected}	" <<< "$got"; then
            printf 'SELF-TEST FAIL: expected %s to fire, got:\n%s\n' "$expected" "${got:-<none>}" >&2
            failures=$((failures + 1))
        fi
    }

    check_sample "R-01" <<'EOF'
+++ b/crates/vl/src/hub.rs
+    if url.starts_with("sftp://") { return Err(anyhow!("unsupported")); }
EOF

    check_sample "R-02" <<'EOF'
+++ b/crates/veil-core/src/repo.rs
+    let pol = self.effective_policy()?;
EOF

    check_sample "R-03" <<'EOF'
+++ b/crates/veil-server/src/landing/service.rs
+    tracing::warn!("landing conflict on {:?}", conflict_paths);
EOF

    check_sample "R-04" <<'EOF'
+++ b/crates/veil-server/src/sync.rs
+    verify_upload_receipt(&tx, project_id, &uploaded_ids).await?;
EOF

    check_sample "R-05" <<'EOF'
+++ b/crates/veil-core/src/merge.rs
+    let vis = repo.verified_visibility(blob_id)?;
EOF

    check_sample "R-06" <<'EOF'
+++ b/crates/veil-core/src/embargo.rs
+    if self.is_embargoed(change_id) { withheld.insert(change_id); }
EOF

    check_sample "R-07" <<'EOF'
+++ b/crates/veil-server/src/sync.rs
+    perm::check_write(&viewer, &changed_paths, ".veilrules")?;
EOF

    check_sample "R-08" <<'EOF'
+++ b/crates/veil-server/src/api.rs
+    Router::new().route("/v1/projects/{p}/widgets", get(list_widgets))
EOF

    check_sample "R-09" <<'EOF'
+++ b/crates/veil-server/src/changes.rs
+    if let Some(only) = &viewer.only { check_narrow_scope(only)?; }
EOF

    check_sample "R-10" <<'EOF'
+++ b/crates/veil-server/src/limits/body.rs
+    let key = Key::Person(viewer.person_id);
EOF

    check_sample "R-11" <<'EOF'
+++ b/crates/veil-server/src/query/graph.rs
+    sqlx::query("SELECT id FROM view_commits WHERE project_id = $1 AND hidden_for_embargo IS NULL")
EOF

    check_sample "R-12" <<'EOF'
+++ b/crates/veil-server/migrations/0043_sample.sql
+-- veil: online indexes
+CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sample ON branches (project_id);
EOF

    check_sample "R-13" <<'EOF'
+++ b/crates/veil-server/migrations/0043_sample.sql
+ALTER TABLE projects ADD COLUMN IF NOT EXISTS note TEXT;
EOF

    check_sample "R-14" <<'EOF'
+++ b/crates/veil-server/src/changes.rs
+    sqlx::query("SELECT snapshot_id FROM projections WHERE project_id = $1 AND projected_id = $2").persistent(false)
EOF

    check_sample "R-15" <<'EOF'
+++ b/crates/veil-server/src/prs/review_gate.rs
+    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(-project_id)
EOF

    check_sample "R-16" <<'EOF'
+++ b/crates/veil-server/src/sync.rs
+    tx.commit().await?;
+    hub.caches.tips_moved(project_id, &moved).await;
EOF

    check_sample "R-17" <<'EOF'
+++ b/crates/veil-server/src/db.rs
+    let opts = parse_pg_tls(&database_url, "sslmode=verify-full")?;
EOF

    check_sample "R-18" <<'EOF'
+++ b/crates/veil-server/src/pack_gc.rs
+    guard_root_write(&mut tx, project_id, expected_gc_epoch).await?;
EOF

    check_sample "R-19" <<'EOF'
+++ b/crates/veil-server/src/sync.rs
+    ensure_kind_matches(entry.kind, ObjectKind::Tree)?;
EOF

    check_sample "R-20" <<'EOF'
+++ b/crates/veil-core/src/store.rs
+    let gen_before = self.pack_gen();
EOF

    check_sample "R-21" <<'EOF'
+++ b/crates/veil-server/src/pack.rs
+    packs.maybe_schedule(project_id);
EOF

    check_sample "R-22" <<'EOF'
+++ b/crates/veil-server/src/caches.rs
+    let mut hasher = blake3::Hasher::new();
EOF

    check_sample "R-23" <<'EOF'
+++ b/crates/veil-server/src/embargo.rs
+    pub async fn release_one(hub: &Hub, embargo_id: i64) -> Result<ReleaseOutcome> {
EOF

    check_sample "R-24" <<'EOF'
+++ b/crates/veil-server/src/api.rs
+    resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
EOF

    check_sample "R-25" <<'EOF'
+++ b/crates/veil-server/src/cache/relay.rs
+    const HTTP_BUFFER: usize = MAX_CHAIN + 16 * 1024;
EOF

    check_sample "R-26" <<'EOF'
+++ b/crates/veil-server/src/sync.rs
+    tokio::spawn(limits::in_request(locals, async move { work().await }));
EOF

    check_sample "R-27" <<'EOF'
+++ b/crates/veil-server/src/main.rs
+    #[global_allocator] static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
EOF

    check_sample "R-28" <<'EOF'
+++ b/crates/veil-core/src/oplog.rs
+    let base = shared_base(&ops, left, right)?;
EOF

    check_sample "R-29" <<'EOF'
+++ b/crates/veil-core/src/checkout.rs
+    barrier_sync_dir(&dir_path, libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
EOF

    check_sample "R-30" <<'EOF'
+++ b/crates/vl/src/ws_socket.rs
+    verify_revset_confined(&repo, &revset_expr)?;
EOF

    check_sample "R-31" <<'EOF'
+++ b/crates/vl/src/hub_cmd.rs
+    if report.has_quarantined() { std::process::exit(3); }
EOF

    check_sample "R-32" <<'EOF'
+++ b/crates/veil-core/src/store.rs
+    let meta = std::fs::metadata(path)?;
EOF

    check_sample "R-33" <<'EOF'
+++ b/crates/veil-server/tests/server_hub/prs.rs
+    assert!(!body.contains("5d2e"));
EOF

    check_sample "R-34" <<'EOF'
+++ b/crates/veil-server/tests/server_hub/startup.rs
+    let hub = TestHub::start_own().await;
EOF

    check_sample "R-35" <<'EOF'
+++ b/crates/veil-server/tests/server_hub/landing.rs
+    if resp.status() == 200 { assert_eq!(resp.json()["landed"], true); }
EOF

    check_sample "R-36" <<'EOF'
+++ b/crates/veil-server/tests/server_hub/pack_gc.rs
+    let swept = pack_gc::mark_and_sweep(&hub, project_id).await?;
EOF

    if [[ "$failures" -ne 0 ]]; then
        printf 'SELF-TEST FAILED (%d failure(s))\n' "$failures" >&2
        return 1
    fi
    printf 'SELF-TEST OK: neutral diff matched 0 items; all 36 triggers (R-01..R-36) fired.\n'
}

main() {
    case "${1:-}" in
        -h|--help)
            usage
            exit 0
            ;;
        --self-test)
            run_self_test
            exit 0
            ;;
        --stdin)
            run_on_diff_text
            exit 0
            ;;
        -*)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac

    local range="${1:-integration...HEAD}"
    if [[ "$range" == *..* && "$range" != *...* ]]; then
        range="${range/../...}"
    fi
    git diff --unified=0 --no-color --no-renames "$range" | run_on_diff_text
}

main "$@"
