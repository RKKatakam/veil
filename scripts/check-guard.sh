#!/usr/bin/env bash
# Flag every diff hunk on a branch/range that modifies what judges the change:
#   - test assertions removed or weakened, #[ignore] added, retries/sleeps/loops
#     added around assertions, widened tolerances or timeouts in existing tests;
#   - property-test models/oracles (proptest files, check_* helpers in core_props,
#     deleted proptest-regressions seeds);
#   - the checks themselves: scripts/verify-server.sh, scripts/bench-server.sh,
#     scripts/bench-scale.sh, scripts/check-wasm.sh, guard/stamp/hook scripts,
#     deploy/gates.sh, .github/workflows/*, crates/veil-bench/src/** gates,
#     .claude/skills/**, CLAUDE.md, docs/RELIABILITY.md, docs/VERIFICATION.md,
#     docs/review-evals.md, *.toml lint config, and #[allow(...)] additions.
#
# Always run the base branch's copy when reviewing a branch:
#   git show integration:scripts/check-guard.sh | bash -s -- integration...<branch>
#
# Modes (CHECK_GUARD=off|observe|enforce, default observe):
#   off      do nothing, exit 0
#   observe  print flagged hunks and append to .git/check-guard.log, exit 0
#   enforce  exit 1 if any hunk is flagged unless a commit in the range carries
#            a non-empty `Check-change-approved: <reason>` trailer
set -uo pipefail

usage() {
    cat <<'EOF'
usage: scripts/check-guard.sh [<range>]
       scripts/check-guard.sh --stdin
       scripts/check-guard.sh --self-test

Flags every diff hunk in <range> (default: integration...HEAD) that changes
assertions, property-test models/oracles, benchmark gates, lint config or
verification scripts/rules.

Environment:
  CHECK_GUARD=off|observe|enforce   Mode (default: observe)
  CHECK_GUARD_LOG=<path>            Override log file (default: .git/check-guard.log)
EOF
}

MODE="${CHECK_GUARD:-observe}"
case "$MODE" in
    off|observe|enforce) ;;
    *)
        echo "check-guard: invalid CHECK_GUARD='$MODE' (expected off, observe, or enforce)" >&2
        exit 2
        ;;
esac

# Analyze a unified diff on stdin and emit `file:line — kind — first_line` lines.
# Arguments:
#   $1  newline-separated paths known to use proptest (optional)
#   $2  newline-separated `path:line` entries where #[cfg(test)] starts (optional)
analyze_diff() {
    local proptest_list="${1:-}"
    local cfg_test_list="${2:-}"

    awk -v proptest_list="$proptest_list" -v cfg_test_list="$cfg_test_list" '
    BEGIN {
        n = split(proptest_list, pa, "\n")
        for (i = 1; i <= n; i++) {
            if (pa[i] != "") proptest_file[pa[i]] = 1
        }
        n = split(cfg_test_list, ca, "\n")
        for (i = 1; i <= n; i++) {
            if (ca[i] != "") {
                sep = index(ca[i], ":")
                if (sep > 0) {
                    p = substr(ca[i], 1, sep - 1)
                    ln = substr(ca[i], sep + 1) + 0
                    if (ln > 0) cfg_test_line[p] = ln
                }
            }
        }
        in_hunk = 0
        file = ""
        old_file = ""
    }

    function trim(s) {
        sub(/^[[:space:]]+/, "", s)
        sub(/[[:space:]]+$/, "", s)
        return s
    }

    function format_first_line(s,    prefix, body) {
        if (s == "") return "(file metadata change)"
        prefix = substr(s, 1, 1)
        body = trim(substr(s, 2))
        s = prefix " " body
        if (length(s) > 120) {
            s = substr(s, 1, 117) "..."
        }
        return s
    }

    function is_comment_line(lang, body) {
        body = trim(body)
        if (body == "") return 1
        if (lang == "rs") {
            return (body ~ /^\/\//)
        }
        if (lang == "sh" || lang == "toml" || lang == "yml") {
            return (body ~ /^#/)
        }
        return 0
    }

    function count_re(str, pat,    c, s, idx) {
        c = 0
        s = str
        while (match(s, pat)) {
            c++
            idx = RSTART + (RLENGTH > 0 ? RLENGTH : 1)
            s = substr(s, idx)
        }
        return c
    }

    function is_check_script(f) {
        if (f == "scripts/verify-server.sh" ||
            f == "scripts/bench-server.sh" ||
            f == "scripts/bench-scale.sh" ||
            f == "scripts/check-wasm.sh" ||
            f == "scripts/check-guard.sh" ||
            f == "scripts/verify-stamp.sh" ||
            f == "scripts/unverified.sh" ||
            f == "deploy/gates.sh") return 1
        if (f ~ /^scripts\/hooks\//) return 1
        if (f ~ /^\.github\/workflows\//) return 1
        return 0
    }

    function is_check_rules(f) {
        if (f == "CLAUDE.md" ||
            f == "docs/RELIABILITY.md" ||
            f == "docs/VERIFICATION.md" ||
            f == "docs/review-evals.md") return 1
        if (f ~ /^\.claude\/skills\//) return 1
        return 0
    }

    function is_test_path(f) {
        if (f ~ /(^|\/)tests\//) return 1
        if (f ~ /(_test|_tests|tests)\.rs$/) return 1
        return 0
    }

    function is_proptest_path(f) {
        if (proptest_file[f]) return 1
        if (f ~ /core_props\// || f ~ /_props\.rs$/ || f ~ /proptest/) return 1
        return 0
    }

    # Extract largest numeric literal matching `<pat>` where the number immediately
    # follows `<pat>` (e.g. pat = "from_secs\\(").
    function max_num_after(text, pat,    mx, found, s, rest) {
        mx = -1
        found = 0
        s = text
        while (match(s, pat "[0-9]+(_[0-9]+)*(\\.[0-9]+)?")) {
            rest = substr(s, RSTART, RLENGTH)
            sub("^" pat, "", rest)
            gsub(/_/, "", rest)
            val = rest + 0.0
            if (!found || val > mx) {
                mx = val
                found = 1
            }
            s = substr(s, RSTART + RLENGTH)
        }
        return found ? mx : -1
    }

    function check_widened_numbers(del_t, add_t,    pats, np, i, dmax, amax) {
        np = split("from_secs\\(|from_millis\\(|from_micros\\(|Duration::new\\(|STEP_LIMIT=|timeout[[:space:]]+|tries[[:space:]]*<=?[[:space:]]*|attempts[[:space:]]*<=?[[:space:]]*|tolerance[[:space:]]*=[[:space:]]*|epsilon[[:space:]]*=[[:space:]]*", pats, "|")
        for (i = 1; i <= np; i++) {
            dmax = max_num_after(del_t, pats[i])
            amax = max_num_after(add_t, pats[i])
            if (dmax >= 0 && amax > dmax) return 1
        }
        # Upper-bound assertion loosened: e.g. `assert!(x < 0.01)` -> `assert!(x < 0.1)` or `<= 100` -> `<= 500`
        if (del_t ~ /(assert|prop_assert)[[:space:]!]/ && add_t ~ /(assert|prop_assert)[[:space:]!]/) {
            dmax = max_num_after(del_t, "<=?[[:space:]]*")
            amax = max_num_after(add_t, "<=?[[:space:]]*")
            if (dmax >= 0 && amax > dmax) return 1
        }
        # Exponential/multiplicative deadline backoff added in existing test (`deadline *= 2`)
        if (del_t !~ /deadline[[:space:]]*\*=/ && add_t ~ /deadline[[:space:]]*\*=/) return 1
        return 0
    }

    function flush_hunk(    lang, kind, in_test, del_strict, add_strict, del_any, add_any, del_sp, add_sp, del_ign, add_ign, del_allow, add_allow, pure_new_fn, pure_new_fixture, i, pfx, bdy, tail_new_test) {
        if (!in_hunk || file == "") {
            in_hunk = 0
            return
        }
        in_hunk = 0
        if (raw_changes == 0) return

        lang = "other"
        if (file ~ /\.rs$/) lang = "rs"
        else if (file ~ /\.toml$/) lang = "toml"
        else if (file ~ /\.sh$/) lang = "sh"
        else if (file ~ /\.(yml|yaml)$/) lang = "yml"
        else if (file ~ /\.md$/) lang = "md"

        # Compute existing-code additions (`ex_*`): exclude brand-new `#[test]` functions
        # appended strictly after the last deleted line in the hunk.
        ex_add = ""
        ex_all = ""
        ex_code_add_n = 0
        ex_first_add = ""
        ex_assert_add = ""
        tail_new_test = 0
        for (i = 1; i <= hunk_n; i++) {
            pfx = h_pfx[i]
            bdy = h_body[i]
            if (i > last_del_idx && pfx == "+" && trim(bdy) ~ /^#\[(tokio::)?test([^a-zA-Z0-9_]|$)/) {
                tail_new_test = 1
            }
            if (!tail_new_test) {
                ex_all = ex_all "\n" bdy
                if (pfx == "+" && !h_cm[i]) {
                    ex_add = ex_add "\n" bdy
                    ex_code_add_n++
                    if (ex_first_add == "") ex_first_add = trim(bdy)
                    if (bdy ~ /(assert|prop_assert|debug_assert)(_eq|_ne)?!/) {
                        ex_assert_add = ex_assert_add "\n" bdy
                    }
                }
            }
        }

        kind = ""

        # 1. Verification / benchmark scripts and CI workflows
        if (is_check_script(file)) {
            if (code_del_n + code_add_n > 0 || file_deleted) {
                kind = "check-script"
            }
        }
        # 2. Review skill and process/reliability docs
        else if (is_check_rules(file)) {
            kind = "check-rules"
        }
        # 3. TOML lint / MSRV configuration
        else if (lang == "toml") {
            if (code_del_n + code_add_n > 0) {
                if (hunk_hdr ~ /\[lints/ ||
                    code_del ~ /(\[lints|clippy|rustflags|rust-version|[[:space:]](allow|warn|deny|forbid)[[:space:]]*=)/ ||
                    code_add ~ /(\[lints|clippy|rustflags|rust-version|[[:space:]](allow|warn|deny|forbid)[[:space:]]*=)/) {
                    kind = "lint-config"
                }
            }
        }

        # 4. Rust checks: #[allow(...)], #[ignore], bench gates, proptest models, test assertions
        if (kind == "" && file ~ /proptest-regressions/ && raw_del_n > 0) {
            kind = "proptest-model"
        }

        if (kind == "" && lang == "rs" && (code_del_n + code_add_n > 0)) {
            del_allow = count_re(code_del, "#!?\\[allow\\(")
            add_allow = count_re(code_add, "#!?\\[allow\\(")
            if (add_allow > del_allow) {
                kind = "lint-allow"
            }

            if (kind == "" && file ~ /^crates\/veil-bench\/src\//) {
                if (hunk_hdr ~ /(GATE_|SERVER_GATE|missed_gates|server_over|known_over_gate|CommitKinds|fn aside)/ ||
                    code_del ~ /(GATE_|SERVER_GATE|missed_gates|gates_missed|server_over_gate|server_over\(|known_over_gate|CommitKinds|fn aside\(|target_ms|meets_target|beats_git)/ ||
                    code_add ~ /(GATE_|SERVER_GATE|missed_gates|gates_missed|server_over_gate|server_over\(|known_over_gate|CommitKinds|fn aside\(|target_ms|meets_target|beats_git)/) {
                    kind = "bench-gate"
                }
            }

            del_ign = count_re(code_del, "#\\[ignore([^a-zA-Z0-9_]|$)")
            add_ign = count_re(code_add, "#\\[ignore([^a-zA-Z0-9_]|$)")
            if (kind == "" && add_ign > del_ign) {
                kind = "test-ignored"
            }

            in_test = is_test_path(file)
            if (!in_test && (file in cfg_test_line) && hunk_new_start >= cfg_test_line[file]) {
                in_test = 1
            }
            if (!in_test && (hunk_hdr ~ /(mod tests|#\[test\])/ || all_hunk ~ /#\[(tokio::)?test([^a-zA-Z0-9_]|$)/)) {
                in_test = 1
            }

            # Property-test model / oracle changes in test files using proptest
            if (kind == "" && in_test && is_proptest_path(file)) {
                pure_new_fn = (code_del_n == 0 && first_add_code ~ /^(pub(\([^)]*\))?[[:space:]]+)?(#\[(tokio::)?test([^a-zA-Z0-9_]|$)[[:space:]]*|fn[[:space:]]+(bug_|test_)|proptest![[:space:]]*\{)/)
                if (!pure_new_fn) {
                    if (hunk_hdr ~ /(fn[[:space:]]+(check_|model|oracle|verify_|arb_)|struct[[:space:]]+Model|impl[[:space:]]+Model|proptest!)/ ||
                        code_del ~ /(fn[[:space:]]+(check_|model|oracle|verify_|arb_)|proptest!|ProptestConfig|cases[[:space:]]*:|prop_compose!|prop_oneof!|BoxedStrategy|TestCaseError|prop_assert)/ ||
                        code_add ~ /(fn[[:space:]]+(check_|model|oracle|verify_|arb_)|proptest!|ProptestConfig|cases[[:space:]]*:|prop_compose!|prop_oneof!|BoxedStrategy|TestCaseError|prop_assert)/ ||
                        ((file ~ /core_props\// || file ~ /_props\.rs$/) && code_del_n > 0 && hunk_hdr !~ /fn[[:space:]]+(bug_|test_)/)) {
                        kind = "proptest-model"
                    }
                }
            }

            # Test assertions removed, weakened, retried, or given wider timeouts/tolerances
            if (kind == "" && in_test) {
                del_sp = count_re(code_del, "#\\[should_panic")
                add_sp = count_re(ex_add, "#\\[should_panic")

                del_strict = count_re(code_del, "(^|[^a-zA-Z0-9_])(prop_assert_eq|prop_assert_ne|debug_assert_eq|debug_assert_ne|assert_eq|assert_ne)!")
                add_strict = count_re(ex_add, "(^|[^a-zA-Z0-9_])(prop_assert_eq|prop_assert_ne|debug_assert_eq|debug_assert_ne|assert_eq|assert_ne)!")

                del_any = del_strict + count_re(code_del, "(^|[^a-zA-Z0-9_])(prop_assert|debug_assert|assert)!")
                add_any = add_strict + count_re(ex_add, "(^|[^a-zA-Z0-9_])(prop_assert|debug_assert|assert)!")

                if (del_sp > add_sp || del_any > add_any) {
                    kind = "assertion-removed"
                }
                else if (del_strict > add_strict && add_any >= del_any) {
                    kind = "assertion-weakened"
                }
                else if (del_any > 0 && code_del !~ /(^|[^a-zA-Z0-9_])if([[:space:]]+let)?[[:space:]][^\n]*(\n[[:space:]]*)?(assert|prop_assert)/ &&
                         ex_add ~ /(^|[^a-zA-Z0-9_])if([[:space:]]+let)?[[:space:]][^\n]*(\n[[:space:]]*)?(assert|prop_assert)/) {
                    kind = "assertion-weakened"
                }
                else if (del_any > 0 && add_any == del_any && count_re(ex_assert_add, "\\|\\|") > count_re(assert_del, "\\|\\|")) {
                    kind = "assertion-weakened"
                }
                else if (code_del_n + ex_code_add_n > 0) {
                    # Purely added top-level test helper/fixture items (fn, struct, enum, type,
                    # const, trait, impl) with zero deletions are new test scaffolding, not
                    # weakening an existing test.
                    pure_new_fixture = (code_del_n == 0 && ex_first_add ~ /^(#\[[a-zA-Z0-9_:()=",[:space:]]+\][[:space:]]*)*(pub(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?(fn|struct|enum|type|trait|impl|mod)[[:space:]<]/)
                    if (!pure_new_fixture) {
                        if (check_widened_numbers(code_del, ex_add)) {
                            kind = "tolerance-or-timeout-widened"
                        }
                        else if (count_re(ex_add, "(thread::sleep|time::sleep|[^a-zA-Z0-9_]sleep\\()") > count_re(code_del, "(thread::sleep|time::sleep|[^a-zA-Z0-9_]sleep\\()") ||
                                 (count_re(ex_add, "(^|[^a-zA-Z0-9_])(loop[[:space:]]*\\{|while[[:space:]]+|tries[[:space:]]*(\\+=|<|>=))") > count_re(code_del, "(^|[^a-zA-Z0-9_])(loop[[:space:]]*\\{|while[[:space:]]+|tries[[:space:]]*(\\+=|<|>=))") &&
                                  (ex_all ~ /(assert|prop_assert|panic!)/ || hunk_hdr ~ /fn[[:space:]]+/))) {
                            kind = "retry-or-sleep-added"
                        }
                    }
                }
            }
        }

        if (kind != "") {
            printf "%s:%d — %s — %s\n", file, first_change_ln, kind, format_first_line(first_change_raw)
        }
    }

    /^diff --git / {
        flush_hunk()
        file = ""
        old_file = ""
        file_deleted = 0
        # Extract a/... and b/... paths
        line = $0
        sub(/^diff --git a\//, "", line)
        idx = index(line, " b/")
        if (idx > 0) {
            old_file = substr(line, 1, idx - 1)
            file = substr(line, idx + 3)
        }
        next
    }

    /^deleted file mode / {
        file_deleted = 1
        next
    }

    /^--- / {
        if ($0 != "--- /dev/null" && substr($0, 1, 6) == "--- a/") {
            old_file = substr($0, 7)
        }
        next
    }

    /^\+\+\+ / {
        if ($0 == "+++ /dev/null") {
            file = old_file
            file_deleted = 1
        } else if (substr($0, 1, 6) == "+++ b/") {
            file = substr($0, 7)
        }
        next
    }

    /^@@ / {
        flush_hunk()
        in_hunk = 1
        hunk_hdr = $0
        # Parse +start from `@@ -a,b +c,d @@`
        hunk_new_start = 1
        if (match($0, /\+[0-9]+/)) {
            hunk_new_start = substr($0, RSTART + 1, RLENGTH - 1) + 0
            if (hunk_new_start == 0) hunk_new_start = 1
        }
        cur_new_ln = hunk_new_start
        first_change_ln = hunk_new_start
        first_change_raw = ""
        has_nonblank_first = 0
        has_code_first = 0
        raw_changes = 0
        raw_del_n = 0
        code_del = ""
        code_add = ""
        code_del_n = 0
        code_add_n = 0
        first_add_code = ""
        all_hunk = ""
        assert_del = ""
        hunk_n = 0
        last_del_idx = 0
        delete h_pfx
        delete h_body
        delete h_cm
        next
    }

    {
        if (!in_hunk) next
        prefix = substr($0, 1, 1)
        if (prefix != "+" && prefix != "-" && prefix != " ") next
        body = substr($0, 2)

        lang = "other"
        if (file ~ /\.rs$/) lang = "rs"
        else if (file ~ /\.toml$/) lang = "toml"
        else if (file ~ /\.sh$/) lang = "sh"
        else if (file ~ /\.(yml|yaml)$/) lang = "yml"
        else if (file ~ /\.md$/) lang = "md"

        is_cm = is_comment_line(lang, body)
        hunk_n++
        h_pfx[hunk_n] = prefix
        h_body[hunk_n] = body
        h_cm[hunk_n] = is_cm

        all_hunk = all_hunk "\n" body

        if (prefix == " ") {
            cur_new_ln++
            next
        }

        if (raw_changes == 0) {
            first_change_ln = cur_new_ln
            first_change_raw = $0
            if (trim(body) != "") has_nonblank_first = 1
            if (!is_cm) has_code_first = 1
        } else if (!has_code_first && !is_cm) {
            first_change_ln = cur_new_ln
            first_change_raw = $0
            has_nonblank_first = 1
            has_code_first = 1
        } else if (!has_nonblank_first && trim(body) != "") {
            first_change_ln = cur_new_ln
            first_change_raw = $0
            has_nonblank_first = 1
        }
        raw_changes++

        if (prefix == "-") {
            raw_del_n++
            last_del_idx = hunk_n
            if (!is_cm) {
                code_del = code_del "\n" body
                code_del_n++
                if (body ~ /(assert|prop_assert|debug_assert)(_eq|_ne)?!/) {
                    assert_del = assert_del "\n" body
                }
            }
        } else if (prefix == "+") {
            if (!is_cm) {
                code_add = code_add "\n" body
                code_add_n++
                if (first_add_code == "") first_add_code = trim(body)
            }
            cur_new_ln++
        }
    }

    END {
        flush_hunk()
    }
    '
}

run_self_test() {
    local tmp
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-guard-selftest.XXXXXX")
    trap 'rm -rf "$tmp"' RETURN

    local pass=0 fail=0

    expect_kind() {
        local label="$1" expected="$2" out
        out=$(cat | analyze_diff "" "")
        if [[ -n "$expected" ]]; then
            if printf '%s\n' "$out" | grep -q " — ${expected} — "; then
                printf '  ok    %-32s -> %s\n' "$label" "$out"
                pass=$((pass + 1))
            else
                printf '  FAIL  %-32s expected kind %s, got: %s\n' "$label" "$expected" "${out:-<none>}" >&2
                fail=$((fail + 1))
            fi
        else
            if [[ -z "$out" ]]; then
                printf '  ok    %-32s -> <nothing flagged>\n' "$label"
                pass=$((pass + 1))
            else
                printf '  FAIL  %-32s expected nothing flagged, got:\n%s\n' "$label" "$out" >&2
                fail=$((fail + 1))
            fi
        fi
    }

    echo "== check-guard self-test =="

    expect_kind "assertion-removed (assert_eq!)" "assertion-removed" <<'EOF'
diff --git a/crates/veil-core/tests/core_engine/engine.rs b/crates/veil-core/tests/core_engine/engine.rs
--- a/crates/veil-core/tests/core_engine/engine.rs
+++ b/crates/veil-core/tests/core_engine/engine.rs
@@ -40,5 +40,4 @@ fn commit_updates_head() {
     let res = repo.commit("msg").unwrap();
-    assert_eq!(res.status, Landed);
     assert!(repo.heads().contains(&res.id));
 }
EOF

    expect_kind "assertion-removed (should_panic)" "assertion-removed" <<'EOF'
diff --git a/crates/veil-core/tests/core_security/access.rs b/crates/veil-core/tests/core_security/access.rs
--- a/crates/veil-core/tests/core_security/access.rs
+++ b/crates/veil-core/tests/core_security/access.rs
@@ -12,5 +12,4 @@
 #[test]
-#[should_panic(expected = "access denied")]
 fn unauthorized_read_panics() {
     read_secret_without_grant();
 }
EOF

    expect_kind "assertion-weakened (eq -> >=)" "assertion-weakened" <<'EOF'
diff --git a/crates/vl/tests/cli_security/access_cli.rs b/crates/vl/tests/cli_security/access_cli.rs
--- a/crates/vl/tests/cli_security/access_cli.rs
+++ b/crates/vl/tests/cli_security/access_cli.rs
@@ -88,4 +88,4 @@ fn exact_audit_count() {
     let rows = fetch_audit_rows();
-    assert_eq!(rows.len(), 2);
+    assert!(rows.len() >= 1);
 }
EOF

    expect_kind "assertion-weakened (if ok guard)" "assertion-weakened" <<'EOF'
diff --git a/crates/vl/tests/cli_basic/cli.rs b/crates/vl/tests/cli_basic/cli.rs
--- a/crates/vl/tests/cli_basic/cli.rs
+++ b/crates/vl/tests/cli_basic/cli.rs
@@ -52,4 +52,4 @@ fn push_checks_outcome() {
     let out = run_vl(&["push"]);
-    assert!(out.stdout.contains("landed"));
+    if out.status.success() { assert!(out.stdout.contains("landed")); }
 }
EOF

    expect_kind "test-ignored" "test-ignored" <<'EOF'
diff --git a/crates/veil-core/tests/core_durability/lock.rs b/crates/veil-core/tests/core_durability/lock.rs
--- a/crates/veil-core/tests/core_durability/lock.rs
+++ b/crates/veil-core/tests/core_durability/lock.rs
@@ -19,3 +19,4 @@
 #[test]
+#[ignore = "flaky on busy CI"]
 fn concurrent_lock_holders_serialize() {
EOF

    expect_kind "retry-or-sleep-added" "retry-or-sleep-added" <<'EOF'
diff --git a/crates/veil-server/tests/server_hub/caches.rs b/crates/veil-server/tests/server_hub/caches.rs
--- a/crates/veil-server/tests/server_hub/caches.rs
+++ b/crates/veil-server/tests/server_hub/caches.rs
@@ -105,4 +105,5 @@ fn cache_invalidates_after_revoke() {
     revoke_member(&hub, &alice);
+    std::thread::sleep(Duration::from_millis(250));
     assert_eq!(hub.get_as(&alice, "/tips").status, 403);
 }
EOF

    expect_kind "tolerance-or-timeout-widened" "tolerance-or-timeout-widened" <<'EOF'
diff --git a/crates/veil-server/tests/server_hub/landing.rs b/crates/veil-server/tests/server_hub/landing.rs
--- a/crates/veil-server/tests/server_hub/landing.rs
+++ b/crates/veil-server/tests/server_hub/landing.rs
@@ -74,4 +74,4 @@ fn batch_finishes_within_sla() {
-    let deadline = Duration::from_secs(2);
+    let deadline = Duration::from_secs(30);
     assert!(run_batch(deadline).is_ok());
 }
EOF

    expect_kind "proptest-model (core_props)" "proptest-model" <<'EOF'
diff --git a/crates/veil-core/tests/core_props/oplog_merge.rs b/crates/veil-core/tests/core_props/oplog_merge.rs
--- a/crates/veil-core/tests/core_props/oplog_merge.rs
+++ b/crates/veil-core/tests/core_props/oplog_merge.rs
@@ -646,4 +646,4 @@ fn check_model(cmds: &[Cmd], repo: &Repo) {
-    Key::Head(h) => vals.contains(&got) || losers.contains(h),
+    Key::Head(h) => vals.contains(&got) || losers.contains(h) || diverged(h),
 }
EOF

    expect_kind "check-script (verify-server.sh)" "check-script" <<'EOF'
diff --git a/scripts/verify-server.sh b/scripts/verify-server.sh
--- a/scripts/verify-server.sh
+++ b/scripts/verify-server.sh
@@ -180,3 +180,3 @@
-STEP_LIMIT=1800 step yugabyte "$BIN"
+echo "skipping yugabyte"
EOF

    expect_kind "bench-gate (load.rs)" "bench-gate" <<'EOF'
diff --git a/crates/veil-bench/src/load.rs b/crates/veil-bench/src/load.rs
--- a/crates/veil-bench/src/load.rs
+++ b/crates/veil-bench/src/load.rs
@@ -140,3 +140,3 @@
-pub const GATE_COMMITS_PER_PUSH: f64 = 1.0;
+pub const GATE_COMMITS_PER_PUSH: f64 = 2.0;
EOF

    expect_kind "check-rules (SKILL.md)" "check-rules" <<'EOF'
diff --git a/.claude/skills/veil-review/SKILL.md b/.claude/skills/veil-review/SKILL.md
--- a/.claude/skills/veil-review/SKILL.md
+++ b/.claude/skills/veil-review/SKILL.md
@@ -39,3 +39,3 @@
-| **A** | sealing, policy | Deep |
+| **A** | sealing | Quick |
EOF

    expect_kind "lint-config (Cargo.toml)" "lint-config" <<'EOF'
diff --git a/crates/veil-core/Cargo.toml b/crates/veil-core/Cargo.toml
--- a/crates/veil-core/Cargo.toml
+++ b/crates/veil-core/Cargo.toml
@@ -67,2 +67,4 @@
 [lints.rust]
+[lints.clippy]
+too_many_arguments = "allow"
EOF

    expect_kind "lint-allow (#[allow(...)])" "lint-allow" <<'EOF'
diff --git a/crates/veil-core/src/repo.rs b/crates/veil-core/src/repo.rs
--- a/crates/veil-core/src/repo.rs
+++ b/crates/veil-core/src/repo.rs
@@ -210,2 +210,3 @@ impl Repo {
+    #[allow(clippy::too_many_arguments)]
     pub fn apply_change(&mut self) {}
EOF

    expect_kind "neutral diff (product fix + new test + un-ignore)" "" <<'EOF'
diff --git a/crates/veil-core/Cargo.toml b/crates/veil-core/Cargo.toml
--- a/crates/veil-core/Cargo.toml
+++ b/crates/veil-core/Cargo.toml
@@ -20,2 +20,3 @@
 [dependencies]
+blake3 = "1.5"
diff --git a/crates/veil-core/src/oplog.rs b/crates/veil-core/src/oplog.rs
--- a/crates/veil-core/src/oplog.rs
+++ b/crates/veil-core/src/oplog.rs
@@ -90,4 +90,6 @@ pub fn shared_base(op_id: &OpId) -> Result<bool> {
-    let timeout = Duration::from_secs(5);
+    let timeout = Duration::from_secs(30);
+    loop { break; }
     Ok(true)
 }
diff --git a/crates/veil-bench/src/load.rs b/crates/veil-bench/src/load.rs
--- a/crates/veil-bench/src/load.rs
+++ b/crates/veil-bench/src/load.rs
@@ -150,3 +150,3 @@
-/// 1,024 connections: a bound of about 480 MiB.
+/// 1,024 connections: a bound of about 496 MiB.
diff --git a/crates/veil-core/tests/core_engine/engine.rs b/crates/veil-core/tests/core_engine/engine.rs
--- a/crates/veil-core/tests/core_engine/engine.rs
+++ b/crates/veil-core/tests/core_engine/engine.rs
@@ -120,4 +120,3 @@
 #[test]
-#[ignore = "BUG-2999: fixed now"]
 fn bug_2999_now_passes() {
     assert_eq!(1 + 1, 2);
 }
@@ -200,2 +199,12 @@ fn bug_2999_now_passes() {
+
+#[test]
+fn bug_3000_new_regression_test_with_poll() {
+    let until = Instant::now() + Duration::from_secs(10);
+    while Instant::now() < until {
+        std::thread::sleep(Duration::from_millis(10));
+        break;
+    }
+    assert_eq!(compute_answer(), Landed);
+}
EOF

    # Also test off / observe / enforce + Check-change-approved in a tiny scratch git repo
    local repo="$tmp/repo"
    git init -q "$repo"
    git -C "$repo" config user.email "test@veil.local"
    git -C "$repo" config user.name "Test"
    mkdir -p "$repo/crates/veil-core/tests"
    cat >"$repo/crates/veil-core/tests/t.rs" <<'EOF'
#[test]
fn demo() {
    assert_eq!(2 + 2, 4);
    assert!(true);
}
EOF
    git -C "$repo" add .
    git -C "$repo" commit -q -m "base"
    git -C "$repo" branch integration
    git -C "$repo" checkout -q -b t3/test-branch
    cat >"$repo/crates/veil-core/tests/t.rs" <<'EOF'
#[test]
fn demo() {
    assert!(true);
}
EOF
    git -C "$repo" commit -q -am "drop assertion without approval"

    if [[ -f "$0" ]]; then
        local script_abs rc_obs rc_enf rc_off rc_app
        script_abs="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
        (cd "$repo" && CHECK_GUARD=off bash "$script_abs" integration...HEAD >/dev/null)
        rc_off=$?
        (cd "$repo" && CHECK_GUARD=observe bash "$script_abs" integration...HEAD >/dev/null)
        rc_obs=$?
        (cd "$repo" && CHECK_GUARD=enforce bash -s -- integration...HEAD <"$script_abs" >/dev/null 2>&1)
        rc_enf=$?
        git -C "$repo" commit -q --amend -m $'drop assertion\n\nCheck-change-approved: redundant with property test'
        (cd "$repo" && CHECK_GUARD=enforce bash -s -- integration...HEAD <"$script_abs" >/dev/null 2>&1)
        rc_app=$?
        if [[ "$rc_off" -eq 0 && "$rc_obs" -eq 0 && "$rc_enf" -eq 1 && "$rc_app" -eq 0 && -f "$repo/.git/check-guard.log" ]]; then
            printf '  ok    modes off=0 observe=0(+log) enforce=1 enforce+approved=0\n'
            pass=$((pass + 1))
        else
            printf '  FAIL  modes: off=%d obs=%d enf=%d app=%d\n' "$rc_off" "$rc_obs" "$rc_enf" "$rc_app" >&2
            fail=$((fail + 1))
        fi
    fi

    echo "check-guard self-test: $pass passed, $fail failed"
    [[ "$fail" -eq 0 ]]
}

STDIN_MODE=0
RANGE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --self-test)
            run_self_test
            exit $?
            ;;
        --stdin)
            STDIN_MODE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            [[ $# -gt 0 ]] && RANGE="$1"
            break
            ;;
        -*)
            echo "check-guard: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -n "$RANGE" ]]; then
                echo "check-guard: unexpected extra argument '$1'" >&2
                exit 2
            fi
            RANGE="$1"
            shift
            ;;
    esac
done

[[ "$MODE" == "off" ]] && exit 0

if [[ "$STDIN_MODE" -eq 1 ]]; then
    FINDINGS=$(analyze_diff "" "")
    RANGE_LABEL="stdin"
    APPROVED_REASON="${CHECK_GUARD_APPROVED_REASON:-}"
else
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        echo "check-guard: not inside a git repository" >&2
        exit 2
    fi

    RANGE="${RANGE:-integration...HEAD}"
    RANGE_LABEL="$RANGE"

    # Normalize <range> for both `git diff` (changes introduced by the right-hand
    # side relative to merge-base when branches diverged, so `<m>^1..<m>^2` and
    # `integration...HEAD` both inspect only the branch's own changes) and
    # `git log` (commits on the right-hand side not in the left-hand side).
    DIFF_SPEC=""
    LOG_SPEC=""
    RHS_REV="HEAD"
    if [[ "$RANGE" =~ ^(.+)\.\.\.(.+)$ ]]; then
        LHS="${BASH_REMATCH[1]}"
        RHS="${BASH_REMATCH[2]}"
        DIFF_SPEC="${LHS}...${RHS}"
        LOG_SPEC="${LHS}..${RHS}"
        RHS_REV="$RHS"
    elif [[ "$RANGE" =~ ^(.+)\.\.(.+)$ ]]; then
        LHS="${BASH_REMATCH[1]}"
        RHS="${BASH_REMATCH[2]}"
        LOG_SPEC="${LHS}..${RHS}"
        RHS_REV="$RHS"
        if git merge-base --is-ancestor "$LHS" "$RHS" 2>/dev/null ||
           git merge-base --is-ancestor "$RHS" "$LHS" 2>/dev/null; then
            DIFF_SPEC="${LHS}..${RHS}"
        else
            DIFF_SPEC="${LHS}...${RHS}"
        fi
    else
        DIFF_SPEC="$RANGE"
        LOG_SPEC="$RANGE"
        RHS_REV="$RANGE"
    fi

    if ! DIFF_TEXT=$(git diff --no-renames -U3 "$DIFF_SPEC"); then
        echo "check-guard: git diff failed for range '$RANGE'" >&2
        exit 2
    fi

    # Collect proptest test files and #[cfg(test)] start lines on RHS_REV for
    # changed Rust files so hunks inside unit test modules or proptest files
    # are classified accurately even when the hunk header lacks that keyword.
    PROPTEST_FILES=""
    CFG_TEST_LINES=""
    if git rev-parse --verify "${RHS_REV}^{tree}" >/dev/null 2>&1; then
        while IFS= read -r f; do
            [[ -z "$f" || "$f" != *.rs ]] && continue
            if [[ "$f" == crates/*/tests/* || "$f" == tests/* ]]; then
                if git grep -q 'proptest' "$RHS_REV" -- "$f" 2>/dev/null; then
                    PROPTEST_FILES+="${f}"$'\n'
                fi
            elif [[ "$f" == crates/*/src/* ]]; then
                cfg_ln=$(git show "${RHS_REV}:${f}" 2>/dev/null | awk '/^[[:space:]]*#\[cfg\(test\)\]/{print NR; exit}')
                if [[ -n "${cfg_ln:-}" ]]; then
                    CFG_TEST_LINES+="${f}:${cfg_ln}"$'\n'
                fi
            fi
        done < <(git diff --no-renames --name-only "$DIFF_SPEC" 2>/dev/null)
    fi

    FINDINGS=$(printf '%s\n' "$DIFF_TEXT" | analyze_diff "$PROPTEST_FILES" "$CFG_TEST_LINES")

    APPROVED_REASON=""
    if [[ -n "$LOG_SPEC" ]]; then
        APPROVED_REASON=$(git log --format=%B "$LOG_SPEC" 2>/dev/null |
            sed -nE 's/^[[:space:]]*[Cc]heck-change-approved:[[:space:]]*(.+)$/\1/p' |
            awk '{
                s = $0
                sub(/^[[:space:]]+/, "", s)
                sub(/[[:space:]]+$/, "", s)
                if (s != "" && s != "<reason>" && s != "..." && s != "…") {
                    print s
                    exit
                }
            }')
    fi
fi

[[ -z "$FINDINGS" ]] && exit 0

printf '%s\n' "$FINDINGS"

# Log flagged hunks to .git/check-guard.log (worktree-aware via --git-path).
LOG_FILE="${CHECK_GUARD_LOG:-}"
if [[ -z "$LOG_FILE" && "$STDIN_MODE" -eq 0 ]]; then
    LOG_FILE=$(git rev-parse --git-path check-guard.log 2>/dev/null || echo ".git/check-guard.log")
fi
if [[ -n "$LOG_FILE" ]]; then
    STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    COUNT=$(printf '%s\n' "$FINDINGS" | wc -l | tr -d ' ')
    {
        printf '[%s] mode=%s range=%s flagged=%s approved=%s\n' \
            "$STAMP" "$MODE" "$RANGE_LABEL" "$COUNT" "${APPROVED_REASON:-no}"
        printf '%s\n' "$FINDINGS" | sed 's/^/  /'
    } >>"$LOG_FILE" 2>/dev/null || true
fi

if [[ "$MODE" == "enforce" ]]; then
    if [[ -n "$APPROVED_REASON" ]]; then
        printf 'check-guard: approved (%s)\n' "$APPROVED_REASON" >&2
        exit 0
    fi
    echo "check-guard: enforce mode refused unapproved check/oracle/assertion changes (add 'Check-change-approved: <reason>' to a commit in the range after review)" >&2
    exit 1
fi

exit 0
