#!/bin/bash
# Temporary (review of s8k, not committed): 16 parallel copies of the BUG-1572
# tests, several rounds, on a Boat machine with its own PostgreSQL.
set -u
D() { if docker info >/dev/null 2>&1; then docker "$@"; else sudo docker "$@"; fi; }
D rm -f s8kr-pg >/dev/null 2>&1
D run -d --name s8kr-pg -e POSTGRES_PASSWORD=veil -e POSTGRES_USER=veil -e POSTGRES_DB=veil -p 127.0.0.1:55432:5432 postgres:17-alpine -c max_connections=1500 >/dev/null || exit 1
for i in $(seq 90); do D exec s8kr-pg pg_isready -U veil -h 127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done
sleep 2
cargo build -q -p vl -p veil-server || exit 1
BIN=$(cargo test -p veil-server --features containers --test server_hub --no-run 2>&1 | grep -o 'target/debug/deps/server_hub-[0-9a-f]*' | head -1)
[ -n "$BIN" ] || exit 1
export VEIL_TEST_VL=$PWD/target/debug/vl VEIL_TEST_DATABASE_URL=postgres://veil:veil@127.0.0.1:55432/veil
mkdir -p .scratch/tmp .scratch/load; export TMPDIR=$PWD/.scratch/tmp
TESTS="workspaces::s8jr_the_move_rebases_stacks_merges_workspaces_and_divergent_changes workspaces::bug_1572_a_pulled_tag_named_like_a_change_id_is_read_through_its_remote_tag workspaces::s8kr_a_push_moves_first_and_runs_its_hook_once workspaces::s8kr_ws_exec_never_runs_its_command_twice_across_a_move"
ROUNDS=${ROUNDS:-6}; COPIES=${COPIES:-16}
fail=0 runs=0
for r in $(seq "$ROUNDS"); do
  pids=""
  for i in $(seq "$COPIES"); do
    VEIL_TEST_DB_PREFIX=l${r}x${i}x timeout 1500 "$BIN" --exact $TESTS --test-threads=2 > .scratch/load/$r-$i.log 2>&1 &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p"; done
  for i in $(seq "$COPIES"); do
    runs=$((runs+1))
    if ! grep -q "test result: ok. 4 passed" .scratch/load/$r-$i.log; then
      fail=$((fail+1)); echo "=== round $r copy $i FAILED"; grep -E "panicked at" -A12 .scratch/load/$r-$i.log | head -80; tail -5 .scratch/load/$r-$i.log
    fi
  done
  echo "round $r done: $fail failed of $runs so far"
done
echo "s8kr-load: $fail of $runs copies failed (4 tests each)"
D rm -f s8kr-pg >/dev/null 2>&1
[ "$fail" = 0 ]
