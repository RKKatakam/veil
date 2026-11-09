#!/bin/bash
# Temporary (review of s8k, not committed): the review's server_hub tests, alone, on a Boat machine.
set -u
D() { if docker info >/dev/null 2>&1; then docker "$@"; else sudo docker "$@"; fi; }
D rm -f s8kr-pg2 >/dev/null 2>&1
D run -d --name s8kr-pg2 -e POSTGRES_PASSWORD=veil -e POSTGRES_USER=veil -e POSTGRES_DB=veil -p 127.0.0.1:55433:5432 postgres:17-alpine -c max_connections=500 >/dev/null || exit 1
for i in $(seq 90); do D exec s8kr-pg2 pg_isready -U veil -h 127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done
sleep 2
cargo build -q -p vl -p veil-server || exit 1
BIN=$(cargo test -p veil-server --features containers --test server_hub --no-run 2>&1 | grep -o 'target/debug/deps/server_hub-[0-9a-f]*' | head -1)
[ -n "$BIN" ] || exit 1
export VEIL_TEST_VL=$PWD/target/debug/vl VEIL_TEST_DATABASE_URL=postgres://veil:veil@127.0.0.1:55433/veil
mkdir -p .scratch/tmp; export TMPDIR=$PWD/.scratch/tmp
echo "=== guarantee tests (one thread: the request counter is the hub's)"
VEIL_TEST_DB_PREFIX=g1x timeout 1500 "$BIN" --exact --test-threads=1 --nocapture \
  workspaces::s8kr_a_push_after_the_server_moved_costs_no_request_a_tag \
  workspaces::s8jr_a_push_costs_no_request_a_tag \
  workspaces::s8kr_a_push_moves_first_and_runs_its_hook_once \
  workspaces::s8kr_ws_exec_never_runs_its_command_twice_across_a_move \
  workspaces::bug_1572_a_pulled_tag_named_like_a_change_id_is_read_through_its_remote_tag 2>&1 | grep -v "^\s*$" | grep -v migration | tail -40
echo "=== ignored reproductions (expected to fail)"
VEIL_TEST_DB_PREFIX=g2x timeout 1500 "$BIN" --exact --ignored --test-threads=2 \
  workspaces::bug_1573_a_workspace_never_synced_runs_on_the_current_view_after_an_access_change \
  workspaces::bug_1574_a_sandbox_whose_root_the_server_refuses_keeps_a_readable_record 2>&1 | grep -E "^test |test result" 
D rm -f s8kr-pg2 >/dev/null 2>&1
