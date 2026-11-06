#!/usr/bin/env bash
# Generate a golden fixture set with a given `vl` binary.
#
#   generate.sh <path/to/vl> <output-dir> [<previous-fixture-set>]
#
# Every repository format must have a fixture set produced by the release
# that introduced it (see docs/FORMAT.md, "Compatibility fixtures"). Never
# regenerate an existing set: it records what that release wrote.
#
# The set contains three identities (alice, bob, carol) and three
# repositories:
#   alice/          project directory: packed and loose objects, a cloaked
#                   directory, a scope ring with a grant, a revocation (key
#                   generation 1) and a rotation, a released and an
#                   unreleased embargo, a vault, a stat cache and checkout
#                   state, an isolated file
#   team-remote/    bare remote alice pushed to (ciphertext and rings)
#   public-mirror/  bare public remote (cloaked content withheld)
#
# With a previous fixture set (format 3 on: pass format-2), also:
#   home-dave/      a *legacy* identity (copied from the previous set's
#                   carol: signing key derived from the encryption key),
#                   granted to `team` in alice/ next to the new identities
# From format 4 on, alice/ also holds a merge with conflict entries (tag
# `conflicted`): a cloaked file's conflict left unresolved, a public one
# resolved with `vl resolve`.
# From format 7 on, alice/ also holds a key ring of ring format 4 (scope
# `rule-fixture`: an invite, shares by members, a member's removal of their
# own device), written by the `write_format_7_extras` test before the pushes.
# From format 6 on, the last thing written to alice/ is concurrent
# operations (the `write_format_6_extras` test): a merge whose sides carry
# `rewritten` and `workspace`, and two heads left unmerged.
# From format 5 on, alice/ also holds symlinks (public and sealed), a
# link/file conflict and annotated tags (signed, and cloaked with a sealed
# message): tags `links`, `link-conflict`, `v5.0`, `team-release`. They are
# written through the engine by the `write_format_5_extras` test of
# tests/core_format/format_compat.rs: set VEIL_FIXTURE_EXTRAS to that test
# binary (`cargo test -p veil-core --test core_format --no-run` prints it).
#
#   upgraded/       the previous set's alice/ and team-remote/ (and their
#                   identities) after `vl -R team-remote upgrade` (a bare
#                   repository is upgraded structurally),
#                   `vl upgrade` and one more commit pushed: old sealed
#                   objects and ring changes next to new ones
#
# team-remote/ and public-mirror/ are written through path remotes, which
# `vl` keeps only as a test fixture since the Veil server replaced them:
# <path/to/vl> must be a debug build (`cargo build -p vl`), run here with
# VEIL_TEST_PATH_REMOTES set.
set -euo pipefail
export VEIL_TEST_PATH_REMOTES=1

VL=$(realpath "$1")
OUT=$2
PREV=${3:+$(realpath "$3")}
mkdir -p "$OUT"
OUT=$(realpath "$OUT")
if [ -e "$OUT/alice" ]; then
    echo "refusing to overwrite $OUT" >&2
    exit 1
fi

as() { # as <user> <args…>   (runs vl in alice/ as that user)
    local who=$1
    shift
    VEIL_HOME="$OUT/home-$who" VEIL_USER=$who "$VL" -R "$OUT/alice" "$@"
}
pubkey() { VEIL_HOME="$OUT/home-$1" VEIL_USER=$1 "$VL" identity show | awk '/^public key/ {print $3}'; }

mkdir -p "$OUT/alice"
cd "$OUT/alice"
BOB=$(pubkey bob)
CAROL=$(pubkey carol)

printf 'Fixture project\n' > README.md
as alice init "$OUT/alice" >/dev/null 2>&1

mkdir -p src/util bin secrets docs
printf 'fn main() {\n    println!("v1");\n}\n' > src/main.rs
printf 'pub fn shout(s: &str) -> String {\n    s.to_uppercase()\n}\n' > src/util/strings.rs
printf '#!/bin/sh\necho run\n' > bin/run.sh
chmod +x bin/run.sh
printf 'team-only notes v1\n' > secrets/notes.txt
for i in $(seq 1 200); do echo "line $i of a long document that compresses well"; done > docs/big.txt
printf 'DB_PASSWORD=fixture-not-a-secret-1234\n' > .env
as alice cloak secrets/ --scope team >/dev/null
as alice commit -m "initial import" >/dev/null
as alice tag set main -r @- >/dev/null

# Ring: grant bob, grant and revoke carol (generation 1), rotate (generation 2).
as alice scope grant team "$BOB" --name bob >/dev/null
as alice scope grant team "$CAROL" --name carol >/dev/null
if [ -n "$PREV" ]; then
    mkdir -p "$OUT/home-dave"
    cp "$PREV/home-carol/identity.json" "$OUT/home-dave/identity.json"
    DAVE=$(pubkey dave)
    as alice scope grant team "$DAVE" --name dave >/dev/null
fi
as alice scope revoke team "$CAROL" >/dev/null
as alice scope rotate team >/dev/null

# Second commit: new versions (delta candidates), sealed under the new generation.
for i in $(seq 1 200); do echo "line $i of a long document that compresses well (rev 2)"; done > docs/big.txt
printf 'team-only notes v2\n' > secrets/notes.txt
printf 'fn main() {\n    println!("v2");\n}\n' > src/main.rs
as alice commit -m "second: edit docs and notes" >/dev/null
as alice tag set main -r @- >/dev/null

# An abandoned experiment, then pack everything: the experiment stays in
# the pack as gc-pending (grace period), and old operations are pruned.
printf 'experiment\n' > experiment.txt
as alice commit -m "experiment (abandoned)" >/dev/null
as alice abandon @- >/dev/null
as alice gc --keep-ops-days 0 >/dev/null
test -s "$OUT/alice/.veil/objects/gc/pending"
test -s "$OUT/alice/.veil/ops_pruned"

# Released embargo.
as alice ws new fix-a -r main --cloak team >/dev/null
printf 'pub fn fix_a() {}\n' | as alice ws write fix-a src/fix_a.rs >/dev/null
as alice merge fix-a@ --into main --embargo -m "Fix A (released)" >/dev/null
EA=$(as alice embargo list | awk '/manual release/ {print $1}' | head -1)
as alice embargo release "$EA" --yes >/dev/null  # vl ≥ 1.0 asks without --yes

# Loose objects after the pack.
printf 'fn main() {\n    println!("v3");\n}\n' > src/main.rs
as alice commit -m "third: loose objects" >/dev/null
as alice tag set main -r @- >/dev/null

# Format 4 on: first-class conflicts. A merge of two lines that edit the
# same lines of a public file and of a cloaked one records conflict
# entries (one side of the cloaked file sealed under the new generation);
# the public one is resolved with `vl resolve --theirs`, the cloaked one
# stays unresolved at the tag `conflicted`.
if "$VL" resolve --help >/dev/null 2>&1; then
    as alice ws new side-a -r main >/dev/null
    as alice ws new side-b -r main >/dev/null
    printf 'pub fn shout(s: &str) -> String {\n    s.to_uppercase() + "!"\n}\n' | as alice ws write side-a src/util/strings.rs >/dev/null
    printf 'team-only notes (side a)\n' | as alice ws write side-a secrets/notes.txt >/dev/null
    printf 'pub fn shout(s: &str) -> String {\n    s.to_ascii_uppercase()\n}\n' | as alice ws write side-b src/util/strings.rs >/dev/null
    printf 'team-only notes (side b)\n' | as alice ws write side-b secrets/notes.txt >/dev/null
    as alice new side-a@ side-b@ -m "conflicted merge" >/dev/null 2>&1
    as alice resolve src/util/strings.rs --theirs >/dev/null
    as alice commit -m "keep side b's strings.rs" >/dev/null
    as alice tag set conflicted -r @- >/dev/null
    as alice new main >/dev/null
fi

# Format 5 on: links and annotated tags (see the header).
if [ "$("$VL" --version | sed -n 's/^repository format: //p')" -ge 5 ]; then
    : "${VEIL_FIXTURE_EXTRAS:?set VEIL_FIXTURE_EXTRAS to the core_format test binary}"
    VEIL_FIXTURE_DIR="$OUT" "$VEIL_FIXTURE_EXTRAS" --ignored --exact format_compat::write_format_5_extras >/dev/null
fi

# Unreleased embargo with a deadline far in the future.
as alice ws new fix-b -r main --cloak team >/dev/null
printf 'pub fn fix_b() {}\n' | as alice ws write fix-b src/fix_b.rs >/dev/null
as alice merge fix-b@ --into main --embargo --until 2099-01-01 -m "Fix B (embargoed)" >/dev/null

# Format 7 on: a ring of format 4 (an invite, shares by members, a member's
# removal of their own device), pushed with the rest.
if [ "$("$VL" --version | sed -n 's/^repository format: //p')" -ge 7 ]; then
    VEIL_FIXTURE_DIR="$OUT" "$VEIL_FIXTURE_EXTRAS" --ignored --exact format_compat::write_format_7_extras >/dev/null
fi

# A cloaked tag and a vault secret.
as alice tag set team-only -r fix-a@ --cloak team >/dev/null
as alice secret set API_TOKEN fixture-value >/dev/null

as alice remote add origin "$OUT/team-remote" >/dev/null
as alice remote add mirror "$OUT/public-mirror" --public >/dev/null
as alice push origin >/dev/null 2>&1
as alice push mirror >/dev/null 2>&1

# Remotes are recorded with absolute paths; make them relative to alice/.
sed -i.bak -e "s#$OUT/#../#g" "$OUT/alice/.veil/repo.json" && rm "$OUT/alice/.veil/repo.json.bak"

# A lock file must not be left behind; the pointer and caches are kept.
test ! -e "$OUT/alice/.veil/lock"
as alice log > "$OUT/alice-log.txt"

# Format 6 on: concurrent operations, last (any later command would merge
# the two heads they leave).
if [ "$("$VL" --version | sed -n 's/^repository format: //p')" -ge 6 ]; then
    VEIL_FIXTURE_DIR="$OUT" "$VEIL_FIXTURE_EXTRAS" --ignored --exact format_compat::write_format_6_extras >/dev/null
    test "$(ls "$OUT/alice/.veil/op_heads" | wc -l)" -eq 2
fi

if [ -n "$PREV" ]; then
    U="$OUT/upgraded"
    mkdir -p "$U"
    for part in alice team-remote home-alice home-bob home-carol; do
        cp -R "$PREV/$part" "$U/$part"
    done
    up() { # up <user> <args…>   (runs vl in upgraded/alice as that user)
        local who=$1
        shift
        VEIL_HOME="$U/home-$who" VEIL_USER=$who "$VL" -R "$U/alice" "$@"
    }
    VEIL_HOME="$U/home-alice" VEIL_USER=alice "$VL" -R "$U/team-remote" upgrade >/dev/null
    up alice upgrade >/dev/null
    printf 'team-only notes v3 (after the upgrade)\n' > "$U/alice/secrets/notes.txt"
    printf 'after the upgrade\n' > "$U/alice/UPGRADED.md"
    up alice commit -m "fourth: after the upgrade" >/dev/null
    up alice tag set main -r @- >/dev/null
    # Only `main`: the format-6 set's extras amend `links` after its push,
    # so its other tags differ from its remote.
    up alice push origin --tag main >/dev/null 2>&1
    test ! -e "$U/alice/.veil/lock"
    test ! -e "$U/alice/.veil/upgrade.json"
fi
"$VL" --version > "$OUT/VERSION"
echo "fixture written to $OUT"
