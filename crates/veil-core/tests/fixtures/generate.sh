#!/usr/bin/env bash
# Generate a golden fixture set with a given `vl` binary.
#
#   generate.sh <path/to/vl> <output-dir>
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
set -euo pipefail

VL=$(realpath "$1")
OUT=$2
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
pubkey() { VEIL_HOME="$OUT/home-$1" VEIL_USER=$1 "$VL" identity show | grep -o 'veil1[0-9a-f]\{128\}' | head -1; }

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
as alice embargo release "$EA" >/dev/null

# Loose objects after the pack.
printf 'fn main() {\n    println!("v3");\n}\n' > src/main.rs
as alice commit -m "third: loose objects" >/dev/null
as alice tag set main -r @- >/dev/null

# Unreleased embargo with a deadline far in the future.
as alice ws new fix-b -r main --cloak team >/dev/null
printf 'pub fn fix_b() {}\n' | as alice ws write fix-b src/fix_b.rs >/dev/null
as alice merge fix-b@ --into main --embargo --until 2099-01-01 -m "Fix B (embargoed)" >/dev/null

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
"$VL" --version > "$OUT/VERSION"
echo "fixture written to $OUT"
