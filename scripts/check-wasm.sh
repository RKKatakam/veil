#!/usr/bin/env bash
# The portable engine: veil-core without an operating system or the zstd C
# library, as it runs in a browser (docs/ARCHITECTURE.md, "Builds without
# an operating system"). CI runs this in the `wasm` job of
# .github/workflows/ci.yml; run it locally before changing anything in
# veil-core that could reach for the OS (std::fs, std::process, threads,
# clocks, libc).
#
#   1. veil-core builds for wasm32-unknown-unknown with the `wasm` features;
#   2. the same feature set, natively: the portable tests and the example,
#      and native `vl` opening a repository the portable engine wrote;
#   3. the pure-Rust zstd decoder against the C library's output;
#   4. clippy over the portable configurations;
#   5. the example built for wasm32 and run under node (skipped, with a
#      note, when node is not installed).
#
# Step 5 builds with getrandom's `custom` backend (the example takes its
# randomness from the host), not the `wasm` feature's WebCrypto backend:
# that one needs wasm-bindgen's JS glue, and getrandom 0.4.3 does not
# compile with both. Step 1 covers the `wasm` feature build itself.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
LOCKED=${LOCKED---locked}

if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx "$TARGET"; then
    rustup target add "$TARGET"
fi

step() { printf '\n==> %s\n' "$*"; }

step "veil-core for $TARGET (--no-default-features --features wasm)"
cargo build $LOCKED -p veil-core --target "$TARGET" --no-default-features --features wasm

step "the WASM feature set on the host: portable tests and the example"
cargo test $LOCKED -p veil-core --no-default-features --features wasm --test portable
cargo run $LOCKED -q -p veil-core --no-default-features --features wasm --example wasm_smoke >/dev/null
cargo run $LOCKED -q -p veil-core --no-default-features --features wasm --example web_wasm >/dev/null

step "native vl opens a repository the portable engine wrote"
export_dir=$(mktemp -d)
trap 'rm -rf "$export_dir"' EXIT
VEIL_PORTABLE_EXPORT="$export_dir" cargo test $LOCKED -q -p veil-core --no-default-features --features wasm \
    --test portable a_repository_for_native_vl
cargo build $LOCKED -q -p vl
vl="$PWD/target/debug/vl"
(
    cd "$export_dir/repo"
    export VEIL_HOME="$export_dir/home"
    "$vl" fsck
    "$vl" log >"$export_dir/log.txt"
    grep -q "portable: after gc" "$export_dir/log.txt"
    grep -q "portable: merge" "$export_dir/log.txt"
    test "$("$vl" cat secrets/.env.plan)" = "team-only plan"
    test "$("$vl" cat src/lib.rs)" = "pub fn portable() {}"
    "$vl" gc >/dev/null
    "$vl" fsck >/dev/null
    test "$("$vl" cat README.md)" = "written without an operating system"
)
echo "vl: fsck clean, log, cat (sealed and public), gc"

step "pure-Rust zstd decoder against libzstd (--features ruzstd)"
cargo test $LOCKED -p veil-core --features ruzstd --lib pack::

step "clippy, portable configurations"
cargo clippy $LOCKED -p veil-core --no-default-features --features wasm --lib --examples --test portable -- -D warnings
cargo clippy $LOCKED -p veil-core --target "$TARGET" --no-default-features --features wasm --lib -- -D warnings
cargo clippy $LOCKED -p veil-core --features ruzstd --lib --tests --examples -- -D warnings

step "the example on $TARGET under node"
# A separate target directory: the RUSTFLAGS would otherwise invalidate
# the main build's cache.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}/wasm-smoke"
RUSTFLAGS='--cfg getrandom_backend="custom"' \
    cargo build $LOCKED -p veil-core --release --target "$TARGET" \
    --no-default-features --features ruzstd --example wasm_smoke --example web_wasm
wasm="$CARGO_TARGET_DIR/$TARGET/release/examples/wasm_smoke.wasm"
web_wasm="$CARGO_TARGET_DIR/$TARGET/release/examples/web_wasm.wasm"
printf 'wasm_smoke.wasm: %s bytes\n' "$(wc -c <"$wasm" | tr -d ' ')"
printf 'web_wasm.wasm: %s bytes\n' "$(wc -c <"$web_wasm" | tr -d ' ')"
if command -v node >/dev/null; then
    node scripts/wasm-smoke.mjs "$wasm"
    node scripts/web-wasm.mjs "$web_wasm"
else
    echo "node not found: built for $TARGET but not run (install node to run it)"
fi
