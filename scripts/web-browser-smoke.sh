#!/usr/bin/env bash
# The web client in a real browser: a headless Chromium, driven over the
# DevTools protocol with a virtual WebAuthn authenticator, enrolls a passkey
# with a `vl web` code, signs in, opens a file page, signs out, signs in
# again and, with PRF, shows a secret (scripts/web-browser-smoke.mjs, started
# by the ignored test server_hub::browser). No other test runs the pages'
# JavaScript.
#
#   bash scripts/web-browser-smoke.sh [RUNNER...]
#
# It installs and downloads nothing: it uses the Chromium named by
# VEIL_CHROMIUM, one on PATH, or one Playwright left in ~/.cache/ms-playwright,
# and exits 2 when there is none (the web client is then unproven in a real
# browser on this machine). It needs node 22 or later.
#
# The test needs what every server test needs (VEIL_TEST_DATABASE_URL,
# VEIL_TEST_VL, …: see scripts/verify-server.sh). With them set, it runs
# through cargo. RUNNER is a command that sets them up and takes libtest
# filters and flags instead.
set -euo pipefail
cd "$(dirname "$0")/.."

chromium=${VEIL_CHROMIUM:-}
if [ -z "$chromium" ]; then
    for name in chromium chromium-browser google-chrome google-chrome-stable chrome-headless-shell; do
        if command -v "$name" >/dev/null; then chromium=$(command -v "$name"); break; fi
    done
fi
if [ -z "$chromium" ]; then
    for found in "$HOME"/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell \
                 "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux64/chrome; do
        if [ -x "$found" ]; then chromium=$found; fi
    done
fi
if [ -z "$chromium" ] || [ ! -x "$chromium" ]; then
    echo "no Chromium found (VEIL_CHROMIUM, PATH, ~/.cache/ms-playwright): the web client is NOT proven in a real browser here" >&2
    exit 2
fi
if ! command -v node >/dev/null || [ "$(node -p 'Number(process.versions.node.split(".")[0]) >= 22')" != true ]; then
    echo "node 22 or later is needed (its built-in WebSocket)" >&2
    exit 2
fi
echo "Chromium: $chromium ($("$chromium" --version 2>/dev/null || echo 'version unknown'))"

# The Workers' WASM, where the server looks for it (as scripts/check-wasm.sh
# builds it: a target directory of its own, for the RUSTFLAGS).
CARGO_TARGET_DIR=target/wasm-smoke RUSTFLAGS='--cfg getrandom_backend="custom"' \
    cargo build --locked -p veil-core --release --target wasm32-unknown-unknown \
    --no-default-features --features ruzstd --example web_wasm --example web_secret_worker

export VEIL_CHROMIUM=$chromium
if [ $# -gt 0 ]; then
    exec "$@" browser:: --ignored --nocapture
fi
: "${VEIL_TEST_DATABASE_URL:?set the server tests' environment (scripts/verify-server.sh), or pass a RUNNER}"
exec cargo test -p veil-server --features containers --test server_hub browser:: -- --ignored --nocapture
