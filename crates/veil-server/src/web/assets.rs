//! Static CSS, Trusted-Types-safe progressive-enhancement JS, and optional
//! `veil-core` WASM binary served at `/static/{asset}` (`docs/HUB.md` §13.39).

use axum::{
    extract::Path,
    http::header,
    response::{IntoResponse, Response},
};

use crate::error::{Error, Result};

pub const APP_CSS: &str = r#":root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #14171f;
  --muted: #5a6270;
  --border: #d8dee9;
  --surface: #f6f8fa;
  --accent: #1d4ed8;
  --badge-bg: #eef2ff;
  --badge-fg: #1e3a8a;
  --seal-bg: #fef3c7;
  --seal-fg: #92400e;
  --add-bg: #dcfce7;
  --add-fg: #14532d;
  --del-bg: #fee2e2;
  --del-fg: #7f1d1d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #8b949e;
    --border: #30363d;
    --surface: #161b22;
    --accent: #58a6ff;
    --badge-bg: #1f2937;
    --badge-fg: #93c5fd;
    --seal-bg: #3b2a10;
    --seal-fg: #fcd34d;
    --add-bg: #122d1f;
    --add-fg: #86efac;
    --del-bg: #36181c;
    --del-fg: #fca5a5;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.5;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  padding: 0.65rem 1.25rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}
.brand { font-weight: 700; font-size: 1.05rem; color: var(--fg); }
.nav-tabs { display: flex; gap: 0.9rem; flex-wrap: wrap; align-items: center; }
.nav-tabs a.active { font-weight: 700; border-bottom: 2px solid var(--accent); }
.container { max-width: 1120px; margin: 1.25rem auto; padding: 0 1.25rem 3rem; }
.card {
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  margin-bottom: 1rem;
  overflow: hidden;
}
.card-header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0.6rem 0.9rem;
  font-weight: 600;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.card-body { padding: 0.9rem; }
.badge {
  display: inline-block;
  padding: 0.1rem 0.45rem;
  border-radius: 4px;
  font-size: 0.78rem;
  font-weight: 600;
  background: var(--badge-bg);
  color: var(--badge-fg);
}
.badge-sealed { background: var(--seal-bg); color: var(--seal-fg); }
.muted { color: var(--muted); font-size: 0.9rem; }
.mono, code, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.86rem;
}
table.listing, table.code-table {
  width: 100%;
  border-collapse: collapse;
}
table.listing th, table.listing td {
  text-align: left;
  padding: 0.45rem 0.75rem;
  border-bottom: 1px solid var(--border);
}
table.code-table td {
  padding: 0.08rem 0.6rem;
  vertical-align: top;
  white-space: pre-wrap;
  word-break: break-word;
}
td.ln {
  width: 1%;
  white-space: nowrap;
  text-align: right;
  color: var(--muted);
  user-select: none;
  border-right: 1px solid var(--border);
}
tr.diff-add td { background: var(--add-bg); color: var(--add-fg); }
tr.diff-del td { background: var(--del-bg); color: var(--del-fg); }
.pager {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  margin: 0.85rem 0;
}
.btn, button {
  padding: 0.38rem 0.75rem;
  border: 1px solid var(--border);
  border-radius: 5px;
  background: var(--surface);
  color: var(--fg);
  cursor: pointer;
  font-size: 0.88rem;
}
input[type="text"], input[type="search"], textarea, select {
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: 5px;
  background: var(--bg);
  color: var(--fg);
  font-size: 0.9rem;
}
.form-row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin: 0.5rem 0; }
textarea { width: 100%; min-height: 4.5rem; }
"#;

/// Strict-CSP & Trusted-Types-compliant client script:
/// - Never assigns to `innerHTML`, `outerHTML`, or `document.write`.
/// - Lazily loads `/static/veil_web.wasm` (`veil-core` on `wasm32-unknown-unknown`,
///   with zero secret-decryption exports) for in-memory `hub-login` and
///   `hub-pr-review` signing so device private keys never leave browser memory.
pub const APP_JS: &str = r#"'use strict';
(function () {
  if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
      window.trustedTypes.createPolicy('veil', {
        createHTML: function () { throw new TypeError('HTML sinks disabled'); },
        createScript: function () { throw new TypeError('eval disabled'); },
        createScriptURL: function (u) {
          if (u === '/static/app.js') return u;
          throw new TypeError('Blocked script URL');
        }
      });
    } catch (_) {}
  }

  function csrfToken() {
    var m = document.querySelector('meta[name="veil-csrf"]');
    return m ? (m.getAttribute('content') || '') : '';
  }

  var navForm = document.getElementById('veil-goto-project');
  if (navForm) {
    navForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var inp = document.getElementById('veil-project-input');
      var name = inp ? inp.value.trim() : '';
      if (name) {
        window.location.assign('/p/' + encodeURIComponent(name));
      }
    });
  }

  var wasmPromise = null;
  function loadWasm() {
    if (wasmPromise) return wasmPromise;
    var memory = null;
    var imports = {
      env: {
        veil_now_ms: function () { return Date.now(); },
        veil_random_fill: function (ptr, len) {
          for (var off = 0; off < len; off += 65536) {
            var n = Math.min(65536, len - off);
            crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, n));
          }
          return 0;
        }
      }
    };
    wasmPromise = fetch('/static/veil_web.wasm', { credentials: 'same-origin' })
      .then(function (r) {
        if (!r.ok) throw new Error('WASM engine unavailable; use a short-lived vl web session token');
        return r.arrayBuffer();
      })
      .then(function (buf) { return WebAssembly.instantiate(buf, imports); })
      .then(function (res) {
        memory = res.instance.exports.memory;
        return { ex: res.instance.exports, memory: memory };
      });
    return wasmPromise;
  }

  function putStr(w, s) {
    var bytes = new TextEncoder().encode(s);
    if (bytes.length === 0) return [0, 0];
    var ptr = w.ex.veil_web_alloc(bytes.length);
    new Uint8Array(w.memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  }

  function readOut(w) {
    var ptr = w.ex.veil_web_out_ptr();
    var len = w.ex.veil_web_out_len();
    return new TextDecoder().decode(new Uint8Array(w.memory.buffer, ptr, len));
  }

  function freeAll(w, allocs) {
    for (var i = 0; i < allocs.length; i++) {
      if (allocs[i][1] > 0) w.ex.veil_web_free(allocs[i][0], allocs[i][1]);
    }
  }

  var devForm = document.getElementById('veil-device-login-form');
  if (devForm) {
    devForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var statusEl = document.getElementById('veil-login-status');
      var idField = document.getElementById('veil-identity-json');
      var idJson = idField ? idField.value.trim() : '';
      if (idField) idField.value = '';
      if (!idJson) return;
      var parsed;
      try { parsed = JSON.parse(idJson); } catch (_) {
        if (statusEl) statusEl.textContent = 'Invalid identity JSON.';
        return;
      }
      var pubKey = parsed.verifying_key || parsed.signing_public || '';
      loadWasm().then(function (w) {
        return fetch('/v1/auth/challenge', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ key: pubKey })
        }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j, w: w }; }); });
      }).then(function (step) {
        if (!step.ok) throw new Error(step.j.message || 'Challenge failed');
        var w = step.w;
        var a1 = putStr(w, idJson);
        var a2 = putStr(w, window.location.host);
        var a3 = putStr(w, step.j.challenge);
        var rc = w.ex.veil_web_sign_login(a1[0], a1[1], a2[0], a2[1], a3[0], a3[1]);
        var out = readOut(w);
        freeAll(w, [a1, a2, a3]);
        if (rc !== 0) throw new Error(out);
        return fetch('/web/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'accept': 'application/json' },
          body: out
        });
      }).then(function (r) {
        if (!r.ok) throw new Error('Sign-in refused');
        window.location.assign('/');
      }).catch(function (err) {
        if (statusEl) statusEl.textContent = String(err.message || err);
      });
    });
  }

  var revForm = document.getElementById('veil-wasm-review-form');
  if (revForm) {
    revForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var proj = revForm.getAttribute('data-project') || '';
      var prId = revForm.getAttribute('data-pr') || '';
      var patch = revForm.getAttribute('data-patch') || '';
      var verdictEl = document.getElementById('veil-review-verdict');
      var bodyEl = document.getElementById('veil-review-body');
      var idEl = document.getElementById('veil-review-identity');
      var statusEl = document.getElementById('veil-review-status');
      var idJson = idEl ? idEl.value.trim() : '';
      if (idEl) idEl.value = '';
      var verdict = verdictEl ? verdictEl.value : 'approve';
      var body = bodyEl ? bodyEl.value : '';
      loadWasm().then(function (w) {
        var a1 = putStr(w, idJson);
        var a2 = putStr(w, proj);
        var a3 = putStr(w, prId);
        var a4 = putStr(w, patch);
        var a5 = putStr(w, verdict);
        var rc = w.ex.veil_web_sign_review(a1[0], a1[1], a2[0], a2[1], a3[0], a3[1], a4[0], a4[1], a5[0], a5[1]);
        var out = readOut(w);
        freeAll(w, [a1, a2, a3, a4, a5]);
        if (rc !== 0) throw new Error(out);
        var sig = JSON.parse(out);
        return fetch('/v1/projects/' + encodeURIComponent(proj) + '/prs/' + encodeURIComponent(prId) + '/reviews', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-veil-csrf': csrfToken()
          },
          body: JSON.stringify({ patch: patch, verdict: verdict, body: body || null, signature: sig })
        });
      }).then(function (r) {
        if (!r.ok) throw new Error('Review submission refused');
        window.location.reload();
      }).catch(function (err) {
        if (statusEl) statusEl.textContent = String(err.message || err);
      });
    });
  }
})();
"#;

pub async fn static_route(Path(asset): Path<String>) -> Result<Response> {
    match asset.as_str() {
        "app.css" => Ok((
            [
                (header::CONTENT_TYPE, "text/css; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            APP_CSS,
        )
            .into_response()),
        "app.js" => Ok((
            [
                (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            APP_JS,
        )
            .into_response()),
        "veil_web.wasm" => {
            let candidates = [
                std::env::var_os("VEIL_WEB_WASM_PATH").map(std::path::PathBuf::from),
                Some(std::path::PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../target/wasm32-unknown-unknown/release/examples/web_wasm.wasm"
                ))),
            ];
            for cand in candidates.into_iter().flatten() {
                if let Ok(bytes) = tokio::fs::read(&cand).await {
                    return Ok((
                        [
                            (header::CONTENT_TYPE, "application/wasm"),
                            (header::CACHE_CONTROL, "public, max-age=300"),
                        ],
                        bytes,
                    )
                        .into_response());
                }
            }
            Err(Error::not_found("asset not found"))
        }
        _ => Err(Error::not_found("asset not found")),
    }
}
