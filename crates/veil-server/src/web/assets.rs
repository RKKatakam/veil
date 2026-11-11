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
/// - Enrolls passkeys via WebAuthn + PRF, generating browser device keys inside
///   a dedicated Web Worker (`/static/enroll-worker.js` + `/static/veil_web.wasm`)
///   and storing only the PRF-encrypted `sealed_identity_hex` in IndexedDB.
/// - Contains zero secret-decryption code (`secrets.js` and `secret-worker.js`
///   are served only on projects where an admin turned `web_secrets` on).
pub const APP_JS: &str = r#"'use strict';
(function () {
  var ttPolicy = null;
  if (window.trustedTypes && window.trustedTypes.createPolicy) {
    try {
      ttPolicy = window.trustedTypes.createPolicy('veil', {
        createHTML: function () { throw new TypeError('HTML sinks disabled'); },
        createScript: function () { throw new TypeError('eval disabled'); },
        createScriptURL: function (u) {
          if (u === '/static/app.js' || u === '/static/enroll-worker.js') return u;
          if (/^\/p\/[a-z0-9._-]+\/web\/secret(s|-worker)\.js$/.test(u)) return u;
          throw new TypeError('Blocked script URL');
        }
      });
    } catch (_) {}
  }
  window.__veilTrustedScriptURL = function (u) {
    return ttPolicy ? ttPolicy.createScriptURL(u) : u;
  };

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

  var logoutForms = document.querySelectorAll('form[action="/web/logout"]');
  for (var li = 0; li < logoutForms.length; li++) {
    logoutForms[li].addEventListener('submit', function () {
      try {
        if (window.indexedDB) indexedDB.deleteDatabase('veil_web_devices');
      } catch (_) {}
    });
  }

  function b64urlDecode(s) {
    var pad = s.replace(/-/g, '+').replace(/_/g, '/');
    while (pad.length % 4) pad += '=';
    var bin = atob(pad);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlEncode(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function saveSealedDevice(rec) {
    return new Promise(function (resolve, reject) {
      if (!window.indexedDB) return reject(new Error('IndexedDB unavailable'));
      var req = indexedDB.open('veil_web_devices', 1);
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains('devices')) {
          db.createObjectStore('devices', { keyPath: 'credential_id' });
        }
      };
      req.onerror = function () { reject(new Error('Cannot open browser device store')); };
      req.onsuccess = function () {
        var db = req.result;
        var tx = db.transaction('devices', 'readwrite');
        tx.objectStore('devices').put(rec);
        tx.oncomplete = function () { resolve(); };
        tx.onerror = function () { reject(new Error('Cannot store encrypted browser device')); };
      };
    });
  }

  function sealBrowserDeviceInWorker(person, credId, prfBytes) {
    return new Promise(function (resolve, reject) {
      var copy = prfBytes.slice();
      var w = new Worker(window.__veilTrustedScriptURL('/static/enroll-worker.js'));
      w.onmessage = function (ev) {
        w.terminate();
        if (ev.data && ev.data.ok) resolve(ev.data.bundle);
        else reject(new Error((ev.data && ev.data.error) || 'Worker key generation failed'));
      };
      w.onerror = function () {
        w.terminate();
        reject(new Error('Enrollment Worker failed'));
      };
      w.postMessage({ person: person, credential_id: credId, prf_output: copy.buffer }, [copy.buffer]);
    });
  }

  var enrollForm = document.getElementById('veil-passkey-enroll-form');
  if (enrollForm) {
    enrollForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var statusEl = document.getElementById('veil-login-status');
      var codeInput = document.getElementById('veil-enroll-code');
      var code = codeInput ? codeInput.value.trim() : '';
      if (!code) return;
      if (!window.PublicKeyCredential || !navigator.credentials) {
        if (statusEl) statusEl.textContent = 'WebAuthn passkeys are not supported in this browser.';
        return;
      }
      if (statusEl) statusEl.textContent = 'Starting passkey registration…';
      var beginData = null;
      fetch('/web/passkey/register/begin', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'accept': 'application/json' },
        body: JSON.stringify({ code: code })
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.message || 'Enrollment code rejected');
          beginData = j;
          var saltBytes = b64urlDecode(j.prf_salt);
          return navigator.credentials.create({
            publicKey: {
              challenge: b64urlDecode(j.challenge),
              rp: { name: 'Veil Hub', id: j.rp_id },
              user: {
                id: b64urlDecode(j.user_id),
                name: j.person,
                displayName: j.person
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -8 }
              ],
              authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
              attestation: 'none',
              extensions: { prf: { eval: { first: saltBytes } } }
            }
          });
        });
      }).then(function (cred) {
        var credId = b64urlEncode(new Uint8Array(cred.rawId));
        var resp = cred.response;
        var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
        var first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
        var prfPromise = first
          ? Promise.resolve(new Uint8Array(first))
          : (ext && ext.prf && ext.prf.enabled
              ? navigator.credentials.get({
                  publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rpId: beginData.rp_id,
                    allowCredentials: [{ type: 'public-key', id: new Uint8Array(cred.rawId) }],
                    userVerification: 'required',
                    extensions: { prf: { eval: { first: b64urlDecode(beginData.prf_salt) } } }
                  }
                }).then(function (a) {
                  var e2 = a.getClientExtensionResults ? a.getClientExtensionResults() : {};
                  var f2 = e2 && e2.prf && e2.prf.results && e2.prf.results.first;
                  return f2 ? new Uint8Array(f2) : null;
                })
              : Promise.resolve(null));

        return prfPromise.then(function (prfOut) {
          if (!prfOut) {
            return {
              credId: credId,
              resp: resp,
              prfSupported: false,
              publicIdentity: null
            };
          }
          return sealBrowserDeviceInWorker(beginData.person, credId, prfOut).then(function (bundle) {
            prfOut.fill(0);
            return saveSealedDevice({
              credential_id: credId,
              person: beginData.person,
              fingerprint: bundle.fingerprint,
              prf_salt: beginData.prf_salt,
              sealed_identity_hex: bundle.sealed_identity_hex
            }).then(function () {
              return {
                credId: credId,
                resp: resp,
                prfSupported: true,
                publicIdentity: bundle.public_identity
              };
            });
          });
        });
      }).then(function (step) {
        return fetch('/web/passkey/register/finish', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'accept': 'application/json' },
          body: JSON.stringify({
            code: code,
            credential_id: step.credId,
            client_data_json: b64urlEncode(new Uint8Array(step.resp.clientDataJSON)),
            attestation_object: b64urlEncode(new Uint8Array(step.resp.attestationObject)),
            prf_supported: step.prfSupported,
            prf_salt: beginData.prf_salt,
            public_identity: step.publicIdentity
          })
        });
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.message || 'Passkey registration failed');
          if (statusEl) statusEl.textContent = j.message || 'Passkey enrolled.';
          if (j.prf_supported) {
            window.setTimeout(function () { window.location.assign('/'); }, 1500);
          }
        });
      }).catch(function (err) {
        if (statusEl) statusEl.textContent = String(err.message || err);
      });
    });
  }

  var loginForm = document.getElementById('veil-passkey-login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var statusEl = document.getElementById('veil-login-status');
      var personEl = document.getElementById('veil-passkey-person');
      var person = personEl ? personEl.value.trim() : '';
      if (!window.PublicKeyCredential || !navigator.credentials) {
        if (statusEl) statusEl.textContent = 'WebAuthn passkeys are not supported in this browser.';
        return;
      }
      fetch('/web/passkey/login/begin', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'accept': 'application/json' },
        body: JSON.stringify(person ? { person: person } : {})
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.message || 'Cannot start passkey sign-in');
          var allow = (j.allow_credentials || []).map(function (c) {
            return { type: 'public-key', id: b64urlDecode(c.id) };
          });
          return navigator.credentials.get({
            publicKey: {
              challenge: b64urlDecode(j.challenge),
              rpId: j.rp_id,
              allowCredentials: allow,
              userVerification: 'required'
            }
          });
        });
      }).then(function (assertion) {
        var resp = assertion.response;
        return fetch('/web/passkey/login/finish', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'accept': 'application/json' },
          body: JSON.stringify({
            credential_id: b64urlEncode(new Uint8Array(assertion.rawId)),
            client_data_json: b64urlEncode(new Uint8Array(resp.clientDataJSON)),
            authenticator_data: b64urlEncode(new Uint8Array(resp.authenticatorData)),
            signature: b64urlEncode(new Uint8Array(resp.signature))
          })
        });
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.message || 'Passkey sign-in refused');
          window.location.assign('/');
        });
      }).catch(function (err) {
        if (statusEl) statusEl.textContent = String(err.message || err);
      });
    });
  }
})();
"#;

const ENROLL_WORKER_JS: &str = r#"'use strict';
(function () {
  var rawFetch = self.fetch.bind(self);
  self.fetch = function (url) {
    if (url !== '/static/veil_web.wasm') {
      return Promise.reject(new Error('Enrollment Worker only fetches /static/veil_web.wasm'));
    }
    return rawFetch(url, { method: 'GET', credentials: 'same-origin' });
  };

  function putBytes(ex, mem, bytes) {
    if (!bytes.length) return [0, 0];
    var ptr = ex.veil_web_alloc(bytes.length);
    new Uint8Array(mem.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  }

  function putStr(ex, mem, s) {
    return putBytes(ex, mem, new TextEncoder().encode(s || ''));
  }

  function zeroAndFree(ex, mem, pair) {
    if (pair[1] > 0) {
      new Uint8Array(mem.buffer, pair[0], pair[1]).fill(0);
      ex.veil_web_free(pair[0], pair[1]);
    }
  }

  self.onmessage = function (ev) {
    var msg = ev.data || {};
    var prfBytes = new Uint8Array(msg.prf_output || new ArrayBuffer(0));
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
    self.fetch('/static/veil_web.wasm')
      .then(function (r) {
        if (!r.ok) throw new Error('WASM engine unavailable');
        return r.arrayBuffer();
      })
      .then(function (buf) { return WebAssembly.instantiate(buf, imports); })
      .then(function (inst) {
        memory = inst.instance.exports.memory;
        var ex = inst.instance.exports;
        var aPerson = putStr(ex, memory, msg.person || '');
        var aCred = putStr(ex, memory, msg.credential_id || '');
        var aPrf = putBytes(ex, memory, prfBytes);
        prfBytes.fill(0);
        var rc = ex.veil_web_seal_new_device(
          aPerson[0], aPerson[1],
          aCred[0], aCred[1],
          aPrf[0], aPrf[1]
        );
        var outPtr = ex.veil_web_out_ptr();
        var outLen = ex.veil_web_out_len();
        var outTxt = new TextDecoder().decode(new Uint8Array(memory.buffer, outPtr, outLen));
        zeroAndFree(ex, memory, aPerson);
        zeroAndFree(ex, memory, aCred);
        zeroAndFree(ex, memory, aPrf);
        if (rc !== 0) throw new Error(outTxt);
        self.postMessage({ ok: true, bundle: JSON.parse(outTxt) });
      })
      .catch(function (err) {
        prfBytes.fill(0);
        self.postMessage({ ok: false, error: String(err.message || err) });
      });
  };
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
        "enroll-worker.js" => Ok((
            [
                (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            ENROLL_WORKER_JS,
        )
            .into_response()),
        "veil_web.wasm" => {
            let candidates = [
                std::env::var_os("VEIL_WEB_WASM_PATH").map(std::path::PathBuf::from),
                Some(std::path::PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../target/wasm-smoke/wasm32-unknown-unknown/release/examples/web_wasm.wasm"
                ))),
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
