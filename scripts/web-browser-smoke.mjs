// The web client in a real browser (docs/HUB.md §13.39, §13.40): a headless
// Chromium driven over the DevTools protocol, with a virtual WebAuthn
// authenticator (CTAP 2.1, user verification, PRF). No test of the server
// runs the pages' JavaScript; this does:
//
//   enroll a passkey with a `vl web` code, sign in, open a file page, sign
//   out, sign in again; and, with PRF, turn browser secrets on, confirm the
//   browser device from `vl`, "Show secret", sign out and in and show it
//   again, then "Remove this browser".
//
// It is started by the ignored test `server_hub::browser::…`, which makes
// the server, the project and the person and passes them in the environment
// (run `scripts/web-browser-smoke.sh`). It needs node 22 or later (its
// built-in WebSocket) and a Chromium; it installs and downloads nothing.
//
// Every step prints `ok: <step>`; any failure, any uncaught exception in a
// page or a Worker, and any Content-Security-Policy violation ends it with
// exit status 1.

import { spawn, execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const env = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set (run scripts/web-browser-smoke.sh)`);
  return v;
};
const chromium = env('VEIL_CHROMIUM');
const origin = env('VEIL_SMOKE_ORIGIN'); // https://localhost:PORT (WebAuthn needs a host name, not an IP address)
const project = env('VEIL_SMOKE_PROJECT');
const person = env('VEIL_SMOKE_PERSON');
const repo = env('VEIL_SMOKE_REPO');
const vlBin = env('VEIL_SMOKE_VL');
const publicMarker = env('VEIL_SMOKE_PUBLIC_TEXT');
const secretText = env('VEIL_SMOKE_SECRET_TEXT');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ok = (step) => console.log(`ok: ${step}`);
const vl = (...args) => execFileSync(vlBin, args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 });

// The test server's certificate is self-signed: the browser accepts that
// one key and no other (never `--ignore-certificate-errors`: Chromium
// refuses WebAuthn on a page with a certificate error).
const spki = createHash('sha256')
  .update(new X509Certificate(readFileSync(env('VEIL_HUB_CA'))).publicKey.export({ type: 'spki', format: 'der' }))
  .digest('base64');

const profile = mkdtempSync(join(tmpdir(), 'veil-browser-smoke-'));
const browser = spawn(
  chromium,
  [
    ...(chromium.includes('headless-shell') || chromium.includes('headless_shell') ? [] : ['--headless=new']),
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    `--ignore-certificate-errors-spki-list=${spki}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    // The test machine's containers have no user namespaces for Chromium's
    // sandbox; the only pages loaded are the test server's.
    '--no-sandbox',
    'about:blank',
  ],
  { stdio: ['ignore', 'ignore', 'pipe'] },
);
let failed = false;
const finish = (code) => {
  try {
    browser.kill('SIGKILL');
  } catch (_) {}
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch (_) {}
  process.exit(code);
};
const fail = (why) => {
  if (failed) return;
  failed = true;
  console.error(`FAILED: ${why}`);
  finish(1);
};
process.on('unhandledRejection', (e) => fail(e && e.stack ? e.stack : String(e)));
setTimeout(() => fail('the smoke did not finish in four minutes'), 240000).unref();

const endpoint = await new Promise((resolve, reject) => {
  let err = '';
  browser.stderr.on('data', (d) => {
    err += d;
    const m = err.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  browser.on('exit', (code) => reject(new Error(`Chromium exited (${code}) before it listened:\n${err}`)));
});

// ---- the DevTools protocol -------------------------------------------------
const ws = new WebSocket(endpoint);
await new Promise((resolve, reject) => {
  ws.addEventListener('open', resolve);
  ws.addEventListener('error', () => reject(new Error('cannot connect to the DevTools endpoint')));
});
let nextId = 1;
const waiting = new Map();
const problems = [];
let dialogs = 0;
ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id) {
    const w = waiting.get(msg.id);
    waiting.delete(msg.id);
    if (w) msg.error ? w.reject(new Error(`${w.method}: ${msg.error.message}`)) : w.resolve(msg.result);
    return;
  }
  switch (msg.method) {
    case 'Page.javascriptDialogOpening':
      // "Show secret" states the honest limit and asks first.
      dialogs += 1;
      send('Page.handleJavaScriptDialog', { accept: true }, msg.sessionId);
      break;
    case 'Runtime.exceptionThrown':
      problems.push(`uncaught exception: ${msg.params.exceptionDetails.text} ${JSON.stringify(msg.params.exceptionDetails.exception?.description ?? '')}`);
      break;
    case 'Log.entryAdded':
      if (msg.params.entry.level === 'error' || msg.params.entry.source === 'security' || /Content Security Policy|TrustedScript|TrustedHTML/.test(msg.params.entry.text)) {
        // A page the smoke asks for while signed out answers 401: expected.
        if (!/status of 40[134]/.test(msg.params.entry.text)) problems.push(`${msg.params.entry.source}: ${msg.params.entry.text} (${msg.params.entry.url ?? ''})`);
      }
      break;
    case 'Target.attachedToTarget':
      // Workers of the page: their exceptions and CSP violations count too.
      if (msg.params.targetInfo.type === 'worker') {
        send('Runtime.enable', {}, msg.params.sessionId).catch(() => {});
        send('Log.enable', {}, msg.params.sessionId).catch(() => {});
        send('Runtime.runIfWaitingForDebugger', {}, msg.params.sessionId).catch(() => {});
      }
      break;
  }
});
function send(method, params = {}, sessionId) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    waiting.set(id, { resolve, reject, method });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
const page = (method, params) => send(method, params, sessionId);
await page('Page.enable');
await page('Runtime.enable');
await page('Log.enable');
await page('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
await page('WebAuthn.enable', { enableUI: false });
const { authenticatorId } = await page('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2',
    ctap2Version: 'ctap2_1',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true,
  },
});

async function evaluate(expression) {
  const r = await page('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(`in the page: ${r.exceptionDetails.text} ${r.exceptionDetails.exception?.description ?? ''}\n  ${expression}`);
  return r.result.value;
}
/// Until `expression` is truthy in the page (its value), at most `ms`.
async function until(expression, what, ms = 30000) {
  const end = Date.now() + ms;
  let last;
  for (;;) {
    try {
      last = await evaluate(expression);
      if (last) return last;
    } catch (e) {
      last = String(e.message); // a navigation in flight: the context is gone, ask again
    }
    if (Date.now() > end) {
      const where = await evaluate('location.href + "\\n" + document.body.innerText.slice(0, 1500)').catch(() => '(no page)');
      throw new Error(`waited ${ms} ms for: ${what}\n  last: ${JSON.stringify(last)}\n  page: ${where}`);
    }
    await sleep(100);
  }
}
async function goto(path) {
  await page('Page.navigate', { url: origin + path });
  await until(`document.readyState === 'complete' && location.href === ${JSON.stringify(origin + path)}`, `the page ${path}`);
}
const text = () => evaluate('document.body.innerText');
const status = () => evaluate(`(document.getElementById('veil-login-status') || {}).textContent || ''`);
async function signIn() {
  await goto('/login');
  await evaluate(`document.getElementById('veil-passkey-person').value = ${JSON.stringify(person)}; document.querySelector('#veil-passkey-login-form button').click(); true`);
}
async function signedIn(what) {
  await until(`location.pathname === '/' && document.body.innerText.includes('Signed in as') || (document.getElementById('veil-login-status') || {}).textContent`, what);
  const said = await status().catch(() => '');
  if ((await evaluate('location.pathname')) !== '/') throw new Error(`${what}: the page says "${said}"`);
  if (!(await text()).includes(person)) throw new Error(`${what}: the page does not name ${person}`);
}
async function signOut() {
  await evaluate(`document.body.setAttribute('data-smoke-leaving', '1'); document.querySelector('form[action="/web/logout"] button').click(); true`);
  // The form's answer: a redirect to the home page, signed out.
  await until(`document.readyState === 'complete' && !document.body.hasAttribute('data-smoke-leaving')`, 'the answer to "Sign out"');
  const [path, shown] = JSON.parse(await evaluate(`JSON.stringify([location.pathname, document.body.innerText])`));
  if (path !== '/' || shown.includes('Signed in as') || !shown.includes('Sign in')) throw new Error(`"Sign out" answered ${path}: ${shown}`);
}
async function showSecret(what) {
  await goto(`/p/${project}/file/.env`);
  await until(`document.getElementById('veil-show-secret') !== null`, `${what}: the "Show secret" control`);
  if ((await text()).includes(secretText)) throw new Error(`${what}: the page holds the secret before it is asked for`);
  const before = dialogs;
  await evaluate(`document.getElementById('veil-show-secret').click(); true`);
  await until(
    `(function () { var b = document.getElementById('veil-secret-plaintext'); var s = document.getElementById('veil-secret-status'); return (b && !b.hidden) || (s && s.textContent && !/Touch your passkey/.test(s.textContent)); })()`,
    `${what}: the secret, or why not`,
    60000,
  );
  const shown = await evaluate(`(function () { var b = document.getElementById('veil-secret-plaintext'); return b && !b.hidden ? b.textContent : null; })()`);
  if (shown !== secretText) {
    throw new Error(`${what}: shown ${JSON.stringify(shown)}, the page says "${await evaluate(`document.getElementById('veil-secret-status').textContent`)}"`);
  }
  if (dialogs !== before + 1) throw new Error(`${what}: the honest-limit question was asked ${dialogs - before} times`);
  // "Hide" clears it from the page.
  await evaluate(`document.getElementById('veil-hide-secret').click(); true`);
  if ((await text()).includes(secretText)) throw new Error(`${what}: "Hide" left the secret on the page`);
}

// ---- the smoke ---------------------------------------------------------------
// 1. Enroll: `vl web`, the link, "Register passkey".
const enrollment = JSON.parse(vl('web', '--json', '--label', 'smoke browser'));
await goto(`/login?enroll=${enrollment.code}`);
const protocol = await evaluate(`performance.getEntriesByType('navigation')[0].nextHopProtocol`);
if (protocol !== 'h2') throw new Error(`the browser spoke ${protocol} to the server, not HTTP/2`);
ok('the browser speaks HTTP/2 to the server');
if ((await evaluate(`document.getElementById('veil-enroll-code').value`)) !== enrollment.code) throw new Error('the link did not fill in the enrollment code');
await evaluate(`document.querySelector('#veil-passkey-enroll-form button').click(); true`);
const enrolled = await until(
  `(function () { var s = (document.getElementById('veil-login-status') || {}).textContent || ''; return /Passkey enrolled|Signed in with passkey|can't open secrets/.test(s) ? s : (location.pathname === '/devices' ? 'redirected' : (/…$/.test(s) || !s ? '' : 'ERROR: ' + s)); })()`,
  'the enrollment to finish',
  60000,
);
if (enrolled.startsWith('ERROR: ')) throw new Error(`the enrollment failed: the page says "${enrolled.slice(7)}"`);
const { credentials } = await page('WebAuthn.getCredentials', { authenticatorId });
if (credentials.length !== 1) throw new Error(`the authenticator holds ${credentials.length} credentials after the enrollment`);
const prf = !/can't open secrets/.test(enrolled);
ok(`enrolled a passkey with a vl web code (${prf ? 'with PRF: the browser made device keys in a Worker' : 'WITHOUT PRF: this Chromium\'s virtual authenticator has none'})`);
// After a PRF enrollment the page goes to "Your devices", which shows the
// fingerprint to confirm for as long as it waits.
if (prf) await until(`location.pathname === '/devices' && document.body.innerText.includes('vl identity confirm')`, '"Your devices" after a PRF enrollment');

// 2. "Your devices" lists it, by its fingerprint and label.
await goto('/devices');
const devices = await text();
const fingerprint = (devices.match(/([0-9A-F]{4}(?:-[0-9A-F]{4}){4})\s*\(this browser\)/) || [])[1];
if (!fingerprint) throw new Error(`"Your devices" does not mark this browser:\n${devices}`);
if (!devices.includes('smoke browser') || !devices.includes('Remove this browser')) throw new Error(`"Your devices" lacks the label or the removal:\n${devices}`);
if (!vl('identity', 'list').includes(fingerprint)) throw new Error('`vl identity list` does not show the passkey');
ok(`"Your devices" and vl identity list show the passkey ${fingerprint}`);

// 3. A file page.
await goto(`/p/${project}/file/public/hello.txt`);
if (!(await text()).includes(publicMarker)) throw new Error(`the file page does not show the file:\n${await text()}`);
ok('opened a file page');

// 4. Sign out (a form `POST`, the same-origin check), then the passkey signs in again.
await signOut();
await page('Page.navigate', { url: origin + '/devices' });
await until(`document.readyState === 'complete' && !document.body.innerText.includes('Remove this browser')`, 'no devices page when signed out');
ok('signed out: the session is over');
await signIn();
await signedIn('signing in again with the passkey after signing out');
ok('signed in again with the passkey');

if (prf) {
  // 5. An admin turns browser secrets on (a form in the browser), `vl`
  //    confirms the browser device and shares the keys.
  await goto(`/p/${project}/admin`);
  await evaluate(`(function () { var f = document.querySelector('form[action$="/admin/web-secrets"]'); f.querySelector('input[name="acknowledge_limit"]').checked = true; f.querySelector('button').click(); return true; })()`);
  await until(`document.body.innerText.includes('Turn off browser secrets')`, 'browser secrets turned on');
  vl('identity', 'confirm', fingerprint);
  vl('share-keys');
  await goto('/devices');
  if (!(await text()).includes('confirmed to open secrets')) throw new Error(`"Your devices" does not show the browser as confirmed:\n${await text()}`);
  ok('browser secrets on; the browser device confirmed from vl');

  // 6. "Show secret": the passkey's PRF, the Worker, the plaintext on the page only.
  await showSecret('the first "Show secret"');
  ok('"Show secret" decrypted the secret in the Worker');

  // 7. Signing out keeps the browser's device key: after signing in again
  //    the secret still opens.
  await signOut();
  await signIn();
  await signedIn('signing in after the secret was shown');
  await showSecret('"Show secret" after signing out and in');
  ok('after signing out and in again, "Show secret" still works');
}

// 8. "Remove this browser": the passkey no longer signs in.
await goto('/devices');
await evaluate(`(function () { var b = Array.from(document.querySelectorAll('form.veil-remove-browser button')).find(function (b) { return b.textContent === 'Remove this browser'; }); b.click(); return true; })()`);
await until(`location.pathname === '/login'`, 'the sign-in page after "Remove this browser"');
await signIn();
const refused = await until(`(document.getElementById('veil-login-status') || {}).textContent || (location.pathname === '/' && document.body.innerText.includes('Signed in as') ? 'SIGNED IN' : '')`, 'the removed passkey to be refused');
if (refused === 'SIGNED IN' || !/revoked|unknown/i.test(refused)) throw new Error(`after "Remove this browser" a sign-in says "${refused}"`);
if (vl('identity', 'list').includes(fingerprint)) throw new Error('`vl identity list` still shows the removed browser');
ok('"Remove this browser": the passkey no longer signs in');

if (problems.length) {
  fail(`the pages ran with errors:\n  ${problems.join('\n  ')}`);
} else {
  ok(prf ? 'the whole smoke, with secrets' : 'the smoke WITHOUT secrets (no PRF)');
  finish(0);
}
