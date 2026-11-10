// Verify crates/veil-core/examples/web_wasm.rs on wasm32-unknown-unknown
// under node (scripts/check-wasm.sh):
//   1. exported symbols contain zero unseal / decrypt / keychain / ring entrypoints;
//   2. sealed envelopes and non-content file metadata classify strictly as "sealed"
//      without exposing secret bytes;
//   3. bounded text diffing produces exact unified-diff hunks and flags oversized inputs;
//   4. device-signed login (hub-login) and PR review (hub-pr-review) work in WASM memory.
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import assert from "node:assert/strict";

const file = process.argv[2];
if (!file) {
  console.error("usage: node scripts/web-wasm.mjs <web_wasm.wasm>");
  process.exit(2);
}

let memory;
const imports = {
  env: {
    veil_now_ms: () => Date.now(),
    veil_random_fill: (ptr, len) => {
      for (let off = 0; off < len; off += 65536) {
        const n = Math.min(65536, len - off);
        webcrypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, n));
      }
      return 0;
    },
  },
};

const { instance } = await WebAssembly.instantiate(readFileSync(file), imports);
memory = instance.exports.memory;
const ex = instance.exports;

// Threat 18 / Guarantee 2: the web WASM module exports no secret-decryption or keyring path.
const exportNames = Object.keys(ex);
for (const name of exportNames) {
  for (const forbidden of ["unseal", "decrypt", "keychain", "ring", "unwrap_key", "secret_share"]) {
    assert(
      !name.toLowerCase().includes(forbidden),
      `forbidden secret-related export in web WASM: ${name}`
    );
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function putBytes(bytes) {
  if (bytes.length === 0) return [0, 0];
  const ptr = ex.veil_web_alloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

function putStr(s) {
  return putBytes(enc.encode(s));
}

function readOut() {
  const ptr = ex.veil_web_out_ptr();
  const len = ex.veil_web_out_len();
  return dec.decode(new Uint8Array(memory.buffer, ptr, len));
}

function freeAll(allocs) {
  for (const [ptr, len] of allocs) {
    if (len > 0) ex.veil_web_free(ptr, len);
  }
}

// 1. Sealed metadata and raw sealed objects never expose secret bytes.
{
  const a1 = putStr('{"sealed":true,"encoding":"object","kind":"file"}');
  assert.equal(ex.veil_web_classify_file(a1[0], a1[1]), 0);
  assert.equal(JSON.parse(readOut()), "sealed");

  const a2 = putStr('{"sealed":false,"encoding":"object","kind":"file"}');
  assert.equal(ex.veil_web_classify_file(a2[0], a2[1]), 0);
  assert.equal(JSON.parse(readOut()), "sealed");

  const a3 = putStr('{"sealed":false,"encoding":"content","kind":"file"}');
  assert.equal(ex.veil_web_classify_file(a3[0], a3[1]), 0);
  assert.equal(JSON.parse(readOut()), "plain_file");

  const secretMarker = "SEALED_WASM_CANARY_987654321";
  const a4 = putStr(`veil:seal\n${secretMarker}`);
  assert.equal(ex.veil_web_inspect_object(a4[0], a4[1]), 0);
  const out = readOut();
  assert(!out.includes(secretMarker), "sealed object leaked marker");
  assert.deepEqual(JSON.parse(out), { kind: "sealed" });
  freeAll([a1, a2, a3, a4]);
}

// 2. Bounded diffing in WASM.
{
  const oldB = putStr("fn answer() -> u32 {\n    41\n}\n");
  const newB = putStr("fn answer() -> u32 {\n    42\n}\n");
  assert.equal(ex.veil_web_diff(oldB[0], oldB[1], newB[0], newB[1], 4096), 0);
  const diff = JSON.parse(readOut());
  assert.equal(diff.binary, false);
  assert.equal(diff.too_large, false);
  assert.equal(diff.hunks.length, 1);
  assert(diff.hunks[0].lines.some((l) => l.startsWith("-    41")));
  assert(diff.hunks[0].lines.some((l) => l.startsWith("+    42")));

  assert.equal(ex.veil_web_diff(oldB[0], oldB[1], newB[0], newB[1], 8), 0);
  const capped = JSON.parse(readOut());
  assert.equal(capped.too_large, true);
  assert.equal(capped.hunks.length, 0);
  freeAll([oldB, newB]);
}

// 3. Device-signed login and PR review in WASM memory.
{
  const nm = putStr("alice");
  assert.equal(ex.veil_web_generate_identity(nm[0], nm[1]), 0);
  const idJson = JSON.parse(readOut());
  const idB = putStr(idJson);
  const hubB = putStr("127.0.0.1:8443");
  const chalB = putStr("ab".repeat(32));
  assert.equal(ex.veil_web_sign_login(idB[0], idB[1], hubB[0], hubB[1], chalB[0], chalB[1]), 0);
  const login = JSON.parse(readOut());
  assert.equal(login.hub, "127.0.0.1:8443");
  assert.equal(login.signature.length, 128);
  assert(login.identity.startsWith("veil1"));

  const projB = putStr("acme");
  const prB = putStr("pr-1234abcd");
  const patchB = putStr("patch-digest");
  const verdictB = putStr("approve");
  assert.equal(
    ex.veil_web_sign_review(
      idB[0], idB[1],
      projB[0], projB[1],
      prB[0], prB[1],
      patchB[0], patchB[1],
      verdictB[0], verdictB[1]
    ),
    0
  );
  const reviewSig = JSON.parse(readOut());
  assert.equal(reviewSig.length, 128);

  const badVerdict = putStr("ship-it");
  assert.equal(
    ex.veil_web_sign_review(
      idB[0], idB[1],
      projB[0], projB[1],
      prB[0], prB[1],
      patchB[0], patchB[1],
      badVerdict[0], badVerdict[1]
    ),
    1
  );
  freeAll([nm, idB, hubB, chalB, projB, prB, patchB, verdictB, badVerdict]);
}

console.log("web_wasm: ok on wasm32-unknown-unknown");
