// Verify crates/veil-core/examples/web_wasm.rs on wasm32-unknown-unknown
// under node (scripts/check-wasm.sh):
//   1. exported symbols contain zero unseal / decrypt / keychain / ring entrypoints
//      and zero raw identity.json signing entrypoints (BUG-1871);
//   2. sealed envelopes and non-content file metadata classify strictly as "sealed"
//      without exposing secret bytes;
//   3. bounded text diffing produces exact unified-diff hunks and flags oversized inputs;
//   4. browser device enrollment generates a distinct device in WASM memory and
//      seals its private keys under a 32-byte WebAuthn PRF output without
//      exposing plain private keys.
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

// Threat 18 / BUG-1871: the main web WASM module exports no secret-decryption,
// keyring, or raw identity.json signing entrypoints.
const exportNames = Object.keys(ex);
for (const name of exportNames) {
  for (const forbidden of [
    "unseal",
    "decrypt",
    "keychain",
    "ring",
    "unwrap_key",
    "secret_share",
    "sign_login",
    "sign_review",
    "generate_identity",
  ]) {
    assert(
      !name.toLowerCase().includes(forbidden),
      `forbidden export in web WASM: ${name}`
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

// 3. Passkey-PRF browser device generation seals private keys in WASM memory.
{
  const nm = putStr("alice");
  const cred = putStr("cred-wasm-node-test");
  const prf = new Uint8Array(32);
  prf.fill(0x5c);
  const prfB = putBytes(prf);
  assert.equal(ex.veil_web_seal_new_device(nm[0], nm[1], cred[0], cred[1], prfB[0], prfB[1]), 0);
  const rawJson = readOut();
  assert(!rawJson.includes("signing_seed"), "plain signing seed leaked from WASM");
  const bundle1 = JSON.parse(rawJson);
  assert(bundle1.public_identity.startsWith("veil1"));
  assert.equal(bundle1.signing_key.length, 64);
  assert.equal(bundle1.member_id.length, 69);
  assert.equal(bundle1.fingerprint.length, 24);
  assert(bundle1.sealed_identity_hex.length > 128);

  assert.equal(ex.veil_web_seal_new_device(nm[0], nm[1], cred[0], cred[1], prfB[0], prfB[1]), 0);
  const bundle2 = JSON.parse(readOut());
  assert.notEqual(bundle1.signing_key, bundle2.signing_key);

  const zeroPrf = putBytes(new Uint8Array(32));
  assert.equal(ex.veil_web_seal_new_device(nm[0], nm[1], cred[0], cred[1], zeroPrf[0], zeroPrf[1]), 1);
  freeAll([nm, cred, prfB, zeroPrf]);
}

console.log("web_wasm: ok on wasm32-unknown-unknown");
