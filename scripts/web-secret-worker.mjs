// Verify crates/veil-core/examples/web_secret_worker.rs on wasm32-unknown-unknown
// under node (scripts/check-wasm.sh):
//   1. unseals a PRF-encrypted browser device identity inside Worker WASM memory
//      without exposing plain private keys;
//   2. refuses wrong PRF outputs and mismatched credential IDs;
//   3. verifies signed KeyRings, project fingerprints, and content-addressed
//      ObjectIds, opening an authorized sealed secret on demand;
//   4. refuses post-revocation rotated generations, wrong project fingerprints,
//      empty/deleted ring maps, and tampered object IDs.
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import assert from "node:assert/strict";

const file = process.argv[2];
const fixtureJson = process.argv[3];
if (!file || !fixtureJson) {
  console.error("usage: node scripts/web-secret-worker.mjs <web_secret_worker.wasm> <fixture.json>");
  process.exit(2);
}

const fx = JSON.parse(readFileSync(fixtureJson, "utf8"));

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

const enc = new TextEncoder();
const dec = new TextDecoder();

function fromHex(h) {
  return Uint8Array.from(Buffer.from(h, "hex"));
}

function putBytes(bytes) {
  if (bytes.length === 0) return [0, 0];
  const ptr = ex.veil_worker_alloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

function putStr(s) {
  return putBytes(enc.encode(s));
}

function readOut() {
  const ptr = ex.veil_worker_out_ptr();
  const len = ex.veil_worker_out_len();
  return dec.decode(new Uint8Array(memory.buffer, ptr, len));
}

function freeAll(allocs) {
  for (const [ptr, len] of allocs) {
    if (len > 0) ex.veil_worker_free(ptr, len);
  }
}

const prfBytes = fromHex(fx.prf_hex);
const objBytes = fromHex(fx.object_hex);
const rotObjBytes = fromHex(fx.rotated_object_hex);

// 1. Verify PRF-sealed browser device identity in WASM memory; wrong PRF or credential fails.
{
  const cred = putStr(fx.credential_id);
  const prf = putBytes(prfBytes);
  const sealed = putStr(fx.sealed_identity_hex);
  assert.equal(ex.veil_worker_verify_device(cred[0], cred[1], prf[0], prf[1], sealed[0], sealed[1]), 0);
  const out = readOut();
  assert(!out.includes("signing_seed"), "private key leaked from Worker WASM");
  const dev = JSON.parse(out);
  assert(dev.public_identity.startsWith("veil1"));
  assert.equal(dev.fingerprint.length, 24);

  const wrongPrf = new Uint8Array(32);
  wrongPrf.fill(0x99);
  const wrongPrfB = putBytes(wrongPrf);
  assert.equal(ex.veil_worker_verify_device(cred[0], cred[1], wrongPrfB[0], wrongPrfB[1], sealed[0], sealed[1]), 1);

  const wrongCred = putStr("cred-other");
  assert.equal(ex.veil_worker_verify_device(wrongCred[0], wrongCred[1], prf[0], prf[1], sealed[0], sealed[1]), 1);
  freeAll([cred, prf, sealed, wrongPrfB, wrongCred]);
}

// 2. Authorized secret opens cleanly; wrong project fingerprint, tampered ObjectId,
//    deleted rings, or post-revocation generation all fail closed.
{
  const cred = putStr(fx.credential_id);
  const prf = putBytes(prfBytes);
  const sealed = putStr(fx.sealed_identity_hex);
  const rings = putStr(fx.rings_json);
  const projFp = putStr(fx.project_fp);
  const oid = putStr(fx.object_id);
  const obj = putBytes(objBytes);

  assert.equal(
    ex.veil_worker_open_secret(
      cred[0], cred[1],
      prf[0], prf[1],
      sealed[0], sealed[1],
      rings[0], rings[1],
      projFp[0], projFp[1],
      oid[0], oid[1],
      obj[0], obj[1]
    ),
    0
  );
  const opened = JSON.parse(readOut());
  assert.equal(opened.scope, "team");
  assert.equal(opened.binary, false);
  assert.equal(opened.text, fx.expected_plaintext);

  // Wrong project fingerprint refused.
  const badFp = putStr("0000-0000-0000-0000-0000");
  assert.equal(
    ex.veil_worker_open_secret(
      cred[0], cred[1], prf[0], prf[1], sealed[0], sealed[1],
      rings[0], rings[1], badFp[0], badFp[1], oid[0], oid[1], obj[0], obj[1]
    ),
    1
  );

  // Tampered ObjectId refused.
  const badOid = putStr("f".repeat(64));
  assert.equal(
    ex.veil_worker_open_secret(
      cred[0], cred[1], prf[0], prf[1], sealed[0], sealed[1],
      rings[0], rings[1], projFp[0], projFp[1], badOid[0], badOid[1], obj[0], obj[1]
    ),
    1
  );

  // Empty rings (after device removal) refused.
  const emptyRings = putStr("{}");
  assert.equal(
    ex.veil_worker_open_secret(
      cred[0], cred[1], prf[0], prf[1], sealed[0], sealed[1],
      emptyRings[0], emptyRings[1], projFp[0], projFp[1], oid[0], oid[1], obj[0], obj[1]
    ),
    1
  );

  // Post-revocation rotated generation refused.
  const rotOid = putStr(fx.rotated_object_id);
  const rotObj = putBytes(rotObjBytes);
  assert.equal(
    ex.veil_worker_open_secret(
      cred[0], cred[1], prf[0], prf[1], sealed[0], sealed[1],
      rings[0], rings[1], projFp[0], projFp[1], rotOid[0], rotOid[1], rotObj[0], rotObj[1]
    ),
    1
  );

  freeAll([cred, prf, sealed, rings, projFp, oid, obj, badFp, badOid, emptyRings, rotOid, rotObj]);
}

console.log("web_secret_worker: ok on wasm32-unknown-unknown");
