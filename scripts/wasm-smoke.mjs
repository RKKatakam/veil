// Run crates/veil-core/examples/wasm_smoke.rs, built for
// wasm32-unknown-unknown, under node: a plain WebAssembly instance whose
// only imports are a clock and randomness (see scripts/check-wasm.sh).
//
//   node scripts/wasm-smoke.mjs path/to/wasm_smoke.wasm
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const file = process.argv[2];
if (!file) {
  console.error("usage: node scripts/wasm-smoke.mjs <wasm_smoke.wasm>");
  process.exit(2);
}

let memory;
const imports = {
  env: {
    veil_now_ms: () => Date.now(),
    // getrandom's custom backend: fill [ptr, ptr+len) from WebCrypto
    // (getRandomValues takes at most 65536 bytes per call).
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
const started = performance.now();
const code = instance.exports.veil_smoke_run();
const ms = (performance.now() - started).toFixed(0);
const ptr = instance.exports.veil_smoke_report_ptr();
const len = instance.exports.veil_smoke_report_len();
const report = new TextDecoder().decode(new Uint8Array(memory.buffer, ptr, len));
process.stdout.write(report);
if (code !== 0) {
  console.error(`wasm_smoke failed (code ${code}): ${report}`);
  process.exit(1);
}
console.log(`wasm_smoke: ok in ${ms} ms on wasm32-unknown-unknown`);
