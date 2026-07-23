// Validate the extension's WebCrypto against the shared conformance vectors.
// Run: node src/jitcrypto.test.mjs   (from the extension/ dir)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { b64uEncode, b64uDecode, pae, canonServerName, importSecret, buildProof } from "./jitcrypto.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "core", "testdata", "vectors.json"), "utf8"));
const fromHex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (u) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

let fail = 0;
const ok = (c, m) => { if (!c) { console.log("  FAIL:", m); fail++; } };

for (const c of V.pae) {
  const pieces = c.pieces.map(b64uDecode);
  ok(toHex(pae(pieces)) === c.out_hex, "pae " + c.pieces_utf8.join(","));
}
for (const c of V.canon_server_name) {
  ok(canonServerName(c.in) === c.out, "canon_server_name " + c.in);
}
for (const c of V.proof) {
  const key = await importSecret(fromHex(c.secret_hex));
  const proof = await buildProof(key, c.server_name, c.kid, fromHex(c.nonce_raw_hex));
  ok(proof === c.proof_b64url, "proof " + c.server_name);
  // round-trip encode/decode
  ok(b64uEncode(b64uDecode(c.nonce_b64url)) === c.nonce_b64url, "b64u round-trip " + c.server_name);
}

console.log(fail === 0
  ? "extension jitcrypto vs vectors: ALL MATCH (WebCrypto interop with the Lua server)"
  : `${fail} FAILURES`);
process.exit(fail === 0 ? 0 : 1);
