// JIT Network Access - Copyright (C) 2026 Slopapalooza
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Enrollment trust boundary (PROTOCOL §2.1 / §7).
//
// A registration URL can be served by ANY origin — the extension only steers the
// tab to its own consent page, it does not vouch for the server. So the rule the
// enrollment path has to hold is: whatever the user was shown and approved is
// the most that can be enrolled. A server may narrow that set; it must never
// widen it. These tests pin that, plus the surrounding refusals.
//
// Run: node src/enroll_core.test.mjs   (also wired into `npm test`)

import assert from "node:assert";

// --- minimal chrome + fetch doubles ----------------------------------------

let permissionsGranted = true;
let requestedOrigins = [];
let removedOrigins = [];

globalThis.chrome = {
  permissions: {
    async request({ origins }) {
      requestedOrigins.push(...origins);
      return permissionsGranted;
    },
    async contains() {
      return permissionsGranted;
    },
    async remove({ origins }) {
      removedOrigins.push(...origins);
      return true;
    },
  },
  storage: { local: { async get(k) { return { tokens: tokenStore }; }, async set(o) { if (o.tokens) tokenStore = o.tokens; } } },
};

let tokenStore = [];

// Minimal in-memory IndexedDB, enough for store.js's put/get/delete of one
// object store. node has no indexedDB, and stubbing it here is what lets the
// tests cover the store's OWN decisions (kid collision) rather than stopping at
// the module boundary.
const idbData = new Map();
globalThis.indexedDB = {
  open() {
    const req = {};
    queueMicrotask(() => {
      const db = {
        createObjectStore() {},
        transaction() {
          const t = {};
          const store = {
            put(v, k) { idbData.set(k, v); queueMicrotask(() => t.oncomplete && t.oncomplete()); return {}; },
            get(k) { const r = { result: idbData.get(k) }; queueMicrotask(() => t.oncomplete && t.oncomplete()); return r; },
            delete(k) { idbData.delete(k); queueMicrotask(() => t.oncomplete && t.oncomplete()); return {}; },
          };
          t.objectStore = () => store;
          return t;
        },
      };
      req.result = db;
      if (req.onupgradeneeded) req.onupgradeneeded();
      if (req.onsuccess) req.onsuccess();
    });
    return req;
  },
};

let lastResponse = null;
globalThis.fetch = async () => lastResponse;

function mkResponse({ status = 204, headers = {} } = {}) {
  const h = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => (h.has(k.toLowerCase()) ? h.get(k.toLowerCase()) : null) },
  };
}

const SECRET_B64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"; // 32 bytes

const { enrollToken, normalizeOrigins, exchangeCode } = await import("./enroll_core.js");

let pass = 0;
const fail = [];
async function t(name, fn) {
  try {
    await fn();
    pass++;
    console.log("  PASS:", name);
  } catch (e) {
    fail.push(name);
    console.log("  FAIL:", name, "\n         ", e.message);
  }
}

async function expectThrow(fn, re, what) {
  let threw = null;
  try {
    await fn();
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, what + " — expected a throw, got success");
  assert.ok(re.test(threw.message), what + ` — message was "${threw.message}"`);
}

console.log("enroll_core trust boundary:");

await t("a server that WIDENS the consented origin set is rejected", async () => {
  permissionsGranted = true;
  requestedOrigins = [];
  lastResponse = mkResponse({
    headers: {
      "X-JIT-Secret": SECRET_B64,
      "X-JIT-Kid": "kid_a",
      // consent was for a.example.com only
      "X-JIT-Origins": "https://a.example.com,https://bank.example.com",
    },
  });
  removedOrigins = [];
  await expectThrow(
    () => enrollToken({
      code: "c", server: "https://enroll.example.com",
      origins: ["https://a.example.com"],
    }),
    /not asked about/i,
    "widening must abort",
  );
  // An aborted enrollment must not leave host permissions behind: the user
  // would be holding access they never completed agreeing to and cannot see
  // listed anywhere in the extension.
  assert.ok(
    removedOrigins.includes("https://a.example.com/*"),
    "aborting enrollment must roll back the host permissions it requested, got " +
      JSON.stringify(removedOrigins));
});

await t("a server that NARROWS the consented set is honoured", async () => {
  tokenStore = [];
  permissionsGranted = true;
  lastResponse = mkResponse({
    headers: {
      "X-JIT-Secret": SECRET_B64,
      "X-JIT-Kid": "kid_a",
      "X-JIT-Origins": "https://a.example.com",
    },
  });
  // Reaches store.enroll(), which needs IndexedDB; the point is that it gets
  // PAST the origin check, so any failure must not be the widening error.
  let result = null, msg = "";
  try {
    result = await enrollToken({
      code: "c", server: "https://enroll.example.com",
      origins: ["https://a.example.com", "https://b.example.com"],
    });
  } catch (e) {
    msg = e.message;
  }
  assert.ok(!/not asked about/i.test(msg), "narrowing must not be treated as widening");
  // The point of the case: the NARROWED set is what gets enrolled. Asserting
  // only "did not throw the widening error" passed even if the full consented
  // set was enrolled, which is the opposite of honouring the server's narrowing.
  assert.ok(result, "narrowing should complete enrollment, got error: " + msg);
  assert.deepStrictEqual(result.origins, ["https://a.example.com"],
    "only the origin the server kept should be enrolled");
});

await t("a bare hostname in X-JIT-Origins is accepted (PROTOCOL §2.1 form)", async () => {
  tokenStore = [];   // previous case enrolled kid_a
  permissionsGranted = true;
  lastResponse = mkResponse({
    headers: {
      "X-JIT-Secret": SECRET_B64,
      "X-JIT-Kid": "kid_a",
      "X-JIT-Origins": "a.example.com",   // bare host, as §2.1 shows
    },
  });
  const r = await enrollToken({
    code: "c", server: "https://enroll.example.com",
    origins: ["https://a.example.com"],
  });
  assert.deepStrictEqual(r.origins, ["https://a.example.com"]);
});

await t("a colliding kid is refused rather than silently replacing a token", async () => {
  tokenStore = [];
  const { enroll } = await import("./store.js");
  await enroll({ kid: "kid_dup", secretBytes: new Uint8Array(32), origins: ["https://x.example.com"] });
  await expectThrow(
    () => enroll({ kid: "kid_dup", secretBytes: new Uint8Array(32), origins: ["https://y.example.com"] }),
    /already enrolled/i,
    "colliding kid",
  );
});

await t("declining the permission prompt aborts before any network call", async () => {
  permissionsGranted = false;
  lastResponse = mkResponse({ headers: { "X-JIT-Secret": SECRET_B64, "X-JIT-Kid": "k" } });
  await expectThrow(
    () => enrollToken({ code: "c", server: "https://e.example.com", origins: ["https://a.example.com"] }),
    /declined/i,
    "declined permission",
  );
});

await t("a non-https origin is refused", async () => {
  permissionsGranted = true;
  assert.throws(() => normalizeOrigins(["http://a.example.com"]), /https/);
});

await t("a non-https enrollment server is refused", async () => {
  await expectThrow(() => exchangeCode("http://e.example.com", "c"), /https/i, "http server");
});

await t("a non-2xx enroll response is reported, not parsed for a secret", async () => {
  lastResponse = mkResponse({ status: 403, headers: {} });
  await expectThrow(() => exchangeCode("https://e.example.com", "c"), /HTTP 403/, "403 response");
});

await t("the enroll request carries the protocol version field", async () => {
  let seen = null;
  globalThis.fetch = async (_url, init) => {
    seen = JSON.parse(init.body);
    return mkResponse({ headers: { "X-JIT-Secret": SECRET_B64, "X-JIT-Kid": "k" } });
  };
  await exchangeCode("https://e.example.com", "code123");
  assert.strictEqual(seen.v, 1, "PROTOCOL §2.1 requires v:1 in the request body");
  assert.strictEqual(seen.code, "code123");
  globalThis.fetch = async () => lastResponse;
});

await t("the enroll fetch refuses to follow redirects", async () => {
  let init = null;
  globalThis.fetch = async (_url, i) => {
    init = i;
    return mkResponse({ headers: { "X-JIT-Secret": SECRET_B64, "X-JIT-Kid": "k" } });
  };
  await exchangeCode("https://e.example.com", "c");
  assert.strictEqual(init.redirect, "error", "a redirect would replay the one-time code elsewhere");
  assert.strictEqual(init.credentials, "omit");
  globalThis.fetch = async () => lastResponse;
});

console.log(`\n${pass} passed, ${fail.length} failed`);
if (fail.length) process.exit(1);
