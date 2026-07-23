-- Conformance check for the Lua core against the shared vectors.
-- Run under OpenResty (ngx.* + resty.openssl required):
--
--   resty -I core/lua core/lua/test_vectors.lua
--
-- Exits non-zero on any mismatch. This is the Lua half of core/SPEC.md §8;
-- the Python half is `generate_vectors.py --check`.

package.path = "core/lua/?.lua;" .. package.path

local cjson  = require "cjson"
local pae    = require "jitaccess.core.pae"
local canon  = require "jitaccess.core.canon"
local crypto = require "jitaccess.core.crypto"

local function fromhex(s)
  return (s:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end
local function tohex(s)
  return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local f = assert(io.open("core/testdata/vectors.json", "r"))
local V = cjson.decode(f:read("*a")); f:close()

local fails, checks = 0, 0
local function ok(cond, msg)
  checks = checks + 1
  if not cond then fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end
end

-- PAE
for _, c in ipairs(V.pae) do
  local parts = {}
  for i, b64 in ipairs(c.pieces) do parts[i] = crypto.b64u_decode(b64) or "" end
  ok(tohex(pae.encode(parts)) == c.out_hex, "pae " .. table.concat(c.pieces_utf8, ","))
end

-- server_name
for _, c in ipairs(V.canon_server_name) do
  ok(canon.canon_server_name(c["in"]) == c.out, "canon_server_name " .. c["in"])
end

-- ip (skip the intentional-invalid vectors, marked "<invalid")
for _, c in ipairs(V.canon_ip) do
  if c.out:sub(1, 8) ~= "<invalid" then
    ok(canon.canon_ip(c["in"], c.v6_prefix, c.v4_prefix) == c.out, "canon_ip " .. c["in"] .. "/" .. c.v6_prefix)
  end
end

-- proof
for _, c in ipairs(V.proof) do
  local nonce_raw = fromhex(c.nonce_raw_hex)
  ok(tohex(crypto.proof_canonical(c.server_name, c.kid, nonce_raw)) == c.canonical_hex,
     "proof_canonical " .. c.server_name)
  local tag = crypto.build_proof(fromhex(c.secret_hex), c.server_name, c.kid, nonce_raw)
  ok(crypto.b64u_encode(tag) == c.proof_b64url, "proof " .. c.server_name)
end

-- nonce
for _, c in ipairs(V.nonce) do
  local nonce = crypto.issue_nonce(fromhex(c.nonce_key_hex), c.ts, fromhex(c.rand_hex),
                                   c.server_name, c.ip, c.v6_prefix)
  ok(tohex(nonce) == c.nonce_hex, "nonce hex " .. c.server_name)
  ok(crypto.b64u_encode(nonce) == c.nonce_b64url, "nonce b64 " .. c.server_name)
  local vok = crypto.verify_nonce(fromhex(c.nonce_key_hex), nonce, c.server_name, c.ip,
                                  c.ts + 5, 60, c.v6_prefix)
  ok(vok == true, "verify_nonce " .. c.server_name)
end

io.write(string.format("%d checks, %d failures\n", checks, fails))
os.exit(fails == 0 and 0 or 1)
