-- jitaccess.core.crypto — proof & nonce cryptography (docs/PROTOCOL.md §3, §5)
--
-- Depends on lua-resty-openssl (bundled with BunkerWeb/OpenResty) for HMAC-SHA256
-- and a CSPRNG, and on ngx.{encode,decode}_base64 for base64url.
--
-- NOTE: not executed on the dev host (no Lua runtime). The proof and nonce
-- constructions were cross-checked against core/testdata/vectors.json via an
-- equivalent port before commit; the harness re-validates under real Lua.

local hmac    = require "resty.openssl.hmac"
local rand    = require "resty.openssl.rand"
local pae     = require "jitaccess.core.pae"
local canon   = require "jitaccess.core.canon"
local bit     = require "bit"      -- LuaJIT

local bor, bxor = bit.bor, bit.bxor
local byte, sub, char = string.byte, string.sub, string.char
local floor = math.floor
local concat = table.concat

local PROOF_DOMAIN = "jitaccess-v1"
local NONCE_DOMAIN = "jitaccess-nonce-v1"
local NONCE_LEN    = 56

local _M = { _VERSION = "0.1.0", PROOF_DOMAIN = PROOF_DOMAIN, NONCE_DOMAIN = NONCE_DOMAIN }

-- ---- base64url (no padding) ------------------------------------------------

function _M.b64u_encode(s)
  local b = ngx.encode_base64(s, true)          -- no padding, standard alphabet
  return (b:gsub("[+/]", { ["+"] = "-", ["/"] = "_" }))
end

function _M.b64u_decode(s)
  s = (s:gsub("[-_]", { ["-"] = "+", ["_"] = "/" }))
  local rem = #s % 4
  if rem == 2 then s = s .. "=="
  elseif rem == 3 then s = s .. "="
  elseif rem == 1 then return nil end
  return ngx.decode_base64(s)
end

-- ---- primitives ------------------------------------------------------------

local function hmac_sha256(key, data)
  local h, err = hmac.new(key, "sha256")
  if not h then return nil, err end
  local out
  out, err = h:final(data)
  if not out then return nil, err end
  return out
end
_M.hmac_sha256 = hmac_sha256

-- Constant-time equality. Length is not secret (proof/MAC lengths are fixed),
-- so an early length check is safe; the byte loop is branch-free on content.
local function ct_equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bor(diff, bxor(byte(a, i), byte(b, i)))
  end
  return diff == 0
end
_M.ct_equal = ct_equal

-- CSPRNG; fails closed (returns nil) on error — callers MUST reject on nil.
function _M.random_bytes(n)
  local b, err = rand.bytes(n)
  if not b or #b ~= n then return nil, err or "rng failed" end
  return b
end

local function be64(n)
  local b = {}
  for i = 8, 1, -1 do
    b[i] = char(n % 256)
    n = floor(n / 256)
  end
  return concat(b)
end

-- ---- proof (the knock) -----------------------------------------------------

function _M.proof_canonical(server_name, kid, nonce_raw)
  return pae.encode({ PROOF_DOMAIN, canon.canon_server_name(server_name), kid, nonce_raw })
end

function _M.build_proof(secret, server_name, kid, nonce_raw)
  return hmac_sha256(secret, _M.proof_canonical(server_name, kid, nonce_raw))
end

function _M.verify_proof(secret, server_name, kid, nonce_raw, tag)
  local expect = _M.build_proof(secret, server_name, kid, nonce_raw)
  if not expect then return false end
  return ct_equal(expect, tag)
end

-- ---- stateless nonce -------------------------------------------------------

local function nonce_mac(nonce_key, ts, rand16, server_name, ip, v6_prefix)
  local ip_c = canon.canon_ip(ip, v6_prefix)
  if not ip_c then return nil, "bad ip" end
  local input = pae.encode({
    NONCE_DOMAIN, be64(ts), rand16,
    canon.canon_server_name(server_name), ip_c,
  })
  return hmac_sha256(nonce_key, input)
end

-- returns nonce (56 bytes, raw) or nil,err
function _M.issue_nonce(nonce_key, ts, rand16, server_name, ip, v6_prefix)
  if #rand16 ~= 16 then return nil, "rand must be 16 bytes" end
  local mac, err = nonce_mac(nonce_key, ts, rand16, server_name, ip, v6_prefix)
  if not mac then return nil, err end
  return be64(ts) .. rand16 .. mac
end

-- returns ok(bool), rand16|nil. Does NOT enforce single-use (see store.NonceStore).
function _M.verify_nonce(nonce_key, nonce, server_name, ip, now, ttl, v6_prefix)
  if type(nonce) ~= "string" or #nonce ~= NONCE_LEN then return false end
  local ts = 0
  for i = 1, 8 do ts = ts * 256 + byte(nonce, i) end
  local rand16 = sub(nonce, 9, 24)
  local mac = sub(nonce, 25, 56)
  local expect = nonce_mac(nonce_key, ts, rand16, server_name, ip, v6_prefix)
  if not expect or not ct_equal(expect, mac) then return false end
  if now < ts or (now - ts) >= ttl then return false end
  return true, rand16
end

return _M
