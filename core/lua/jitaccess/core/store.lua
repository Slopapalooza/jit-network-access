-- JIT Network Access - Copyright (C) 2026 Slopapalooza
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- jitaccess.core.store — GrantStore + NonceStore (core/SPEC.md §4, §5)
--
-- Simple/default backend: ngx.shared dicts (process-local, worker-shared, no
-- external dependency). Hardened/shared backend: Redis — present here as
-- explicit fail-closed stubs (TODO(hardened)) so the adapters never change when
-- it's wired later.
--
-- Grants invert the ban fail-direction, so every error path denies. See
-- SECURITY-REVIEW C1/C3/H3 and core/SPEC.md §7.
--
-- NOTE: not executed on the dev host; shdict semantics validated by the harness.

local cjson = require "cjson.safe"

local _M = { _VERSION = "0.1.0" }
local methods = {}
local mt = { __index = methods }

local GRANT_PREFIX = "jit:grant:"
local NONCE_PREFIX = "jit:nonce:"

-- Constant-time string equality for the ip+cookie hash comparison.
--
-- Delegates to jitaccess.core.crypto rather than keeping a second copy: the
-- local one accumulated with `(x == y and 0 or 1)`, which branches per byte and
-- so was not actually constant-time, unlike crypto.ct_equal's branch-free
-- bor/bxor accumulator and Go's subtle.ConstantTimeCompare. Two implementations
-- of one primitive is exactly how that drift happens.
local ct_equal = require("jitaccess.core.crypto").ct_equal

-- opts.grants  : ngx.shared dict for grants        (required, Simple)
-- opts.nonces  : ngx.shared dict for spent nonces  (required, Simple) — MUST be
--                a dedicated dict, isolated from grants and from BunkerWeb bans
--                so a nonce flood can't evict grants/bans (SECURITY-REVIEW H5).
-- opts.redis   : Hardened shared backend (optional; stubbed)
-- opts.tenant  : Hardened namespace (optional)
function _M.new(opts)
  assert(opts and opts.grants and opts.nonces, "store.new: grants and nonces dicts required")
  return setmetatable({
    grants = opts.grants,
    nonces = opts.nonces,
    -- Rate-limit counters get their OWN dict. SPEC §5 requires the nonce dict to
    -- be dedicated to spent-nonce claims: sharing it let an unauthenticated
    -- attacker mint one counter per source address and LRU-evict spent-nonce
    -- markers (re-enabling replay inside the TTL) and enrollment codes.
    -- Falls back to the nonce dict so a caller that has not declared the third
    -- dict still runs, with the documented caveat.
    rl     = opts.rl or opts.nonces,
    redis  = opts.redis,     -- HARDENED: nil in Simple mode
    tenant = opts.tenant,    -- HARDENED
  }, mt)
end

-- Key schema (core/SPEC.md §4.1). For ip+cookie binding the cookie hash is part
-- of the key: without it one (service, ip) pair held exactly ONE grant, so two
-- enrolled devices behind a single NAT egress evicted each other on every knock
-- and flapped indefinitely — precisely the deployment ip+cookie exists to serve.
-- `ip` binding keeps the two-part key, so the default profile is unchanged.
local function grant_key(self, sname_canon, ip_canon, cookie_hash)
  -- TODO(hardened): if self.tenant then prefix "jit:" .. tenant .. ":grant:" ...
  local k = GRANT_PREFIX .. sname_canon .. ":" .. ip_canon
  if cookie_hash then k = k .. ":" .. cookie_hash end
  return k
end

-- ---- GrantStore ------------------------------------------------------------

-- Create/refresh a grant. ttl seconds. Returns true or nil,err (fail closed).
function methods:put_grant(sname_canon, ip_canon, rec, ttl)
  if self.redis then
    -- TODO(hardened): sign rec (mac = HMAC/AEAD(grant_sign_key, canonical(rec)))
    -- then redis SET key json EX ttl; on any error return nil (caller denies).
    return nil, "hardened redis backend not implemented"
  end
  local json = cjson.encode(rec)
  if not json then return nil, "encode failed" end
  -- A device-bound record is stored under its own cookie-qualified key.
  local ck = (rec.binding == "ip+cookie") and rec.cookie_hash or nil
  local ok, err = self.grants:set(grant_key(self, sname_canon, ip_canon, ck), json, ttl)
  if not ok then return nil, err end
  return true
end

-- Fetch the raw grant record (or nil). The kid/expiry/cookie RE-CHECK required
-- by SPEC §4.3 is composed in :is_allowed below (it needs the registry + now).
--
-- cookie_hash, when the client presented one, selects that device's own grant;
-- otherwise the ip-bound key is used. Looking the hash up (rather than scanning)
-- means a device can only ever find its OWN record.
function methods:get_grant(sname_canon, ip_canon, cookie_hash)
  if self.redis then
    -- TODO(hardened): redis GET + verify mac before trusting; error -> nil (deny).
    return nil
  end
  local json
  if cookie_hash then
    json = self.grants:get(grant_key(self, sname_canon, ip_canon, cookie_hash))
  end
  if not json then
    json = self.grants:get(grant_key(self, sname_canon, ip_canon))
  end
  if not json then return nil end
  return cjson.decode(json)   -- nil on corrupt -> treated as no grant (deny)
end

-- SPEC §4.3 is_allowed: grant present AND kid still registered AND token not
-- expired AND (ip+cookie) cookie matches. registry is duck-typed (has :lookup,
-- :is_expired). Any failure -> nil (deny). This is the function the adapter's
-- access phase calls.
--
-- Break-glass carve-out: a grant created directly by an admin over the
-- authenticated internal API (rec.manual == true) skips the registry re-check,
-- since there may be no token/kid behind it. TTL still bounds it, and revoke
-- still removes it. This is what makes the gate testable and recoverable in M1
-- before the knock protocol (M2) issues registry-backed grants.
function methods:is_allowed(sname_canon, ip_canon, registry, now, cookie_hash_present)
  local rec = self:get_grant(sname_canon, ip_canon, cookie_hash_present)
  if not rec then return nil end
  -- The key concatenates fields with ":", and a canonical server_name can itself
  -- contain ":" (a bracketed IPv6 literal canonicalizes to 2001:db8::1), so the
  -- key alone is a weak identifier. Confirm the record actually describes this
  -- request rather than trusting where it was filed.
  if rec.service ~= sname_canon or rec.ip ~= ip_canon then return nil end
  -- Check the record's OWN expiry, not just the dict TTL. shdict:set(k,v,0) means
  -- "never expire", and the BunkerWeb admin API passes ttl straight through
  -- (0 is truthy in Lua, so `tonumber(body.ttl) or 3600` keeps it), so a grant
  -- created with ttl=0 lived forever here while Go denied it on `now >= g.Exp`.
  if type(rec.exp) ~= "number" or now >= rec.exp then return nil end
  if not rec.manual then
    local token = registry and registry:lookup(rec.kid)
    if not token then return nil end               -- kid revoked/unknown -> deny
    if registry:is_expired(token, now) then return nil end
    -- Re-check the per-service allow-list too, not just registry membership.
    -- Dropping a kid from one site's allow-list while leaving the token
    -- registered (it may still serve another site) otherwise left the
    -- de-authorized device admitted for the whole grant TTL, while deleting the
    -- token evicted it at once — two admin actions that look equivalent from
    -- the console behaving differently.
    if not registry:allowed_for_service(rec.kid, sname_canon) then return nil end
  end
  if rec.binding == "ip+cookie" then
    -- The grant is additionally bound to the browser that knocked: the client
    -- must present the opaque grant-id cookie whose hash we stored. On shared
    -- egress (office NAT, CGNAT, VPN) this stops a co-located client that
    -- merely shares the IP from inheriting access (SECURITY-REVIEW C5/H11).
    if not cookie_hash_present or not rec.cookie_hash then return nil end
    if not ct_equal(cookie_hash_present, rec.cookie_hash) then return nil end
  end
  return rec
end

-- Build a grant record. `opts` = { kid, binding, cookie_hash, manual, now }.
function _M.record(sname_canon, ip_canon, kid, ttl, opts)
  opts = opts or {}
  local now = opts.now or ngx.time()
  return {
    v = 1,
    kid = kid,
    service = sname_canon,
    ip = ip_canon,
    binding = opts.binding or "ip",
    cookie_hash = opts.cookie_hash,
    manual = opts.manual or false,
    issued = now,
    exp = now + ttl,
  }
end

-- Remove EVERY grant for (service, ip): the ip-bound one and any device-bound
-- ones. An admin revoking an address means "this address loses access", not
-- "one of the devices there does" — with ip+cookie there may be several, and
-- leaving the rest behind would be a silent partial revoke.
function methods:del_grant(sname_canon, ip_canon)
  if self.redis then return nil, "hardened redis backend not implemented" end
  self.grants:delete(grant_key(self, sname_canon, ip_canon))
  -- Match each record's OWN fields, never a key prefix. Keys join fields with
  -- ":" and a canonical IPv6 address contains ":", so a prefix scan for
  -- 2001:db8::1 also deleted the unrelated client 2001:db8::1:2 — a silent
  -- over-revoke that looked like a correct one.
  for _, k in ipairs(self.grants:get_keys(0)) do
    local json = self.grants:get(k)
    if json then
      local rec = cjson.decode(json)
      if rec and rec.service == sname_canon and rec.ip == ip_canon then
        self.grants:delete(k)
      end
    end
  end
  return true
end

-- Sweep every grant for a kid (revoke a lost device — SECURITY-REVIEW H3).
-- Simple/local: scan the grant dict. get_keys is O(n) and fine at self-host
-- scale; at large scale the Hardened backend uses a bykid index instead.
function methods:revoke_token(kid)
  if self.redis then return nil, "hardened redis backend not implemented" end
  local keys = self.grants:get_keys(0)   -- all keys (home scale)
  local n = 0
  for _, k in ipairs(keys) do
    local json = self.grants:get(k)
    if json then
      local rec = cjson.decode(json)
      if rec and rec.kid == kid then
        self.grants:delete(k)
        n = n + 1
      end
    end
  end
  return n
end

function methods:list()
  if self.redis then return {} end
  local out = {}
  for _, k in ipairs(self.grants:get_keys(0)) do
    local json = self.grants:get(k)
    if json then
      local rec = cjson.decode(json)
      if rec then out[#out + 1] = rec end
    end
  end
  return out
end

-- ---- enrollment codes (single-use, TTL) ------------------------------------
-- Admin-issued one-time codes that the client exchanges at /enroll for its
-- token secret, so the secret is never placed in a QR/URL (DESIGN §6.1 / R5).
-- Stored in the dedicated nonce dict (ephemeral, single-use) under an ec: prefix.

local ENROLL_PREFIX = "jit:ec:"

function methods:enroll_code_put(code, data, ttl)
  if self.redis then return nil, "hardened redis backend not implemented" end
  local json = cjson.encode(data)
  if not json then return nil, "encode failed" end
  local ok, err = self.nonces:set(ENROLL_PREFIX .. code, json, ttl)
  if not ok then return nil, err end
  return true
end

-- Consume a code (single-use): returns its data table, or nil.
--
-- PROTOCOL §2.1 requires the code be marked consumed ATOMICALLY. A read then
-- delete is not: two requests racing across workers both `get` before either
-- `delete`, so both receive the secret and two devices end up sharing one
-- long-term key — which breaks "one token = one device" and makes regenerating
-- the token useless as a revocation.
--
-- `add` on a shared dict IS atomic across workers, so the winner of a claim
-- marker is the single consumer. Same primitive as nonce_claim below; the marker
-- outlives the code so a late loser cannot re-consume a re-issued one.
local CLAIM_PREFIX = "jit:ecx:"

-- Read a code WITHOUT consuming it, so a caller can reject one it cannot serve
-- (unknown kid) before burning it. Mirrors EnrollStore.Peek in core/go; without
-- it the Lua engines destroyed a perfectly good enrollment code on any hostile
-- POST naming a kid this instance does not have.
function methods:enroll_code_peek(code)
  if self.redis then return nil end
  local json = self.nonces:get(ENROLL_PREFIX .. code)
  if not json then return nil end
  return cjson.decode(json)
end

function methods:enroll_code_consume(code)
  if self.redis then return nil end
  local key = ENROLL_PREFIX .. code
  local json = self.nonces:get(key)
  if not json then return nil end
  -- Exactly one caller can win this; everyone else sees "exists" and gets nil.
  local won = self.nonces:add(CLAIM_PREFIX .. code, true, 900)
  if won ~= true then return nil end
  self.nonces:delete(key)
  return cjson.decode(json)
end

-- ---- NonceStore (single-use claim) -----------------------------------------

-- Atomically claim a nonce as spent. id = base64url/hex of the nonce's rand.
-- Returns true on first use, false if already spent. On Hardened backend a
-- backend error MUST fail closed (return false) — never allow-on-error.
function methods:nonce_claim(id, ttl)
  if self.redis then
    -- TODO(hardened): redis SET key 1 NX EX ttl; reply nil (set) -> first use;
    -- reply "OK" absent / error -> already spent OR unknown -> return false.
    return false   -- fail closed until implemented
  end
  -- shdict:add returns (ok, err, forcible); ok=false with err="exists" means spent.
  local ok = self.nonces:add(NONCE_PREFIX .. id, true, ttl)
  return ok == true
end

return _M
