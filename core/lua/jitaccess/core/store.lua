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
    redis  = opts.redis,     -- HARDENED: nil in Simple mode
    tenant = opts.tenant,    -- HARDENED
  }, mt)
end

local function grant_key(self, sname_canon, ip_canon)
  -- TODO(hardened): if self.tenant then prefix "jit:" .. tenant .. ":grant:" ...
  return GRANT_PREFIX .. sname_canon .. ":" .. ip_canon
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
  local ok, err = self.grants:set(grant_key(self, sname_canon, ip_canon), json, ttl)
  if not ok then return nil, err end
  return true
end

-- Fetch the raw grant record (or nil). The kid/expiry/cookie RE-CHECK required
-- by SPEC §4.3 is composed in :is_allowed below (it needs the registry + now).
function methods:get_grant(sname_canon, ip_canon)
  if self.redis then
    -- TODO(hardened): redis GET + verify mac before trusting; error -> nil (deny).
    return nil
  end
  local json = self.grants:get(grant_key(self, sname_canon, ip_canon))
  if not json then return nil end
  return cjson.decode(json)   -- nil on corrupt -> treated as no grant (deny)
end

-- SPEC §4.3 is_allowed: grant present AND kid still registered AND token not
-- expired AND (ip+cookie) cookie matches. registry is duck-typed (has :lookup,
-- :is_expired). Any failure -> nil (deny). This is the function the adapter's
-- access phase calls.
function methods:is_allowed(sname_canon, ip_canon, registry, now, cookie_hash_present)
  local rec = self:get_grant(sname_canon, ip_canon)
  if not rec then return nil end
  local token = registry:lookup(rec.kid)
  if not token then return nil end                 -- kid revoked -> deny
  if registry:is_expired(token, now) then return nil end
  if rec.binding == "ip+cookie" then
    -- HARDENED: compare presented opaque grant-id cookie hash to rec.cookie_hash
    if not cookie_hash_present or cookie_hash_present ~= rec.cookie_hash then return nil end
  end
  return rec
end

function methods:del_grant(sname_canon, ip_canon)
  if self.redis then return nil, "hardened redis backend not implemented" end
  self.grants:delete(grant_key(self, sname_canon, ip_canon))
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
