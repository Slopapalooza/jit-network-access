-- jitaccess.lua — BunkerWeb plugin main (adapter L4).
--
-- M2: the challenge/respond knock protocol on top of the M1 gate.
--   init()      : parse JIT_ACCESS_TOKEN_* into a registry, per-service
--                 allow-lists, and an ephemeral per-instance nonce key.
--   access()    : serve GET <prefix>/challenge and POST <prefix>/respond;
--                 grant-check + interstitial/stealth deny otherwise.
--   api()       : manual break-glass grant management (M1).
-- Simple profile: local lua_shared_dict store, no Redis.
--
-- Fail-closed is the invariant (SECURITY-REVIEW C1 / DESIGN §11 R1): access()
-- wraps everything in its own pcall and denies on any internal error.
--
-- Verified end-to-end on BunkerWeb 1.6.10; core crypto runs under the bundled
-- LuaJIT + resty.openssl and matches core/testdata/vectors.json.

local class    = require "middleclass"
local plugin   = require "bunkerweb.plugin"
local utils    = require "bunkerweb.utils"
local cjson    = require "cjson.safe"

local ccanon    = require "jitaccess.core.canon"
local ccrypto   = require "jitaccess.core.crypto"
local cstore    = require "jitaccess.core.store"
local cregistry = require "jitaccess.core.registry"

local get_multiple_variables = utils.get_multiple_variables

local jitaccess = class("jitaccess", plugin)

local MARKER = "challenge; v=1"
local DUMMY_KEY = string.rep("\0", 32)   -- equalized-work HMAC key for unknown kid

local function deny_status()
  if utils.get_deny_status then
    local ok, s = pcall(utils.get_deny_status)
    if ok and s then return s end
  end
  return ngx.HTTP_FORBIDDEN
end

-- ---- lifecycle -------------------------------------------------------------

function jitaccess:initialize(ctx)
  plugin.initialize(self, "jitaccess", ctx)
  local grants, nonces = ngx.shared.jit_grants, ngx.shared.jit_nonces
  if grants and nonces then
    self.store = cstore.new({ grants = grants, nonces = nonces })
  end
  -- registry + per-service allow-lists + nonce key, materialized by init()
  local tokens = self.internalstore and self.internalstore:get("plugin_jitaccess_registry", true) or {}
  local services = self.internalstore and self.internalstore:get("plugin_jitaccess_services", true) or {}
  self.registry = cregistry.new(tokens, services)
  self.nonce_key = self.internalstore and self.internalstore:get("plugin_jitaccess_noncekey", true)
  -- rate limit (best-effort, per-IP, on knock endpoints)
  local rl = self.variables and self.variables["JIT_ACCESS_RATELIMIT"] or "10r/m"
  local n, unit = tostring(rl):match("^(%d+)r/([smhd])$")
  self.rate_limit = tonumber(n)
  self.rate_window = ({ s = 1, m = 60, h = 3600, d = 86400 })[unit or "m"] or 60
end

-- init phase (init_by_lua): parse settings once, store for the request path.
function jitaccess:init()
  local variables, err = get_multiple_variables({ "USE_JIT_ACCESS", "JIT_ACCESS_TOKENS", "JIT_ACCESS_TOKEN" })
  if not variables then
    return self:ret(false, "can't read jitaccess variables: " .. tostring(err))
  end

  -- token registry from the global JIT_ACCESS_TOKEN_* entries
  local tokens, ntok = {}, 0
  local gvars = variables["global"] or {}
  for key, value in pairs(gvars) do
    if value ~= "" and key:match("^JIT_ACCESS_TOKEN(_?%d*)$") then
      local kid, b64secret, rest = value:match("^([^:]+):([^:]+):(.*)$")
      if kid and b64secret then
        local secret = ccrypto.b64u_decode(b64secret)
        if secret and #secret >= 16 then
          local label, expires = rest, nil
          local l, e = rest:match("^(.*):(%d+)$")
          if e then label = l; expires = tonumber(e) end
          tokens[kid] = { secret = secret, alg = "HMAC-SHA256", label = label, expires = expires }
          ntok = ntok + 1
        else
          self.logger:log(ngx.WARN, "jitaccess: bad secret for token, skipping kid " .. tostring(kid))
        end
      end
    end
  end

  -- per-service allow-lists (which kids may open which canonical service)
  local services = {}
  for scope, vars in pairs(variables) do
    if scope ~= "global" and vars["USE_JIT_ACCESS"] == "yes" then
      local allow = {}
      for kid in tostring(vars["JIT_ACCESS_TOKENS"] or ""):gmatch("%S+") do
        if kid == "*" then allow["*"] = true else allow[kid] = true end
      end
      services[ccanon.canon_server_name(scope)] = allow
    end
  end

  self.internalstore:set("plugin_jitaccess_registry", tokens, nil, true)
  self.internalstore:set("plugin_jitaccess_services", services, nil, true)

  -- ephemeral per-instance nonce key (kept across reloads while shm survives)
  local nk = self.internalstore:get("plugin_jitaccess_noncekey", true)
  if not nk then
    nk = ccrypto.random_bytes(32)
    if not nk then return self:ret(false, "jitaccess: RNG failed for nonce key") end
    self.internalstore:set("plugin_jitaccess_noncekey", nk, nil, true)
  end

  return self:ret(true, "jitaccess init: " .. ntok .. " token(s)")
end

-- ---- helpers ---------------------------------------------------------------

function jitaccess:metric(kind, key, val)
  if self.set_metric then pcall(self.set_metric, self, kind, key, val) end
end

function jitaccess:server_name_canon()
  local sn = (ngx.ctx.bw and ngx.ctx.bw.server_name) or ngx.var.server_name
  if not sn or sn == "" then return nil end
  return ccanon.canon_server_name(sn)
end

function jitaccess:ipv6_prefix()
  return tonumber((self.variables and self.variables["JIT_ACCESS_IPV6_PREFIX"]) or "128") or 128
end

function jitaccess:client_ip_canon()
  -- SECURITY (R2 / SECURITY-REVIEW C2): key grants on an IP the client cannot
  -- forge. BunkerWeb's realip rewrites ngx.var.remote_addr from X-Forwarded-For /
  -- X-Real-IP when USE_REAL_IP=yes, so remote_addr is spoofable on any instance
  -- with realip enabled. Default (Simple) therefore uses $realip_remote_addr —
  -- the actual TCP peer nginx preserves before realip — which cannot be moved by
  -- a request header. Hardened deployments genuinely behind a trusted proxy set
  -- JIT_ACCESS_TRUST_REALIP=yes to key on the resolved client instead (only safe
  -- with a correctly narrowed REAL_IP_FROM).
  local ip
  if self.variables and self.variables["JIT_ACCESS_TRUST_REALIP"] == "yes" then
    ip = (ngx.ctx.bw and ngx.ctx.bw.remote_addr) or ngx.var.remote_addr
  else
    ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
  end
  if not ip or ip == "" then return nil end
  return ccanon.canon_ip(ip, self:ipv6_prefix())
end

function jitaccess:cookie_hash()
  return nil   -- HARDENED (M6): opaque grant-id cookie. M1/M2 = ip binding.
end

-- best-effort per-IP rate limit on knock endpoints (shared nonce dict, rl: prefix)
function jitaccess:rate_ok(ip)
  if not self.rate_limit or self.rate_limit <= 0 or not self.store then return true end
  local n = self.store.nonces:incr("rl:" .. ip, 1, 0, self.rate_window)
  if not n then return true end
  return n <= self.rate_limit
end

function jitaccess:deny(reason)
  local mode = (self.variables and self.variables["JIT_ACCESS_FAILURE_MODE"]) or "interstitial"
  if mode == "stealth" then
    return self:ret(true, reason .. " (stealth 404)", ngx.HTTP_NOT_FOUND)
  end
  pcall(function()
    ngx.header["X-JIT-Access"] = MARKER
    ngx.header["Cache-Control"] = "no-store"
  end)
  return self:ret(true, reason .. " (interstitial)", deny_status())
end

-- ---- knock protocol --------------------------------------------------------

function jitaccess:challenge(sname, ip)
  if not self:rate_ok(ip) then return self:deny("jit challenge rate-limited") end
  if not self.nonce_key then return self:deny("jit no nonce key") end
  local rand = ccrypto.random_bytes(16)
  if not rand then return self:deny("jit rng") end
  local nonce = ccrypto.issue_nonce(self.nonce_key, ngx.time(), rand, sname, ip, self:ipv6_prefix())
  if not nonce then return self:deny("jit nonce mint") end
  pcall(function()
    ngx.header["X-JIT-Nonce"] = ccrypto.b64u_encode(nonce)
    ngx.header["X-JIT-TS"] = tostring(ngx.time())
    ngx.header["Cache-Control"] = "no-store"
  end)
  return self:ret(true, "jit challenge", ngx.HTTP_NO_CONTENT)
end

-- Returns true on a fully valid knock (and creates the grant), false otherwise.
-- Equalized work: always decode + always compute exactly one proof HMAC (dummy
-- key when the kid is unknown/not-allowed) so failure reasons are indistinguishable.
function jitaccess:verify_knock(sname, ip, body)
  local nonce = type(body.nonce) == "string" and ccrypto.b64u_decode(body.nonce) or nil
  local proof = type(body.proof) == "string" and ccrypto.b64u_decode(body.proof) or nil
  local kid = type(body.kid) == "string" and body.kid or ""
  local proof_len_ok = proof ~= nil and #proof == 32
  local now = ngx.time()
  local nttl = tonumber(self.variables["JIT_ACCESS_NONCE_TTL"] or "60") or 60

  local nok, rand = false, nil
  if nonce then
    nok, rand = ccrypto.verify_nonce(self.nonce_key, nonce, sname, ip, now, nttl, self:ipv6_prefix())
  end
  local token = self.registry:authorize(kid, sname, now)   -- nil if unknown/expired/not-allowed
  local secret = (token and token.secret) or DUMMY_KEY
  local proof_ok = false
  if proof_len_ok and nonce then
    proof_ok = ccrypto.verify_proof(secret, sname, kid, nonce, proof)
  end

  if not (nok and token and proof_ok) then return false end

  -- verify-then-burn: single-use claim only after a fully valid proof
  if not self.store:nonce_claim(ccrypto.b64u_encode(rand), nttl) then return false end

  local ttl = tonumber(self.variables["JIT_ACCESS_GRANT_TIME"] or "3600") or 3600
  local rec = cstore.record(sname, ip, kid, ttl,
                            { manual = false, binding = self.variables["JIT_ACCESS_BINDING"] or "ip" })
  return self.store:put_grant(sname, ip, rec, ttl) == true
end

function jitaccess:respond(sname, ip)
  if not self:rate_ok(ip) then return self:deny("jit respond rate-limited") end
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  local body = data and cjson.decode(data) or {}
  if type(body) ~= "table" then body = {} end
  if self:verify_knock(sname, ip, body) then
    self:metric("counters", "jit_knock_ok", 1)
    return self:ret(true, "jit knock accepted", ngx.HTTP_NO_CONTENT)
  end
  self:metric("counters", "jit_knock_fail", 1)
  return self:deny("jit knock rejected")
end

-- POST /enroll {code}: exchange a single-use enrollment code for the token
-- secret. Response is a 204 carrying the material in headers (the access phase
-- can't cleanly emit a body under BunkerWeb's dispatcher); over TLS + single-use
-- code this is fine, and the secret never rode in a QR/URL (DESIGN §6.1 / R5).
function jitaccess:enroll(sname, ip)
  if not self:rate_ok(ip) then return self:deny("jit enroll rate-limited") end
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  local body = data and cjson.decode(data) or {}
  if type(body) ~= "table" or type(body.code) ~= "string" then
    return self:deny("jit enroll bad request")
  end
  local rec = self.store:enroll_code_consume(body.code)   -- single-use
  if not rec then return self:deny("jit enroll invalid/used code") end
  local token = self.registry:lookup(rec.kid)
  if not token then return self:deny("jit enroll unknown kid") end
  pcall(function()
    ngx.header["X-JIT-Kid"] = rec.kid
    ngx.header["X-JIT-Secret"] = ccrypto.b64u_encode(token.secret)
    ngx.header["X-JIT-Alg"] = token.alg or "HMAC-SHA256"
    ngx.header["X-JIT-Origins"] = table.concat(rec.origins or {}, ",")
    ngx.header["Cache-Control"] = "no-store"
  end)
  self:metric("counters", "jit_enroll_ok", 1)
  return self:ret(true, "jit enroll ok", ngx.HTTP_NO_CONTENT)
end

-- ---- phases ----------------------------------------------------------------

function jitaccess:set()
  pcall(function()
    ngx.var.is_jit_allowed = "no"
    if ngx.ctx.bw then ngx.ctx.bw.is_jit_allowed = "no" end
  end)
  return self:ret(true, "jit set")
end

function jitaccess:access()
  local ok, res = pcall(function() return self:_access() end)
  if not ok then
    self.logger:log(ngx.ERR, "jitaccess access() error (failing closed): " .. tostring(res))
    return self:ret(true, "jit internal error (deny)", deny_status())
  end
  return res
end

function jitaccess:_access()
  local v = self.variables
  if not v or v["USE_JIT_ACCESS"] ~= "yes" then
    return self:ret(true, "jit disabled")
  end
  if not self.store then
    return self:ret(true, "jit store unavailable (deny)", deny_status())
  end

  local sname = self:server_name_canon()
  local ip = self:client_ip_canon()
  if not sname or not ip then
    return self:deny("jit missing/invalid server_name or ip")
  end

  -- Protocol endpoints, served BEFORE the grant check (a knocker isn't granted).
  local prefix = v["JIT_ACCESS_URI_PREFIX"] or "/.well-known/jit-access"
  local uri = ngx.var.uri or ""
  local method = ngx.req.get_method()
  if uri == prefix .. "/challenge" and method == "GET" then
    return self:challenge(sname, ip)
  elseif uri == prefix .. "/respond" and method == "POST" then
    return self:respond(sname, ip)
  elseif uri == prefix .. "/enroll" and method == "POST" then
    return self:enroll(sname, ip)
  elseif uri == prefix or uri:sub(1, #prefix + 1) == prefix .. "/" then
    return self:deny("jit protocol endpoint")
  end

  -- Grant check
  local now = ngx.time()
  local rec = self.store:is_allowed(sname, ip, self.registry, now, self:cookie_hash())
  if rec then
    pcall(function()
      ngx.var.is_jit_allowed = "yes"
      if ngx.ctx.bw then ngx.ctx.bw.is_jit_allowed = "yes" end
    end)
    self:metric("counters", "jit_granted", 1)
    if v["JIT_ACCESS_SKIP_CHECKS"] == "yes" then
      return self:ret(true, "jit granted (skip checks)", ngx.OK)
    end
    return self:ret(true, "jit granted")
  end

  self:metric("counters", "jit_denied", 1)
  return self:deny("jit no grant")
end

-- ---- internal API (management) ---------------------------------------------

function jitaccess:api()
  local uri = ngx.var.uri or ""
  if uri:sub(1, 11) ~= "/jitaccess/" then
    return self:ret(false, "not a jitaccess endpoint")
  end
  if not self.store then
    return self:ret(true, "jit store unavailable", ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  local method = ngx.req.get_method()

  if method == "GET" and uri == "/jitaccess/grants" then
    local list = self.store:list()
    return self:ret(true, cjson.encode({ grants = list, count = #list }), ngx.HTTP_OK)
  end

  local body = {}
  if method == "POST" then
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    if data then body = cjson.decode(data) or {} end
  end

  local function target()
    local service = body.service and ccanon.canon_server_name(body.service)
    local ip = body.ip and ccanon.canon_ip(body.ip, tonumber(body.ipv6_prefix) or 128)
    return service, ip
  end

  if method == "POST" and uri == "/jitaccess/grant" then
    local service, ip = target()
    local ttl = tonumber(body.ttl) or 3600
    if not service or not ip then return self:ret(true, "service and valid ip required", ngx.HTTP_BAD_REQUEST) end
    local rec = cstore.record(service, ip, body.kid or "__manual__", ttl,
                              { manual = true, binding = body.binding or "ip" })
    local ok, err = self.store:put_grant(service, ip, rec, ttl)
    if not ok then return self:ret(true, "grant failed: " .. tostring(err), ngx.HTTP_INTERNAL_SERVER_ERROR) end
    return self:ret(true, cjson.encode({ granted = true, service = service, ip = ip, ttl = ttl, exp = rec.exp }), ngx.HTTP_OK)
  end

  if method == "POST" and uri == "/jitaccess/revoke" then
    local service, ip = target()
    if not service or not ip then return self:ret(true, "service and valid ip required", ngx.HTTP_BAD_REQUEST) end
    self.store:del_grant(service, ip)
    return self:ret(true, cjson.encode({ revoked = true, service = service, ip = ip }), ngx.HTTP_OK)
  end

  if method == "POST" and uri == "/jitaccess/revoke-token" then
    if not body.kid then return self:ret(true, "kid required", ngx.HTTP_BAD_REQUEST) end
    local n = self.store:revoke_token(body.kid)
    return self:ret(true, cjson.encode({ revoked_token = body.kid, grants_removed = n }), ngx.HTTP_OK)
  end

  if method == "POST" and uri == "/jitaccess/enroll-code" then
    if type(body.kid) ~= "string" or not self.registry:lookup(body.kid) then
      return self:ret(true, "known kid required", ngx.HTTP_BAD_REQUEST)
    end
    local rand = ccrypto.random_bytes(12)
    if not rand then return self:ret(true, "rng failed", ngx.HTTP_INTERNAL_SERVER_ERROR) end
    local code = ccrypto.b64u_encode(rand)
    -- Link lifetime: explicit body.ttl wins, else the JIT_ACCESS_ENROLL_TTL
    -- setting (default 24 h). Clamped so a typo can't mint an immortal code.
    local ttl = tonumber(body.ttl)
        or tonumber((self.variables and self.variables["JIT_ACCESS_ENROLL_TTL"]) or "")
        or 86400
    if ttl < 300 then ttl = 300 elseif ttl > 604800 then ttl = 604800 end
    local origins = type(body.origins) == "table" and body.origins or {}
    local ok, err = self.store:enroll_code_put(code, { kid = body.kid, origins = origins }, ttl)
    if not ok then return self:ret(true, "code create failed: " .. tostring(err), ngx.HTTP_INTERNAL_SERVER_ERROR) end
    local resp = { code = code, kid = body.kid, ttl = ttl, origins = origins }
    -- A registration URL the admin hands to a user: browsing to it lets the
    -- extension pick up the token (it intercepts <server>/.well-known/jit-access/
    -- register before the request is served). Assumes the default URI prefix.
    if type(body.server) == "string" and body.server:match("^https://[^/]") then
      local base = body.server:gsub("/+$", "")
      resp.register_url = base .. "/.well-known/jit-access/register?code=" .. code
      if #origins > 0 then resp.register_url = resp.register_url .. "&origins=" .. table.concat(origins, ",") end
    end
    return self:ret(true, cjson.encode(resp), ngx.HTTP_OK)
  end

  return self:ret(true, "unknown jitaccess endpoint", ngx.HTTP_NOT_FOUND)
end

return jitaccess
