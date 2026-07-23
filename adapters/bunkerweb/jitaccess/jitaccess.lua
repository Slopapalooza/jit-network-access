-- jitaccess.lua — BunkerWeb plugin main (adapter L4).
--
-- M1: the gate + grant lifecycle, Simple profile (local lua_shared_dict store,
-- no Redis). A JIT-enabled service is dark; a valid grant admits. Grants are
-- created in M1 via the authenticated internal API (api() below) — the
-- challenge/respond knock protocol that issues registry-backed grants is M2
-- (marked TODO(M2)).
--
-- Fail-closed is the invariant (SECURITY-REVIEW C1 / DESIGN §11 R1): access()
-- wraps everything in its own pcall and denies on ANY internal error, rather
-- than relying on BunkerWeb's chain (which logs-and-continues -> fail open).
--
-- NOTE: not executed on the dev host (no Lua/BunkerWeb); validated by
-- test/harness. The portable core it embeds (canon/store) is vector-verified.

local class    = require "middleclass"
local plugin   = require "bunkerweb.plugin"
local utils    = require "bunkerweb.utils"
local cjson    = require "cjson.safe"

local ccanon    = require "jitaccess.core.canon"
local cstore    = require "jitaccess.core.store"
local cregistry = require "jitaccess.core.registry"

local jitaccess = class("jitaccess", plugin)

local MARKER = "challenge; v=1"

local function deny_status()
  if utils.get_deny_status then
    local ok, s = pcall(utils.get_deny_status)
    if ok and s then return s end
  end
  return ngx.HTTP_FORBIDDEN
end

function jitaccess:initialize(ctx)
  plugin.initialize(self, "jitaccess", ctx)
  local grants, nonces = ngx.shared.jit_grants, ngx.shared.jit_nonces
  if grants and nonces then
    self.store = cstore.new({ grants = grants, nonces = nonces })
  end
  -- M1 grants are admin/manual (break-glass), so an empty registry is fine.
  -- TODO(M2): load the materialized registry.json + per-service allow-lists,
  -- and keep an ephemeral per-instance nonce_key for the knock protocol.
  self.registry = cregistry.new({}, {})
end

-- record a metric without ever letting a metric error affect the gate decision
function jitaccess:metric(kind, key, val)
  if self.set_metric then pcall(self.set_metric, self, kind, key, val) end
end

function jitaccess:server_name_canon()
  local sn = (ngx.ctx.bw and ngx.ctx.bw.server_name) or ngx.var.server_name
  if not sn or sn == "" then return nil end
  return ccanon.canon_server_name(sn)
end

function jitaccess:client_ip_canon()
  -- Simple mode: the TCP peer. Trusting X-Forwarded-* is Hardened only and
  -- requires an explicit trusted-proxy real-IP config (SECURITY-REVIEW R2).
  local ip = (ngx.ctx.bw and ngx.ctx.bw.remote_addr) or ngx.var.remote_addr
  if not ip or ip == "" then return nil end
  local prefix = tonumber((self.variables and self.variables["JIT_ACCESS_IPV6_PREFIX"]) or "128") or 128
  return ccanon.canon_ip(ip, prefix)   -- nil on unparseable -> caller denies
end

function jitaccess:cookie_hash()
  -- HARDENED (M6): read + hash the opaque grant-id cookie. M1 = ip binding.
  return nil
end

-- set phase: default the CRS-visible flag (mirrors whitelist:set()).
function jitaccess:set()
  pcall(function()
    ngx.var.is_jit_allowed = "no"
    if ngx.ctx.bw then ngx.ctx.bw.is_jit_allowed = "no" end
  end)
  return self:ret(true, "jit set")
end

function jitaccess:deny(reason)
  local mode = (self.variables and self.variables["JIT_ACCESS_FAILURE_MODE"]) or "interstitial"
  if mode == "stealth" then
    return self:ret(true, reason .. " (stealth 404)", ngx.HTTP_NOT_FOUND)
  end
  pcall(function()
    ngx.header["X-JIT-Access"] = MARKER          -- extension detection hook
    ngx.header["Cache-Control"] = "no-store"
  end)
  return self:ret(true, reason .. " (interstitial)", deny_status())
end

-- fail-closed wrapper: any error -> explicit deny, never fall through to allow.
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
    return self:ret(true, "jit disabled")            -- chain continues normally
  end
  if not self.store then
    return self:ret(true, "jit store unavailable (deny)", deny_status())  -- fail closed
  end

  local sname = self:server_name_canon()
  local ip = self:client_ip_canon()
  if not sname or not ip then
    return self:deny("jit missing/invalid server_name or ip")
  end

  -- Protocol endpoints are served BEFORE the grant check (a knocker is not yet
  -- granted). TODO(M2): implement /challenge, /respond, /enroll here. Until then
  -- they must NEVER pass through to the upstream — deny like anything else.
  local prefix = v["JIT_ACCESS_URI_PREFIX"] or "/.well-known/jit-access"
  local uri = ngx.var.uri or ""
  if uri == prefix or uri:sub(1, #prefix + 1) == prefix .. "/" then
    return self:deny("jit protocol endpoint not implemented (M2)")
  end

  local now = ngx.time()
  local rec = self.store:is_allowed(sname, ip, self.registry, now, self:cookie_hash())
  if rec then
    pcall(function()
      ngx.var.is_jit_allowed = "yes"
      if ngx.ctx.bw then ngx.ctx.bw.is_jit_allowed = "yes" end
    end)
    self:metric("counters", "jit_granted", 1)
    if v["JIT_ACCESS_SKIP_CHECKS"] == "yes" then
      return self:ret(true, "jit granted (skip checks)", ngx.OK)   -- short-circuit chain
    end
    return self:ret(true, "jit granted")                            -- chain continues (WAF still runs)
  end

  self:metric("counters", "jit_denied", 1)
  return self:deny("jit no grant")
end

-- ---- internal API (management) ---------------------------------------------
-- Dispatched by api:do_api_call() on the already-authenticated internal API
-- vhost (API_WHITELIST_IP / API_TOKEN). Mirrors /ban, /unban.
function jitaccess:api()
  local uri = ngx.var.uri or ""
  if uri:sub(1, 11) ~= "/jitaccess/" then
    return self:ret(false, "not a jitaccess endpoint")   -- let other handlers try
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

  local function parse_target()
    local service = body.service and ccanon.canon_server_name(body.service)
    local ip = body.ip and ccanon.canon_ip(body.ip, tonumber(body.ipv6_prefix) or 128)
    return service, ip
  end

  if method == "POST" and uri == "/jitaccess/grant" then
    local service, ip = parse_target()
    local ttl = tonumber(body.ttl) or 3600
    if not service or not ip then
      return self:ret(true, "service and valid ip required", ngx.HTTP_BAD_REQUEST)
    end
    local rec = cstore.record(service, ip, body.kid or "__manual__", ttl,
                              { manual = true, binding = body.binding or "ip" })
    local ok, err = self.store:put_grant(service, ip, rec, ttl)
    if not ok then
      return self:ret(true, "grant failed: " .. tostring(err), ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return self:ret(true, cjson.encode({ granted = true, service = service, ip = ip, ttl = ttl, exp = rec.exp }), ngx.HTTP_OK)
  end

  if method == "POST" and uri == "/jitaccess/revoke" then
    local service, ip = parse_target()
    if not service or not ip then
      return self:ret(true, "service and valid ip required", ngx.HTTP_BAD_REQUEST)
    end
    self.store:del_grant(service, ip)
    return self:ret(true, cjson.encode({ revoked = true, service = service, ip = ip }), ngx.HTTP_OK)
  end

  if method == "POST" and uri == "/jitaccess/revoke-token" then
    if not body.kid then return self:ret(true, "kid required", ngx.HTTP_BAD_REQUEST) end
    local n = self.store:revoke_token(body.kid)
    return self:ret(true, cjson.encode({ revoked_token = body.kid, grants_removed = n }), ngx.HTTP_OK)
  end

  return self:ret(true, "unknown jitaccess endpoint", ngx.HTTP_NOT_FOUND)
end

return jitaccess
