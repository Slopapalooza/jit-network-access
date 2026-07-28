-- JIT Network Access - Copyright (C) 2026 Slopapalooza
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- jitaccess.openresty — native OpenResty gate (L4 adapter).
--
-- The same portable core (core/lua/jitaccess/core) the BunkerWeb plugin runs,
-- wired directly into an OpenResty access phase. In-process, so it reads the
-- un-forgeable TCP peer and needs no sidecar, no Redis, no database.
--
--   init_by_lua_block   { require("jitaccess.openresty").init({...}) }
--   access_by_lua_block { require("jitaccess.openresty").access()   }
--
-- Requires two shared dicts (see conf/jitaccess.conf):
--   lua_shared_dict jit_grants 16m;
--   lua_shared_dict jit_nonces 16m;
--
-- NOT executed on the dev host (no OpenResty). Syntax is checked against the
-- Lua 5.1 grammar and the crypto core it calls is vector-verified in three
-- languages; treat the wiring as reviewed-but-unrun until you exercise it.

local ccanon    = require "jitaccess.core.canon"
local ccrypto   = require "jitaccess.core.crypto"
local cstore    = require "jitaccess.core.store"
local cregistry = require "jitaccess.core.registry"
local cpages    = require "jitaccess.core.pages"
local cjson     = require "cjson.safe"

local _M = { _VERSION = "0.1.0" }

local MARKER       = "challenge; v=1"
local DUMMY_KEY    = string.rep("\0", 32)
local GRANT_COOKIE = "__Host-jit-grant"

local cfg, registry, store, nonce_key

-- ---- init ------------------------------------------------------------------

-- opts = {
--   uri_prefix   = "/.well-known/jit-access",
--   grant_ttl    = 3600, nonce_ttl = 60, enroll_ttl = 86400,
--   ipv6_prefix  = 128,  rate_limit = 10,
--   trust_forwarded = false,       -- key on X-Forwarded-For instead of the peer
--   tokens   = { { kid=, secret=<b64url>, label=, expires= }, ... },
--   services = { ["app.example.com"] = { tokens={"kid_a"} | {"*"},
--                                        binding="ip"|"ip+cookie",
--                                        failure_mode="interstitial"|"stealth",
--                                        grant_ttl= }, ... },
-- }
function _M.init(opts)
  opts = opts or {}
  cfg = {
    uri_prefix      = "/" .. tostring(opts.uri_prefix or "/.well-known/jit-access"):gsub("^/+", ""):gsub("/+$", ""),
    grant_ttl       = tonumber(opts.grant_ttl) or 3600,
    nonce_ttl       = tonumber(opts.nonce_ttl) or 60,
    enroll_ttl      = tonumber(opts.enroll_ttl) or 86400,
    -- Clamped: canon_ip rejects an out-of-range prefix, so an unclamped typo
    -- would deny every IPv6 client site-wide rather than degrade to /128.
    ipv6_prefix     = (function()
      local n = tonumber(opts.ipv6_prefix) or 128
      if n < 0 or n > 128 then
        ngx.log(ngx.WARN, "jitaccess: ipv6_prefix ", tostring(n), " out of range, using 128")
        return 128
      end
      return n
    end)(),
    rate_limit      = tonumber(opts.rate_limit) or 10,
    trust_forwarded = opts.trust_forwarded == true,
    services        = {},
  }

  local tokens = {}
  for _, t in ipairs(opts.tokens or {}) do
    local secret = t.secret and ccrypto.b64u_decode(t.secret)
    if not secret or #secret < 16 then
      error("jitaccess: token " .. tostring(t.kid) .. ": secret must be base64url of >= 16 bytes")
    end
    tokens[t.kid] = { secret = secret, alg = "HMAC-SHA256", label = t.label, expires = t.expires }
  end

  local services = {}
  for name, svc in pairs(opts.services or {}) do
    local canon = ccanon.canon_server_name(name)
    local allow = {}
    for _, kid in ipairs(svc.tokens or {}) do allow[kid] = true end
    services[canon] = allow
    cfg.services[canon] = {
      binding      = svc.binding or "ip",
      failure_mode = svc.failure_mode or "interstitial",
      grant_ttl    = tonumber(svc.grant_ttl) or cfg.grant_ttl,
    }
  end

  registry = cregistry.new(tokens, services)

  local grants, nonces = ngx.shared.jit_grants, ngx.shared.jit_nonces
  if not grants or not nonces then
    error("jitaccess: missing shared dicts — declare 'lua_shared_dict jit_grants 16m;' and 'lua_shared_dict jit_nonces 16m;'")
  end
  store = cstore.new({ grants = grants, nonces = nonces, rl = ngx.shared.jit_rl })

  -- Ephemeral, per-process. Nonces live ~60s, so nothing needs to survive a
  -- restart, and no key material touches disk.
  nonce_key = ccrypto.random_bytes(32)
  if not nonce_key then error("jitaccess: RNG failed for the nonce key") end

  local n = 0
  for _ in pairs(tokens) do n = n + 1 end
  ngx.log(ngx.NOTICE, "jitaccess: initialized with ", n, " token(s)")
  return true
end

-- ---- request helpers -------------------------------------------------------

-- The service name decides the allow-list, binding, grant_ttl and failure_mode,
-- so it must not be something the client can set.
--
-- $host is the request-line host / Host header — client-controlled. $server_name
-- is the name nginx MATCHED from the config, which no header can move. Prefer
-- the latter, exactly as the BunkerWeb sibling does.
--
-- $host is still consulted when the matched block has no usable server_name
-- (e.g. `server_name _;`), but only if it names a CONFIGURED service — otherwise
-- a mismatched Host on a default_server used to fall through to deny(nil), which
-- renders the INTERSTITIAL regardless of the service's failure_mode, announcing a
-- gate the operator configured to be invisible.
local function service_name()
  local sn = ngx.var.server_name
  if sn and sn ~= "" and sn ~= "_" then
    return ccanon.canon_server_name(sn)
  end
  local h = ngx.var.host
  if not h or h == "" then return nil end
  local canon = ccanon.canon_server_name(h)
  if canon and cfg and cfg.services[canon] then return canon end
  return nil
end

-- Grants key on the TCP peer by default: a request header cannot move it
-- (SECURITY-REVIEW C2/R2). trust_forwarded is only safe behind a proxy whose
-- realip config is correctly narrowed.
local function client_ip()
  local ip
  if cfg.trust_forwarded then
    ip = ngx.var.remote_addr
  else
    ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
  end
  if not ip or ip == "" then return nil end
  return ccanon.canon_ip(ip, cfg.ipv6_prefix)
end

local function grant_cookie()
  local header = ngx.var.http_cookie
  if not header or header == "" then return nil end
  for pair in header:gmatch("[^;]+") do
    local k, v = pair:match("^%s*([^=%s]+)%s*=%s*(.-)%s*$")
    if k == GRANT_COOKIE and v ~= "" then return v end
  end
  return nil
end

local function cookie_hash()
  local v = grant_cookie()
  if not v then return nil end
  return ccrypto.sha256_hex(v)
end

-- Per-IP fixed-window counter for the knock endpoints.
--
-- A rejection returns the SAME generic response as any other failure (PROTOCOL
-- §6). Answering 429 here was an endpoint-discovery oracle: in stealth mode the
-- protocol paths replied 429 while every other path replied 404.
local function rate_ok(ip)
  if not cfg.rate_limit or cfg.rate_limit <= 0 then return true end
  local n = store.rl:incr("rl:" .. ip, 1, 0, 60)
  -- incr fails when the dict is full or errors. Failing OPEN there means an
  -- attacker who fills the dict also switches the throttle off, so deny instead.
  if not n then return false end
  return n <= cfg.rate_limit
end

-- interstitial = 403 + detection marker; stealth = bare 404.
-- default_failure_mode is what deny() uses when there is no service to consult
-- (unknown host, uninitialised gate). It defaults to the STRICTER of the modes
-- configured, so a deployment that asked for stealth anywhere never answers an
-- unknown host with the branded interstitial + X-JIT-Access marker.
local function default_failure_mode()
  if not cfg or not cfg.services then return "interstitial" end
  for _, svc in pairs(cfg.services) do
    if svc.failure_mode == "stealth" then return "stealth" end
  end
  return "interstitial"
end

local function deny(svc)
  local mode = (svc and svc.failure_mode) or default_failure_mode()
  if mode == "stealth" then
    -- No Cache-Control: nginx's own 404 does not carry one, and stealth mode is
    -- only stealthy if the response is indistinguishable from an unrouted path.
    return ngx.exit(ngx.HTTP_NOT_FOUND)
  end
  ngx.header["Cache-Control"] = "no-store"
  ngx.header["X-JIT-Access"] = MARKER
  ngx.header["Content-Type"] = "text/html; charset=utf-8"
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.say([[<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device authorization required</title>
<style>body{font:15px/1.6 system-ui,sans-serif;color:#24313f;background:#f4f6f8;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border:1px solid #e2e7ec;border-radius:10px;padding:2rem;max-width:30rem;margin:1rem}
h1{font-size:1.2rem;margin:0 0 .6rem}p{margin:.5rem 0 0;color:#67727e}</style></head><body>
<div class="card"><h1>Device authorization required</h1>
<p>This service is restricted to enrolled devices. If your device is enrolled,
authorization happens automatically &mdash; reload the page.</p>
<p>Otherwise contact your administrator to enroll this device.</p></div></body></html>]])
  return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function read_json_body()
  ngx.req.read_body()
  local data = ngx.req.get_body_data()
  if not data then return {} end
  local body = cjson.decode(data)
  if type(body) ~= "table" then return {} end
  return body
end

-- ---- protocol endpoints ----------------------------------------------------

local function challenge(sname, ip, svc)
  if not rate_ok(ip) then return deny(svc) end   -- generic response, never a distinguishable 429
  local rand = ccrypto.random_bytes(16)
  if not rand then return deny(svc) end
  local ts = ngx.time()
  local nonce = ccrypto.issue_nonce(nonce_key, ts, rand, sname, ip, cfg.ipv6_prefix)
  if not nonce then return deny(svc) end
  ngx.header["X-JIT-Nonce"] = ccrypto.b64u_encode(nonce)
  ngx.header["X-JIT-TS"] = tostring(ts)
  ngx.header["Cache-Control"] = "no-store"
  return ngx.exit(ngx.HTTP_NO_CONTENT)
end

local function respond(sname, ip, svc)
  if not rate_ok(ip) then return deny(svc) end   -- generic response, never a distinguishable 429
  local body = read_json_body()

  local nonce = type(body.nonce) == "string" and ccrypto.b64u_decode(body.nonce) or nil
  local proof = type(body.proof) == "string" and ccrypto.b64u_decode(body.proof) or nil
  local kid   = type(body.kid) == "string" and body.kid or ""
  local now   = ngx.time()

  local nok, rand = false, nil
  if nonce then
    nok, rand = ccrypto.verify_nonce(nonce_key, nonce, sname, ip, now, cfg.nonce_ttl, cfg.ipv6_prefix)
  end

  -- Equalized work: always compute exactly one HMAC, with a dummy key when the
  -- kid is unknown, so failures are indistinguishable (PROTOCOL §6).
  local token = registry:authorize(kid, sname, now)
  local secret = (token and token.secret) or DUMMY_KEY
  local proof_ok = false
  if nonce and proof and #proof == 32 then
    proof_ok = ccrypto.verify_proof(secret, sname, kid, nonce, proof)
  end
  if not (nok and token and proof_ok) then return deny(svc) end

  -- verify-then-burn: a bad proof never consumes a nonce
  if not store:nonce_claim(ccrypto.b64u_encode(rand), cfg.nonce_ttl) then return deny(svc) end

  local ttl = svc.grant_ttl
  local ch
  if svc.binding == "ip+cookie" then
    local raw = ccrypto.random_bytes(32)
    if not raw then return deny(svc) end          -- fail closed, never downgrade to ip-only
    local id = ccrypto.b64u_encode(raw)
    ch = ccrypto.sha256_hex(id)
    ngx.header["Set-Cookie"] = GRANT_COOKIE .. "=" .. id ..
      "; Path=/; Max-Age=" .. tostring(ttl) .. "; Secure; HttpOnly; SameSite=Strict"
  end

  local rec = cstore.record(sname, ip, kid, ttl, { binding = svc.binding, cookie_hash = ch })
  if store:put_grant(sname, ip, rec, ttl) ~= true then return deny(svc) end

  ngx.header["Cache-Control"] = "no-store"
  return ngx.exit(ngx.HTTP_NO_CONTENT)
end

local function enroll(sname, ip, svc)
  if not rate_ok(ip) then return deny(svc) end   -- generic response, never a distinguishable 429
  local body = read_json_body()
  if type(body.code) ~= "string" or body.code == "" then return deny(svc) end
  -- Validate BEFORE burning: consume is single-use, so checking the kid
  -- afterwards let any hostile POST destroy a valid enrollment code.
  local peek = store:enroll_code_peek(body.code)
  if not peek or not registry:lookup(peek.kid) then return deny(svc) end
  local rec = store:enroll_code_consume(body.code)          -- single-use
  if not rec then return deny(svc) end
  local token = registry:lookup(rec.kid)
  if not token then return deny(svc) end
  ngx.header["X-JIT-Kid"] = rec.kid
  ngx.header["X-JIT-Secret"] = ccrypto.b64u_encode(token.secret)
  ngx.header["X-JIT-Alg"] = token.alg or "HMAC-SHA256"
  ngx.header["X-JIT-Origins"] = table.concat(rec.origins or {}, ",")
  ngx.header["Cache-Control"] = "no-store"
  return ngx.exit(ngx.HTTP_NO_CONTENT)
end

-- ---- the gate --------------------------------------------------------------

local function _access()
  -- init() never ran (the init_by_lua_block include is missing, or it errored,
  -- or this is a different http block). A bare `return` here would fall through
  -- to the upstream, i.e. every request served UNGATED and silently — the exact
  -- fail-open SPEC §7.1 forbids. The pcall wrapper below cannot catch this
  -- because nothing is thrown, so the deny has to be explicit.
  if not cfg or not store then
    ngx.log(ngx.ERR, "jitaccess: not initialized (missing init_by_lua_block?) — failing closed")
    return deny(nil)
  end
  local sname = service_name()
  local ip = client_ip()
  if not sname or not ip then return deny(nil) end

  local svc = cfg.services[sname]
  if not svc then return deny(nil) end               -- unconfigured service: opt in explicitly

  local prefix = cfg.uri_prefix
  local uri = ngx.var.uri or ""
  if uri == prefix or uri:sub(1, #prefix + 1) == prefix .. "/" then
    local method = ngx.req.get_method()
    if uri == prefix .. "/challenge" and method == "GET"  then return challenge(sname, ip, svc) end
    if uri == prefix .. "/respond"   and method == "POST" then return respond(sname, ip, svc) end
    if uri == prefix .. "/enroll"    and method == "POST" then return enroll(sname, ip, svc) end
    if uri == prefix .. "/register"  and method == "GET"  then
      -- Only a browser WITHOUT the extension gets here; an installed one
      -- intercepts the navigation client-side. Identical for any code value, so
      -- it is no enrollment-code oracle.
      ngx.header["Content-Type"] = "text/html; charset=utf-8"
      ngx.header["Cache-Control"] = "no-store"
      ngx.header["Referrer-Policy"] = "no-referrer"   -- the URL carries a single-use code
      ngx.status = ngx.HTTP_OK
      ngx.say(cpages.REGISTER_HTML)
      return ngx.exit(ngx.HTTP_OK)
    end
    return deny(svc)                                  -- any other path under the prefix stays dark
  end

  if store:is_allowed(sname, ip, registry, ngx.time(), cookie_hash()) then
    return                                            -- admitted: fall through to the upstream
  end
  return deny(svc)
end

-- Fail closed on ANY internal error: an exception must never fall through to
-- "allow" (SPEC §7 / SECURITY-REVIEW C1).
function _M.access()
  local ok, err = pcall(_access)
  if not ok then
    ngx.log(ngx.ERR, "jitaccess: access() error (failing closed): ", tostring(err))
    return ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

-- Mint a single-use enrollment code (call from an admin location, or from
-- init_worker/timer tooling). Returns the code.
function _M.mint_enroll_code(kid, origins, ttl)
  if not store then return nil, "not initialized" end
  if not registry:lookup(kid) then return nil, "unknown kid" end
  local raw = ccrypto.random_bytes(12)
  if not raw then return nil, "rng failed" end
  local code = ccrypto.b64u_encode(raw)
  local ok, err = store:enroll_code_put(code, { kid = kid, origins = origins or {} },
                                        tonumber(ttl) or cfg.enroll_ttl)
  if not ok then return nil, err end
  return code
end

return _M
