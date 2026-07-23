-- jitaccess.lua — BunkerWeb plugin main (adapter L4).
--
-- STATUS: M0 skeleton. Wires the portable core (jitaccess.core.*) and the
-- BunkerWeb plugin base class, and establishes the FAIL-CLOSED access wrapper.
-- The full challenge/respond/grant-check protocol lands in M1 — every spot that
-- needs it is marked TODO(M1). Until then, enabling the plugin denies (safe):
-- a service with USE_JIT_ACCESS=yes is dark, never accidentally open.
--
-- Design: DESIGN.md §5.3 · fail-closed rationale: SECURITY-REVIEW C1 / §11 R1.

local class  = require "middleclass"
local plugin = require "bunkerweb.plugin"
local utils  = require "bunkerweb.utils"

-- portable core (vendored into ./core by build-vendor.sh)
local ccrypto  = require "jitaccess.core.crypto"
local ccanon   = require "jitaccess.core.canon"
local cstore   = require "jitaccess.core.store"
local cregistry= require "jitaccess.core.registry"

local jitaccess = class("jitaccess", plugin)

local DENY_STATUS = utils.get_deny_status and utils.get_deny_status() or 403

function jitaccess:initialize(ctx)
  plugin.initialize(self, "jitaccess", ctx)
  -- store over the process-local dicts (Simple mode; no Redis).
  -- Guarded so a missing dict never throws on the request path.
  local grants = ngx.shared.jit_grants
  local nonces = ngx.shared.jit_nonces
  if grants and nonces then
    self.store = cstore.new({ grants = grants, nonces = nonces })
  end
  -- TODO(M1): build the TokenRegistry from JIT_ACCESS_TOKEN_* (materialized by
  -- the jitaccess-registry job into internalstore) and the per-service
  -- JIT_ACCESS_TOKENS allow-lists; keep an ephemeral per-instance nonce_key.
  self.registry = cregistry.new({}, {})
end

-- set phase: default the CRS-visible flag. Mirrors whitelist:set().
function jitaccess:set()
  ngx.var.is_jit_allowed = "no"
  if self.ctx and self.ctx.bw then self.ctx.bw.is_jit_allowed = "no" end
  return self:ret(true, "jit set")
end

-- The fail-closed wrapper. BunkerWeb's chain would let a thrown error fall
-- through to "allow" (verified — SECURITY-REVIEW C1); we never rely on that.
-- Any error inside _access -> explicit deny.
function jitaccess:access()
  local ok, res = pcall(function() return self:_access() end)
  if not ok then
    self.logger:log(ngx.ERR, "jitaccess access() error (failing closed): " .. tostring(res))
    return self:ret(true, "jit internal error (deny)", DENY_STATUS)
  end
  return res
end

function jitaccess:_access()
  local enabled = self.variables and self.variables["USE_JIT_ACCESS"] == "yes"
  if not enabled then
    return self:ret(true, "jit disabled")            -- chain continues normally
  end

  -- TODO(M1): the real protocol, in order:
  --   1. if URI under JIT_ACCESS_URI_PREFIX -> handle /challenge, /respond,
  --      /enroll (served BEFORE the grant check), equalized-work generic 404 on
  --      failure, knock endpoints excluded from badbehavior.
  --   2. grant check: ip from the trusted real-IP source only; store:is_allowed
  --      with registry re-check; set $is_jit_allowed on success.
  --   3. not allowed -> interstitial (403 + X-JIT-Access marker) or stealth 404.
  -- Until M1 lands, a JIT-enabled service is intentionally dark:
  local mode = (self.variables and self.variables["JIT_ACCESS_FAILURE_MODE"]) or "interstitial"
  if mode == "stealth" then
    return self:ret(true, "jit not yet implemented (stealth deny)", ngx.HTTP_NOT_FOUND)
  end
  return self:ret(true, "jit not yet implemented (deny)", DENY_STATUS)
end

return jitaccess
