-- JIT Network Access - Copyright (C) 2026 Slopapalooza
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- jitaccess.core.registry — TokenRegistry (core/SPEC.md §3)
--
-- Pure over its input. The adapter parses backend config (BunkerWeb settings /
-- Authorizer file) into the two tables below and hands them in; this module
-- only answers lookups. Keeping it pure means no I/O on the request path and
-- trivial testability.
--
--   tokens[kid]            = { secret = <raw bytes>, alg = "HMAC-SHA256",
--                             expires = <unix|nil> }
--   services[sname_canon]  = { ["*"] = true }  -- any registered kid
--                          or { [kid] = true, ... }  -- explicit allow-list

local _M = { _VERSION = "0.1.0" }
local methods = {}
local mt = { __index = methods }

function _M.new(tokens, services)
  return setmetatable({ tokens = tokens or {}, services = services or {} }, mt)
end

function methods:lookup(kid)
  return self.tokens[kid]
end

-- expires == nil OR 0 means "never expires". Go encodes the sentinel as 0
-- (`Expires int64 // unix seconds; 0 = never`) and the adapter loaders pass
-- whatever the config held, so a token written with 0 was treated as
-- ALREADY EXPIRED here and permanently denied — the same registry admitting the
-- device on a Go engine and locking it out on a Lua one.
function methods:is_expired(token, now)
  if token == nil or token.expires == nil or token.expires == 0 then return false end
  return now >= token.expires
end

-- Which key holds the allow-list for this service?
--
-- Two registry shapes exist. A MULTI-SERVICE registry (BunkerWeb, OpenResty,
-- the Go Authorizer) keys allow-lists by canonical server name. A SITE-SCOPED
-- one (the Caddy/Traefik adapters) is built per site and stores a single
-- allow-list under "*". Resolving it here lets store:is_allowed re-check the
-- allow-list without knowing which shape it was handed. Mirrors allowKey() in
-- core/go/registry.go.
function methods:allow_key(sname_canon)
  if self.services[sname_canon] then return sname_canon end
  if self.services["*"] then
    local n = 0
    for _ in pairs(self.services) do n = n + 1 end
    if n == 1 then return "*" end
  end
  return sname_canon
end

-- Is this kid permitted to open this (already-canonical) service?
function methods:allowed_for_service(kid, sname_canon)
  local svc = self.services[self:allow_key(sname_canon)]
  if not svc then return false end
  if svc["*"] then return true end
  return svc[kid] == true
end

-- Convenience: full policy check for a knock (kid known, service allowed, not expired).
-- Returns token|nil. Callers still verify the proof separately.
function methods:authorize(kid, sname_canon, now)
  local token = self.tokens[kid]
  if not token then return nil, "unknown kid" end
  if self:is_expired(token, now) then return nil, "token expired" end
  if not self:allowed_for_service(kid, sname_canon) then return nil, "kid not allowed for service" end
  return token
end

return _M
