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

local sha256_hex = require("jitaccess.core.crypto").sha256_hex

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

-- Which secret does this token hold? Lowercase-hex SHA-256 of the raw bytes:
-- the same primitive as the cookie hash, and identical to Token.Fingerprint()
-- in core/go/registry.go. A grant records the fingerprint of the secret that
-- verified its knock and store:is_allowed re-checks it on every request, so
-- regenerating a secret in place (same kid, new bytes) evicts the old device's
-- grants exactly like deleting the kid does. Before this the re-check stopped
-- at "kid still registered", so the old device kept its grant for the full
-- grant TTL — and on BunkerWeb, where the new registry loads a minute after
-- the config is saved, could re-knock with the old secret in that window and
-- mint a grant that outlived the rotation. nil when there is no secret.
function _M.fingerprint(token)
  if type(token) ~= "table" or type(token.secret) ~= "string" then return nil end
  return sha256_hex(token.secret)
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
  -- SPEC §3 pins the algorithm per kid so a future second algorithm can never
  -- be negotiated down. Every loader wrote the field and nothing read it, so
  -- the pin was decorative; enforced here and in store:is_allowed.
  if token.alg ~= "HMAC-SHA256" then return nil, "token algorithm is not the pinned one" end
  if self:is_expired(token, now) then return nil, "token expired" end
  if not self:allowed_for_service(kid, sname_canon) then return nil, "kid not allowed for service" end
  return token
end

return _M
