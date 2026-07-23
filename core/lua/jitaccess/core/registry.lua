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

function methods:is_expired(token, now)
  return token ~= nil and token.expires ~= nil and now >= token.expires
end

-- Is this kid permitted to open this (already-canonical) service?
function methods:allowed_for_service(kid, sname_canon)
  local svc = self.services[sname_canon]
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
