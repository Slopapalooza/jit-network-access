-- jitaccess.core.pae — Pre-Authentication Encoding (PASETO-compatible)
--
-- LE64(n)    = 8-byte little-endian of n, top bit of the last byte cleared
-- PAE(parts) = LE64(#parts) .. for each p: LE64(#p) .. p
--
-- Makes a list of variable-length byte strings injective, so no two distinct
-- field lists collide inside an HMAC (SECURITY-REVIEW H1). See core/SPEC.md §2,
-- docs/PROTOCOL.md §5.1. Pinned by core/testdata/vectors.json ("pae").
--
-- NOTE: not executed on the dev host (no Lua runtime); validated against the
-- shared vectors by the docker harness. Pure module — no ngx/resty deps.

local concat = table.concat
local char = string.char
local floor = math.floor

local _M = { _VERSION = "0.1.0" }

-- 8-byte little-endian, high bit of the final byte cleared (PASETO PAE).
-- Lengths here are tiny; the div/mod loop avoids any 32/64-bit bitop width traps.
local function le64(n)
  local b = {}
  for i = 1, 8 do
    b[i] = char(n % 256)
    n = floor(n / 256)
  end
  -- clear the top bit of the last byte without needing the bit library
  b[8] = char(string.byte(b[8]) % 128)
  return concat(b)
end
_M.le64 = le64

-- parts: array-like table of byte strings
function _M.encode(parts)
  local out = { le64(#parts) }
  local j = 1
  for i = 1, #parts do
    local p = parts[i]
    j = j + 1; out[j] = le64(#p)
    j = j + 1; out[j] = p
  end
  return concat(out)
end

return _M
