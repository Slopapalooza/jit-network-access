-- JIT Network Access - Copyright (C) 2026 Slopapalooza
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- jitaccess.core.canon — normative canonicalization (docs/PROTOCOL.md §4)
--
-- canon_server_name(host)             -> string
-- canon_ip(addr, v6_prefix, v4_prefix) -> string | nil, err
--
-- These MUST produce byte-identical output to the Python/Go references so that
-- MAC inputs and grant keys match across engines (SECURITY-REVIEW H1/C10).
-- Pinned by core/testdata/vectors.json ("canon_server_name", "canon_ip").
--
-- NOTE: not executed on the dev host (no Lua runtime). The IPv6 algorithm here
-- was cross-checked against the vectors via an equivalent port before commit;
-- the harness re-validates it under real Lua. Pure module.

local floor = math.floor
local format = string.format

local _M = { _VERSION = "0.1.0" }

-- ---- server_name -----------------------------------------------------------

-- Trim whitespace and trailing dots to a fixpoint BEFORE the port strip as
-- well as after. Doing it only after meant removing a trailing dot could
-- expose a port that then survived to the next pass: "[:0." became "[:0"
-- became "[", and "example.com:443." became "example.com:443" became
-- "example.com". Two layers canonicalizing the same Host a different number
-- of times would hold two different names for one service.
local function trim_dots_and_space(s)
  while true do
    local t = s:gsub("^%s+", ""):gsub("%s+$", ""):gsub("%.$", "")
    if t == s then return s end
    s = t
  end
end

function _M.canon_server_name(host)
  host = trim_dots_and_space(host)

  -- A bracketed literal delimits its own host. The port strip below is guarded
  -- by colon count alone rather than by "was it bracketed": no valid IPv6
  -- address has exactly one colon, so the guard only ever protected malformed
  -- input like "[a:80]" - which then canonicalized to "a:80" and, on a second
  -- pass, to "a".
  -- The inner text is trimmed because the Python and Go references both strip
  -- it, so without it "[ ::1 ]" canonicalized to "::1" on three engines and
  -- " ::1 " here -- a different MAC input and grant key for the same client.
  -- [^%]]* not [^%]]+ : Go and Python treat [] as an empty bracketed host.
  local inner = host:match("^%[([^%]]*)%]")
  if inner then host = trim_dots_and_space(inner) end

  -- Strip a trailing :port - but ONLY when the host has exactly one colon.
  --
  -- An unbracketed host with several colons is an IPv6 literal: RFC 3986
  -- requires brackets to carry a port, so there is no port to strip. Stripping
  -- anyway truncated "2001:db8::1" to "2001:db8:" - and "2001:db8::2" to the
  -- SAME value, which is a cross-service collision in both the grant key and
  -- the MAC input, the exact class PAE framing exists to prevent. It also made
  -- the bracketed and unbracketed spellings of one host canonicalize
  -- differently, so a grant made via one would not match a request via the
  -- other.
  local _, ncolons = host:gsub(":", "")
  if ncolons == 1 then
    local h = host:match("^(.-):%d+$")
    if h then host = h end
  end
  return trim_dots_and_space(host):lower()
end

-- ---- ip --------------------------------------------------------------------

local canon_ipv4_nums  -- forward decl

local function canon_ipv4(addr, prefix)
  local o1, o2, o3, o4 = addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not o4 then return nil, "bad ipv4" end
  local octs = { o1, o2, o3, o4 }
  for i = 1, 4 do
    local s = octs[i]
    if #s > 1 and s:sub(1, 1) == "0" then return nil, "ipv4 leading zero" end
    if tonumber(s) > 255 then return nil, "ipv4 octet>255" end
  end
  return canon_ipv4_nums(tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4), prefix)
end

canon_ipv4_nums = function(o1, o2, o3, o4, prefix)
  if prefix < 32 then
    local n = ((o1 * 256 + o2) * 256 + o3) * 256 + o4
    local d = 2 ^ (32 - prefix)
    n = floor(n / d) * d
    o1 = floor(n / 16777216) % 256
    o2 = floor(n / 65536) % 256
    o3 = floor(n / 256) % 256
    o4 = n % 256
  end
  return o1 .. "." .. o2 .. "." .. o3 .. "." .. o4
end

-- expand an IPv6 string to exactly 8 numeric groups (or nil,err)
local function ipv6_groups(addr)
  addr = addr:lower()
  -- embedded IPv4 in the last 32 bits -> two hex groups
  if addr:find(".", 1, true) then
    local head, quad = addr:match("^(.*:)(%d+%.%d+%.%d+%.%d+)$")
    if not head then return nil, "bad v4-in-v6" end
    local qa, qb, qc, qd = quad:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not qd then return nil, "bad v4-in-v6" end
    -- Same leading-zero rejection as the plain IPv4 path. Go and Python reject
    -- "::ffff:01.2.3.4"; accepting it here meant one engine keyed a grant on an
    -- address the others refused outright.
    for _, o in ipairs({ qa, qb, qc, qd }) do
      if #o > 1 and o:sub(1, 1) == "0" then return nil, "v4-in-v6 leading zero" end
    end
    local a, b, c, d = tonumber(qa), tonumber(qb), tonumber(qc), tonumber(qd)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil, "bad v4-in-v6" end
    addr = head .. format("%x:%x", a * 256 + b, c * 256 + d)
  end

  local raw = {}
  local dbl = addr:find("::", 1, true)
  -- Exactly one "::" is legal. "1::2::3" is ambiguous and both Go (net/netip)
  -- and Python (ipaddress) reject it; accepting it here meant two engines
  -- disagreed about what address a grant was keyed on.
  if dbl and addr:find("::", dbl + 2, true) then return nil, "multiple ::" end
  -- Stray colons. These checks are UNCONDITIONAL: gating them on `not dbl` meant
  -- they never ran for any address containing "::", which is every case they
  -- were written to catch. gmatch("[^:]+") below silently drops the extra
  -- colons, so ":::" , ":1::2" and "1::2:" all reached the 8-group count and
  -- were accepted — while Go, Python and the shipped vectors all reject them.
  if addr:find(":::", 1, true) then return nil, "colon run" end
  if addr:sub(1, 1) == ":" and addr:sub(1, 2) ~= "::" then return nil, "stray colon" end
  if addr:sub(-1) == ":" and addr:sub(-2) ~= "::" then return nil, "stray colon" end
  if dbl then
    local left, right = addr:sub(1, dbl - 1), addr:sub(dbl + 2)
    local lg, rg = {}, {}
    if left ~= "" then for g in left:gmatch("[^:]+") do lg[#lg + 1] = g end end
    if right ~= "" then for g in right:gmatch("[^:]+") do rg[#rg + 1] = g end end
    local missing = 8 - (#lg + #rg)
    if missing < 1 then return nil, "bad ::" end
    for _, g in ipairs(lg) do raw[#raw + 1] = g end
    for _ = 1, missing do raw[#raw + 1] = "0" end
    for _, g in ipairs(rg) do raw[#raw + 1] = g end
  else
    for g in addr:gmatch("[^:]+") do raw[#raw + 1] = g end
  end

  if #raw ~= 8 then return nil, "ipv6 needs 8 groups" end
  local nums = {}
  for i = 1, 8 do
    local g = raw[i]
    if not g:match("^%x%x?%x?%x?$") then return nil, "bad ipv6 group" end
    nums[i] = tonumber(g, 16)
  end
  return nums
end

-- RFC 5952 compression of 8 uint16 groups
local function compress(nums)
  local best_start, best_len = 0, 0
  local i = 1
  while i <= 8 do
    if nums[i] == 0 then
      local j = i
      while j <= 8 and nums[j] == 0 do j = j + 1 end
      local len = j - i
      if len > best_len then best_start, best_len = i, len end
      i = j
    else
      i = i + 1
    end
  end
  local parts = {}
  for k = 1, 8 do parts[k] = format("%x", nums[k]) end
  if best_len >= 2 then
    local left, right = {}, {}
    for k = 1, best_start - 1 do left[#left + 1] = parts[k] end
    for k = best_start + best_len, 8 do right[#right + 1] = parts[k] end
    return table.concat(left, ":") .. "::" .. table.concat(right, ":")
  end
  return table.concat(parts, ":")
end

local function canon_ipv6(addr, prefix, v4_prefix)
  local nums, err = ipv6_groups(addr)
  if not nums then return nil, err end
  -- IPv4-mapped (::ffff:a.b.c.d) normalizes to IPv4 (match Python ipv4_mapped).
  -- The result is an IPv4 address, so the IPv4 prefix applies to it — passing a
  -- hard-coded 32 here meant a dual-stack client reaching a v4_prefix-masked
  -- deployment got a DIFFERENT grant key than the same client over plain IPv4.
  if nums[1] == 0 and nums[2] == 0 and nums[3] == 0 and nums[4] == 0
     and nums[5] == 0 and nums[6] == 0xffff then
    return canon_ipv4_nums(floor(nums[7] / 256), nums[7] % 256,
                           floor(nums[8] / 256), nums[8] % 256, v4_prefix)
  end
  if prefix < 128 then
    for i = 1, 8 do
      local lo = (i - 1) * 16
      if prefix >= i * 16 then          -- keep whole group
      elseif prefix <= lo then
        nums[i] = 0
      else
        local shift = 2 ^ (16 - (prefix - lo))
        nums[i] = floor(nums[i] / shift) * shift
      end
    end
  end
  return compress(nums)
end

function _M.canon_ip(addr, v6_prefix, v4_prefix)
  if type(addr) ~= "string" or addr == "" then return nil, "empty address" end
  v6_prefix = v6_prefix or 128
  v4_prefix = v4_prefix or 32
  -- Go errors on a negative prefix rather than masking with it; match that
  -- instead of silently collapsing every client onto "::" or "0.0.0.0".
  if v6_prefix < 0 or v6_prefix > 128 then return nil, "bad v6 prefix" end
  if v4_prefix < 0 or v4_prefix > 32 then return nil, "bad v4 prefix" end
  if addr:find(":", 1, true) then
    return canon_ipv6(addr, v6_prefix, v4_prefix)
  end
  return canon_ipv4(addr, v4_prefix)
end

return _M
