"""Line-for-line transliteration of canon.lua (canon_ip + canon_server_name).

    python3 core/lua/canon_port_check.py core/testdata/vectors.json

WHY THIS EXISTS: this project is developed on hosts without a Lua runtime, so
`core/lua/test_vectors.lua` can only be run on a real OpenResty box. That gap is
not theoretical — a colon-strictness check in canon.lua was once gated so that it
never ran for any address containing "::", which left the Lua core failing three
of its OWN shipped vectors, and nothing on the dev host noticed.

This port is a stand-in for that missing runtime: same order of checks, same
string operations, so a divergence here means a divergence there. It is NOT a
replacement for running test_vectors.lua under real Lua — string semantics,
integer/float behavior and the `bit` library are not modeled — but it catches
the logic errors, which is where the failures have actually come from.

Keep it in step with canon.lua when either changes.

canon_server_name is modeled at the BYTE level on purpose: Lua strings are
byte strings, %s and %d are ASCII-only, and string.lower() is C tolower() in
the C locale. Python's str equivalents are all Unicode-aware, so a str-level
port would hide exactly the divergences it exists to find.
"""
import json
import pathlib
import re
import sys


def canon_ipv4_nums(o1, o2, o3, o4, prefix):
    if prefix < 32:
        n = ((o1 * 256 + o2) * 256 + o3) * 256 + o4
        d = 2 ** (32 - prefix)
        n = (n // d) * d
        o1 = (n // 16777216) % 256
        o2 = (n // 65536) % 256
        o3 = (n // 256) % 256
        o4 = n % 256
    return f"{o1}.{o2}.{o3}.{o4}"


def canon_ipv4(addr, prefix):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", addr)
    if not m:
        return None, "bad ipv4"
    octs = list(m.groups())
    for o in octs:
        if len(o) > 1 and o[0] == "0":
            return None, "ipv4 leading zero"
        if int(o) > 255:
            return None, "ipv4 octet>255"
    return canon_ipv4_nums(*(int(o) for o in octs), prefix), None


def ipv6_groups(addr):
    addr = addr.lower()
    if "." in addr:
        m = re.fullmatch(r"(.*:)(\d+\.\d+\.\d+\.\d+)", addr)
        if not m:
            return None, "bad v4-in-v6"
        head, quad = m.groups()
        qm = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", quad)
        if not qm:
            return None, "bad v4-in-v6"
        for o in qm.groups():
            if len(o) > 1 and o[0] == "0":
                return None, "v4-in-v6 leading zero"
        a, b, c, d = (int(x) for x in qm.groups())
        if a > 255 or b > 255 or c > 255 or d > 255:
            return None, "bad v4-in-v6"
        addr = head + f"{a * 256 + b:x}:{c * 256 + d:x}"

    raw = []
    dbl = addr.find("::")
    dbl = None if dbl == -1 else dbl + 1          # lua find() is 1-based
    if dbl is not None and addr.find("::", dbl + 1) != -1:
        return None, "multiple ::"
    if ":::" in addr:
        return None, "colon run"
    if addr[:1] == ":" and addr[:2] != "::":
        return None, "stray colon"
    if addr[-1:] == ":" and addr[-2:] != "::":
        return None, "stray colon"

    if dbl is not None:
        left, right = addr[:dbl - 1], addr[dbl + 1:]
        lg = [g for g in left.split(":") if g] if left else []
        rg = [g for g in right.split(":") if g] if right else []
        missing = 8 - (len(lg) + len(rg))
        if missing < 1:
            return None, "bad ::"
        raw = lg + ["0"] * missing + rg
    else:
        raw = [g for g in addr.split(":") if g]

    if len(raw) != 8:
        return None, "ipv6 needs 8 groups"
    nums = []
    for g in raw:
        if not re.fullmatch(r"[0-9a-f]{1,4}", g):
            return None, "bad ipv6 group"
        nums.append(int(g, 16))
    return nums, None


def compress(nums):
    best_start, best_len, i = 0, 0, 0
    while i < 8:
        if nums[i] == 0:
            j = i
            while j < 8 and nums[j] == 0:
                j += 1
            if j - i > best_len:
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    parts = [f"{n:x}" for n in nums]
    if best_len >= 2:
        return ":".join(parts[:best_start]) + "::" + ":".join(parts[best_start + best_len:])
    return ":".join(parts)


def canon_ipv6(addr, prefix, v4_prefix):
    nums, err = ipv6_groups(addr)
    if nums is None:
        return None, err
    if nums[:6] == [0, 0, 0, 0, 0, 0xffff]:
        return canon_ipv4_nums(nums[6] // 256, nums[6] % 256, nums[7] // 256, nums[7] % 256, v4_prefix), None
    if prefix < 128:
        for i in range(8):
            lo = i * 16
            if prefix >= (i + 1) * 16:
                continue
            if prefix <= lo:
                nums[i] = 0
            else:
                shift = 2 ** (16 - (prefix - lo))
                nums[i] = (nums[i] // shift) * shift
    return compress(nums), None


def canon_ip(addr, v6_prefix=128, v4_prefix=32):
    if not isinstance(addr, str) or addr == "":
        return None, "empty address"
    if v6_prefix < 0 or v6_prefix > 128:
        return None, "bad v6 prefix"
    if v4_prefix < 0 or v4_prefix > 32:
        return None, "bad v4 prefix"
    if ":" in addr:
        return canon_ipv6(addr, v6_prefix, v4_prefix)
    return canon_ipv4(addr, v4_prefix)



# ---- canon_server_name -----------------------------------------------------

_LUA_SPACE = b" \t\n\x0b\x0c\r"          # Lua's "%s"
_LUA_LOWER = bytes.maketrans(bytes(range(65, 91)), bytes(range(97, 123)))


def _lua_trim(b):
    return b.strip(_LUA_SPACE)


def _lua_trim_dots_and_space(b):
    while True:
        t = _lua_trim(b)
        if t.endswith(b"."):
            t = t[:-1]
        if t == b:
            return b
        b = t


def canon_server_name(host):
    """Models canon.lua's canon_server_name. Takes/returns str; works on bytes."""
    b = _lua_trim_dots_and_space(host.encode("utf-8", "surrogatepass"))

    m = re.match(rb"\[([^\]]*)\]", b)   # Lua: ^%[([^%]]*)%]
    if m:
        b = _lua_trim_dots_and_space(m.group(1))

    if b.count(b":") == 1:
        m = re.fullmatch(rb"(.*?):[0-9]+", b, re.S)   # Lua: ^(.-):%d+$
        if m:
            b = m.group(1)

    b = _lua_trim_dots_and_space(b)
    return b.translate(_LUA_LOWER).decode("utf-8", "surrogatepass")


if __name__ == "__main__":
    vec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    fails = 0
    for e in vec["canon_ip"]:
        got, err = canon_ip(e["in"], e["v6_prefix"], e["v4_prefix"])
        if e["valid"]:
            ok = got == e["out"]
        else:
            ok = got is None
        if not ok:
            fails += 1
            print(f"  FAIL {e['in']!r:26} v6={e['v6_prefix']} v4={e['v4_prefix']} "
                  f"expected={'reject' if not e['valid'] else e['out']!r} got={got!r} ({err})")
    extra = [":::", ":1::2", "1::2:", "1:::2", "2001:db8:::1", ":2001:db8::1", "2001:db8::1:"]
    for a in extra:
        got, err = canon_ip(a)
        if got is not None:
            fails += 1
            print(f"  FAIL {a!r} should be rejected, got {got!r}")
    accept = ["::", "::1", "1::", "1::2", "2001:db8::1", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8"]
    for a in accept:
        got, err = canon_ip(a)
        if got is None:
            fails += 1
            print(f"  FAIL {a!r} should be accepted, got rejected ({err})")
    for e in vec["canon_server_name"]:
        got = canon_server_name(e["in"])
        if got != e["out"]:
            fails += 1
            print(f"  FAIL canon_server_name {e['in']!r:26} expected={e['out']!r} got={got!r}")
    print(f"lua canon port vs vectors: {'ALL PASS' if not fails else str(fails) + ' FAILURES'}")
    sys.exit(1 if fails else 0)
