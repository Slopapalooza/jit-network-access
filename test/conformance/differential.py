#!/usr/bin/env python3
"""Differential fuzzer for the canonicalizers, across all four references.

    python3 test/conformance/differential.py [--count N] [--seed N]

WHY THIS EXISTS
---------------
canon_server_name and canon_ip decide the grant key and the MAC input. They are
implemented four times — Go (core/go), Python (core/py), JavaScript
(extension/src) and Lua (core/lua) — and a one-byte disagreement between any two
means a knock minted on one engine does not verify on another, or worse, that two
different targets share a key.

vectors.json pins the answers for inputs somebody thought of. Every divergence
this project has actually hit came from an input nobody thought of: a "::" that
skipped a strictness check, an unbracketed IPv6 that got its last group eaten as
a port, a Unicode digit that counted as a port number in Python and not anywhere
else. This throws generated input at all four at once and diffs the answers, so
those show up as a disagreement instead of as a production bypass.

Lua has no runtime on the dev host, so the Lua column is core/lua/
canon_port_check.py — a byte-level transliteration of canon.lua. It models the
logic, not the runtime; see that file's docstring for what it does and does not
cover.

SCOPE: inputs are valid UTF-8. A Host header is bytes and Go and Lua can hold
arbitrary ones, but a JS string cannot represent them faithfully, so a
byte-level comparison across all four is not well defined. Go's own
FuzzCanonServerName covers arbitrary bytes for that reason.

Exit status is nonzero if any two references disagree.
"""
import argparse
import itertools
import json
import pathlib
import random
import subprocess
import sys
import tempfile

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core" / "py"))
sys.path.insert(0, str(ROOT / "core" / "lua"))

import jitcrypto as py_ref                  # noqa: E402
import canon_port_check as lua_ref          # noqa: E402

# Characters that mean something to one of the parsers: brackets and colons for
# the IPv6 forms, dot for the root label, the ASCII and non-ASCII spaces, ASCII
# and non-ASCII digits and letters, and percent for the IPv6 zone id.
NAME_ALPHABET = "[]:. \tazAZ09-% é٤"
IP_ALPHABET = "0129:.fF%[]e"

# Prefixes: in range, on the boundary, and out of range in both directions —
# out-of-range acceptance was a real Go/Lua split.
V6_PREFIXES = [-1, 0, 1, 64, 127, 128, 129]
V4_PREFIXES = [-1, 0, 1, 24, 31, 32, 33]

NAME_SEEDS = [
    "", ".", "..", "...", " ", "  .  ", "example.com", "EXAMPLE.com",
    "example.com.", "example.com..", "example.com...", "example.com:443",
    "example.com.:443", "example.com:", "example.com:0", ":443", ":",
    "host:notaport", "host :80", " host : 80 ", "host\t:80",
    "2001:db8::1", "2001:db8::2", "[2001:db8::1]", "[2001:db8::1]:8443",
    "[2001:DB8::1]", "::1", "[::1]", "[ ::1 ]", "[]", "[]:80", "[", "]",
    "[example.com.]", "[example.com.]:443", "[a]b", "a]b", "a[b",
    "fe80::1%eth0", "[fe80::1%eth0]:443", "1:2:3:4:5:6:7:8",
    "xn--caf-dma.example.com", "café.example.com", "CAFÉ.example.com",
    "host:٤٤٣", "host ", " host ",
    "9wiki.internal", "wiki.internal",
]

IP_SEEDS = [
    "", ":", "::", ":::", "::1", "1::", "1::2", "1:::2", "1::2::3",
    "1.2.3.4", "01.2.3.4", "192.168.001.005", "1.2.3.256", "1.2.3",
    "1.2.3.4.5", "2001:db8::1", "2001:0db8::1", "2001:DB8::1",
    "2001:db8:0:0:0:0:0:1", "::ffff:1.2.3.4", "::ffff:01.2.3.4",
    "fe80::1%eth0", "[2001:db8::1]", "2001:db8::1:", ":2001:db8::1",
    "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "::ffff:1.2.3.4.5",
    " 1.2.3.4", "1.2.3.4 ", "+1.2.3.4", "1.2.3.4%25", "0:0:0:0:0:0:0:0",
]


def _combos(alphabet, max_len):
    for n in range(1, max_len + 1):
        for t in itertools.product(alphabet, repeat=n):
            yield "".join(t)


def gen_names(rng, count):
    out = list(NAME_SEEDS)
    out += list(_combos(NAME_ALPHABET, 2))
    seen = set(out)
    while len(out) < count:
        n = rng.randint(3, 12)
        s = "".join(rng.choice(NAME_ALPHABET) for _ in range(n))
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def gen_ips(rng, count):
    addrs = list(IP_SEEDS) + list(_combos(IP_ALPHABET, 2))
    seen = set(addrs)
    while len(addrs) < count:
        n = rng.randint(3, 20)
        s = "".join(rng.choice(IP_ALPHABET) for _ in range(n))
        if s not in seen:
            seen.add(s)
            addrs.append(s)
    cases = []
    for a in addrs:
        cases.append({"addr": a, "v6": 128, "v4": 32})
        cases.append({"addr": a, "v6": rng.choice(V6_PREFIXES), "v4": rng.choice(V4_PREFIXES)})
    return cases


def run_go(cases_path):
    p = subprocess.run(
        ["go", "run", "./canonprobe", str(cases_path)],
        cwd=ROOT / "core" / "go", capture_output=True, text=True, encoding="utf-8",
    )
    if p.returncode != 0:
        sys.exit(f"go probe failed:\n{p.stderr}")
    return json.loads(p.stdout)


def run_node(cases_path):
    probe = ROOT / "test" / "conformance" / "canonprobe.mjs"
    p = subprocess.run(
        ["node", str(probe), str(cases_path)],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
    )
    if p.returncode != 0:
        sys.exit(f"node probe failed:\n{p.stderr}")
    return json.loads(p.stdout)


def report(kind, rows, limit=15):
    """rows: list of (input_label, {impl: answer}). Returns the divergence count."""
    bad = []
    for label, answers in rows:
        if len({json.dumps(v) for v in answers.values()}) > 1:
            bad.append((label, answers))
    if not bad:
        print(f"  {kind}: all references agree ({len(rows)} cases)")
        return 0
    print(f"  {kind}: {len(bad)} DIVERGENCES of {len(rows)} cases")
    for label, answers in bad[:limit]:
        print(f"    {label}")
        for impl, v in answers.items():
            print(f"        {impl:8} {ascii(v)}")
    if len(bad) > limit:
        print(f"    ... and {len(bad) - limit} more")
    return len(bad)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20000,
                    help="generated inputs per canonicalizer (default 20000)")
    ap.add_argument("--seed", type=int, default=20260728,
                    help="RNG seed; a failure is reproducible from it")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    names = gen_names(rng, args.count)
    ips = gen_ips(rng, args.count)
    print(f"differential: {len(names)} server names, {len(ips)} ip cases, seed {args.seed}")

    with tempfile.TemporaryDirectory() as td:
        cases_path = pathlib.Path(td) / "cases.json"
        cases_path.write_text(
            json.dumps({"server_names": names, "ips": ips}), encoding="utf-8")
        go = run_go(cases_path)
        js = run_node(cases_path)

    py_names = [py_ref.canon_server_name(s) for s in names]
    lua_names = [lua_ref.canon_server_name(s) for s in names]

    py_ips, lua_ips = [], []
    for c in ips:
        try:
            py_ips.append(py_ref.canon_ip(c["addr"], c["v6"], c["v4"]))
        except Exception:
            py_ips.append(None)
        got, _ = lua_ref.canon_ip(c["addr"], c["v6"], c["v4"])
        lua_ips.append(got)

    failures = 0

    failures += report("canon_server_name", [
        (f"in={ascii(s)}", {"go": go["server_names"][i], "python": py_names[i],
                       "js": js["server_names"][i], "lua": lua_names[i]})
        for i, s in enumerate(names)
    ])

    failures += report("canon_ip", [
        (f"in={ascii(c['addr'])} v6={c['v6']} v4={c['v4']}",
         {"go": go["ips"][i], "python": py_ips[i], "lua": lua_ips[i]})
        for i, c in enumerate(ips)
    ])

    # Idempotency, per reference. A canonical form must already be canonical:
    # canonicalization happens at more than one layer (config keys at load, Host
    # at request), so a result that moves on a second pass means two layers can
    # hold different names for one service.
    idem = []
    for i, s in enumerate(names):
        for impl, fn, first in (("python", py_ref.canon_server_name, py_names[i]),
                                ("lua", lua_ref.canon_server_name, lua_names[i])):
            again = fn(first)
            if again != first:
                idem.append((impl, s, first, again))
    if idem:
        failures += len(idem)
        print(f"  idempotency: {len(idem)} FAILURES")
        for impl, s, first, again in idem[:15]:
            print(f"    {impl:8} {ascii(s)} -> {ascii(first)} -> {ascii(again)}")
    else:
        print(f"  idempotency: stable in every reference ({len(names)} cases)")

    print("DIFFERENTIAL: " + ("PASS" if not failures else f"{failures} FAILURES"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
