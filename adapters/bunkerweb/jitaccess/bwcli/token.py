#!/usr/bin/env python3
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
bwcli jitaccess token [label...] - generate a JIT Access device token.

Prints the JIT_ACCESS_TOKEN setting line to add to your config and a direct
setup string for quick testing. For the recommended one-time-code enrollment
(secret never in the QR), create the token, then mint a code from the web UI or
via  POST /jitaccess/enroll-code  on the instance internal API.

Pure Python - no instance interaction, safe to run anywhere.
"""
import base64
import os
import sys


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main() -> int:
    label = " ".join(sys.argv[1:]).strip() or "device"
    if ":" in label:
        print("label must not contain ':'", file=sys.stderr)
        return 2
    kid = "kid_" + b64u(os.urandom(9))
    secret = b64u(os.urandom(32))

    # This tool exists to hand a freshly-minted secret to an operator, so the
    # secret HAS to reach stdout — CodeQL flags that as
    # py/clear-text-logging-sensitive-data and it is intentional here, not a
    # defect. What is worth guarding is the accident: piping this into a file or
    # a CI log persists a live credential somewhere nobody is watching. Say so
    # on stderr, which does not pollute the output being captured.
    if not sys.stdout.isatty():
        print(
            "warning: output is being redirected and contains a live secret - "
            "make sure the destination is not a log, a CI artifact or a repo.",
            file=sys.stderr,
        )

    print("# 1) Add to your GLOBAL config (use JIT_ACCESS_TOKEN, then _1/_2/... for more):")
    print(f"JIT_ACCESS_TOKEN={kid}:{secret}:{label}")
    print()
    print("# 2) Allow this token on the service(s) it should open (multisite):")
    print(f"#    <server_name>_JIT_ACCESS_TOKENS={kid}")
    print()
    print("# 3a) Recommended enrollment - mint a one-time code (secret not in the string):")
    print(f'#     curl -s -H "Host: bwapi" -H "Authorization: Bearer $API_TOKEN" \\')
    print(f'#       -X POST http://127.0.0.1:5000/jitaccess/enroll-code \\')
    print(f'#       -d \'{{"kid":"{kid}","origins":["https://YOUR-SERVICE"]}}\'')
    print(f"#     -> gives <code>; hand the user:")
    print(f"#     jitaccess://enroll?v=1&server=https://YOUR-SERVICE&code=<code>&origins=https://YOUR-SERVICE")
    print()
    print("# 3b) Direct setup string (testing only - carries the secret):")
    print(f"jitaccess://enroll?v=1&kid={kid}&secret={secret}&origins=https://YOUR-SERVICE&label={label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
