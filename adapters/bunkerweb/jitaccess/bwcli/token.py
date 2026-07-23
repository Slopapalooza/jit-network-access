#!/usr/bin/env python3
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
