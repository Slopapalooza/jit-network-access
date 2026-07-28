#!/usr/bin/env python3
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pack a directory into a signed CRX3, without needing Chrome.

    python3 crx3.py <source-dir> <out.crx> <signing-key.pem>
    python3 crx3.py --id <signing-key.pem>      print the extension id
    python3 crx3.py --verify <file.crx>         re-check a packed artifact

Driving `chrome --pack-extension` works on a desktop but is a poor fit for CI:
it needs a real browser, writes its output next to the input, and reports
failure by producing nothing. The CRX3 container is small enough to build
directly, which makes the artifact reproducible and the build runnable anywhere
openssl exists.

CRX3 layout:

    "Cr24" | uint32le(3) | uint32le(len(header)) | header | zip

`header` is a CrxFileHeader protobuf:

    message AsymmetricKeyProof { bytes public_key = 1; bytes signature = 2; }
    message CrxFileHeader {
      repeated AsymmetricKeyProof sha256_with_rsa = 2;
      bytes signed_header_data = 10000;         a serialized SignedData
    }
    message SignedData { bytes crx_id = 1; }    first 16 bytes of sha256(SPKI)

The signature is RSA PKCS#1 v1.5 over SHA-256 of:

    SIG_CONTEXT | uint32le(len(signed_header_data)) | signed_header_data | zip
"""
import hashlib
import io
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import zipfile

# "CRX3 SignedData" followed by one NUL byte. Built rather than written as an
# escape so the source stays free of literal control characters.
SIG_CONTEXT = b"CRX3 SignedData" + bytes(1)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num: int, payload: bytes) -> bytes:
    """One length-delimited protobuf field (wire type 2)."""
    return _varint((num << 3) | 2) + _varint(len(payload)) + payload


def _read_varint(b: bytes, i: int):
    n = shift = 0
    while True:
        x = b[i]
        i += 1
        n |= (x & 0x7F) << shift
        if not x & 0x80:
            return n, i
        shift += 7


def _read_fields(b: bytes) -> dict:
    i, out = 0, {}
    while i < len(b):
        key, i = _read_varint(b, i)
        ln, i = _read_varint(b, i)
        out[key >> 3] = b[i:i + ln]
        i += ln
    return out


def _openssl(args: list, stdin: bytes = b"") -> bytes:
    p = subprocess.run(["openssl"] + args, input=stdin, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(f"openssl {' '.join(args)} failed: {p.stderr.decode(errors='replace')}")
    return p.stdout


def public_key_der(key_pem: pathlib.Path) -> bytes:
    """SubjectPublicKeyInfo DER for the signing key."""
    return _openssl(["rsa", "-in", str(key_pem), "-pubout", "-outform", "DER"])


def _id_from_spki(spki: bytes) -> str:
    """Chrome's id: sha256(SPKI)[:16], hex, mapped 0-f to a-p."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(spki).hexdigest()[:32])


def extension_id(key_pem: pathlib.Path) -> str:
    return _id_from_spki(public_key_der(key_pem))


# Every shipped file is text, and .gitattributes normalizes the repo to LF — so a
# Linux checkout and a Windows working tree hold DIFFERENT bytes for identical
# source. Normalizing here makes the archive CONTENT independent of who built it.
CRLF = bytes([13, 10])
LF = bytes([10])


def zip_dir(src: pathlib.Path) -> bytes:
    """Zip with sorted entries, fixed timestamps and modes, and content
    normalized to LF.

    Reproducible for a given source tree AND toolchain — not across them: the
    deflate stream depends on the zlib build, so a Windows and a Linux build of
    the same commit produce archives whose ENTRIES are byte-identical but whose
    containers differ by a few bytes. A published checksum therefore pins a
    specific build, which is why one builder must own a release's artifacts (see
    .github/workflows/extension-release.yml)."""
    # mkstemp hands back an OPEN descriptor; on Windows the file cannot be
    # unlinked until it is closed.
    fd, name = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    tmp = pathlib.Path(name)
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src.rglob("*")):
            if f.is_file():
                arcname = str(f.relative_to(src)).replace("\\", "/")
                zi = zipfile.ZipInfo(arcname, (2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o644 << 16
                z.writestr(zi, f.read_bytes().replace(CRLF, LF))
    data = tmp.read_bytes()
    tmp.unlink()
    return data


def pack(src: pathlib.Path, out: pathlib.Path, key_pem: pathlib.Path) -> str:
    spki = public_key_der(key_pem)
    signed_header_data = _field(1, hashlib.sha256(spki).digest()[:16])  # SignedData{crx_id}
    payload = zip_dir(src)

    to_sign = SIG_CONTEXT + struct.pack("<I", len(signed_header_data)) + signed_header_data + payload
    fd, name = tempfile.mkstemp()
    os.close(fd)
    tmp = pathlib.Path(name)
    try:
        tmp.write_bytes(to_sign)
        signature = _openssl(["dgst", "-sha256", "-sign", str(key_pem), str(tmp)])
    finally:
        tmp.unlink()

    proof = _field(1, spki) + _field(2, signature)          # AsymmetricKeyProof
    header = _field(2, proof) + _field(10000, signed_header_data)
    out.write_bytes(b"Cr24" + struct.pack("<II", 3, len(header)) + header + payload)
    return _id_from_spki(spki)


def verify(crx: pathlib.Path) -> str:
    """Re-check a packed CRX's signature. A malformed artifact installs nowhere,
    and learning that from a user is expensive — so the build checks its own
    output rather than assuming the packer worked."""
    raw = crx.read_bytes()
    if raw[:4] != b"Cr24":
        raise SystemExit(f"{crx}: not a CRX (bad magic)")
    ver, hlen = struct.unpack("<II", raw[4:12])
    if ver != 3:
        raise SystemExit(f"{crx}: CRX version {ver}, expected 3")

    header, payload = raw[12:12 + hlen], raw[12 + hlen:]
    f = _read_fields(header)
    proof = _read_fields(f[2])
    spki, sig, shd = proof[1], proof[2], f[10000]

    signed = SIG_CONTEXT + struct.pack("<I", len(shd)) + shd + payload
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        (d / "pub.der").write_bytes(spki)
        (d / "sig").write_bytes(sig)
        (d / "data").write_bytes(signed)
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(d / "pub.der"),
             "-keyform", "DER", "-signature", str(d / "sig"), str(d / "data")],
            capture_output=True, text=True)
    if "Verified OK" not in r.stdout:
        raise SystemExit(f"{crx}: SIGNATURE DOES NOT VERIFY")

    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        if "manifest.json" not in z.namelist():
            raise SystemExit(f"{crx}: payload has no manifest.json")
        entries = len(z.namelist())
    ident = _id_from_spki(spki)
    print(f"  crx verified: id={ident} entries={entries}")
    return ident


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--id":
        print(extension_id(pathlib.Path(sys.argv[2])))
    elif len(sys.argv) == 3 and sys.argv[1] == "--verify":
        verify(pathlib.Path(sys.argv[2]))
    elif len(sys.argv) == 4:
        print(pack(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])))
    else:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        sys.exit(2)
