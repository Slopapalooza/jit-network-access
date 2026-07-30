#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Install the JIT Network Access Authorizer on Debian or Ubuntu.
#
#   sudo ./install.sh                      # latest release for this architecture
#   sudo ./install.sh --version v1.0.0     # a specific release
#   sudo ./install.sh --binary ./jitaccess-authorizer   # one you built yourself
#   sudo ./install.sh --uninstall
#
# What it does, all of it idempotent:
#   * verifies the download against the release SHA256SUMS (never blindly)
#   * creates a `jitaccess` system user with no shell and no home
#   * installs the binary, a hardened systemd unit, and — only if there is no
#     config yet — generates one with a real device token already in it
#   * validates the config with the binary's own -check before starting anything
#
# It deliberately does NOT touch your web server config. Gating a site is a
# decision about that site; see adapters/nginx/README.md for the snippet.
set -euo pipefail

REPO="Slopapalooza/jit-network-access"
BIN_NAME="jitaccess-authorizer"
PREFIX="/usr/local"
CONF_DIR="/etc/jitaccess"
CONF="$CONF_DIR/config.json"
UNIT="/etc/systemd/system/jit-authorizer.service"
SVC_USER="jitaccess"

VERSION=""
LOCAL_BINARY=""
DO_UNINSTALL=0
NO_START=0

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '4,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)   VERSION="${2:-}"; shift 2 ;;
    --binary)    LOCAL_BINARY="${2:-}"; shift 2 ;;
    --prefix)    PREFIX="${2:-}"; shift 2 ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    --no-start)  NO_START=1; shift ;;
    -h|--help)   usage ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0)"
command -v systemctl >/dev/null 2>&1 || die "systemd not found — this installer targets Debian/Ubuntu"

# ---------------------------------------------------------------- uninstall
if [ "$DO_UNINSTALL" -eq 1 ]; then
  echo "== uninstalling =="
  if systemctl list-unit-files jit-authorizer.service >/dev/null 2>&1; then
    systemctl disable --now jit-authorizer.service >/dev/null 2>&1 || true
    ok "service stopped and disabled"
  fi
  rm -f "$UNIT" && systemctl daemon-reload
  rm -f "$PREFIX/bin/$BIN_NAME"
  ok "binary and unit removed"
  # The config holds device secrets that may still be enrolled in browsers.
  # Deleting it silently would be destroying credentials the operator may need
  # to revoke properly first.
  if [ -e "$CONF" ]; then
    warn "kept $CONF — it contains device secrets. Remove it yourself when you are sure."
  fi
  if id "$SVC_USER" >/dev/null 2>&1; then
    warn "kept the '$SVC_USER' user. Remove with: userdel $SVC_USER"
  fi
  exit 0
fi

# ---------------------------------------------------------------- obtain binary
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "$LOCAL_BINARY" ]; then
  [ -f "$LOCAL_BINARY" ] || die "no such file: $LOCAL_BINARY"
  cp "$LOCAL_BINARY" "$TMP/$BIN_NAME"
  say "using local binary: $LOCAL_BINARY"
else
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture: $(uname -m) (amd64 and arm64 are published; use --binary to install one you built)" ;;
  esac
  command -v curl >/dev/null 2>&1 || die "curl is required (apt install curl)"

  if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$VERSION" ] || die "could not determine the latest release; pass --version"
  fi
  say "installing $VERSION (linux/$ARCH)"

  BASE="https://github.com/$REPO/releases/download/$VERSION"
  ASSET="$BIN_NAME-$VERSION-linux-$ARCH"
  curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET" || die "download failed: $BASE/$ASSET"
  curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

  # Verify before anything is executed or copied into place.
  ( cd "$TMP" && grep " \*\{0,1\}$ASSET\$" SHA256SUMS > want.txt \
      && sha256sum -c want.txt >/dev/null 2>&1 ) \
    || die "checksum mismatch for $ASSET — refusing to install"
  ok "checksum verified against SHA256SUMS"
  mv "$TMP/$ASSET" "$TMP/$BIN_NAME"
fi

chmod 0755 "$TMP/$BIN_NAME"

# ---------------------------------------------------------------- user + files
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent \
          --shell /usr/sbin/nologin "$SVC_USER"
  ok "created system user '$SVC_USER'"
else
  say "system user '$SVC_USER' already exists"
fi

install -o root -g root -m 0755 "$TMP/$BIN_NAME" "$PREFIX/bin/$BIN_NAME"
ok "installed $PREFIX/bin/$BIN_NAME ($("$PREFIX/bin/$BIN_NAME" -version))"

install -d -o root -g "$SVC_USER" -m 0750 "$CONF_DIR"

if [ -e "$CONF" ]; then
  say "keeping existing $CONF"
else
  # Generate a config that actually starts, with a real token in it. Shipping a
  # placeholder secret would mean the service fails its own -check on first
  # boot, and the usual response to that is to paste in something weak.
  if command -v openssl >/dev/null 2>&1; then
    rnd() { openssl rand -base64 "$1"; }
  else
    rnd() { head -c "$1" /dev/urandom | base64; }
  fi
  b64u() { tr '+/' '-_' | tr -d '=\n'; }
  KID="kid_$(rnd 9 | b64u)"
  SECRET="$(rnd 32 | b64u)"
  ADMIN="$(rnd 32 | b64u)"

  umask 077
  cat > "$CONF" <<JSON
{
  "listen": "127.0.0.1:8998",
  "admin_token": "$ADMIN",
  "trusted_proxies": ["127.0.0.1/32", "::1/128"],

  "grant_ttl": 3600,
  "nonce_ttl": 60,
  "rate_limit_per_min": 10,

  "services": {
    "app.example.com": {
      "tokens": ["$KID"],
      "failure_mode": "interstitial",
      "binding": "ip"
    }
  },

  "tokens": [
    { "kid": "$KID", "secret": "$SECRET", "label": "first device" }
  ]
}
JSON
  chown root:"$SVC_USER" "$CONF"
  chmod 0640 "$CONF"
  ok "generated $CONF with a device token already in it"
  GENERATED_KID="$KID"
fi

install -o root -g root -m 0644 \
  "$(dirname "$0")/../systemd/jit-authorizer.service" "$UNIT" 2>/dev/null \
  || die "could not find the systemd unit next to this script (expected ../systemd/jit-authorizer.service)"
systemctl daemon-reload
ok "installed $UNIT"

# ---------------------------------------------------------------- validate + start
if ! "$PREFIX/bin/$BIN_NAME" -config "$CONF" -check; then
  die "config did not validate — nothing was started. Fix $CONF and re-run."
fi
ok "config validates"

if [ "$NO_START" -eq 1 ]; then
  say "not starting (--no-start). Start with: systemctl enable --now jit-authorizer"
else
  systemctl enable --now jit-authorizer.service
  sleep 1
  if systemctl is-active --quiet jit-authorizer.service; then
    ok "jit-authorizer is running on 127.0.0.1:8998"
  else
    die "service failed to start — see: journalctl -u jit-authorizer -n 50"
  fi
fi

cat <<EOF

Next steps
  1. Edit $CONF: replace app.example.com with the host you want to gate.
     Then:  systemctl reload jit-authorizer     (reload, not restart — live grants survive)
  2. Gate the site in your web server. For NGINX, include the snippet from
     adapters/nginx/jitaccess.conf inside the server { } block.
  3. Enroll a browser. Mint a one-time code with the admin API. "server" is not
     optional here: without it the response carries no register_url, only the
     bare code.
       curl -s -X POST http://127.0.0.1:8998/admin/enroll-code \\
         -H "Authorization: Bearer \$(sudo sed -n 's/.*"admin_token": *"\([^"]*\)".*/\1/p' $CONF)" \\
         -H 'Content-Type: application/json' \\
         -d '{"kid":"${GENERATED_KID:-<your kid>}",
              "origins":["https://app.example.com"],
              "server":"https://app.example.com"}'
     Hand the returned register_url to the user; the extension does the rest.

  The admin token and every device secret live in $CONF (0640, root:$SVC_USER).
  Treat that file as a credential store.
EOF
