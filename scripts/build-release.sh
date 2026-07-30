#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Assemble every release artifact into dist/.
#
#   ./scripts/build-release.sh v1.0.0
#
# Runs identically on a laptop and in CI — the release workflow calls this and
# does nothing else, so what gets published is what you can reproduce locally.
# Nothing here needs a signing key or a registry; the container image is built
# separately by the workflow because it needs a registry login.
#
# Each adapter needs a different shape of artifact, which is why this is a
# script rather than a matrix:
#
#   Authorizer  static binaries          the only thing with no dependencies
#   Caddy       a whole Caddy binary     the module is compiled in
#   Traefik     nothing                  Yaegi fetches source at the git tag
#   OpenResty   Lua tree + conf          dropped into lua_package_path
#   BunkerWeb   plugin tarball           EXTERNAL_PLUGIN_URLS wants a tar.gz
#   Kubernetes  manifests                plus the image the workflow pushes
#   deploy      install.sh + unit        the Debian/Ubuntu path
set -euo pipefail

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
case "$VERSION" in
  v*) ;;
  *) echo "version should look like v1.0.0" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
dist="$repo/dist"
# The leading v is right for a git tag and wrong inside a binary's -version.
bare="${VERSION#v}"

rm -rf "$dist"
mkdir -p "$dist"
echo "building $VERSION into dist/"

# ---- Go binaries -----------------------------------------------------------
# -trimpath so the paths of whoever built it are not baked in; -s -w to drop
# the symbol table. CGO off keeps them static, which is what makes the install
# script a copy rather than a dependency hunt.
go_build() {
  local module="$1" pkg="$2" name="$3" goarch="$4"
  local out="$dist/$name-$VERSION-linux-$goarch"
  ( cd "$repo/$module" \
    && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
       go build -trimpath -ldflags "-s -w -X main.version=$bare" -o "$out" "$pkg" )
  echo "  $(basename "$out")"
}

echo "== binaries =="
for arch in amd64 arm64; do
  go_build authorizer      .                 jitaccess-authorizer "$arch"
  go_build adapters/caddy  ./cmd/caddy-jit   caddy-jit            "$arch"
done

# ---- source-shaped adapters ------------------------------------------------
echo "== adapter packages =="

# OpenResty: the portable Lua core plus the adapter shim, laid out so that
# lua_package_path "/usr/local/share/jitaccess/?.lua;;" just works.
stage="$(mktemp -d)"
mkdir -p "$stage/jitaccess-openresty"
cp -r "$repo/core/lua/jitaccess" "$stage/jitaccess-openresty/"
cp -r "$repo/adapters/openresty/lib/jitaccess/openresty.lua" "$stage/jitaccess-openresty/jitaccess/"
cp -r "$repo/adapters/openresty/conf" "$stage/jitaccess-openresty/"
cp "$repo/adapters/openresty/README.md" "$stage/jitaccess-openresty/"
tar -C "$stage" -czf "$dist/jitaccess-openresty-$VERSION.tar.gz" jitaccess-openresty
rm -rf "$stage"
echo "  jitaccess-openresty-$VERSION.tar.gz"

# BunkerWeb: build-vendor.sh already produces exactly the tarball
# EXTERNAL_PLUGIN_URLS expects, so use it rather than reimplementing the layout.
"$repo/adapters/bunkerweb/build-vendor.sh" >/dev/null
cp "$repo/adapters/bunkerweb/jitaccess.tar.gz" "$dist/jitaccess-bunkerweb-$VERSION.tar.gz"
echo "  jitaccess-bunkerweb-$VERSION.tar.gz"

# Kubernetes: manifests only. The image they reference is pushed by the
# workflow; these are useless without it, which the README says.
stage="$(mktemp -d)"
mkdir -p "$stage/jitaccess-kubernetes"
cp "$repo"/adapters/kubernetes/*.yaml "$stage/jitaccess-kubernetes/"
cp "$repo/adapters/kubernetes/README.md" "$stage/jitaccess-kubernetes/"
tar -C "$stage" -czf "$dist/jitaccess-kubernetes-$VERSION.tar.gz" jitaccess-kubernetes
rm -rf "$stage"
echo "  jitaccess-kubernetes-$VERSION.tar.gz"

# deploy: install.sh expects ../systemd/ next to it, so the tree ships whole.
stage="$(mktemp -d)"
cp -r "$repo/deploy" "$stage/deploy"
chmod +x "$stage/deploy/debian/install.sh"
tar -C "$stage" -czf "$dist/jitaccess-deploy-$VERSION.tar.gz" deploy
rm -rf "$stage"
echo "  jitaccess-deploy-$VERSION.tar.gz"

# ---- checksums -------------------------------------------------------------
# install.sh verifies against this before it executes anything it downloaded.
( cd "$dist" && sha256sum ./* > SHA256SUMS && sed -i 's| \./| |' SHA256SUMS )
echo "== SHA256SUMS =="
sed 's/^/  /' "$dist/SHA256SUMS"

echo
echo "dist/ ready ($(find "$dist" -type f | wc -l) files)"
