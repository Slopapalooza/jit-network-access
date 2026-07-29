#!/usr/bin/env bash
# JIT Network Access - Copyright (C) 2026 Slopapalooza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stand up a single-node kind cluster with ingress-nginx and gate a service
# behind the Authorizer, exactly as adapters/kubernetes/ documents.
#
#   ./setup.sh            # create cluster + deploy
#   ./setup.sh --destroy  # tear it all down
#
# The ingress is published on host port 8085 so ../run-k8s.sh can knock it with
# the same client and token as every other engine.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../../.." && pwd)"
CLUSTER=jit-lab
DOCKER="${DOCKER:-sudo docker}"
KIND="${KIND:-sudo kind}"
KUBECTL="${KUBECTL:-sudo kubectl}"

if [ "${1:-}" = "--destroy" ]; then
  $KIND delete cluster --name "$CLUSTER"
  exit 0
fi

echo "==> building the Authorizer image"
$DOCKER build -q -t jitaccess-authorizer:lab -f "$repo/authorizer/Dockerfile" "$repo"

echo "==> creating kind cluster '$CLUSTER'"
if $KIND get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "    already exists, reusing"
else
  $KIND create cluster --config "$here/kind-config.yaml" --wait 120s
fi

echo "==> loading the Authorizer image into the cluster (never pulled)"
$KIND load docker-image jitaccess-authorizer:lab --name "$CLUSTER"

echo "==> installing ingress-nginx"
$KUBECTL apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
echo "    waiting for the controller to be ready (this is the slow part)"
$KUBECTL wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=300s

echo "==> deploying the Authorizer, the protected service and both Ingresses"

# The gated Ingress carries an auth-snippet. ingress-nginx has shipped
# allow-snippet-annotations=false by default since v1.9.0, and 1.12+ additionally
# gates snippets behind --annotations-risk-level=Critical, so without this the
# annotation is either rejected by the admission webhook or silently ignored and
# the lab exercises a configuration production does not use.
# annotations-risk-level is the half this was missing: the comment above named
# it but the patch only set allow-snippet-annotations, so the admission webhook
# still refused the gated Ingress with
#   "annotation group ExternalAuth contains risky annotation based on ingress
#    configuration"
# On an existing cluster that is invisible — the previously-created Ingress is
# left in place and everything still passes — but a lab built from scratch never
# gets the gated Ingress at all.
${SUDO:-sudo} kubectl -n ingress-nginx patch configmap ingress-nginx-controller --type merge \
  -p '{"data":{"allow-snippet-annotations":"true","annotations-risk-level":"Critical"}}' >/dev/null 2>&1 || true
${SUDO:-sudo} kubectl -n ingress-nginx rollout restart deploy/ingress-nginx-controller >/dev/null 2>&1 || true
${SUDO:-sudo} kubectl -n ingress-nginx rollout status deploy/ingress-nginx-controller --timeout=180s >/dev/null 2>&1 || true
$KUBECTL apply -f "$here/lab-manifests.yaml"

# `kind load docker-image` replaces the image on the node, but the Deployment
# spec is unchanged, so Kubernetes has no reason to roll the pod and it keeps
# running the OLD build. Re-running this script therefore appeared to update the
# Authorizer while testing code from whenever the pod last started — which is
# exactly how a traversal probe "failed" against a fix that was already in.
# Force the roll so the image that was just loaded is the one being tested.
$KUBECTL -n jit-system rollout restart deploy/jit-authorizer
$KUBECTL -n jit-system rollout status deploy/jit-authorizer --timeout=180s
$KUBECTL -n default    rollout status deploy/upstream       --timeout=180s

echo
echo "ready — the gated service is on http://app.example.com:8085"
echo "  curl --resolve app.example.com:8085:127.0.0.1 http://app.example.com:8085/"
