#!/usr/bin/env bash
# Offline validation of the GitOps tree against a throwaway kube-apiserver (envtest).
# Needs Go, kubectl (for `kubectl kustomize`) and python3. No Docker, no cluster,
# and your kubeconfig is never read or modified.
set -euo pipefail
cd "$(dirname "$0")"
unset KUBECONFIG

ALB_VERSION="${ALB_VERSION:-1.12.4}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.21.3}"
FLUX_VERSION="${FLUX_VERSION:-v2.10.0}"
K8S_VERSION="${K8S_VERSION:-1.33.x}"
CACHE=.crds-cache

mkdir -p "$CACHE/alb"
fetch() { [[ -s $2 ]] || curl -fsSL "$1" -o "$2"; }
fetch "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml" "$CACHE/gateway-api.yaml"
fetch "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml" "$CACHE/cert-manager.yaml"
fetch "https://github.com/fluxcd/flux2/releases/download/${FLUX_VERSION}/install.yaml" "$CACHE/flux.yaml"

# AGC CRDs are not in the Helm chart: the controller's init container installs them
# from this image at runtime. Extract the same files (not redistributed here).
if ! ls "$CACHE"/alb/*.yaml >/dev/null 2>&1; then
  tmp=$(mktemp -d)
  go run github.com/google/go-containerregistry/cmd/crane@v0.20.6 export \
    "mcr.microsoft.com/application-lb/images/alb-controller-crds:${ALB_VERSION}" - | tar -x -C "$tmp" alb-controller-crds
  cp "$tmp"/alb-controller-crds/agc-crds/*.yaml "$tmp"/alb-controller-crds/extra-crds/*.yaml "$CACHE/alb/"
  rm -rf "$tmp"
fi

echo "== python: inventory script unit tests"
python3 -m unittest discover -s ../scripts -p 'test_*.py' -v

echo "== go: envtest (K8s ${K8S_VERSION})"
KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.21 use "$K8S_VERSION" -p path)"
export KUBEBUILDER_ASSETS
go test -count=1 -v ./...
