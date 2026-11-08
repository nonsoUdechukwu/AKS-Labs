#!/usr/bin/env bash
# Offline validation of the AKS security baseline against a throwaway kube-apiserver
# (envtest). Needs Go and python3. No Docker, no cluster, and your kubeconfig is
# never read or modified.
set -euo pipefail
cd "$(dirname "$0")"
unset KUBECONFIG

K8S_VERSION="${K8S_VERSION:-1.37.0}"

echo "== python: posture script unit tests"
python3 -m unittest discover -s ../scripts -p 'test_*.py' -v

echo "== go: envtest (Kubernetes ${K8S_VERSION})"
KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.25 use "$K8S_VERSION" -p path)"
export KUBEBUILDER_ASSETS
go test -count=1 -v ./...
