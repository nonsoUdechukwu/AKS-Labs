#!/usr/bin/env bash
# Remove lab workloads. Pass --all to also delete the resource group.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

kubectl delete -f "$ROOT/scenarios/09-intree-storageclass.yaml" --ignore-not-found >/dev/null 2>&1 || true
kubectl delete namespace lab-apps lab-legacy --ignore-not-found

if [[ ${1:-} == "--all" ]]; then
  RG="${RG:-rg-lab-safeguards}"
  echo "Deleting resource group $RG (async)..."
  az group delete --name "$RG" --yes --no-wait
fi
