#!/usr/bin/env bash
# Azure Policy syncs assignments to the cluster asynchronously (allow 15-20 minutes after
# enabling or changing safeguards). This waits until the in-cluster policy objects
# reflect the requested level, so scenario runs don't race the sync.
#
#   ./scripts/wait-for-safeguards.sh Enforce
set -euo pipefail

LEVEL="${1:?usage: wait-for-safeguards.sh <Warn|Enforce> [timeout-minutes]}"
TIMEOUT_MIN="${2:-30}"
case "$LEVEL" in
Warn) want="warn" ;;
Enforce) want="deny" ;;
*) echo "level must be Warn or Enforce" >&2 && exit 2 ;;
esac

deadline=$(($(date +%s) + TIMEOUT_MIN * 60))
while :; do
  # Gatekeeper constraints created by the safeguards policy assignment. Other assignments
  # (for example Defender for Cloud's SecurityCenterBuiltIn) add audit-only constraints, so
  # filter on the assignment. Current add-on versions set enforcementAction to "scoped" and
  # put the real action (warn or deny, alongside dryrun for audit) in scopedEnforcementActions.
  actions="$(kubectl get constraints -o json 2>/dev/null |
    jq -r '.items[]
      | select((.metadata.annotations["azure-policy-assignment-id"] // "") | test("deployment-safeguards"; "i"))
      # These two stay at warn under Enforce: probes is warn-only, the annotation policy is informational.
      | select(.metadata.annotations["azure-policy-definition-reference-id"]
          | IN("ensureProbesConfiguredInKubernetesCluster", "printMutationsAnnotations") | not)
      | if .spec.enforcementAction == "scoped"
        then ([.spec.scopedEnforcementActions[]?.action | select(. != "dryrun")] | first // "dryrun")
        else (.spec.enforcementAction // "deny") end' | sort | uniq -c || true)"
  total="$(awk '{s += $1} END {print s + 0}' <<<"$actions")"
  matching="$(awk -v w="$want" '$2 == w {s += $1} END {print s + 0}' <<<"$actions")"

  # Newer add-on versions may also render native ValidatingAdmissionPolicies.
  vap="$(kubectl get validatingadmissionpolicybindings -o name 2>/dev/null | grep -ci azure || true)"

  echo "$(date +%H:%M:%S) safeguards constraints=$total (enforcementAction=$want: $matching), azure VAP bindings=$vap"
  if ((total > 0 && matching == total)); then
    echo "Safeguards look synced at level $LEVEL."
    exit 0
  fi
  if (($(date +%s) > deadline)); then
    echo "Timed out after ${TIMEOUT_MIN}m. Check: kubectl -n kube-system get pods -l app=azure-policy; kubectl -n gatekeeper-system get pods" >&2
    exit 1
  fi
  sleep 30
done
