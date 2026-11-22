#!/usr/bin/env bash
# Run every scenario against the current cluster and compare with the expected outcome
# for a given safeguards level and Pod Security Standards level.
#
#   ./scripts/run-scenarios.sh Warn Privileged
#   ./scripts/run-scenarios.sh Enforce Restricted
#
# Most cases use server-side dry-run, which runs the full admission chain (mutating and
# validating webhooks, VAPs) without persisting anything. Mutation cases are applied for
# real so you can inspect the pods the scheduler actually sees, then deleted.
set -euo pipefail

LEVEL="${1:?usage: run-scenarios.sh <Warn|Enforce> [Privileged|Baseline|Restricted]}"
PSS="${2:-Privileged}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SC="$ROOT/scenarios"
OUT="$ROOT/results-${LEVEL}-${PSS}.md"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

case "$LEVEL" in Warn | Enforce) ;; *) echo "level must be Warn or Enforce" >&2 && exit 2 ;; esac
case "$PSS" in Privileged | Baseline | Restricted) ;; *) echo "pss must be Privileged, Baseline or Restricted" >&2 && exit 2 ;; esac

for bin in kubectl jq; do
  command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 2; }
done

expected() {
  local class="$1" blocked
  case "$class" in
  compliant | excluded) echo ADMIT ;;
  ds-deny) [[ $LEVEL == Warn ]] && echo WARN || echo DENY ;;
  ds-mutate) [[ $LEVEL == Warn ]] && echo WARN || echo MUTATE ;;
  mutate-only) [[ $LEVEL == Warn ]] && echo ADMIT || echo MUTATE ;;
  pss-baseline | pss-restricted)
    blocked=false
    [[ $class == pss-baseline && $PSS != Privileged ]] && blocked=true
    [[ $class == pss-restricted && $PSS == Restricted ]] && blocked=true
    if [[ $blocked == false ]]; then echo ADMIT; elif [[ $LEVEL == Warn ]]; then echo WARN; else echo DENY; fi
    ;;
  *) echo "?" ;;
  esac
}

# Prints "<OUTCOME>\t<evidence>" for a dry-run attempt.
dry_run() {
  local file="$1" rc=0
  if [[ $file == "@node-label" ]]; then
    local node
    node="$(kubectl get nodes -l kubernetes.azure.com/mode=user -o name | head -n1)"
    kubectl label --dry-run=server "$node" lab.example.com/owner=me --overwrite >"$TMP/out" 2>"$TMP/err" || rc=$?
  else
    kubectl apply --dry-run=server -f "$SC/$file" >"$TMP/out" 2>"$TMP/err" || rc=$?
  fi
  local evidence
  # Keep just the policy message, e.g. "[azurepolicy-k8sazurev2...] Please specify an explicit...".
  evidence="$(grep -m1 -E 'denied|Warning:|Error' "$TMP/err" |
    sed -E 's/.*denied the request: //; s/^Warning: //' | cut -c1-180 | tr '|' '/' || true)"
  if ((rc != 0)) && grep -qiE 'denied|forbidden' "$TMP/err"; then
    printf 'DENY\t%s\n' "$evidence"
  elif ((rc != 0)); then
    printf 'ERROR\t%s\n' "$evidence"
  elif grep -qE 'Warning: (\[azurepolicy|would violate PodSecurity)' "$TMP/err"; then
    printf 'WARN\t%s\n' "$evidence"
  else
    printf 'ADMIT\t\n'
  fi
}

# Applies a mutation scenario for real and checks what the pod ended up with.
mutate_check() {
  local id="$1" file="$2" ns="$3" name pod spec rc=0
  name="$(awk '/^  name:/{print $2; exit}' "$SC/$file")"
  kubectl apply -f "$SC/$file" >"$TMP/out" 2>"$TMP/err" || rc=$?
  if ((rc != 0)); then
    printf 'DENY\t%s\n' "$(grep -m1 denied "$TMP/err" | sed -E 's/.*denied the request: //' | cut -c1-180 || true)"
    return
  fi
  kubectl -n "$ns" rollout status "deploy/$name" --timeout=180s >/dev/null 2>&1 || true
  pod="$(kubectl -n "$ns" get pods -l "app=$name" -o name | head -n1)"
  spec="$(kubectl -n "$ns" get "$pod" -o json | jq -c '{r: .spec.containers[0].resources, t: (.spec.topologySpreadConstraints // []), a: (.spec.affinity.podAntiAffinity // null)}')"
  kubectl delete -f "$SC/$file" --wait=false >/dev/null 2>&1 || true

  local mutated=false
  case "$id" in
  S04) jq -e '.r.requests.cpu == "500m" and (.r.requests.memory == "2Gi" or .r.requests.memory == "2048Mi")' <<<"$spec" >/dev/null && mutated=true ;;
  S05) jq -e '.r.requests.cpu == "100m" and .r.requests.memory == "100Mi"' <<<"$spec" >/dev/null && mutated=true ;;
  S06) jq -e '(.t | length) > 0 or .a != null' <<<"$spec" >/dev/null && mutated=true ;;
  esac
  if [[ $mutated == true ]]; then printf 'MUTATE\t%s\n' "$spec"; else printf 'ADMIT\t%s\n' "$spec"; fi
}

echo "Preparing namespaces and the golden workload (S01 is needed by S07)..."
kubectl apply -f "$SC/00-namespaces.yaml" >/dev/null
kubectl apply -f "$SC/01-compliant.yaml" >/dev/null 2>"$TMP/s01.err" || true

{
  echo "# Deployment Safeguards scenarios: level=$LEVEL, pss=$PSS"
  echo
  echo "Run at $(date -u +%Y-%m-%dT%H:%M:%SZ) against \`$(kubectl config current-context)\`."
  echo
  echo "| ID | Scenario | Expected | Actual | Result | Evidence |"
  echo "|---|---|---|---|---|---|"
} >"$OUT"

fail=0
while IFS=$'\t' read -r id file ns class title; do
  [[ -z $id || $id == \#* ]] && continue
  want="$(expected "$class")"
  if [[ $want == MUTATE ]]; then
    got_line="$(mutate_check "$id" "$file" "$ns")"
  else
    got_line="$(dry_run "$file")"
  fi
  got="${got_line%%$'\t'*}"
  evidence="${got_line#*$'\t'}"
  if [[ $got == "$want" ]]; then mark="✅"; else mark="❌" && fail=$((fail + 1)); fi
  printf '%-4s %-38s expected=%-6s actual=%-6s %s\n' "$id" "$title" "$want" "$got" "$mark"
  printf "| %s | %s | %s | %s | %s | \`%s\` |\n" "$id" "$title" "$want" "$got" "$mark" "${evidence:0:160}" >>"$OUT"
done <"$SC/expected.tsv"

echo
echo "Results written to $OUT"
if ((fail > 0)); then
  echo "$fail scenario(s) differed from the expected outcome. Check the policy sync (scripts/wait-for-safeguards.sh) before filing it as a bug."
  exit 1
fi
