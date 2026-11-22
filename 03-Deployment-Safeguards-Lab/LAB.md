# AKS Deployment Safeguards: a hands-on lab from Warn to Enforce

*Build a disposable cluster with Terraform or Bicep, run 13 scenarios against it, and see which safeguards warn, deny or rewrite your workloads. Then move the same rules into CI so a bad manifest fails the pull request instead of the deploy.*

> **Outcome:** By the end of this lab you will have:
> - An AKS Standard cluster with Deployment Safeguards, built from either Terraform (`azurerm_kubernetes_cluster_deployment_safeguard`) or Bicep (`Microsoft.ContainerService/deploymentSafeguards`).
> - A repeatable four-round test (Warn, then Enforce, then Baseline PSS, then Restricted PSS). A runner compares every scenario with the expected outcome and writes a Markdown evidence table.
> - Seen both mutators at work, including the one that gives each container without requests 2 GiB of memory.
> - An exclusion strategy that doesn't turn into a permanent bypass.
> - A `preflight.py` linter and a GitHub Actions workflow that catch the same problems at review time. The preflight is covered by 84 offline tests.
> - Live results from all four rounds on AKS 1.36, including four places where the cluster behaved differently from what the documentation led me to expect.

**Time:** 90 minutes (plus about 10 minutes of cluster build) · **Cost:** about US$0.50/hour · **Code:** [`terraform/`](terraform/), [`bicep/`](bicep/), [`scenarios/`](scenarios/), [`scripts/`](scripts/), [`preflight/`](preflight/), [`ci/`](ci/)

## Why run a lab on Deployment Safeguards

Every platform team writes the same wiki page: "Set requests. Add probes. Don't use `:latest`. Spread your replicas." Every platform team also finds out that wiki pages don't run at admission time.

Deployment Safeguards puts that page into admission control. It is a Microsoft-maintained set of Azure Policy definitions for Kubernetes best practices, and you turn it on with one setting instead of assembling the policies yourself. On AKS Automatic it is always on, at `Enforce` with Baseline Pod Security Standards, and you can't switch it to `Warn`. On AKS Standard, where most production clusters still run, it is opt-in.

The documentation lists the policies. It doesn't show what happens to a real team's manifests when you move from `Warn` to `Enforce`, and that change is where adoption usually fails. Workloads that deployed yesterday are denied today. Pods that requested 50 MiB now request 2 GiB, and the cluster autoscaler notices before you do. And the "temporary" namespace exclusion is still there two years later.

This lab makes each of those failures happen on purpose, in a cluster you'll delete before lunch.

## How it works

```
kubectl apply ──► kube-apiserver
                    │
                    ├─ mutating admission ── safeguards-workload-mutating-webhook (Enforce only)
                    │                          • resource requests/limits defaults and floors
                    │                          • pod anti-affinity + topology spread
                    │                          • (node pools) CriticalAddonsOnly removed from user pools
                    │
                    ├─ validating admission ─ safeguards: Azure Policy add-on (Gatekeeper constraints)
                    │                          PSS: AKS-managed ValidatingAdmissionPolicies
                    │                          • Warn    → admitted + "Warning: [azurepolicy-…]"
                    │                          • Enforce → "denied the request: [azurepolicy-…]"
                    │                                      or "ValidatingAdmissionPolicy 'aks-managed-…' denied"
                    │
                    └─ etcd
```

Five facts shape the rest of the lab:

1. The Azure Policy add-on is the only prerequisite. Cluster admins don't need Azure Policy permissions to turn safeguards on, but the add-on must be installed and the `Microsoft.PolicyInsights` provider registered.
2. It's all or nothing. You can't choose individual safeguards or individual mutations. You control three things: the level (`Warn` or `Enforce`), the Pod Security Standards level (`Privileged`, `Baseline` or `Restricted`) and the list of excluded namespaces.
3. Mutation runs before validation. In `Enforce`, a Deployment with no requests is fixed and admitted. A Deployment that uses `:latest` can't be fixed, so it is denied.
4. It fails open. Validation runs on Gatekeeper, and if the webhook doesn't answer in time, the request is admitted. Treat safeguards as a guardrail for well-meaning teams and pair it with the controls in [Securing AKS in 2026](../08-aks-security-2026/ARTICLE.md) for anything security-relevant.
5. Policy sync is asynchronous. Microsoft says to allow 15 to 20 minutes after you enable safeguards or change the level. On my cluster, level and PSS changes showed up within a minute or two of `az aks safeguards update` returning, but the first enablement takes longer. Don't guess: [`wait-for-safeguards.sh`](scripts/wait-for-safeguards.sh) tells you when the sync is done.

## What gets checked, and what each level does

| Safeguard | `Warn` | `Enforce` | Scenario |
| --- | --- | --- | --- |
| Container images must not use `latest` (or no tag) | warning | deny | S02 |
| Readiness and liveness probes required | warning | warning (stays at warn, see below) | S03 |
| CPU and memory requests required | warning | mutate: 500m CPU, 2048Mi memory | S04 |
| Request and limit floor | none | mutate: raised to 100m CPU, 100Mi memory | S05 |
| Anti-affinity or topology spread for >1 replica | warning | mutate: preferred anti-affinity + `maxSkew: 1` spread | S06 |
| Services must use unique selectors (same selector and an overlapping port) | warning | deny | S07 |
| No `kubernetes.azure.com` label key (exact key only) | warning | deny | S08 |
| StorageClass must use a CSI driver | warning | deny | S09 |
| Can't edit individual nodes (label or taint) | warning | deny | S10 |
| Reserved system pool taints (`CriticalAddonsOnly` on user pools) | n/a | mutate: taint removed | Bonus B1 |
| Only allowed images | parameterised by the initiative; this lab doesn't change it | n/a | n/a |
| PSS Baseline (host namespaces, privileged, hostPath, hostPort, capabilities, …) | warning\* | deny\* | S11 |
| PSS Restricted (non-root, seccomp, drop ALL, no privilege escalation, volume types) | warning\* | deny\* | S12 |

\* Applies only when the PSS level is set to Baseline or Restricted. The AKS Standard default is Privileged, which enforces nothing. PSS findings follow the safeguards level: at `Warn` they are warnings, at `Enforce` they are denials. S01 is the golden workload that passes everything, including Restricted. S13 repeats S02's violation in an excluded namespace.

## Lab layout

```
03-Deployment-Safeguards-Lab/
├── terraform/            # AKS Standard + Azure Policy add-on + azurerm_kubernetes_cluster_deployment_safeguard
├── bicep/                # Same, with Microsoft.ContainerService/deploymentSafeguards@2025-07-01
├── scenarios/            # S01–S13 manifests + expected.tsv (the outcome matrix)
├── scripts/
│   ├── wait-for-safeguards.sh   # block until the policy sync reflects the requested level
│   ├── run-scenarios.sh         # run all scenarios, compare to expected, write results-<level>-<pss>.md
│   └── cleanup.sh
├── preflight/            # offline shift-left linter + 84 pytest cases
└── ci/                   # GitHub Actions workflow for app repos
```

## Step 1: Deploy the cluster

The cluster is small on purpose: one system node (tainted `CriticalAddonsOnly`), two user nodes, the Free tier and Azure CNI Overlay with Cilium. The only setting this lab depends on is `azure_policy_enabled = true`.

### Option A: Terraform

```bash
az provider register --namespace Microsoft.PolicyInsights
cd terraform
cp terraform.tfvars.example terraform.tfvars   # set subscription_id
terraform init && terraform apply
$(terraform output -raw get_credentials)
```

The safeguard is its own resource, so changing the level is an in-place update and never replaces the cluster:

```hcl
resource "azurerm_kubernetes_cluster_deployment_safeguard" "lab" {
  kubernetes_cluster_id        = azurerm_kubernetes_cluster.lab.id
  level                        = var.safeguards_level    # Warn | Enforce
  pod_security_standards_level = var.pss_level           # Privileged | Baseline | Restricted
  excluded_namespaces          = var.excluded_namespaces # ["lab-legacy"]
}
```

### Option B: Bicep

```bash
az provider register --namespace Microsoft.PolicyInsights
az group create -n rg-lab-safeguards -l westeurope
az deployment group create -g rg-lab-safeguards -f bicep/main.bicep -p bicep/main.bicepparam
az aks get-credentials -g rg-lab-safeguards -n aks-lab-safeguards
```

In ARM, Deployment Safeguards is an extension resource on the cluster, and its name is always `default`:

```bicep
resource safeguards 'Microsoft.ContainerService/deploymentSafeguards@2025-07-01' = {
  name: 'default'
  scope: aks
  properties: {
    level: safeguardsLevel                          // Warn | Enforce
    podSecurityStandardsLevel: podSecurityStandardsLevel
    excludedNamespaces: excludedNamespaces
  }
}
```

The resource also returns a read-only `systemExcludedNamespaces` list of the namespaces AKS exempts on your behalf, and the template outputs it. Read it once before you add your own exclusions, so you know what is already outside the guardrail.

### Option C: CLI only (for comparison)

`az aks safeguards` is GA in the core CLI:

```bash
az aks safeguards create -g <rg> -n <cluster> --level Warn --excluded-ns lab-legacy
az aks safeguards update -g <rg> -n <cluster> --level Enforce --pss-level Restricted
az aks safeguards show   -g <rg> -n <cluster> -o table
```

> **Architect's note:** Pick one owner. If Terraform owns the safeguard and someone runs `az aks safeguards update`, the next plan reverts the change. That's correct, as long as everyone knows Git is the source of truth. Raise the level in the same pull request as the workload fixes that make the change safe.

## Step 2: Wait for the policy sync

```bash
./scripts/wait-for-safeguards.sh Warn
# 21:25:33 safeguards constraints=10 (enforcementAction=warn: 10), azure VAP bindings=0
# Safeguards look synced at level Warn.
```

The script reads the Gatekeeper constraints created by the safeguards policy assignment and checks their effective action: `warn` for Warn, `deny` for Enforce. Two details caught me out on a live cluster:

- Current add-on versions set `enforcementAction: scoped` and put the real action in `spec.scopedEnforcementActions` (for example `warn` plus `dryrun` for audit). A script that only reads `enforcementAction` never sees `warn` or `deny` and waits forever.
- If Defender for Cloud is on, its `SecurityCenterBuiltIn` assignment adds a dozen audit-only (`dryrun`) constraints of the same `K8sAzure*` kinds. The script filters on the assignment ID so they don't skew the count.

The exact counts depend on the safeguards version and the PSS level. With PSS at Baseline or Restricted, AKS also creates `aks-managed-baseline-*` and `aks-managed-restricted-*` ValidatingAdmissionPolicy bindings, set to `[Warn Audit]` at Warn and `[Deny Audit]` at Enforce.

## Step 3: Round 1, Warn + Privileged (observe)

```bash
./scripts/run-scenarios.sh Warn Privileged
```

Most cases use server-side dry-run (`kubectl apply --dry-run=server`). The request goes through the full admission chain, mutating and validating webhooks included, but nothing is persisted, so you can point it at a shared cluster.

Output from my run (AKS 1.36, one-node Standard cluster):

```
S01  Golden path (Restricted-ready)         expected=ADMIT  actual=ADMIT
S02  :latest image tag                      expected=WARN   actual=WARN
S03  No readiness/liveness probes           expected=WARN   actual=WARN
S04  No requests/limits                     expected=WARN   actual=WARN
S05  Requests below 100m/100Mi floor        expected=ADMIT  actual=ADMIT
S06  3 replicas, no spread rules            expected=WARN   actual=WARN
S07  Service selector clash                 expected=WARN   actual=WARN
S08  kubernetes.azure.com label             expected=WARN   actual=WARN
S09  In-tree azure-disk StorageClass        expected=WARN   actual=WARN
S10  kubectl label on a single node         expected=WARN   actual=WARN
S11  hostNetwork + privileged               expected=ADMIT  actual=ADMIT
S12  Root, no seccomp, no cap drop          expected=ADMIT  actual=ADMIT
S13  :latest in excluded namespace          expected=ADMIT  actual=ADMIT
```

My first run had S07 and S08 admitted with no warning. Both were scenario bugs, and both taught me something about the policies:

- S07: the unique-selector policy only flags a clash when the two Services share a selector and at least one port/protocol pair. My duplicate used port 8080 against the golden Service's port 80, so there was no clash. Headless Services are skipped too.
- S08: the reserved-label policy matches the exact key `kubernetes.azure.com`. My scenario used `kubernetes.azure.com/team`, which is admitted. So is `kubernetes.azure.com/mode`.

Every run also writes `results-Warn-Privileged.md`, with the first warning or denial message for each scenario as evidence. Commit it next to your rollout ticket.

Stay on `Warn` for at least one release cycle and turn the warnings into a backlog. Compliance also shows up in Azure Policy: open the cluster, select **Policies**, then **Go to Azure Policy**, and pick the Deployment Safeguards initiative. The initiative must be scoped to the cluster's resource group for the assessment to work.

> **Warning:** `Warn` is visible only to whoever runs `kubectl`. If you deploy through Flux, Argo CD or a pipeline, the warning ends up in a controller log that nobody reads. During the Warn phase, use the Azure Policy compliance view or the preflight from Step 7 to track findings.

## Step 4: Round 2, Enforce (block and mutate)

Change the level and re-apply. With Terraform, set `safeguards_level = "Enforce"` and run `terraform apply`. With Bicep, set `param safeguardsLevel = 'Enforce'` and redeploy. Then:

```bash
./scripts/wait-for-safeguards.sh Enforce
./scripts/run-scenarios.sh Enforce Privileged
```

The results now fall into three groups.

- Denied: S02, S07, S08, S09 and S10. None of these can be fixed automatically. A denial looks like this:

  ```
  Error from server (Forbidden): ... admission webhook "validation.gatekeeper.sh" denied the request:
  [azurepolicy-k8sazurev2containernolatestima-<hash>] Avoiding the latest tag for container: web ...
  ```

- Warned but admitted: S03. The probes safeguard stays at `warn` under `Enforce`, so a workload with no probes still deploys. Its constraint is one of two that keep `warn` at Enforce; the other is an informational policy that annotates mutations. If you want probes enforced, enforce them yourself in CI with the preflight from Step 7.

- Mutated and admitted: S04, S05 and S06. The runner applies these for real, waits for the rollout and reads back the pod rather than the Deployment, because the pod spec is what the scheduler places and what you pay for:

  | Scenario | You wrote | The pod got |
  | --- | --- | --- |
  | S04: no resources | nothing | `requests` and `limits` of 500m CPU / 2048Mi memory |
  | S05: tiny resources | `20m/32Mi` requests, `50m/64Mi` limits | 100m / 100Mi requests and limits |
  | S06: 3 replicas, no spread | nothing | preferred `podAntiAffinity` (weight 100) + `topologySpreadConstraints` (`maxSkew: 1`, `ScheduleAnyway`, `kubernetes.io/hostname`) |

  The mutation is also visible without deploying anything. A server-side dry-run of the Deployment returns the rewritten pod template, and kubectl prints `Warning: nores had resource requests and limits added or adjusted…`. The floor applies when only limits are set too: limits of `50m/64Mi` came back as 100m / 100Mi, with requests set to match.

- Admitted unchanged: S01, plus S13 in the excluded namespace.

### The FinOps trap in S04

The resource mutator's default is generous: 2 GiB of memory per container, as both request and limit. A team that never set requests, which is the team this safeguard targets, goes overnight from best effort to 2 GiB guaranteed per container. Add a sidecar and the pod reserves 4 GiB.

A 16 GiB node then fits three or four of those pods, where yesterday it ran twenty. Cluster autoscaler, or [Node Auto Provisioning](../03-node-auto-provisioning/ARTICLE.md), will happily buy nodes to fit them.

The mutator is a fallback. Size the workloads yourself before you get there:
1. During the Warn phase, query workloads without requests and give each one a real value from VPA recommendations or Container Insights.
2. Before you move to Enforce, run a capacity check: the number of containers without requests multiplied by 2 GiB. If that number scares you, you're not ready.
3. Ship sensible requests in your golden templates and Helm defaults so nothing reaches the cluster without them. Don't count on a namespace `LimitRange` as a second net. The mutator rewrites the Deployment's pod template, so by the time the Pod reaches `LimitRanger` it already has 500m / 2Gi, and your LimitRange defaults never apply (bonus scenario B3).

Two more rules from the mutator:
- Memory is handled differently from CPU. If only a memory request exists, the mutator leaves it alone and adds no limit. If only a CPU request or limit exists, it sets both to the same value.
- After mutation, any request above its limit is lowered to the limit, so the pod keeps a valid QoS class.

### The anti-affinity mutator only prefers spreading

S06 gets preferred anti-affinity and `ScheduleAnyway` spread. That improves the odds, but three replicas can still land on one node if that's where the capacity is. For anything with a real availability requirement, write your own spread constraints across `topology.kubernetes.io/zone` with `DoNotSchedule`, and add a PodDisruptionBudget. The mutator skips any workload that already has spread constraints or pod anti-affinity, so your own rules take precedence.

## Step 5: Rounds 3 and 4, Pod Security Standards

```bash
# terraform: pss_level = "Baseline"   |  bicep: podSecurityStandardsLevel = 'Baseline'
./scripts/wait-for-safeguards.sh Enforce
./scripts/run-scenarios.sh Enforce Baseline

# then pss_level = "Restricted"
./scripts/run-scenarios.sh Enforce Restricted
```

| Scenario | Privileged | Baseline | Restricted |
| --- | --- | --- | --- |
| S01: golden path | admit | admit | admit |
| S11: `hostNetwork` + `privileged` | admit | deny | deny |
| S12: root, no seccomp, keeps capabilities | admit | admit | deny |

All four rounds came back 13/13 on my cluster. At Baseline and Restricted, the denials come from AKS-managed ValidatingAdmissionPolicies rather than Gatekeeper, for example `ValidatingAdmissionPolicy 'aks-managed-restricted-privilege-escalation' ... denied request`. I also ran Warn + Restricted: S11 and S12 come back as warnings, so you can measure your distance from Restricted without blocking anything.

S12 matters most. Most off-the-shelf images run as root without a seccomp profile. They pass Baseline, so a cluster can sit at Baseline for months before anyone measures how far it is from Restricted.

The difference between S01 and S12 is what your teams have to add:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: { type: RuntimeDefault }
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true   # not required by Restricted, but do it anyway
        capabilities: { drop: ["ALL"] }
```

> **Architect's note:** In safeguards, the PSS level applies to the whole cluster. The only per-namespace control is exclusion. If you need Restricted for apps and Baseline for a monitoring agent, you have two choices:
> - Exclude the agent's namespace from safeguards and label it with upstream `pod-security.kubernetes.io/enforce=baseline`, so it still has some protection.
> - Keep the cluster at Baseline and enforce Restricted per namespace with upstream Pod Security Admission labels.
>
> Both work. The first keeps Azure Policy compliance reporting for the apps, which is usually what auditors ask for.

## Step 6: Exclusions

S13 repeats S02's `:latest` violation in `lab-legacy`, which is excluded, and it's admitted at every level. Keep in mind that an exclusion turns off both the safeguards and Pod Security Standards for that namespace.

The rules I use on real estates:

| Rule | Why |
| --- | --- |
| Exclusions live in IaC (`excluded_namespaces` / `excludedNamespaces`), never ad hoc CLI | The pull request is the approval, and `git blame` is the audit trail |
| Every excluded namespace gets an owner and an expiry label (`platform.example.com/exclusion-expires: 2026-12-31`) | A stale exclusion is a policy you don't have |
| Excluded namespaces still get upstream PSA labels | Excluding a namespace from safeguards shouldn't leave it at `privileged` |
| Review `systemExcludedNamespaces` after every AKS upgrade | You need to know what the platform exempts for you |
| Never exclude a namespace to "unblock a deploy" | Fix the manifest; the preflight in Step 7 shows what to change |

## Step 7: Run the same checks in CI

A denial at `kubectl apply` time is a failed deployment. The same finding in a pull request is a review comment. [`preflight/preflight.py`](preflight/preflight.py) approximates the safeguards and PSS checks offline:

```bash
python3 preflight/preflight.py --level Enforce --pss Restricted --exclude lab-legacy scenarios/
```

```
DENY    DS-LATEST-TAG        Deployment/lab-apps/latest: container web uses an untagged or ':latest' image (…:latest)
WARN    DS-PROBES            Deployment/lab-apps/noprobes: container web has no readinessProbe, livenessProbe
MUTATE  DS-REQUESTS          Deployment/lab-apps/nores: container web has no cpu/memory requests (Enforce sets 500m / 2048Mi)
MUTATE  DS-REQUEST-FLOOR     Deployment/lab-apps/tiny: container web cpu=20m is below the 100m floor
MUTATE  DS-ANTI-AFFINITY     Deployment/lab-apps/noaff: 3 replicas without podAntiAffinity or topologySpreadConstraints
DENY    DS-UNIQUE-SELECTOR   Service/lab-apps/web-duplicate: selector {'app': 'web'} and port(s) ['TCP:80'] already used by Service web
DENY    DS-RESERVED-LABEL    Deployment/lab-apps/reslabel: label kubernetes.azure.com is reserved for AKS
DENY    DS-CSI-STORAGECLASS  StorageClass/default/lab-intree-disk: in-tree provisioner kubernetes.io/azure-disk; …
DENY    PSS-BASELINE         Deployment/lab-apps/hostnet: hostNetwork is true
DENY    PSS-RESTRICTED       Deployment/lab-apps/rootish: container web must set runAsNonRoot=true
...
verdict: DENY (level=Enforce, pss=Restricted, findings=21)
```

The tool exits non-zero on any `DENY`. It reports `MUTATE` findings without failing, because those workloads do deploy, just not as written. [`ci/safeguards-preflight.yml`](ci/safeguards-preflight.yml) runs kubeconform and then the preflight, and `--github` turns findings into pull request annotations.

**Tested:** [`preflight/tests`](preflight/tests/test_preflight.py) drives the preflight with the same [`expected.tsv`](scenarios/expected.tsv) matrix the live runner uses: 12 manifest scenarios × 2 levels × 3 PSS levels, plus parser edge cases and the behaviour the live run uncovered (port overlap, exact label key, bare Pods), for 84 passing tests. The preflight's verdict for each scenario matches the live cluster in all four rounds.

```bash
pip install pyyaml pytest && pytest -q preflight/tests
```

> **Warning:** The preflight is an approximation. It can't see cluster state (other Services' selectors, the allowed-images parameter) or safeguards added in a later version, so the cluster's verdict is the one that counts. Safeguards are versioned with AKS add-on releases, so re-run `run-scenarios.sh` as a canary after every AKS upgrade.

## Bonus scenarios

| # | Try this | What you should see |
| --- | --- | --- |
| B1 | `az aks nodepool add -g <rg> --cluster-name <aks> -n tainted --node-count 1 --node-taints CriticalAddonsOnly=true:NoSchedule` at Enforce | The reserved system pool taint is removed from the user pool, so your pods can still schedule there |
| B2 | `kubectl taint node <user-node> lab=true:NoSchedule` | Denied at Enforce, like S10. Taint and label node pools through the AKS API instead |
| B3 | Add a `LimitRange` (default requests 250m/256Mi) to `lab-apps` and re-deploy S04 at Enforce | Tested: the pod gets 500m / 2Gi. The mutator rewrites the Deployment template, so `LimitRanger` has nothing left to default. A bare Pod with no requests is different: the mutator leaves it alone, so it's denied at Enforce, or admitted with the LimitRange defaults if one exists |
| B4 | Disable with `az aks safeguards delete …`, then re-run Round 1 | Every scenario is admitted without warnings. This is your rollback path, and it takes effect after the policy sync, not instantly |
| B5 | Run `terraform plan` after an `az aks safeguards update --level Warn` | Terraform reports drift. Decide who owns the setting |

## A rollout plan for a real fleet

| Week | Non-production | Production | Exit criteria |
| --- | --- | --- | --- |
| 0 | Preflight in CI (report only) | n/a | Baseline of findings per team |
| 1-2 | `Warn` + `Privileged` | `Warn` + `Privileged` | Backlog of warnings created; requests sized (no 2 GiB surprises) |
| 3-4 | `Enforce` + `Baseline` | `Warn` + `Baseline` | Zero deny-class findings in non-prod for 2 weeks |
| 5-6 | `Enforce` + `Restricted` | `Enforce` + `Baseline` | Exclusions documented, owned and dated |
| 8+ | n/a | `Enforce` + `Restricted` | Preflight blocking in CI; `run-scenarios.sh` run after each AKS upgrade |

Ship each step as a pull request against the Terraform or Bicep shown above, so rolling back is one revert.

## Gotchas

| Symptom | Cause | Fix |
| --- | --- | --- |
| Nothing is warned or denied for 15 minutes | Policy sync is asynchronous | `wait-for-safeguards.sh` |
| Pods suddenly request 2Gi | Resource mutator defaults | Set explicit requests in templates and charts |
| CI deploys pass, but nobody sees warnings | `Warn` only prints to the client | Use the Azure Policy compliance view and the preflight |
| Can't set `Warn` on AKS Automatic | By design | Use namespace exclusions sparingly |
| A non-compliant pod was admitted | Gatekeeper fails open, or the namespace is excluded or system-excluded | Check `systemExcludedNamespaces` and Gatekeeper health; don't rely on safeguards as a security control |
| Helm charts denied for `:latest` / no probes | Chart defaults | Override `image.tag` and the probe values; fork the chart if you have to |
| The node label or taint step in a runbook now fails | "Cannot edit individual nodes" | Use `az aks nodepool update --labels/--node-taints` |

## What it costs

| Item | Lab estimate |
| --- | --- |
| 3 × `Standard_D2ds_v5` (westeurope, PAYG) | US$0.136/hour each, about US$0.41/hour |
| OS disks, Standard Load Balancer, public IP | a few cents per hour |
| AKS control plane (Free tier), Azure Policy add-on, Deployment Safeguards | no additional charge |
| Total | About US$0.50/hour, so a 2-hour lab costs about a dollar |

Prices are pay-as-you-go rates from the Azure Retail Prices API at the time of writing. Check the [AKS pricing page](https://azure.microsoft.com/en-us/pricing/details/kubernetes-service/) for your region.

## Cleanup

```bash
./scripts/cleanup.sh                         # namespaces + StorageClass
terraform -chdir=terraform destroy           # or:
RG=rg-lab-safeguards ./scripts/cleanup.sh --all
```

## Checklist

- [ ] Azure Policy add-on enabled and `Microsoft.PolicyInsights` registered
- [ ] The safeguard level, PSS level and exclusions live in IaC, with one owner
- [ ] `systemExcludedNamespaces` reviewed
- [ ] Warn phase ran for at least one release cycle, tracked in the compliance view
- [ ] Workloads without requests sized before Enforce (no 2 GiB surprises)
- [ ] Critical workloads define their own zone spread and a PDB
- [ ] PSS raised from Baseline to Restricted, with the golden `securityContext` in your templates
- [ ] Every exclusion has an owner, an expiry and upstream PSA labels
- [ ] Preflight blocking in CI, with `run-scenarios.sh` as a post-upgrade canary
- [ ] Runbooks use node-pool operations, never `kubectl label/taint node`

## References and further reading

**Microsoft Learn**
- [Use Deployment Safeguards to enforce best practices in AKS](https://learn.microsoft.com/en-us/azure/aks/deployment-safeguards): the policy list, mutator rules, error messages and FAQ
- [`az aks safeguards` CLI reference](https://learn.microsoft.com/en-us/cli/azure/aks/safeguards): `create`, `update`, `show`, `--pss-level`, `--excluded-ns`
- [`Microsoft.ContainerService/deploymentSafeguards` template reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.containerservice/deploymentsafeguards): Bicep, ARM and Terraform AzAPI schema
- [Azure Policy for Kubernetes](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/policy-for-kubernetes): how the add-on, Gatekeeper and policy sync work
- [Secure your cluster with Azure Policy](https://learn.microsoft.com/en-us/azure/aks/use-azure-policy): assigning built-in initiatives beyond safeguards
- [Azure Policy built-in definitions for AKS](https://learn.microsoft.com/en-us/azure/aks/policy-reference): the definitions behind each safeguard
- [AKS Automatic overview](https://learn.microsoft.com/en-us/azure/aks/intro-aks-automatic): where safeguards are always on
- [CSI drivers on AKS](https://learn.microsoft.com/en-us/azure/aks/csi-storage-drivers): replacing in-tree StorageClasses (S09)
- [Manage system node pools](https://learn.microsoft.com/en-us/azure/aks/use-system-pools): `CriticalAddonsOnly` and pool separation (B1)
- [Resource management best practices](https://learn.microsoft.com/en-us/azure/aks/developer-best-practices-resource-management): sizing requests before the mutator does it for you
- [Advanced scheduler best practices](https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-advanced-scheduler): taints, tolerations and affinity on AKS

**Upstream and community**
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/): Baseline and Restricted, field by field
- [Topology spread constraints](https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/): what the S06 mutator adds, and how to do better
- [Server-side dry-run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run): why the runner can test admission without side effects
- [Gatekeeper: failing closed](https://open-policy-agent.github.io/gatekeeper/website/docs/failing-closed/): the fail-open trade-off behind safeguards
- [Gatekeeper mutation](https://open-policy-agent.github.io/gatekeeper/website/docs/mutation/): the mechanism behind the mutators
- [`azurerm_kubernetes_cluster_deployment_safeguard`](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster_deployment_safeguard): the Terraform resource used here
- [kubeconform](https://github.com/yannh/kubeconform): the schema check in the CI workflow
- [AKS release notes](https://github.com/Azure/AKS/releases): where new safeguard versions are announced

**In this series**
- [Securing AKS in 2026](../08-aks-security-2026/ARTICLE.md): where safeguards sit in a full security baseline (Layer 4)
- [ValidatingAdmissionPolicy vs Azure Policy](../05-validating-admission-policy-vs-azure-policy/ARTICLE.md): writing your own rules when the curated set isn't enough
- [Node Auto Provisioning](../03-node-auto-provisioning/ARTICLE.md): what happens to node count when the mutator inflates requests
- [The AKS upgrade playbook](../06-aks-upgrade-playbook/ARTICLE.md): safeguards versions ship with AKS upgrades, so re-run the canary
