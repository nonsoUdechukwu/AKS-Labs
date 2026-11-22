# Deployment Safeguards scenarios: level=Warn, pss=Privileged

Run at 2026-11-22T20:26:18Z against `aks-lab`.

| ID | Scenario | Expected | Actual | Result | Evidence |
|---|---|---|---|---|---|
| S01 | Golden path (Restricted-ready) | ADMIT | ADMIT | ✅ | `` |
| S02 | :latest image tag | WARN | WARN | ✅ | `[azurepolicy-k8sazurev2containernolatestima-632d3a809c0e99ccea72] [Implied by gatekeeper-expand-workloads] Avoiding the latest tag for container: web in Kuberne` |
| S03 | No readiness/liveness probes | WARN | WARN | ✅ | `[azurepolicy-k8sazurev2containerenforceprob-63ea9f48d2632646dc36] [Implied by gatekeeper-expand-workloads] Container <web> in your Pod <noprobes-pod> has no <li` |
| S04 | No requests/limits | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1containerrequests-26e035f8d0c06cf5ecb8] [Implied by gatekeeper-expand-workloads] container <web> has no resource requests. For more infor` |
| S05 | Requests below 100m/100Mi floor | ADMIT | ADMIT | ✅ | `` |
| S06 | 3 replicas, no spread rules | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1antiaffinityrules-a186aff655f4878c5964] Deployment with 3 replicas should have either podAntiAffinity or topologySpreadConstraints set to` |
| S07 | Service selector clash | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1uniqueserviceselecto-7165f624ac3f8cd81ee3] same selector as service <web> in namespace <lab-apps> with overlapping ports. For more inform` |
| S08 | kubernetes.azure.com label | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1restrictedlabels-2d38d7860805ea9fa352] [Implied by gatekeeper-expand-workloads] Label <{"kubernetes.azure.com"}> is reserved for AKS use ` |
| S09 | In-tree azure-disk StorageClass | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1enforcecsidriver-686c531c0918b11c2486] Storage class lab-intree-disk use intree provisioner kubernetes.io/azure-disk is not allowed. For ` |
| S10 | kubectl label on a single node | WARN | WARN | ✅ | `[azurepolicy-k8sazurev1restrictednodeedits-df78747d78552fcb8652] Tainting or labelling individual nodes is not recommended. Please use AZ CLI to taint/label nod` |
| S11 | hostNetwork + privileged | ADMIT | ADMIT | ✅ | `` |
| S12 | Root, no seccomp, no cap drop | ADMIT | ADMIT | ✅ | `` |
| S13 | :latest in excluded namespace | ADMIT | ADMIT | ✅ | `` |
