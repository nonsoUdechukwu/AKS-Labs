# Deployment Safeguards scenarios: level=Enforce, pss=Privileged

Run at 2026-11-22T21:28:43Z against `aks-lab`.

| ID | Scenario | Expected | Actual | Result | Evidence |
|---|---|---|---|---|---|
| S01 | Golden path (Restricted-ready) | ADMIT | ADMIT | ✅ | `` |
| S02 | :latest image tag | DENY | DENY | ✅ | `[azurepolicy-k8sazurev2containernolatestima-632d3a809c0e99ccea72] [Implied by gatekeeper-expand-workloads] Avoiding the latest tag for container: web in Kuberne` |
| S03 | No readiness/liveness probes | WARN | WARN | ✅ | `[azurepolicy-k8sazurev2containerenforceprob-63ea9f48d2632646dc36] [Implied by gatekeeper-expand-workloads] Container <web> in your Pod <noprobes-pod> has no <li` |
| S04 | No requests/limits | MUTATE | MUTATE | ✅ | `{"r":{"limits":{"cpu":"500m","memory":"2Gi"},"requests":{"cpu":"500m","memory":"2Gi"}},"t":[{"labelSelector":{"matchLabels":{"app":"nores"}},"maxSkew":1,"topolo` |
| S05 | Requests below 100m/100Mi floor | MUTATE | MUTATE | ✅ | `{"r":{"limits":{"cpu":"100m","memory":"100Mi"},"requests":{"cpu":"100m","memory":"100Mi"}},"t":[{"labelSelector":{"matchLabels":{"app":"tiny"}},"maxSkew":1,"top` |
| S06 | 3 replicas, no spread rules | MUTATE | MUTATE | ✅ | `{"r":{"limits":{"cpu":"250m","memory":"128Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},"t":[{"labelSelector":{"matchLabels":{"app":"noaff"}},"maxSkew":1,"to` |
| S07 | Service selector clash | DENY | DENY | ✅ | `[azurepolicy-k8sazurev1uniqueserviceselecto-7165f624ac3f8cd81ee3] same selector as service <web> in namespace <lab-apps> with overlapping ports. For more inform` |
| S08 | kubernetes.azure.com label | DENY | DENY | ✅ | `[azurepolicy-k8sazurev1restrictedlabels-2d38d7860805ea9fa352] [Implied by gatekeeper-expand-workloads] Label <{"kubernetes.azure.com"}> is reserved for AKS use ` |
| S09 | In-tree azure-disk StorageClass | DENY | DENY | ✅ | `[azurepolicy-k8sazurev1enforcecsidriver-686c531c0918b11c2486] Storage class lab-intree-disk use intree provisioner kubernetes.io/azure-disk is not allowed. For ` |
| S10 | kubectl label on a single node | DENY | DENY | ✅ | `[azurepolicy-k8sazurev1restrictednodeedits-df78747d78552fcb8652] Tainting or labelling individual nodes is not recommended. Please use AZ CLI to taint/label nod` |
| S11 | hostNetwork + privileged | ADMIT | ADMIT | ✅ | `` |
| S12 | Root, no seccomp, no cap drop | ADMIT | ADMIT | ✅ | `` |
| S13 | :latest in excluded namespace | ADMIT | ADMIT | ✅ | `` |
