#!/usr/bin/env python3
"""AKS security posture check: the 2026 baseline as code.

Reads `az aks show` and `az aks nodepool list` JSON (live via az, or from files) and
evaluates the controls from the article. Read-only. Exits 1 if any control FAILs, so it
can gate a pipeline. Controls are grouped by layer; they are not CIS benchmark IDs.

  python3 aks_posture.py -g rg-plat-prod-aks -n aks-plat-prod
  python3 aks_posture.py --cluster-json c.json --nodepools-json np.json --format json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"

# Node images that carry the AKS-2026-0003 (CVE-2026-31431, "Copy Fail") mitigation.
COPY_FAIL_FIXED = (202604, 13, 0)
COPY_FAIL_AFFECTED_SKUS = {"Ubuntu", "Ubuntu2204", "Ubuntu2404", "AzureLinux", "AzureLinux3"}
MODERN_LINUX_SKUS = {"AzureLinux3", "Ubuntu2404", "AzureContainerLinux"}
USERNS_SKUS = {"AzureLinux3", "Ubuntu2404"}


@dataclass
class Result:
    id: str
    layer: str
    title: str
    status: str
    detail: str


def g(obj, path, default=None):
    """Get a nested key from az JSON, tolerating camelCase/None."""
    cur = obj
    for key in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def k8s_minor(version: str | None) -> tuple[int, int]:
    m = re.match(r"(\d+)\.(\d+)", version or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def image_version(node_image: str | None) -> tuple[int, int, int] | None:
    m = re.search(r"(\d{6})\.(\d{2})\.(\d+)$", node_image or "")
    return tuple(int(x) for x in m.groups()) if m else None


def linux_pools(pools):
    return [p for p in pools if (p.get("osType") or "Linux") == "Linux"]


def pool_check(pools, pred, ok_detail, bad_detail):
    bad = [p["name"] for p in pools if not pred(p)]
    return (FAIL, bad_detail + ": " + ", ".join(bad)) if bad else (PASS, ok_detail)


def evaluate(cluster: dict, pools: list[dict], safeguards: dict | None = None) -> list[Result]:
    r: list[Result] = []

    def add(id_, layer, title, status_detail):
        status, detail = status_detail
        r.append(Result(id_, layer, title, status, detail))

    version = g(cluster, "currentKubernetesVersion") or g(cluster, "kubernetesVersion")
    minor = k8s_minor(version)
    lpools = linux_pools(pools)

    # ------------------------------------------------------------- identity
    add("ID-01", "identity", "Local accounts disabled",
        (PASS, "Entra ID only") if g(cluster, "disableLocalAccounts") else
        (FAIL, "static admin kubeconfig available (az aks get-credentials --admin)"))
    add("ID-02", "identity", "Azure RBAC for Kubernetes authorization",
        (PASS, "enabled") if g(cluster, "aadProfile.enableAzureRbac") or g(cluster, "aadProfile.enableAzureRBAC") else
        (FAIL, "authorization lives only in in-cluster RoleBindings"))
    wi = g(cluster, "securityProfile.workloadIdentity.enabled") and g(cluster, "oidcIssuerProfile.enabled")
    add("ID-03", "identity", "Workload identity (OIDC issuer + webhook)",
        (PASS, "enabled") if wi else (FAIL, "pods fall back to secrets or the node identity"))
    add("ID-04", "identity", "Legacy pod identity removed",
        (FAIL, "aad-pod-identity is deprecated; migrate to workload identity")
        if g(cluster, "podIdentityProfile.enabled") else (PASS, "not enabled"))
    add("ID-05", "identity", "Run command disabled",
        (PASS, "disabled") if g(cluster, "apiServerAccessProfile.disableRunCommand") else
        (WARN, "az aks command invoke bypasses network restrictions on the API server"))

    # ------------------------------------------------------------- control plane / network
    private = g(cluster, "apiServerAccessProfile.enablePrivateCluster")
    ranges = g(cluster, "apiServerAccessProfile.authorizedIpRanges") or g(cluster, "apiServerAccessProfile.authorizedIPRanges") or []
    add("NET-01", "network", "API server not open to the internet",
        (PASS, "private cluster") if private else
        (PASS, f"{len(ranges)} authorized range(s)") if ranges else
        (FAIL, "public endpoint reachable from 0.0.0.0/0"))
    add("NET-02", "network", "API server VNet integration",
        (PASS, "enabled") if g(cluster, "apiServerAccessProfile.enableVnetIntegration") else
        (WARN, "node-to-control-plane traffic uses the konnectivity tunnel"))
    policy = g(cluster, "networkProfile.networkPolicy")
    add("NET-03", "network", "NetworkPolicy engine",
        (PASS, policy) if policy and policy != "none" else (FAIL, "NetworkPolicy objects are not enforced"))
    link_local = g(cluster, "networkProfile.podLinkLocalAccess")
    add("NET-04", "network", "Pod access to IMDS",
        (PASS, "IMDS restriction enabled (podLinkLocalAccess=None)") if link_local == "None" else
        (INFO, "pods can reach IMDS unless a NetworkPolicy blocks it (IMDS restriction is preview, check add-on compatibility)"))

    # ------------------------------------------------------------- admission
    policy_addon = g(cluster, "addonProfiles.azurepolicy.enabled") or g(cluster, "addonProfiles.azurePolicy.enabled")
    add("ADM-01", "admission", "Azure Policy add-on",
        (PASS, "enabled") if policy_addon else (FAIL, "no managed admission policy, no Deployment Safeguards"))
    if safeguards is None:
        add("ADM-02", "admission", "Deployment Safeguards", (INFO, "not evaluated (pass --safeguards-json)"))
    else:
        level = g(safeguards, "properties.level") or g(safeguards, "level")
        pss = g(safeguards, "properties.podSecurityStandardsLevel") or g(safeguards, "podSecurityStandardsLevel") or g(safeguards, "podSecurityStandardLevel")
        if level == "Enforce" and pss == "Restricted":
            add("ADM-02", "admission", "Deployment Safeguards", (PASS, "Enforce + Restricted PSS"))
        elif level == "Enforce":
            add("ADM-02", "admission", "Deployment Safeguards", (WARN, f"Enforce, PSS {pss or 'Privileged'} (aim for Restricted)"))
        else:
            add("ADM-02", "admission", "Deployment Safeguards", (FAIL, f"level={level or 'off'}, PSS={pss or 'n/a'}"))

    # ------------------------------------------------------------- nodes
    add("NODE-01", "node", "Kubernetes 1.36+ (GA user namespaces, fine-grained kubelet authz, MutatingAdmissionPolicy)",
        (PASS, version) if minor >= (1, 36) else (WARN, f"{version}: upgrade to unlock the 1.36 security features"))
    add("NODE-02", "node", "Modern Linux OS SKU",
        pool_check(lpools, lambda p: p.get("osSku") in MODERN_LINUX_SKUS,
                   "AzureLinux3 / Ubuntu2404 / AzureContainerLinux", "older OS SKU on"))
    userns_ok = [p["name"] for p in lpools if p.get("osSku") in USERNS_SKUS]
    add("NODE-03", "node", "Pools that can run user-namespaced pods (hostUsers: false)",
        (PASS, ", ".join(userns_ok)) if userns_ok else (WARN, "no Azure Linux 3.0 / Ubuntu 24.04 pool"))
    add("NODE-04", "node", "Trusted Launch (Secure Boot + vTPM)",
        pool_check(lpools, lambda p: g(p, "securityProfile.enableSecureBoot") and g(p, "securityProfile.enableVtpm", g(p, "securityProfile.enableVTPM")),
                   "all Linux pools", "not enabled on"))
    add("NODE-05", "node", "SSH to nodes disabled",
        pool_check(lpools, lambda p: g(p, "securityProfile.sshAccess") in ("Disabled", "EntraId"),
                   "Disabled or Entra ID on all Linux pools", "local-user SSH on"))
    add("NODE-06", "node", "Encryption at host",
        pool_check(pools, lambda p: p.get("enableEncryptionAtHost"), "all pools", "not enabled on"))
    add("NODE-07", "node", "No public IPs on nodes",
        pool_check(pools, lambda p: not p.get("enableNodePublicIp"), "none", "public IPs on"))

    exposed = []
    for p in lpools:
        if p.get("osSku") not in COPY_FAIL_AFFECTED_SKUS:
            continue
        v = image_version(p.get("nodeImageVersion"))
        if v is None or v < COPY_FAIL_FIXED:
            exposed.append(f"{p['name']} ({p.get('nodeImageVersion')})")
    add("NODE-08", "node", "Node image has AKS-2026-0003 (CVE-2026-31431) mitigation",
        (FAIL, "upgrade node image or apply the mitigation DaemonSet: " + ", ".join(exposed)) if exposed else
        (PASS, f"all affected pools on >= {'.'.join(map(str, COPY_FAIL_FIXED))}"))

    channel = g(cluster, "autoUpgradeProfile.upgradeChannel") or "none"
    node_channel = g(cluster, "autoUpgradeProfile.nodeOsUpgradeChannel") or g(cluster, "autoUpgradeProfile.nodeOSUpgradeChannel") or "None"
    add("NODE-09", "node", "Automatic upgrade channels",
        (PASS, f"cluster={channel}, nodeOS={node_channel}") if channel != "none" and node_channel in ("NodeImage", "SecurityPatch") else
        (FAIL, f"cluster={channel}, nodeOS={node_channel}: kernel and runtime CVEs wait for a human"))

    # ------------------------------------------------------------- data
    kms = g(cluster, "securityProfile.azureKeyVaultKms.enabled")
    add("DATA-01", "data", "Secrets encrypted at rest in etcd",
        (PASS, "customer-managed key (KMS)") if kms else
        (PASS, "platform-managed key (default on 1.37+)") if minor >= (1, 37) else
        (WARN, "AKS storage encryption only; enable KMS or upgrade to 1.37+"))

    # ------------------------------------------------------------- supply chain / detection
    add("SUP-01", "supply-chain", "Image Cleaner",
        (PASS, f"every {g(cluster, 'securityProfile.imageCleaner.intervalHours')}h") if g(cluster, "securityProfile.imageCleaner.enabled") else
        (WARN, "stale, vulnerable images stay cached on nodes"))
    add("DET-01", "detection", "Defender for Containers sensor",
        (PASS, "enabled") if g(cluster, "securityProfile.defender.securityMonitoring.enabled") else
        (FAIL, "no runtime threat detection"))
    return r


def az_json(*args: str):
    out = subprocess.run(["az", *args, "-o", "json"], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def render_md(results: list[Result]) -> str:
    icon = {PASS: "✅", FAIL: "❌", WARN: "⚠️", INFO: "ℹ️"}
    lines = ["| ID | Layer | Control | Status | Detail |", "|---|---|---|---|---|"]
    for x in results:
        lines.append(f"| {x.id} | {x.layer} | {x.title} | {icon[x.status]} {x.status} | {x.detail} |")
    counts = {s: sum(1 for x in results if x.status == s) for s in (PASS, FAIL, WARN, INFO)}
    lines.append("")
    lines.append(f"**{counts[PASS]} pass, {counts[FAIL]} fail, {counts[WARN]} warn, {counts[INFO]} info**")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-g", "--resource-group")
    ap.add_argument("-n", "--name")
    ap.add_argument("--cluster-json", help="output of az aks show")
    ap.add_argument("--nodepools-json", help="output of az aks nodepool list")
    ap.add_argument("--safeguards-json", help="output of az aks safeguards show (optional)")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    a = ap.parse_args(argv)

    if a.cluster_json:
        cluster = json.load(open(a.cluster_json))
        pools = json.load(open(a.nodepools_json)) if a.nodepools_json else cluster.get("agentPoolProfiles", [])
    elif a.resource_group and a.name:
        cluster = az_json("aks", "show", "-g", a.resource_group, "-n", a.name)
        pools = az_json("aks", "nodepool", "list", "-g", a.resource_group, "--cluster-name", a.name)
    else:
        ap.error("use -g/-n or --cluster-json")
    safeguards = json.load(open(a.safeguards_json)) if a.safeguards_json else None

    results = evaluate(cluster, pools, safeguards)
    if a.format == "json":
        print(json.dumps([asdict(x) for x in results], indent=2))
    else:
        print(render_md(results))
    return 1 if any(x.status == FAIL for x in results) else 0


if __name__ == "__main__":
    sys.exit(main())
