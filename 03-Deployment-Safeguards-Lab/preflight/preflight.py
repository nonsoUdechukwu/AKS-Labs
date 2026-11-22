#!/usr/bin/env python3
"""Shift-left preflight for AKS Deployment Safeguards.

Approximates what Deployment Safeguards (and its Pod Security Standards option) will do
to a set of manifests at a given level, so pull requests fail fast instead of at
`kubectl apply`. The cluster remains the source of truth; this is a fast, offline signal.

    python3 preflight.py --level Enforce --pss Restricted --exclude lab-legacy k8s/
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
PSS_ORDER = {"Privileged": 0, "Baseline": 1, "Restricted": 2}
BASELINE_CAPS = {
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE",
    "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"}
SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports",
    "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes",
}


@dataclass(frozen=True)
class Rule:
    id: str
    # Effect at Warn and Enforce levels: "warn", "deny", "mutate" or None (no effect).
    warn: str | None
    enforce: str | None
    pss: str | None = None  # minimum PSS level at which the rule applies


RULES = {
    r.id: r
    for r in [
        Rule("DS-LATEST-TAG", "warn", "deny"),
        Rule("DS-PROBES", "warn", "deny"),
        Rule("DS-REQUESTS", "warn", "mutate"),
        Rule("DS-REQUEST-FLOOR", None, "mutate"),
        Rule("DS-ANTI-AFFINITY", "warn", "mutate"),
        Rule("DS-RESERVED-LABEL", "warn", "deny"),
        Rule("DS-CSI-STORAGECLASS", "warn", "deny"),
        Rule("DS-UNIQUE-SELECTOR", "warn", "deny"),
        Rule("PSS-BASELINE", "warn", "deny", pss="Baseline"),
        Rule("PSS-RESTRICTED", "warn", "deny", pss="Restricted"),
    ]
}


@dataclass
class Finding:
    rule: str
    effect: str
    ref: str
    message: str


def _qty(value, unit: str) -> float | None:
    """Convert a Kubernetes quantity to millicores (cpu) or MiB (memory)."""
    if value is None:
        return None
    s = str(value)
    if unit == "cpu":
        return float(s[:-1]) if s.endswith("m") else float(s) * 1000
    m = re.fullmatch(r"([0-9.]+)([KMGTE]i?|[kmgte])?", s)
    if not m:
        return None
    n, suffix = float(m.group(1)), m.group(2) or ""
    factor = {
        "": 1 / 1048576, "k": 1000 / 1048576, "K": 1000 / 1048576, "Ki": 1 / 1024, "M": 1e6 / 1048576,
        "Mi": 1, "G": 1e9 / 1048576, "Gi": 1024, "T": 1e12 / 1048576, "Ti": 1048576,
    }.get(suffix, 1)
    return n * factor


def _pod_spec(doc: dict) -> tuple[dict, dict, int]:
    """Return (pod spec, pod template metadata, replicas) for any workload kind."""
    kind, spec = doc["kind"], doc.get("spec") or {}
    if kind == "Pod":
        return spec, doc.get("metadata") or {}, 1
    if kind == "CronJob":
        tpl = spec["jobTemplate"]["spec"]["template"]
        return tpl.get("spec") or {}, tpl.get("metadata") or {}, 1
    tpl = spec.get("template") or {}
    replicas = spec.get("replicas", 1) if kind in {"Deployment", "StatefulSet", "ReplicaSet"} else 1
    return tpl.get("spec") or {}, tpl.get("metadata") or {}, replicas


def _image_untagged_or_latest(image: str) -> bool:
    if "@" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


def check_workload(doc: dict, ref: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pod, tpl_meta, replicas = _pod_spec(doc)
    containers = pod.get("containers") or []
    all_containers = containers + (pod.get("initContainers") or []) + (pod.get("ephemeralContainers") or [])
    psc = pod.get("securityContext") or {}

    for c in containers:
        name = c.get("name", "?")
        if _image_untagged_or_latest(c.get("image", "")):
            out.append(("DS-LATEST-TAG", f"container {name} uses an untagged or ':latest' image ({c.get('image')})"))
        missing = [p for p in ("readinessProbe", "livenessProbe") if p not in c]
        if missing:
            out.append(("DS-PROBES", f"container {name} has no {', '.join(missing)}"))
        res = c.get("resources") or {}
        req, lim = res.get("requests") or {}, res.get("limits") or {}
        if "cpu" not in req or "memory" not in req:
            out.append(("DS-REQUESTS", f"container {name} has no cpu/memory requests (Enforce sets 500m / 2048Mi)"))
        floors = {"cpu": 100, "memory": 100}
        for bucket in (req, lim):
            for r, floor in floors.items():
                v = _qty(bucket.get(r), r)
                if v is not None and v < floor:
                    out.append(("DS-REQUEST-FLOOR", f"container {name} {r}={bucket[r]} is below the {floor}{'m' if r == 'cpu' else 'Mi'} floor"))

    if replicas > 1:
        aff = (pod.get("affinity") or {}).get("podAntiAffinity")
        if not aff and not pod.get("topologySpreadConstraints"):
            out.append(("DS-ANTI-AFFINITY", f"{replicas} replicas without podAntiAffinity or topologySpreadConstraints"))

    labels = {**((doc.get("metadata") or {}).get("labels") or {}), **(tpl_meta.get("labels") or {})}
    for key in labels:
        if key.split("/", 1)[0] == "kubernetes.azure.com":
            out.append(("DS-RESERVED-LABEL", f"label {key} is reserved for AKS"))

    # Pod Security Standards: Baseline
    for host in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(host):
            out.append(("PSS-BASELINE", f"{host} is true"))
    for v in pod.get("volumes") or []:
        if "hostPath" in v:
            out.append(("PSS-BASELINE", f"hostPath volume {v.get('name')}"))
    for s in psc.get("sysctls") or []:
        if s.get("name") not in SAFE_SYSCTLS:
            out.append(("PSS-BASELINE", f"disallowed sysctl {s.get('name')}"))
    if (psc.get("seccompProfile") or {}).get("type") == "Unconfined":
        out.append(("PSS-BASELINE", "pod seccompProfile is Unconfined"))
    for c in all_containers:
        name, sc = c.get("name", "?"), c.get("securityContext") or {}
        if sc.get("privileged"):
            out.append(("PSS-BASELINE", f"container {name} is privileged"))
        if any(p.get("hostPort") for p in c.get("ports") or []):
            out.append(("PSS-BASELINE", f"container {name} uses hostPort"))
        added = set((sc.get("capabilities") or {}).get("add") or [])
        if added - BASELINE_CAPS:
            out.append(("PSS-BASELINE", f"container {name} adds {sorted(added - BASELINE_CAPS)}"))
        if sc.get("procMount") not in (None, "Default"):
            out.append(("PSS-BASELINE", f"container {name} procMount={sc['procMount']}"))
        if (sc.get("seccompProfile") or {}).get("type") == "Unconfined":
            out.append(("PSS-BASELINE", f"container {name} seccompProfile is Unconfined"))

    # Pod Security Standards: Restricted (container settings override pod settings)
    for v in pod.get("volumes") or []:
        vtype = next((k for k in v if k != "name"), None)
        if vtype not in RESTRICTED_VOLUMES:
            out.append(("PSS-RESTRICTED", f"volume {v.get('name')} type {vtype} not allowed"))
    for c in all_containers:
        name, sc = c.get("name", "?"), c.get("securityContext") or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            out.append(("PSS-RESTRICTED", f"container {name} must set allowPrivilegeEscalation=false"))
        caps = sc.get("capabilities") or {}
        if "ALL" not in (caps.get("drop") or []):
            out.append(("PSS-RESTRICTED", f"container {name} must drop ALL capabilities"))
        if set(caps.get("add") or []) - {"NET_BIND_SERVICE"}:
            out.append(("PSS-RESTRICTED", f"container {name} may only add NET_BIND_SERVICE"))
        if sc.get("runAsNonRoot", psc.get("runAsNonRoot")) is not True:
            out.append(("PSS-RESTRICTED", f"container {name} must set runAsNonRoot=true"))
        if sc.get("runAsUser", psc.get("runAsUser")) == 0:
            out.append(("PSS-RESTRICTED", f"container {name} runs as UID 0"))
        seccomp = (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")
        if seccomp not in ("RuntimeDefault", "Localhost"):
            out.append(("PSS-RESTRICTED", f"container {name} seccompProfile must be RuntimeDefault or Localhost"))
    return out


def evaluate(docs: list[dict], level: str, pss: str, excluded: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    selectors: dict[tuple[str, str], str] = {}
    for doc in docs:
        if not isinstance(doc, dict) or "kind" not in doc:
            continue
        meta = doc.get("metadata") or {}
        ns = meta.get("namespace", "default")
        ref = f"{doc['kind']}/{ns}/{meta.get('name', '?')}"
        if doc["kind"] != "StorageClass" and ns in excluded:
            continue
        raw: list[tuple[str, str]] = []
        if doc["kind"] in WORKLOAD_KINDS:
            raw = check_workload(doc, ref)
        elif doc["kind"] == "StorageClass":
            prov = doc.get("provisioner", "")
            if prov in ("kubernetes.io/azure-disk", "kubernetes.io/azure-file"):
                raw = [("DS-CSI-STORAGECLASS", f"in-tree provisioner {prov}; use disk.csi.azure.com or file.csi.azure.com")]
        elif doc["kind"] == "Service":
            sel = (doc.get("spec") or {}).get("selector")
            if sel:
                key = (ns, yaml.safe_dump(sel, sort_keys=True))
                if key in selectors:
                    raw = [("DS-UNIQUE-SELECTOR", f"selector {sel} already used by Service {selectors[key]}")]
                else:
                    selectors[key] = meta.get("name", "?")
        for rule_id, msg in raw:
            rule = RULES[rule_id]
            if rule.pss and PSS_ORDER[pss] < PSS_ORDER[rule.pss]:
                continue
            effect = rule.warn if level == "Warn" else rule.enforce
            if effect:
                findings.append(Finding(rule_id, effect, ref, msg))
    return findings


def verdict(findings: list[Finding]) -> str:
    effects = {f.effect for f in findings}
    for effect, label in (("deny", "DENY"), ("mutate", "MUTATE"), ("warn", "WARN")):
        if effect in effects:
            return label
    return "ADMIT"


def load(paths: list[str]) -> list[dict]:
    docs: list[dict] = []
    for p in paths:
        path = Path(p)
        files = sorted(path.rglob("*.y*ml")) if path.is_dir() else [path]
        for f in files:
            docs.extend(d for d in yaml.safe_load_all(f.read_text()) if d)
    return docs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--level", choices=["Warn", "Enforce"], default="Enforce")
    ap.add_argument("--pss", choices=list(PSS_ORDER), default="Privileged")
    ap.add_argument("--exclude", action="append", default=[], help="excluded namespace (repeatable)")
    ap.add_argument("--github", action="store_true", help="emit GitHub Actions annotations")
    args = ap.parse_args(argv)

    findings = evaluate(load(args.paths), args.level, args.pss, set(args.exclude))
    for f in findings:
        if args.github:
            kind = "error" if f.effect == "deny" else "warning"
            print(f"::{kind} title={f.rule}::{f.ref}: {f.message}")
        else:
            print(f"{f.effect.upper():7} {f.rule:20} {f.ref}: {f.message}")
    print(f"verdict: {verdict(findings)} (level={args.level}, pss={args.pss}, findings={len(findings)})")
    return 1 if any(f.effect == "deny" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
