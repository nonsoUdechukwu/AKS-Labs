"""Checks the preflight linter against the same expectation matrix the live runner uses."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "preflight"))

import preflight  # noqa: E402

SC = ROOT / "scenarios"
LEVELS = ["Warn", "Enforce"]
PSS = ["Privileged", "Baseline", "Restricted"]


def expected(cls: str, level: str, pss: str) -> str:
    """Python twin of expected() in scripts/run-scenarios.sh."""
    if cls in ("compliant", "excluded"):
        return "ADMIT"
    if cls == "warn-only":
        return "WARN"
    if cls == "ds-deny":
        return "WARN" if level == "Warn" else "DENY"
    if cls == "ds-mutate":
        return "WARN" if level == "Warn" else "MUTATE"
    if cls == "mutate-only":
        return "ADMIT" if level == "Warn" else "MUTATE"
    blocked = (cls == "pss-baseline" and pss != "Privileged") or (cls == "pss-restricted" and pss == "Restricted")
    if not blocked:
        return "ADMIT"
    return "WARN" if level == "Warn" else "DENY"


def rows():
    for line in (SC / "expected.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        sid, file, ns, cls, title = line.split("\t")
        if file.startswith("@"):
            continue  # live-cluster only (node edits)
        yield sid, file, cls


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("pss", PSS)
@pytest.mark.parametrize("sid,file,cls", list(rows()))
def test_matrix(sid, file, cls, level, pss):
    docs = preflight.load([str(SC / file)])
    if sid == "S07":
        # The duplicate only exists relative to the golden Service from S01.
        docs = preflight.load([str(SC / "01-compliant.yaml")]) + docs
    findings = preflight.evaluate(docs, level, pss, {"lab-legacy"})
    assert preflight.verdict(findings) == expected(cls, level, pss), [f.message for f in findings]


def test_excluded_namespace_is_not_exempt_when_not_listed():
    docs = preflight.load([str(SC / "13-excluded-namespace.yaml")])
    assert preflight.verdict(preflight.evaluate(docs, "Enforce", "Privileged", set())) == "DENY"


def _verdict(text: str, level: str = "Enforce") -> str:
    import yaml

    docs = [d for d in yaml.safe_load_all(text) if d]
    return preflight.verdict(preflight.evaluate(docs, level, "Privileged", set()))


SVC = """
apiVersion: v1
kind: Service
metadata: {{name: {name}, namespace: ns}}
spec:
  {extra}selector: {{app: web}}
  ports: [{{port: {port}}}]
"""


@pytest.mark.parametrize(
    "second,want",
    [
        (SVC.format(name="b", port=80, extra=""), "DENY"),
        (SVC.format(name="b", port=8080, extra=""), "ADMIT"),
        (SVC.format(name="b", port=80, extra="clusterIP: None\n  "), "ADMIT"),
    ],
)
def test_unique_selector_needs_overlapping_port(second, want):
    assert _verdict(SVC.format(name="a", port=80, extra="") + "---" + second) == want


def test_reserved_label_is_exact_key_only():
    s08 = (SC / "08-reserved-label.yaml").read_text()
    assert _verdict(s08) == "DENY"
    assert _verdict(s08.replace("kubernetes.azure.com: payments", "kubernetes.azure.com/team: payments")) == "ADMIT"


def test_bare_pod_without_requests_is_denied():
    pod = """
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: ns}
spec:
  containers:
  - name: c
    image: nginx:1.27
    readinessProbe: {tcpSocket: {port: 80}}
    livenessProbe: {tcpSocket: {port: 80}}
"""
    assert _verdict(pod) == "DENY"
    assert _verdict(pod, "Warn") == "WARN"


@pytest.mark.parametrize(
    "image,bad",
    [
        ("nginx", True),
        ("nginx:latest", True),
        ("registry:5000/team/app", True),
        ("registry:5000/team/app:1.2.3", False),
        ("nginx@sha256:" + "a" * 64, False),
    ],
)
def test_image_tag_parsing(image, bad):
    assert preflight._image_untagged_or_latest(image) is bad


def test_quantities():
    assert preflight._qty("250m", "cpu") == 250
    assert preflight._qty("0.5", "cpu") == 500
    assert preflight._qty("2Gi", "memory") == 2048
    assert round(preflight._qty("100M", "memory"), 1) == 95.4
