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
