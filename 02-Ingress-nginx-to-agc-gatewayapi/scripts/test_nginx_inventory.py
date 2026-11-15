import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "nginx_inventory.py")
LEGACY = os.path.join(HERE, "..", "legacy", "ingress-nginx.yaml")


def run(args, stdin=None):
    p = subprocess.run([sys.executable, SCRIPT, *args], input=stdin, capture_output=True, text=True)
    return p.returncode, p.stdout


def ing(name, cls="nginx", ann=None, path="/", path_type="Prefix"):
    return {"kind": "Ingress", "metadata": {"name": name, "namespace": "t", "annotations": ann or {}},
            "spec": {"ingressClassName": cls, "rules": [{"host": "a.example", "http": {"paths": [
                {"path": path, "pathType": path_type,
                 "backend": {"service": {"name": "s", "port": {"number": 80}}}}]}}]}}


class InventoryTest(unittest.TestCase):
    def verdicts(self, items, *extra):
        rc, out = run(["-", "--format", "json", *extra], json.dumps({"items": items}))
        data = json.loads(out)
        return rc, {i["name"]: i["verdict"] for i in data["ingresses"]}

    def test_legacy_fixture(self):
        rc, out = run([LEGACY, "--format", "json"])
        data = json.loads(out)
        got = {i["name"]: i["verdict"] for i in data["ingresses"]}
        self.assertEqual(got, {"web": "policy", "web-canary": "core", "api": "blocker"})
        self.assertEqual(rc, 2, "blockers must fail the pipeline")

    def test_classification(self):
        rc, got = self.verdicts([
            ing("plain"),
            ing("canary", ann={"nginx.ingress.kubernetes.io/canary-weight": "10"}),
            ing("affinity", ann={"nginx.ingress.kubernetes.io/affinity": "cookie"}),
            ing("prefix-rewrite", ann={"nginx.ingress.kubernetes.io/rewrite-target": "/"}),
            ing("capture-rewrite", ann={"nginx.ingress.kubernetes.io/rewrite-target": "/$2"}),
            ing("regex", ann={"nginx.ingress.kubernetes.io/use-regex": "true"}, path="/v[0-9]+/", path_type="ImplementationSpecific"),
            ing("snippet", ann={"nginx.ingress.kubernetes.io/server-snippet": "x"}),
            ing("passthrough", ann={"nginx.ingress.kubernetes.io/ssl-passthrough": "true"}),
            ing("unknown", ann={"nginx.ingress.kubernetes.io/brand-new": "1"}),
            ing("other-class", cls="azure-alb-external"),
        ])
        self.assertEqual(got, {
            "plain": "core", "canary": "core", "affinity": "policy", "prefix-rewrite": "core",
            "capture-rewrite": "manual", "regex": "manual", "snippet": "manual",
            "passthrough": "blocker", "unknown": "manual",
        })
        self.assertEqual(rc, 2)

    def test_internal_class_is_blocker(self):
        rc, got = self.verdicts([ing("priv", cls="nginx-internal")], "--internal-class", "nginx-internal")
        self.assertEqual(got, {"priv": "blocker"})

    def test_no_blockers_exit_zero(self):
        rc, _ = self.verdicts([ing("plain")])
        self.assertEqual(rc, 0)

    def test_markdown_escapes_pipes(self):
        _, out = run([LEGACY])
        self.assertIn(r"/api(/\|$)(.*)", out)


if __name__ == "__main__":
    unittest.main()
