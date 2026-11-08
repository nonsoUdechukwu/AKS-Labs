import copy
import io
import json
import os
import unittest
from contextlib import redirect_stdout

import aks_posture as ap

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return json.load(f)


def by_id(results):
    return {r.id: r for r in results}


class HardenedCluster(unittest.TestCase):
    def setUp(self):
        self.c, self.p = load("hardened-cluster.json"), load("hardened-nodepools.json")

    def test_no_failures(self):
        res = ap.evaluate(self.c, self.p, {"properties": {"level": "Enforce", "podSecurityStandardsLevel": "Restricted"}})
        fails = [r for r in res if r.status == ap.FAIL]
        self.assertEqual(fails, [])
        self.assertEqual(by_id(res)["ADM-02"].status, ap.PASS)

    def test_platform_key_on_137(self):
        self.assertIn("platform-managed", by_id(ap.evaluate(self.c, self.p))["DATA-01"].detail)

    def test_userns_pool_detection(self):
        self.assertEqual(by_id(ap.evaluate(self.c, self.p))["NODE-03"].detail, "system")

    def test_cli_exit_code_zero(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ap.main(["--cluster-json", os.path.join(HERE, "fixtures/hardened-cluster.json"),
                          "--nodepools-json", os.path.join(HERE, "fixtures/hardened-nodepools.json")])
        self.assertEqual(rc, 0)
        self.assertIn("| NODE-08 |", out.getvalue())


class WeakCluster(unittest.TestCase):
    def setUp(self):
        self.res = by_id(ap.evaluate(load("weak-cluster.json"), load("weak-nodepools.json")))

    def test_expected_failures(self):
        for cid in ["ID-01", "ID-02", "ID-03", "ID-04", "NET-01", "NET-03", "ADM-01",
                    "NODE-02", "NODE-04", "NODE-05", "NODE-06", "NODE-07", "NODE-08", "NODE-09", "DET-01"]:
            with self.subTest(cid):
                self.assertEqual(self.res[cid].status, ap.FAIL, self.res[cid])

    def test_windows_pool_ignored_for_linux_controls(self):
        self.assertNotIn("win", self.res["NODE-04"].detail)
        self.assertIn("win", self.res["NODE-06"].detail)

    def test_copy_fail_names_pool_and_image(self):
        self.assertIn("nodepool1 (AKSUbuntu-2204gen2containerd-202603.18.0)", self.res["NODE-08"].detail)

    def test_warnings(self):
        self.assertEqual(self.res["NODE-01"].status, ap.WARN)
        self.assertEqual(self.res["DATA-01"].status, ap.WARN)
        self.assertEqual(self.res["ADM-02"].status, ap.INFO)

    def test_cli_exit_code_and_json(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = ap.main(["--cluster-json", os.path.join(HERE, "fixtures/weak-cluster.json"),
                          "--nodepools-json", os.path.join(HERE, "fixtures/weak-nodepools.json"), "--format", "json"])
        self.assertEqual(rc, 1)
        self.assertTrue(any(r["id"] == "NODE-08" and r["status"] == "FAIL" for r in json.loads(out.getvalue())))


class EdgeCases(unittest.TestCase):
    def test_image_version_parsing(self):
        self.assertEqual(ap.image_version("AKSAzureLinux-V3gen2-202604.13.0"), (202604, 13, 0))
        self.assertIsNone(ap.image_version("garbage"))

    def test_copy_fail_boundary(self):
        c = load("hardened-cluster.json")
        pools = load("hardened-nodepools.json")
        pools[0]["nodeImageVersion"] = "AKSAzureLinux-V3gen2-202604.13.0"
        self.assertEqual(by_id(ap.evaluate(c, pools))["NODE-08"].status, ap.PASS)
        pools[0]["nodeImageVersion"] = "AKSAzureLinux-V3gen2-202604.06.0"
        self.assertEqual(by_id(ap.evaluate(c, pools))["NODE-08"].status, ap.FAIL)

    def test_entra_ssh_counts_as_controlled(self):
        c, pools = load("hardened-cluster.json"), load("hardened-nodepools.json")
        pools[0]["securityProfile"]["sshAccess"] = "EntraId"
        self.assertEqual(by_id(ap.evaluate(c, pools))["NODE-05"].status, ap.PASS)

    def test_imds_restriction_and_safeguards_levels(self):
        c, pools = copy.deepcopy(load("hardened-cluster.json")), load("hardened-nodepools.json")
        c["networkProfile"]["podLinkLocalAccess"] = "None"
        res = by_id(ap.evaluate(c, pools, {"level": "Enforce", "podSecurityStandardsLevel": "Baseline"}))
        self.assertEqual(res["NET-04"].status, ap.PASS)
        self.assertEqual(res["ADM-02"].status, ap.WARN)
        res = by_id(ap.evaluate(c, pools, {"level": "Warn"}))
        self.assertEqual(res["ADM-02"].status, ap.FAIL)

    def test_private_cluster_without_ranges(self):
        c, pools = load("hardened-cluster.json"), load("hardened-nodepools.json")
        c["apiServerAccessProfile"] = {"enablePrivateCluster": True}
        self.assertEqual(by_id(ap.evaluate(c, pools))["NET-01"].detail, "private cluster")


if __name__ == "__main__":
    unittest.main()
