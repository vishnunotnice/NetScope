import tempfile
import unittest
from pathlib import Path

from netscope.models import Host
from netscope.phase2 import AssetStore, RiskScorer, Vulnerability, topology


class PhaseTwoTests(unittest.TestCase):
    def test_risk_is_explainable_and_bounded(self):
        result = RiskScorer().assess(Vulnerability("CVE-TEST", cvss=9.8, epss=.9, kev=True))
        self.assertEqual(result.score, 97)
        self.assertIn("CISA KEV", " ".join(result.explanation))

    def test_inventory_persists_assets_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "netscope.db")
            store = AssetStore(db)
            store.upsert_hosts([Host("192.0.2.10", hostname="demo", trace_hops=["192.0.2.1"])])
            store.audit("asset_import", "fixture", {"count": 1})
            self.assertEqual(store.assets()[0]["hostname"], "demo")
            self.assertEqual(store.assets()[0]["trace_hops"], '["192.0.2.1"]')

    def test_topology_contains_observed_edges(self):
        graph = topology([Host("192.0.2.10", trace_hops=["192.0.2.1"])])
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["data"]["source"], "nmap-traceroute")


if __name__ == "__main__":
    unittest.main()
