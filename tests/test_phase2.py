import json
import tempfile
import unittest

from netscope.models import Host, Service
from netscope.phase2 import AssetStore, RiskScorer, Vulnerability, topology


class PhaseTwoTests(unittest.TestCase):
    def test_risk_score_is_explainable_and_bounded(self):
        assessment = RiskScorer().assess(Vulnerability("CVE-TEST", cvss=9.8, epss=.9, kev=True))
        self.assertEqual(assessment.severity, "critical")
        self.assertLessEqual(assessment.score, 100)
        self.assertGreater(len(assessment.explanation), 2)

    def test_asset_store_persists_assets_and_audit(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as file:
            store = AssetStore(file.name)
            store.upsert_hosts([Host("10.0.0.5", hostname="server", services=[Service(443, service="https")])])
            store.audit("scan", "10.0.0.5", {"authorized": True})
            self.assertEqual(store.assets()[0]["hostname"], "server")
            count = store.db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            self.assertEqual(count, 1)

    def test_topology_is_react_flow_compatible_without_invented_edges(self):
        graph = topology([Host("10.0.0.5", hostname="server")])
        self.assertEqual(graph["nodes"][0]["id"], "10.0.0.5")
        self.assertEqual(graph["edges"], [])


if __name__ == "__main__":
    unittest.main()
