from __future__ import annotations

import csv
import io
import json
import urllib.request
from pathlib import Path
from typing import Any

from .phase2 import NVDClient, Vulnerability


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


class FeedStore:
    def __init__(self, directory: str = ".netscope/feeds"):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def update_kev(self, timeout: int = 30) -> int:
        with urllib.request.urlopen(KEV_URL, timeout=timeout) as response:
            payload = response.read()
        (self.directory / "kev.json").write_bytes(payload)
        return len(json.loads(payload).get("vulnerabilities", []))

    def update_epss(self, timeout: int = 30) -> int:
        with urllib.request.urlopen(EPSS_URL, timeout=timeout) as response:
            payload = response.read()
        import gzip
        text = gzip.decompress(payload).decode("utf-8")
        (self.directory / "epss.csv").write_text(text, encoding="utf-8")
        return sum(1 for line in text.splitlines() if line and not line.startswith("#")) - 1

    def kev_ids(self) -> set[str]:
        path = self.directory / "kev.json"
        if not path.exists(): return set()
        return {item["cveID"] for item in json.loads(path.read_text()).get("vulnerabilities", [])}

    def epss(self, cve_id: str) -> float:
        path = self.directory / "epss.csv"
        if not path.exists(): return 0.0
        with path.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(line for line in stream if not line.startswith("#")):
                if row.get("cve") == cve_id:
                    return float(row.get("epss", 0))
        return 0.0

    def enrich(self, cve_id: str) -> Vulnerability:
        payload = NVDClient().lookup(cve_id)
        item = (payload.get("vulnerabilities") or [{}])[0].get("cve", {})
        descriptions = item.get("descriptions", [])
        metrics = item.get("metrics", {})
        metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [{}])[0]
        cvss_data = metric.get("cvssData", {})
        references = [ref.get("url", "") for ref in item.get("references", [])]
        return Vulnerability(cve_id=cve_id, description=next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""),
            cvss=float(cvss_data.get("baseScore", 0)), epss=self.epss(cve_id), kev=cve_id in self.kev_ids(), references=references)

