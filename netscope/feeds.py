from __future__ import annotations
import csv, gzip, json, urllib.request
from pathlib import Path
from .phase2 import NVDClient, Vulnerability

KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

class FeedStore:
    def __init__(self,directory=".netscope/feeds"): self.directory=Path(directory); self.directory.mkdir(parents=True,exist_ok=True)
    def update_kev(self):
        with urllib.request.urlopen(KEV_URL,timeout=30) as response: data=response.read()
        (self.directory/"kev.json").write_bytes(data); return len(json.loads(data).get("vulnerabilities",[]))
    def update_epss(self):
        with urllib.request.urlopen(EPSS_URL,timeout=30) as response: text=gzip.decompress(response.read()).decode()
        (self.directory/"epss.csv").write_text(text); return sum(1 for line in text.splitlines() if line and not line.startswith("#"))-1
    def kev_ids(self):
        path=self.directory/"kev.json"; return {item["cveID"] for item in json.loads(path.read_text()).get("vulnerabilities",[])} if path.exists() else set()
    def epss(self,cve_id):
        path=self.directory/"epss.csv"
        if not path.exists(): return 0.0
        with path.open() as stream:
            for row in csv.DictReader(line for line in stream if not line.startswith("#")):
                if row.get("cve")==cve_id: return float(row.get("epss",0))
        return 0.0
    def enrich(self,cve_id):
        item=(NVDClient().lookup(cve_id).get("vulnerabilities") or [{}])[0].get("cve",{})
        metrics=item.get("metrics",{}); metric=(metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0].get("cvssData",{})
        description=next((item.get("value","") for item in item.get("descriptions",[]) if item.get("lang")=="en"),"")
        return Vulnerability(cve_id,description,float(metric.get("baseScore",0)),self.epss(cve_id),cve_id in self.kev_ids(),references=[ref.get("url","") for ref in item.get("references",[])])
