from __future__ import annotations

import json
import sqlite3
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import Host


@dataclass
class Vulnerability:
    cve_id: str
    description: str = ""
    cvss: float = 0.0
    epss: float = 0.0
    kev: bool = False
    source: str = "nvd"
    potential_match: bool = False
    references: list[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    score: int
    severity: str
    factors: dict[str, float]
    explanation: list[str]


class RiskScorer:
    """Deterministic, explainable risk score from 0 to 100."""

    def assess(self, vulnerability: Vulnerability, *, exposed: bool = True,
               asset_criticality: float = 1.0, confidence: float = 1.0) -> RiskAssessment:
        cvss = min(max(vulnerability.cvss / 10.0, 0.0), 1.0)
        epss = min(max(vulnerability.epss, 0.0), 1.0)
        kev = 1.0 if vulnerability.kev else 0.0
        exposure = 1.0 if exposed else 0.35
        criticality = min(max(asset_criticality, 0.0), 1.0)
        confidence = min(max(confidence, 0.0), 1.0)
        raw = (cvss * 40 + epss * 20 + kev * 20 + exposure * 10 + criticality * 10) * confidence
        score = round(min(max(raw, 0), 100))
        severity = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
        explanation = [f"CVSS contributes {cvss * 40:.1f}/40", f"EPSS contributes {epss * 20:.1f}/20"]
        if vulnerability.kev:
            explanation.append("CISA KEV listing adds 20 points because exploitation is known")
        explanation.append("The asset is exposed" if exposed else "The asset is not externally exposed")
        explanation.append(f"Asset criticality contributes {criticality * 10:.1f}/10")
        if vulnerability.potential_match:
            explanation.append("Match is potential rather than confirmed; confidence was applied")
        return RiskAssessment(score, severity, {
            "cvss": round(cvss, 3), "epss": round(epss, 3), "kev": kev,
            "exposure": exposure, "criticality": criticality, "confidence": confidence,
        }, explanation)


class NVDClient:
    """Small dependency-free NVD client; callers may inject a transport for tests."""

    def __init__(self, opener=urllib.request.urlopen):
        self.opener = opener

    def lookup(self, cve_id: str, timeout: int = 10) -> dict[str, Any]:
        query = urllib.parse.urlencode({"cveId": cve_id})
        request = urllib.request.Request(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
            headers={"Accept": "application/json", "User-Agent": "NetScope/0.2"},
        )
        with self.opener(request, timeout=timeout) as response:
            return json.load(response)


class AssetStore:
    """SQLite persistence for assets, findings, and audit events."""

    def __init__(self, path: str = "netscope.db") -> None:
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                address TEXT PRIMARY KEY, hostname TEXT, mac TEXT, vendor TEXT,
                status TEXT NOT NULL, os_name TEXT, os_accuracy INTEGER,
                criticality REAL NOT NULL DEFAULT 0.5, last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL,
                cve_id TEXT NOT NULL, score INTEGER NOT NULL, severity TEXT NOT NULL,
                data TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
                target TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
            );
        """)
        self.db.commit()

    def upsert_hosts(self, hosts: Iterable[Host]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for host in hosts:
            self.db.execute("""INSERT INTO assets(address, hostname, mac, vendor, status, os_name, os_accuracy, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(address) DO UPDATE SET
                hostname=excluded.hostname, mac=excluded.mac, vendor=excluded.vendor,
                status=excluded.status, os_name=excluded.os_name, os_accuracy=excluded.os_accuracy,
                last_seen=excluded.last_seen""", (host.address, host.hostname, host.mac, host.vendor,
                host.status, host.os_name, host.os_accuracy, now))
        self.db.commit()

    def assets(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.db.execute("SELECT * FROM assets ORDER BY address")]

    def add_finding(self, address: str, vulnerability: Vulnerability, assessment: RiskAssessment) -> None:
        self.db.execute("INSERT INTO findings(address,cve_id,score,severity,data,created_at) VALUES (?,?,?,?,?,?)",
                        (address, vulnerability.cve_id, assessment.score, assessment.severity,
                         json.dumps({"vulnerability": asdict(vulnerability), "assessment": asdict(assessment)}),
                         datetime.now(timezone.utc).isoformat()))
        self.db.commit()

    def audit(self, action: str, target: str, details: dict[str, Any]) -> None:
        self.db.execute("INSERT INTO audit_log(action,target,details,created_at) VALUES (?,?,?,?)",
                        (action, target, json.dumps(details), datetime.now(timezone.utc).isoformat()))
        self.db.commit()


def topology(hosts: Iterable[Host]) -> dict[str, list[dict[str, Any]]]:
    """Return React Flow-compatible nodes and only defensible subnet edges."""
    nodes: list[dict[str, Any]] = []
    hosts_list = list(hosts)
    for index, host in enumerate(hosts_list):
        nodes.append({"id": host.address, "type": "asset", "position": {"x": (index % 4) * 240, "y": (index // 4) * 160},
                      "data": {"label": host.hostname or host.address, "address": host.address,
                               "os": host.os_name, "status": host.status,
                               "services": [asdict(s) for s in host.services]}})
    return {"nodes": nodes, "edges": []}

