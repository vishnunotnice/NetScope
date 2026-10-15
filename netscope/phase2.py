from __future__ import annotations
import json, sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable
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
    def assess(self, vulnerability: Vulnerability, *, exposed=True, asset_criticality=1.0, confidence=1.0):
        cvss=min(max(vulnerability.cvss/10,0),1); epss=min(max(vulnerability.epss,0),1); kev=1.0 if vulnerability.kev else 0.0; exposure=1.0 if exposed else .35; criticality=min(max(asset_criticality,0),1); confidence=min(max(confidence,0),1)
        score=round(min(100,max(0,(cvss*40+epss*20+kev*20+exposure*10+criticality*10)*confidence)))
        severity="critical" if score>=90 else "high" if score>=70 else "medium" if score>=40 else "low"
        explanation=[f"CVSS contributes {cvss*40:.1f}/40",f"EPSS contributes {epss*20:.1f}/20"]
        if vulnerability.kev: explanation.append("CISA KEV listing adds 20 points because exploitation is known")
        explanation.append("The asset is exposed" if exposed else "The asset is not externally exposed")
        explanation.append(f"Asset criticality contributes {criticality*10:.1f}/10")
        return RiskAssessment(score,severity,{"cvss":round(cvss,3),"epss":round(epss,3),"kev":kev,"exposure":exposure,"criticality":criticality,"confidence":confidence},explanation)

class NVDClient:
    def lookup(self,cve_id,timeout=10):
        import urllib.parse, urllib.request
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?"+urllib.parse.urlencode({"cveId":cve_id})
        with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"NetScope/0.2"}),timeout=timeout) as response: return json.load(response)

class AssetStore:
    def __init__(self,path="netscope.db"):
        self.db=sqlite3.connect(path); self.db.row_factory=sqlite3.Row
        self.db.executescript("CREATE TABLE IF NOT EXISTS assets(address TEXT PRIMARY KEY,hostname TEXT,mac TEXT,vendor TEXT,status TEXT NOT NULL,os_name TEXT,os_accuracy INTEGER,criticality REAL NOT NULL DEFAULT .5,trace_hops TEXT NOT NULL DEFAULT '[]',last_seen TEXT NOT NULL); CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,address TEXT,cve_id TEXT,score INTEGER,severity TEXT,data TEXT,created_at TEXT); CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT,target TEXT,details TEXT,created_at TEXT)"); self._migrate(); self.db.commit()
    def _migrate(self):
        columns={row[1] for row in self.db.execute("PRAGMA table_info(assets)")}
        if "trace_hops" not in columns: self.db.execute("ALTER TABLE assets ADD COLUMN trace_hops TEXT NOT NULL DEFAULT '[]'")
    def upsert_hosts(self,hosts:Iterable[Host]):
        now=datetime.now(timezone.utc).isoformat()
        for h in hosts: self.db.execute("INSERT INTO assets(address,hostname,mac,vendor,status,os_name,os_accuracy,criticality,trace_hops,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(address) DO UPDATE SET hostname=excluded.hostname,mac=excluded.mac,vendor=excluded.vendor,status=excluded.status,os_name=excluded.os_name,os_accuracy=excluded.os_accuracy,trace_hops=excluded.trace_hops,last_seen=excluded.last_seen",(h.address,h.hostname,h.mac,h.vendor,h.status,h.os_name,h.os_accuracy,.5,json.dumps(h.trace_hops),now))
        self.db.commit()
    def assets(self): return [dict(r) for r in self.db.execute("SELECT * FROM assets ORDER BY address")]
    def audit(self,action,target,details): self.db.execute("INSERT INTO audit_log(action,target,details,created_at) VALUES(?,?,?,?)",(action,target,json.dumps(details),datetime.now(timezone.utc).isoformat())); self.db.commit()

def topology(hosts:Iterable[Host]):
    nodes=[]; edges=[]; hosts=list(hosts)
    for i,h in enumerate(hosts):
        nodes.append({"id":h.address,"type":"asset","position":{"x":i%4*240,"y":i//4*160},"data":{"label":h.hostname or h.address,"address":h.address,"os":h.os_name,"status":h.status,"services":[asdict(s) for s in h.services]}})
        previous=h.address
        for hop in h.trace_hops:
            hid="hop:"+hop
            if not any(n["id"]==hid for n in nodes): nodes.append({"id":hid,"type":"network-hop","position":{"x":len(nodes)%4*240,"y":len(nodes)//4*160},"data":{"label":hop,"address":hop,"kind":"traceroute hop"}})
            edges.append({"id":f"trace:{previous}:{hid}","source":previous,"target":hid,"type":"smoothstep","data":{"source":"nmap-traceroute"}}); previous=hid
    return {"nodes":nodes,"edges":edges}
