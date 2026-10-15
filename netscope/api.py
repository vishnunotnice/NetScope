from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse
from .feeds import FeedStore
from .nmap import NmapRunner, PROFILES
from .phase2 import AssetStore
from .scheduler import Scheduler
from .targets import TargetPolicy, parse_allowlist

class Handler(BaseHTTPRequestHandler):
    db="netscope.db"
    def output(self,status,payload):
        body=json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def body(self):
        size=int(self.headers.get("Content-Length",0)); return json.loads(self.rfile.read(size) or b"{}")
    def do_GET(self):
        store=AssetStore(self.db); path=urlparse(self.path).path
        if path=="/api/health": return self.output(200,{"status":"ok"})
        if path=="/api/assets": return self.output(200,store.assets())
        if path=="/api/findings": return self.output(200,[dict(row) for row in store.db.execute("SELECT * FROM findings ORDER BY score DESC")])
        if path=="/api/audit": return self.output(200,[dict(row) for row in store.db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")])
        if path=="/api/schedules": return self.output(200,Scheduler(self.db).list())
        if path=="/api/summary":
            assets=store.assets(); findings=[dict(row) for row in store.db.execute("SELECT * FROM findings")]
            return self.output(200,{"assets":len(assets),"online":sum(a["status"]=="up" for a in assets),"services":sum(len(json.loads(a.get("services") or "[]")) for a in assets),"findings":len(findings),"critical":sum((f.get("severity") or "").lower()=="critical" for f in findings),"schedules":len(Scheduler(self.db).list())})
        if path=="/api/topology":
            nodes=[]; edges=[]
            for index,asset in enumerate(store.assets()):
                nodes.append({"id":asset["address"],"type":"asset","position":{"x":index%4*240,"y":index//4*160},"data":{"label":asset["hostname"] or asset["address"],"address":asset["address"],"os":asset["os_name"],"status":asset["status"],"services":json.loads(asset.get("services") or "[]")}})
                previous=asset["address"]
                for hop in json.loads(asset.get("trace_hops") or "[]"):
                    hid="hop:"+hop
                    if not any(node["id"]==hid for node in nodes): nodes.append({"id":hid,"type":"network-hop","position":{"x":len(nodes)%4*240,"y":len(nodes)//4*160},"data":{"label":hop,"address":hop,"kind":"traceroute hop"}})
                    edges.append({"id":f"trace:{previous}:{hid}","source":previous,"target":hid,"type":"smoothstep","data":{"source":"nmap-traceroute"}}); previous=hid
            return self.output(200,{"nodes":nodes,"edges":edges})
        return self.output(404,{"error":"not found"})
    def do_POST(self):
        path=urlparse(self.path).path; data=self.body()
        try:
            if path=="/api/scan":
                target=data["target"]; profile=data.get("profile","quick"); policy=TargetPolicy(int(data.get("max_addresses",4096)),parse_allowlist(data.get("allow",[]))); policy.validate(target)
                result=NmapRunner().scan(target,profile,bool(data.get("traceroute"))); store=AssetStore(self.db); store.upsert_hosts(result.hosts); store.audit("scan",target,{"profile":profile,"hosts":len(result.hosts)}); return self.output(200,result.to_dict())
            if path=="/api/feeds":
                store=FeedStore(data.get("directory",".netscope/feeds")); action=data.get("action"); count=store.update_kev() if action=="update-kev" else store.update_epss(); AssetStore(self.db).audit("feed_update",action,{"records":count}); return self.output(200,{"action":action,"records":count})
            if path=="/api/schedules":
                item=Scheduler(self.db); identifier=item.add(data["target"],data.get("profile","quick"),int(data.get("every",60))); return self.output(201,{"id":identifier})
            return self.output(404,{"error":"not found"})
        except Exception as exc: return self.output(400,{"error":str(exc)})
    def do_DELETE(self):
        path=urlparse(self.path).path
        if path.startswith("/api/schedules/"):
            Scheduler(self.db).delete(int(path.rsplit("/",1)[1])); return self.output(200,{"deleted":True})
        return self.output(404,{"error":"not found"})
    def do_PATCH(self):
        path=urlparse(self.path).path
        if path.startswith("/api/schedules/"):
            identifier=int(path.rsplit("/",1)[1]); Scheduler(self.db).enabled(identifier,bool(self.body().get("enabled",True))); return self.output(200,{"updated":True})
        return self.output(404,{"error":"not found"})
    def log_message(self,*args): pass

def serve(host="127.0.0.1",port=8000,db="netscope.db"):
    Handler.db=db; ThreadingHTTPServer((host,port),Handler).serve_forever()
