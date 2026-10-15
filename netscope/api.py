from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from .phase2 import AssetStore

class Handler(BaseHTTPRequestHandler):
    db="netscope.db"
    def output(self,status,payload):
        body=json.dumps(payload).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        store=AssetStore(self.db)
        if self.path=="/api/health": return self.output(200,{"status":"ok"})
        if self.path=="/api/assets": return self.output(200,store.assets())
        if self.path=="/api/findings": return self.output(200,[dict(row) for row in store.db.execute("SELECT * FROM findings ORDER BY score DESC")])
        if self.path=="/api/topology":
            nodes=[]; edges=[]
            for index,asset in enumerate(store.assets()):
                nodes.append({"id":asset["address"],"type":"asset","position":{"x":index%4*240,"y":index//4*160},"data":{"label":asset["hostname"] or asset["address"],"address":asset["address"],"os":asset["os_name"],"status":asset["status"],"services":[]}})
                previous=asset["address"]
                for hop in json.loads(asset.get("trace_hops") or "[]"):
                    hid="hop:"+hop
                    if not any(node["id"]==hid for node in nodes): nodes.append({"id":hid,"type":"network-hop","position":{"x":len(nodes)%4*240,"y":len(nodes)//4*160},"data":{"label":hop,"address":hop,"kind":"traceroute hop"}})
                    edges.append({"id":f"trace:{previous}:{hid}","source":previous,"target":hid,"type":"smoothstep","data":{"source":"nmap-traceroute"}}); previous=hid
            return self.output(200,{"nodes":nodes,"edges":edges})
        self.output(404,{"error":"not found"})
    def log_message(self,*args): pass

def serve(host="127.0.0.1",port=8000,db="netscope.db"):
    Handler.db=db; ThreadingHTTPServer((host,port),Handler).serve_forever()
