from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .phase2 import AssetStore


class APIHandler(BaseHTTPRequestHandler):
    store_path = "netscope.db"
    def send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        store = AssetStore(self.store_path)
        if self.path == "/api/health": return self.send_json(200, {"status": "ok"})
        if self.path == "/api/assets": return self.send_json(200, store.assets())
        if self.path == "/api/findings": return self.send_json(200, [dict(x) for x in store.db.execute("SELECT * FROM findings ORDER BY score DESC")])
        if self.path == "/api/topology":
            assets = store.assets(); nodes = [{"id": x["address"], "type": "asset", "position": {"x": (i % 4) * 240, "y": (i // 4) * 160}, "data": {"label": x["hostname"] or x["address"], "address": x["address"], "os": x["os_name"], "status": x["status"], "services": []}} for i, x in enumerate(assets)]
            return self.send_json(200, {"nodes": nodes, "edges": []})
        self.send_json(404, {"error": "not found"})
    def log_message(self, *_): pass


def serve(host="127.0.0.1", port=8000, db="netscope.db"):
    APIHandler.store_path = db
    ThreadingHTTPServer((host, port), APIHandler).serve_forever()

