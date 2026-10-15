from __future__ import annotations
import sqlite3,time
from datetime import datetime,timezone

class Scheduler:
    def __init__(self,path="netscope.db"):
        self.db=sqlite3.connect(path); self.db.row_factory=sqlite3.Row; self.db.execute("CREATE TABLE IF NOT EXISTS schedules(id INTEGER PRIMARY KEY AUTOINCREMENT,target TEXT,profile TEXT,interval_minutes INTEGER,enabled INTEGER DEFAULT 1,last_run TEXT)"); self.db.commit()
    def add(self,target,profile,every):
        if every<1: raise ValueError("interval must be positive")
        cur=self.db.execute("INSERT INTO schedules(target,profile,interval_minutes) VALUES(?,?,?)",(target,profile,every)); self.db.commit(); return cur.lastrowid
    def list(self): return [dict(row) for row in self.db.execute("SELECT * FROM schedules ORDER BY id")]
    def delete(self,identifier): self.db.execute("DELETE FROM schedules WHERE id=?",(identifier,)); self.db.commit()
    def enabled(self,identifier,value): self.db.execute("UPDATE schedules SET enabled=? WHERE id=?",(int(value),identifier)); self.db.commit()
    def daemon(self,callback,poll=30):
        while True:
            now=datetime.now(timezone.utc).timestamp()
            for row in self.list():
                last=datetime.fromisoformat(row["last_run"]).timestamp() if row["last_run"] else 0
                if row["enabled"] and now-last>=row["interval_minutes"]*60:
                    callback(row); self.db.execute("UPDATE schedules SET last_run=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),row["id"])); self.db.commit()
            time.sleep(poll)
