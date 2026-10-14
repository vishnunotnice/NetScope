from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone


class Scheduler:
    def __init__(self, path: str = "netscope.db"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS schedules (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, profile TEXT NOT NULL, interval_minutes INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_run TEXT)")
        self.db.commit()

    def add(self, target: str, profile: str, interval_minutes: int) -> int:
        if interval_minutes < 1: raise ValueError("interval_minutes must be at least 1")
        cur = self.db.execute("INSERT INTO schedules(target,profile,interval_minutes) VALUES(?,?,?)", (target, profile, interval_minutes)); self.db.commit(); return cur.lastrowid

    def list(self): return [dict(row) for row in self.db.execute("SELECT * FROM schedules ORDER BY id")]
    def delete(self, schedule_id: int): self.db.execute("DELETE FROM schedules WHERE id=?", (schedule_id,)); self.db.commit()
    def set_enabled(self, schedule_id: int, enabled: bool): self.db.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(enabled), schedule_id)); self.db.commit()
    def due(self, row):
        if not row["enabled"] or not row["last_run"]: return True
        elapsed = datetime.now(timezone.utc).timestamp() - datetime.fromisoformat(row["last_run"]).timestamp()
        return elapsed >= row["interval_minutes"] * 60
    def mark_run(self, schedule_id: int): self.db.execute("UPDATE schedules SET last_run=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), schedule_id)); self.db.commit()

    def daemon(self, callback, poll_seconds: int = 30):
        while True:
            for row in self.list():
                if self.due(row):
                    callback(row)
                    self.mark_run(row["id"])
            time.sleep(poll_seconds)

