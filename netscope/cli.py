#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys

from .api import serve
from .feeds import FeedStore
from .models import Host, Service
from .phase2 import AssetStore, RiskScorer, Vulnerability, topology
from .scanner import NmapScanner, PROFILES, ScanError
from .scheduler import Scheduler
from .targets import TargetPolicy, TargetValidationError, parse_allowlist


def load_hosts(path: str) -> list[Host]:
    with open(path, encoding="utf-8") as stream: payload = json.load(stream)
    return [Host(**{**item, "services": [Service(**s) for s in item.get("services", [])]}) for item in payload.get("hosts", payload)]


def build_parser():
    parser = argparse.ArgumentParser(prog="netscope", description="Authorized network discovery and vulnerability intelligence")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run an authorized Nmap scan")
    scan.add_argument("target"); scan.add_argument("--profile", choices=tuple(PROFILES), default="quick"); scan.add_argument("--allow", action="append", default=[]); scan.add_argument("--max-addresses", type=int, default=4096); scan.add_argument("--output", default="scan.json")
    for name in ("inventory", "topology"):
        p = sub.add_parser(name); p.add_argument("scan_json"); p.add_argument("--db", default="netscope.db")
    risk = sub.add_parser("risk"); risk.add_argument("cve_id"); risk.add_argument("--cvss", type=float, required=True); risk.add_argument("--epss", type=float, default=0); risk.add_argument("--kev", action="store_true")
    cve = sub.add_parser("cve"); cve.add_argument("cve_id"); cve.add_argument("--db", default="netscope.db")
    feeds = sub.add_parser("feeds"); feeds.add_argument("action", choices=("update-kev", "update-epss")); feeds.add_argument("--directory", default=".netscope/feeds")
    api = sub.add_parser("api"); api.add_argument("--host", default="127.0.0.1"); api.add_argument("--port", type=int, default=8000); api.add_argument("--db", default="netscope.db")
    schedule = sub.add_parser("schedule"); schedule.add_argument("action", choices=("add", "list", "delete", "enable", "disable", "daemon")); schedule.add_argument("--target"); schedule.add_argument("--profile", choices=tuple(PROFILES), default="quick"); schedule.add_argument("--every", type=int, default=60); schedule.add_argument("--id", type=int); schedule.add_argument("--db", default="netscope.db")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            result = NmapScanner(policy=TargetPolicy(args.max_addresses, parse_allowlist(args.allow))).scan(args.target, args.profile)
            payload = result.to_dict(); json.dump(payload, open(args.output, "w", encoding="utf-8"), indent=2); print(json.dumps(payload, indent=2)); return 0
        if args.command == "risk":
            print(json.dumps(RiskScorer().assess(Vulnerability(args.cve_id, cvss=args.cvss, epss=args.epss, kev=args.kev)).__dict__, indent=2)); return 0
        if args.command == "cve":
            vulnerability = FeedStore().enrich(args.cve_id); print(json.dumps(vulnerability.__dict__, indent=2)); return 0
        if args.command == "feeds":
            store = FeedStore(args.directory); count = store.update_kev() if args.action == "update-kev" else store.update_epss(); print(json.dumps({"updated": args.action, "records": count})); return 0
        if args.command == "api": serve(args.host, args.port, args.db); return 0
        if args.command == "schedule":
            scheduler = Scheduler(args.db)
            if args.action == "add": print(json.dumps({"id": scheduler.add(args.target, args.profile, args.every)})); return 0
            if args.action == "list": print(json.dumps(scheduler.list(), indent=2)); return 0
            if args.action == "daemon":
                store = AssetStore(args.db)
                def run(row):
                    result = NmapScanner().scan(row["target"], row["profile"]); store.upsert_hosts(result.hosts); store.audit("scheduled_scan", row["target"], {"profile": row["profile"], "hosts": len(result.hosts)})
                scheduler.daemon(run); return 0
            if args.action == "delete": scheduler.delete(args.id); return 0
            scheduler.set_enabled(args.id, args.action == "enable"); return 0
        hosts = load_hosts(args.scan_json)
        if args.command == "topology": print(json.dumps(topology(hosts), indent=2)); return 0
        store = AssetStore(args.db); store.upsert_hosts(hosts); store.audit("asset_import", args.scan_json, {"count": len(hosts)}); print(json.dumps(store.assets(), indent=2)); return 0
    except (TargetValidationError, ScanError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
