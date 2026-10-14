from __future__ import annotations

import argparse
import json
import sys

from .nmap import NmapError, NmapRunner, PROFILES
from .targets import TargetPolicy, TargetValidationError, parse_allowlist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netscope", description="Authorized network discovery toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, profile in (("discover", "discovery"), ("scan", "quick"), ("services", "service"), ("os", "os")):
        command = sub.add_parser(name)
        command.add_argument("target", help="Authorized IP address or CIDR range")
        command.add_argument("--allow", action="append", default=[], help="Allowed IP/CIDR; may be repeated")
        command.add_argument("--max-addresses", type=int, default=4096)
        command.add_argument("--json", action="store_true", dest="as_json")
        if name == "scan":
            command.add_argument("--profile", choices=tuple(PROFILES), default=profile)
        command.set_defaults(profile=profile)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = TargetPolicy(max_addresses=args.max_addresses, allowlist=parse_allowlist(args.allow))
        policy.validate(args.target)
        result = NmapRunner().scan(args.target, args.profile)
    except (TargetValidationError, NmapError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2) if args.as_json else _summary(result))
    return 0


def _summary(result) -> str:
    lines = [f"Target: {result.target}", f"Profile: {result.profile}", f"Hosts: {len(result.hosts)}"]
    for host in result.hosts:
        services = ", ".join(f"{service.port}/{service.protocol}" for service in host.services) or "no ports"
        lines.append(f"- {host.address} ({host.hostname or 'no hostname'}): {services}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
