from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Sequence

from .models import Host, ScanResult, Service


PROFILES: dict[str, tuple[str, ...]] = {
    "discovery": ("-sn",),
    "quick": ("-sV", "--top-ports", "100"),
    "service": ("-sV", "-p", "1-1024"),
    "full": ("-sV", "-p-"),
    "os": ("-O", "-sV", "--top-ports", "100"),
}


class NmapError(RuntimeError):
    pass


class NmapRunner:
    def __init__(self, executable: str = "nmap") -> None:
        self.executable = executable

    def scan(self, target: str, profile: str = "quick", traceroute: bool = False) -> ScanResult:
        if profile not in PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")
        command = [self.executable, *PROFILES[profile]] + (["--traceroute"] if traceroute else []) + ["-oX", "-", target]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            message = completed.stderr.strip() or f"nmap exited with {completed.returncode}"
            raise NmapError(message)
        return parse_xml(completed.stdout, target=target, profile=profile)


def _text(element: ET.Element | None, attribute: str) -> str | None:
    return element.attrib.get(attribute) if element is not None else None


def parse_xml(xml: str, *, target: str, profile: str) -> ScanResult:
    root = ET.fromstring(xml)
    hosts: list[Host] = []
    for node in root.findall("./host"):
        address_node = node.find("./address[@addrtype='ipv4']")
        if address_node is None:
            address_node = node.find("./address")
        address = _text(address_node, "addr") or "unknown"
        hostname_node = node.find("./hostnames/hostname")
        mac_node = node.find("./address[@addrtype='mac']")
        status = _text(node.find("./status"), "state") or "unknown"
        host = Host(
            address=address,
            hostname=_text(hostname_node, "name"),
            mac=_text(mac_node, "addr"),
            vendor=_text(mac_node, "vendor"),
            status=status,
        )
        for port in node.findall("./ports/port"):
            service_node = port.find("./service")
            host.services.append(
                Service(
                    port=int(port.attrib["portid"]),
                    protocol=port.attrib.get("protocol", "tcp"),
                    state=_text(port.find("./state"), "state") or "unknown",
                    service=_text(service_node, "name"),
                    product=_text(service_node, "product"),
                    version=_text(service_node, "version"),
                    extra={
                        "tunnel": _text(service_node, "tunnel"),
                        "cpe": [c.text for c in service_node.findall("./cpe") if c.text] if service_node is not None else [],
                    },
                )
            )
        osmatch = node.find("./os/osmatch")
        if osmatch is not None:
            host.os_name = osmatch.attrib.get("name")
            host.os_accuracy = int(osmatch.attrib["accuracy"]) if osmatch.attrib.get("accuracy", "").isdigit() else None
            host.os_evidence = [c.attrib.get("name", "") for c in node.findall("./os/osmatch/osclass")]
        host.trace_hops = [h.attrib["ipaddr"] for h in node.findall("./trace/hop") if h.attrib.get("ipaddr")]
        hosts.append(host)
    return ScanResult(
        target=target,
        profile=profile,
        started_at=datetime.now(timezone.utc).isoformat(),
        hosts=hosts,
    )


def command_for(target: str, profile: str) -> Sequence[str]:
    """Expose the exact safe argv for display and tests."""
    return ("nmap", *PROFILES[profile], "-oX", "-", target)
