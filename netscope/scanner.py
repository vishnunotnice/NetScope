from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from .models import Host, ScanResult, Service
from .targets import TargetPolicy


PROFILES = {
    "discovery": ("-sn",),
    "quick": ("-sV", "--top-ports", "100"),
    "service": ("-sV", "-p", "1-1024"),
    "full": ("-sV", "-p-"),
    "os": ("-O", "-sV", "--top-ports", "100"),
}


class ScanError(RuntimeError):
    pass


def _attr(element, name):
    return element.attrib.get(name) if element is not None else None


def parse_nmap_xml(xml: str, target: str, profile: str) -> ScanResult:
    root = ET.fromstring(xml)
    hosts = []
    for node in root.findall("./host"):
        address = node.find("./address[@addrtype='ipv4']")
        if address is None:
            address = node.find("./address")
        mac = node.find("./address[@addrtype='mac']")
        host = Host(address=_attr(address, "addr") or "unknown", hostname=_attr(node.find("./hostnames/hostname"), "name"),
                    mac=_attr(mac, "addr"), vendor=_attr(mac, "vendor"), status=_attr(node.find("./status"), "state") or "unknown")
        for port in node.findall("./ports/port"):
            service = port.find("./service")
            host.services.append(Service(port=int(port.attrib["portid"]), protocol=port.attrib.get("protocol", "tcp"),
                state=_attr(port.find("./state"), "state") or "unknown", service=_attr(service, "name"),
                product=_attr(service, "product"), version=_attr(service, "version"),
                extra={"cpe": [x.text for x in service.findall("./cpe") if x.text] if service is not None else []}))
        osmatch = node.find("./os/osmatch")
        if osmatch is not None:
            host.os_name = osmatch.attrib.get("name")
            host.os_accuracy = int(osmatch.attrib["accuracy"]) if osmatch.attrib.get("accuracy", "").isdigit() else None
            host.os_evidence = [x.attrib.get("name", "") for x in osmatch.findall("./osclass")]
        hosts.append(host)
    return ScanResult(target=target, profile=profile, started_at=datetime.now(timezone.utc).isoformat(), hosts=hosts)


class NmapScanner:
    def __init__(self, executable: str = "nmap", policy: TargetPolicy | None = None):
        self.executable = executable
        self.policy = policy or TargetPolicy()

    def scan(self, target: str, profile: str = "quick") -> ScanResult:
        self.policy.validate(target)
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile: {profile}")
        command = [self.executable, *PROFILES[profile], "-oX", "-", target]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise ScanError("Nmap is not installed. Install it with: brew install nmap") from exc
        if result.returncode:
            raise ScanError(result.stderr.strip() or f"nmap exited with {result.returncode}")
        return parse_nmap_xml(result.stdout, target, profile)

