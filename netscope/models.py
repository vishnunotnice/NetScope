from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Host:
    address: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    status: str = "unknown"
    os_name: str | None = None
    os_accuracy: int | None = None
    os_evidence: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    profile: str
    started_at: str
    hosts: list[Host] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
