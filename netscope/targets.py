from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class TargetValidationError(ValueError):
    pass


@dataclass(frozen=True)
class TargetPolicy:
    max_addresses: int = 4096
    allowlist: tuple[ipaddress._BaseNetwork, ...] = ()

    def validate(self, target: str):
        try:
            value = ipaddress.ip_network(target, strict=False) if "/" in target else ipaddress.ip_address(target)
        except ValueError as exc:
            raise TargetValidationError(f"Invalid IP or CIDR target: {target}") from exc
        size = getattr(value, "num_addresses", 1)
        if size > self.max_addresses:
            raise TargetValidationError(f"Target contains {size} addresses; maximum is {self.max_addresses}")
        if self.allowlist and not any(
            value.subnet_of(network) if hasattr(value, "subnet_of") else value in network
            for network in self.allowlist
        ):
            raise TargetValidationError(f"Target is outside the configured allowlist: {target}")
        return value


def parse_allowlist(values: list[str]):
    return tuple(ipaddress.ip_network(value, strict=False) for value in values)

