"""Scope guard: every target must be explicitly authorized in a scope file.

Scope file format (one entry per line, '#' starts a comment):
    10.10.11.23          single IPv4/IPv6 address
    10.129.0.0/16        CIDR range
"""

from __future__ import annotations

import ipaddress
from pathlib import Path


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope or the scope is invalid."""


class Scope:
    def __init__(self, networks: list[ipaddress._BaseNetwork]):
        if not networks:
            raise ScopeError("scope is empty - refusing to run without an authorized target list")
        self.networks = networks

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        networks = []
        for lineno, raw in enumerate(Path(path).read_text().splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as exc:
                raise ScopeError(
                    f"{path}:{lineno}: '{line}' is not an IP address or CIDR range "
                    "(hostnames are not accepted - resolve them and list the IP)"
                ) from exc
        return cls(networks)

    def contains(self, target: str) -> bool:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def check(self, targets: list[str]) -> None:
        """Raise ScopeError if any target is not covered by the scope."""
        bad = [t for t in targets if not self.contains(t)]
        if bad:
            raise ScopeError(f"out of scope, refusing to continue: {', '.join(bad)}")
