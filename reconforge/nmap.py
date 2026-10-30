"""Run Nmap and parse its XML output into simple data classes."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "ssl/https"}


@dataclass
class Service:
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    cpes: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # NSE script id -> output

    @property
    def label(self) -> str:
        return " ".join(p for p in (self.product, self.version) if p) or self.name

    @property
    def is_web(self) -> bool:
        name = f"{self.tunnel}/{self.name}" if self.tunnel else self.name
        return name in WEB_SERVICES or self.name in WEB_SERVICES or self.name.startswith("http")


@dataclass
class Host:
    address: str
    hostnames: list[str] = field(default_factory=list)
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)  # host-level scripts (e.g. smb2-security-mode)


def _scripts(parent: ET.Element | None) -> dict[str, str]:
    """Collect NSE script output, skipping scripts that failed to run."""
    if parent is None:
        return {}
    out = {}
    for sc in parent.findall("script"):
        text = (sc.get("output") or "").strip()
        if sc.get("id") and text and not text.startswith("ERROR"):
            out[sc.get("id")] = text
    return out


def run_nmap(targets: list[str], xml_out: Path, extra_args: list[str] | None = None) -> Path:
    """Run a service/version scan. Caller must have checked scope first."""
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found in PATH")
    args = extra_args if extra_args else ["-sV", "-sC", "-T4", "--open"]
    cmd = ["nmap", *args, "-oX", str(xml_out), *targets]
    subprocess.run(cmd, check=True)
    return xml_out


def parse_nmap_xml(path: str | Path) -> list[Host]:
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        # Element truthiness depends on child count, so compare with None explicitly
        addr_el = h.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = h.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        host = Host(address=addr_el.get("addr", ""))
        host.hostnames = [n.get("name", "") for n in h.findall("hostnames/hostname")]
        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            host.os_guess = osmatch.get("name", "")
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            s = Service(port=int(p.get("portid", 0)), protocol=p.get("protocol", "tcp"),
                        name=svc.get("name", "unknown") if svc is not None else "unknown")
            if svc is not None:
                s.product = svc.get("product", "")
                s.version = svc.get("version", "")
                s.extrainfo = svc.get("extrainfo", "")
                s.tunnel = svc.get("tunnel", "")
                s.cpes = [c.text for c in svc.findall("cpe") if c.text]
            s.scripts = _scripts(p)
            host.services.append(s)
        host.scripts = _scripts(h.find("hostscript"))
        hosts.append(host)
    return hosts
