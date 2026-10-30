"""Turn Nmap script output and service facts into misconfiguration findings.

CVE lookups only catch vulnerable *versions*. Many real entry points are
misconfigurations instead (anonymous FTP, SMB signing off, empty database
passwords), which Nmap's default scripts already detect. These rules pick
them out so they are not buried in raw scan output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .nmap import Host, Service

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

# Scripts whose output is useful context even when no rule fires
INFO_SCRIPTS = {"http-title", "http-server-header", "ftp-syst", "ssh-hostkey", "http-robots.txt",
                "smb-os-discovery", "ssl-cert", "rdp-ntlm-info"}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    source: str  # script id or "service"


@dataclass
class Rule:
    script: str
    pattern: str
    severity: str
    title: str


RULES = [
    Rule("ftp-anon", r"Anonymous FTP login allowed", "HIGH", "Anonymous FTP login allowed"),
    Rule("mysql-empty-password", r"empty password", "HIGH", "MySQL account with empty password"),
    Rule("ms-sql-empty-password", r"Login Success", "HIGH", "MSSQL account with empty password"),
    Rule("smb-security-mode", r"account_used:\s*guest", "HIGH", "SMB guest access allowed"),
    Rule("smb-security-mode", r"message_signing:\s*disabled", "MEDIUM", "SMB message signing disabled"),
    Rule("smb2-security-mode", r"not required", "MEDIUM", "SMB message signing not required"),
    Rule("http-methods", r"Potentially risky methods", "MEDIUM", "Risky HTTP methods enabled"),
    Rule("http-git", r"Git repository found", "HIGH", "Exposed .git repository"),
    Rule("nfs-showmount", r"/", "MEDIUM", "NFS exports visible"),
]

CLEARTEXT_SERVICES = {"telnet": "Telnet", "ftp": "FTP"}


def _first_lines(text: str, n: int = 3) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    snippet = " / ".join(lines[:n])
    return snippet[:200] + ("..." if len(snippet) > 200 else "")


def _match(scripts: dict[str, str]) -> tuple[list[Finding], set[str]]:
    found, used = [], set()
    for rule in RULES:
        out = scripts.get(rule.script)
        if out and re.search(rule.pattern, out, re.IGNORECASE):
            found.append(Finding(rule.severity, rule.title, _first_lines(out), rule.script))
            used.add(rule.script)
    for sid in sorted(scripts):
        if sid in INFO_SCRIPTS and sid not in used:
            found.append(Finding("INFO", sid, _first_lines(scripts[sid]), sid))
    return found, used


def service_findings(s: Service) -> list[Finding]:
    found, _ = _match(s.scripts)
    if s.name in CLEARTEXT_SERVICES and not s.tunnel:
        found.append(Finding("LOW", f"{CLEARTEXT_SERVICES[s.name]} sends credentials in cleartext",
                             f"{s.name} on {s.port}/{s.protocol} is not wrapped in TLS", "service"))
    return sorted(found, key=lambda f: SEVERITY_ORDER[f.severity])


def host_findings(h: Host) -> list[Finding]:
    found, _ = _match(h.scripts)
    return sorted(found, key=lambda f: SEVERITY_ORDER[f.severity])
