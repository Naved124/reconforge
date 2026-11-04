"""Render findings as a Markdown pentest-style report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .cve import CVE, sort_cves
from .findings import Finding
from .msf import Module
from .nmap import Host, Service

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
CONFIDENCES = ["confirmed-range", "exact-cpe", "unconfirmed", "keyword-guess"]
# Max CVEs listed per service: confirmed-range/exact-cpe ("strong") share one cap
CAPS = {"strong": 10, "unconfirmed": 5, "keyword-guess": 5}


@dataclass
class ServiceFinding:
    service: Service
    cves: list[CVE] = field(default_factory=list)
    modules: dict[str, list[Module]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)  # misconfigurations from scripts


@dataclass
class HostFinding:
    host: Host
    services: list[ServiceFinding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)  # host-level script findings


def _issues(hf: HostFinding) -> list[Finding]:
    """All non-INFO misconfiguration findings on a host."""
    items = [f for f in hf.findings if f.severity != "INFO"]
    for sf in hf.services:
        items += [f for f in sf.findings if f.severity != "INFO"]
    return items


def _count(values: list[str]) -> str:
    counts = {s: values.count(s) for s in set(values)}
    return ", ".join(f"{s.title()} {counts[s]}" for s in SEV_ORDER if s in counts)


def _conf_count(values: list[str]) -> str:
    return ", ".join(f"{c} {values.count(c)}" for c in CONFIDENCES if c in values)


def _cve_lines(sf: "ServiceFinding") -> list[str]:
    """CVE lines for one service, strongest confidence first. confirmed-range and exact-cpe
    share one cap; unconfirmed and keyword-guess each get a smaller one."""
    lines, shown, hidden = [], {}, 0
    for c in sort_cves(sf.cves):
        group = "unconfirmed" if c.confidence == "unconfirmed" else \
            "keyword-guess" if c.confidence == "keyword-guess" else "strong"
        if shown.get(group, 0) >= CAPS[group]:
            hidden += 1
            continue
        shown[group] = shown.get(group, 0) + 1
        score = f"{c.score}" if c.score is not None else "n/a"
        summary = c.summary[:180] + ("..." if len(c.summary) > 180 else "")
        text = f"- **{c.id}** `[{c.confidence}]` ({c.severity}, CVSS {score}): {summary}"
        if c.reason:
            text += f" *({c.reason})*"
        lines.append(text)
        lines += [f"  - Metasploit {m.type}: `{m.fullname}`" for m in sf.modules.get(c.id, [])]
    if hidden:
        lines.append(f"- ...and {hidden} more")
    return lines


def _finding_line(f: Finding) -> str:
    if f.severity == "INFO":
        return f"- *{f.title}*: {f.detail}"
    return f"- **[{f.severity}] {f.title}** (`{f.source}`): {f.detail}"


def render(findings: list[HostFinding], scope_desc: str, offline: bool = False) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "# Reconnaissance Report",
        "",
        f"- **Generated:** {now}",
        f"- **Authorized scope:** {scope_desc}",
        f"- **Hosts up:** {len(findings)}",
    ]
    issues = [f.severity for hf in findings for f in _issues(hf)]
    if issues:
        out.append(f"- **Misconfigurations:** {_count(issues)}")
    cves = [c.severity for hf in findings for sf in hf.services for c in sf.cves]
    if cves:
        out.append(f"- **Candidate CVEs:** {_count(cves)}")
    if cves:
        out.append(f"- **CVE confidence:** {_conf_count([c.confidence for hf in findings for sf in hf.services for c in sf.cves])}")
    if offline:
        out.append("- **CVE lookup:** skipped (offline mode)")
    out += ["", "> Misconfigurations come from Nmap script output. CVEs are matched on the CPE Nmap",
            "> reports, with the detected version checked against NVD's affected ranges. Confidence:",
            "> `confirmed-range` (version inside an affected range), `exact-cpe` (exact CPE match),",
            "> `unconfirmed` (no usable or comparable version, or limited trust such as a distro",
            "> package or vendor alias) and `keyword-guess` (banner keyword search, no CPE).",
            "> Treat all of them as leads to verify manually.", ""]

    for hf in findings:
        h = hf.host
        title = h.address + (f" ({', '.join(h.hostnames)})" if h.hostnames else "")
        out += [f"## {title}", ""]
        if h.os_guess:
            out += [f"OS guess: {h.os_guess}", ""]

        top = sorted(_issues(hf), key=lambda f: SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9)
        if top:
            out += ["**Priority findings:**", ""]
            out += [_finding_line(f) for f in top] + [""]

        out += ["| Port | Service | Version | Issues | CVEs | Metasploit |", "|---|---|---|---|---|---|"]
        for sf in hf.services:
            s = sf.service
            mods = sum(len(v) for v in sf.modules.values())
            n_issues = sum(1 for f in sf.findings if f.severity != "INFO")
            out.append(f"| {s.port}/{s.protocol} | {s.name} | {s.label} | {n_issues} | {len(sf.cves)} | {mods} |")
        out.append("")

        host_info = [f for f in hf.findings if f.severity == "INFO"]
        if host_info:
            out += ["### Host scripts", ""] + [_finding_line(f) for f in host_info] + [""]

        for sf in hf.services:
            s = sf.service
            if not (sf.cves or sf.findings or s.is_web):
                continue
            out += [f"### {s.port}/{s.protocol} - {s.label}", ""]
            n_issues = sum(1 for f in sf.findings if f.severity != "INFO")
            if n_issues:
                out.append(f"- {n_issues} misconfiguration(s) listed under Priority findings")
            for f in sf.findings:
                if f.severity == "INFO":
                    out.append(_finding_line(f))
            out += _cve_lines(sf)
            if s.is_web:
                if sf.cves or sf.findings:
                    out.append("")
                scheme = "https" if (s.tunnel == "ssl" or "https" in s.name) else "http"
                out.append(f"**Manual web testing:** proxy `{scheme}://{h.address}:{s.port}/` through Burp Suite; "
                           "check auth, input handling, hidden directories and known CMS paths.")
            out.append("")

    out += ["## Next steps", "",
            "1. Confirm each priority finding by hand (for example, log in to an anonymous FTP service).",
            "2. Verify each candidate CVE against the exact version (banner, changelog, behaviour).",
            "3. Review `msf_suggestions.rc`; every line is commented out until you confirm it.",
            "4. Test flagged web services manually in Burp Suite.",
            "5. Record confirmed findings with evidence before any exploitation attempt.", ""]
    return "\n".join(out)
