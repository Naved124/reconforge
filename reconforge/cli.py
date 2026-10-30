"""Command-line entry point.

    reconforge scan   --scope scope.txt --target 10.10.11.23 [--out reports]
    reconforge report --scope scope.txt --xml existing_scan.xml [--out reports]
"""

from __future__ import annotations

import argparse
import shlex
import sys
from datetime import datetime
from pathlib import Path

from .cve import NVDClient
from .findings import host_findings, service_findings
from .msf import ModuleIndex, find_metadata, resource_script
from .nmap import parse_nmap_xml, run_nmap
from .report import HostFinding, ServiceFinding, render
from .scope import Scope, ScopeError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconforge",
                                description="Scoped recon-to-report automation for authorized pentests.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--scope", required=True, help="file listing authorized IPs/CIDRs")
        sp.add_argument("--out", default="reports", help="output directory (default: reports)")
        sp.add_argument("--offline", action="store_true", help="skip NVD CVE lookups")
        sp.add_argument("--msf-db", help="path to Metasploit modules_metadata_base.json")

    scan = sub.add_parser("scan", help="run nmap, then analyse and report")
    common(scan)
    scan.add_argument("--target", action="append", required=True, help="IP to scan (repeatable)")
    scan.add_argument("--nmap-args", help='override nmap args, e.g. "-sV -p-"')

    rep = sub.add_parser("report", help="analyse an existing nmap XML file")
    common(rep)
    rep.add_argument("--xml", required=True, help="nmap -oX output file")
    return p


def analyse(hosts, nvd: NVDClient | None, index: ModuleIndex):
    findings, suggestions = [], []
    for h in hosts:
        hf = HostFinding(host=h, findings=host_findings(h))
        for s in h.services:
            sf = ServiceFinding(service=s, findings=service_findings(s))
            if nvd:
                try:
                    sf.cves = nvd.lookup(s.product, s.version)
                except Exception as exc:  # network errors should not kill the whole run
                    print(f"[!] CVE lookup failed for {s.label}: {exc}", file=sys.stderr)
            for c in sf.cves:
                mods = index.modules_for(c.id)
                if mods:
                    sf.modules[c.id] = mods
                    suggestions += [(h.address, s.port, c.id, m) for m in mods]
            hf.services.append(sf)
        findings.append(hf)
    return findings, suggestions


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scope = Scope.from_file(args.scope)
    except (OSError, ScopeError) as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    out = Path(args.out) / datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    try:
        if args.cmd == "scan":
            scope.check(args.target)
            xml = run_nmap(args.target, out / "nmap.xml",
                           shlex.split(args.nmap_args) if args.nmap_args else None)
        else:
            xml = Path(args.xml)
        hosts = parse_nmap_xml(xml)
        scope.check([h.address for h in hosts])  # never report on hosts outside scope
    except ScopeError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 3

    nvd = None if args.offline else NVDClient(cache_dir=Path(args.out) / ".nvd-cache")
    meta = find_metadata(args.msf_db)
    if meta is None:
        print("[i] Metasploit metadata not found; module suggestions skipped (use --msf-db)", file=sys.stderr)
    index = ModuleIndex.load(meta) if meta else ModuleIndex.empty()

    findings, suggestions = analyse(hosts, nvd, index)
    scope_desc = ", ".join(str(n) for n in scope.networks)
    (out / "report.md").write_text(render(findings, scope_desc, offline=args.offline))
    (out / "msf_suggestions.rc").write_text(resource_script(suggestions))
    print(f"[+] {len(hosts)} host(s) analysed -> {out / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
