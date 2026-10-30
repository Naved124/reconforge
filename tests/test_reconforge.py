import json
import shutil
from pathlib import Path

import pytest

from reconforge import cli
from reconforge.cve import NVDClient, parse_nvd_response
from reconforge.msf import ModuleIndex, resource_script
from reconforge.nmap import parse_nmap_xml
from reconforge.scope import Scope, ScopeError

FIX = Path(__file__).parent / "fixtures"


def write_scope(tmp_path, text):
    p = tmp_path / "scope.txt"
    p.write_text(text)
    return p


# --- scope ---------------------------------------------------------------

def test_scope_accepts_ip_and_cidr(tmp_path):
    s = Scope.from_file(write_scope(tmp_path, "10.10.11.23\n10.129.0.0/16  # htb\n"))
    assert s.contains("10.10.11.23")
    assert s.contains("10.129.4.7")
    assert not s.contains("8.8.8.8")


def test_scope_rejects_hostnames(tmp_path):
    with pytest.raises(ScopeError):
        Scope.from_file(write_scope(tmp_path, "example.com\n"))


def test_empty_scope_refused(tmp_path):
    with pytest.raises(ScopeError):
        Scope.from_file(write_scope(tmp_path, "# nothing here\n"))


def test_scope_check_blocks_out_of_scope(tmp_path):
    s = Scope.from_file(write_scope(tmp_path, "10.10.11.23\n"))
    with pytest.raises(ScopeError):
        s.check(["10.10.11.23", "1.1.1.1"])


# --- nmap parsing --------------------------------------------------------

def test_parse_skips_down_hosts_and_closed_ports():
    hosts = parse_nmap_xml(FIX / "scan.xml")
    assert [h.address for h in hosts] == ["10.10.11.23"]
    h = hosts[0]
    assert h.hostnames == ["target.htb"]
    assert h.os_guess.startswith("Linux")
    assert [s.port for s in h.services] == [21, 22, 80, 443]


def test_service_details_and_web_detection():
    _, ssh, http, https = parse_nmap_xml(FIX / "scan.xml")[0].services
    assert ssh.label == "OpenSSH 7.2p2"
    assert ssh.cpes == ["cpe:/a:openbsd:openssh:7.2p2"]
    assert not ssh.is_web
    assert http.is_web and https.is_web
    assert https.tunnel == "ssl"


# --- script findings -----------------------------------------------------

def test_scripts_parsed_and_errors_skipped():
    ftp = parse_nmap_xml(FIX / "scan.xml")[0].services[0]
    assert "ftp-anon" in ftp.scripts
    assert "vmware-version" not in ftp.scripts      # ERROR output dropped


def test_anonymous_ftp_flagged_high():
    from reconforge.findings import service_findings
    ftp = parse_nmap_xml(FIX / "scan.xml")[0].services[0]
    found = service_findings(ftp)
    assert found[0].severity == "HIGH" and found[0].title == "Anonymous FTP login allowed"
    titles = [f.title for f in found]
    assert "FTP sends credentials in cleartext" in titles
    assert "ftp-syst" in titles                       # kept as INFO context


def test_host_script_smb_signing():
    from reconforge.findings import host_findings
    host = parse_nmap_xml(FIX / "scan.xml")[0]
    assert [f.title for f in host_findings(host)] == ["SMB message signing not required"]


# --- CVE lookup ----------------------------------------------------------

def test_nvd_parse_sorted_by_severity():
    cves = parse_nvd_response(json.loads((FIX / "nvd_openssh.json").read_text()))
    assert [c.id for c in cves] == ["CVE-2016-10009", "CVE-2016-6210"]
    assert cves[0].severity == "HIGH" and cves[0].score == 7.3


def test_nvd_client_uses_cache_and_skips_versionless(tmp_path, monkeypatch):
    client = NVDClient(cache_dir=tmp_path, delay=0)
    calls = []
    payload = json.loads((FIX / "nvd_openssh.json").read_text())
    monkeypatch.setattr(client, "_fetch", lambda params: calls.append(params) or payload)
    assert client.lookup("nginx", "") == []          # no version -> no query
    first = client.lookup("OpenSSH", "7.2p2")
    second = client.lookup("OpenSSH", "7.2p2")       # served from cache
    assert len(calls) == 1
    assert [c.id for c in first] == [c.id for c in second]


# --- metasploit mapping --------------------------------------------------

def test_module_index_only_exploit_and_auxiliary():
    idx = ModuleIndex.load(FIX / "msf_meta.json")
    mods = idx.modules_for("cve-2016-6210")
    assert [m.fullname for m in mods] == ["auxiliary/scanner/ssh/ssh_enumusers"]


def test_resource_script_is_fully_commented():
    idx = ModuleIndex.load(FIX / "msf_meta.json")
    mod = idx.modules_for("CVE-2016-6210")[0]
    rc = resource_script([("10.10.11.23", 22, "CVE-2016-6210", mod)])
    assert all(line.startswith("#") or not line.strip() for line in rc.splitlines())
    assert "# use auxiliary/scanner/ssh/ssh_enumusers" in rc


# --- end to end ----------------------------------------------------------

def test_report_command_end_to_end(tmp_path, monkeypatch):
    scope = write_scope(tmp_path, "10.10.11.0/24\n")
    payload = json.loads((FIX / "nvd_openssh.json").read_text())
    empty = {"vulnerabilities": []}

    def fake_lookup(self, product, version, limit=20):
        if not product or not version:
            return []
        return parse_nvd_response(payload if product == "OpenSSH" else empty)

    monkeypatch.setattr(NVDClient, "lookup", fake_lookup)
    out = tmp_path / "reports"
    rc = cli.main(["report", "--scope", str(scope), "--xml", str(FIX / "scan.xml"),
                   "--out", str(out), "--msf-db", str(FIX / "msf_meta.json")])
    assert rc == 0
    run_dir = next(p for p in out.iterdir() if not p.name.startswith("."))
    report = (run_dir / "report.md").read_text()
    assert "CVE-2016-6210" in report
    assert "auxiliary/scanner/ssh/ssh_enumusers" in report
    assert "Burp Suite" in report
    assert "[HIGH] Anonymous FTP login allowed" in report
    assert "Misconfigurations:** High 1, Medium 1, Low 1" in report
    assert "use auxiliary/scanner/ssh/ssh_enumusers" in (run_dir / "msf_suggestions.rc").read_text()


def test_report_refuses_out_of_scope_hosts(tmp_path):
    scope = write_scope(tmp_path, "192.168.56.0/24\n")
    rc = cli.main(["report", "--scope", str(scope), "--xml", str(FIX / "scan.xml"),
                   "--out", str(tmp_path / "r"), "--offline"])
    assert rc == 3


def test_scan_refuses_before_running_nmap(tmp_path, monkeypatch):
    scope = write_scope(tmp_path, "10.10.11.23\n")
    monkeypatch.setattr(cli, "run_nmap", lambda *a, **k: pytest.fail("nmap must not run"))
    rc = cli.main(["scan", "--scope", str(scope), "--target", "8.8.8.8",
                   "--out", str(tmp_path / "r"), "--offline"])
    assert rc == 3
