import json
from pathlib import Path

import pytest

from reconforge.cpe import compare_versions, cpe22_to_23, parse_cpe23, split_update
from reconforge.cve import NVDClient
from reconforge.matching import (DISTRO_NOTE, is_distro_package, match_cve, target_version,
                                 vendors_for_product)
from reconforge.nmap import Service
from reconforge.vendors import MAX_HOPS, VENDOR_ALIASES, apply_alias, resolve_replacement

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def run_match(fixture, cpe22, **kw):
    target = parse_cpe23(cpe22_to_23(cpe22))
    out = {}
    for item in load(fixture)["vulnerabilities"]:
        m = match_cve(item["cve"], target, **kw)
        if m:
            out[item["cve"]["id"]] = m
    return out


# --- CPE 2.2 -> 2.3 -------------------------------------------------------

def test_cpe22_to_23_basic():
    assert cpe22_to_23("cpe:/a:vsftpd:vsftpd:3.0.3") == "cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/a:openbsd:openssh:7.2p2") == "cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*"


def test_cpe22_to_23_missing_version_and_case():
    assert cpe22_to_23("cpe:/a:igor_sysoev:nginx") == "cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*"
    assert cpe22_to_23("CPE:/A:Apache:HTTP_Server:2.4.41") == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


def test_cpe22_to_23_percent_decoding_and_escaping():
    assert cpe22_to_23("cpe:/a:foo:bar:1.0%2b2") == "cpe:2.3:a:foo:bar:1.0\\+2:*:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/o:linux:linux_kernel") == "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"


def test_cpe22_to_23_update_and_packed_edition():
    assert cpe22_to_23("cpe:/a:foo:bar:1.0:beta") == "cpe:2.3:a:foo:bar:1.0:beta:*:*:*:*:*:*"
    assert cpe22_to_23("cpe:/a:foo:bar:1.0:-:~pro~~windows~x64~") == \
        "cpe:2.3:a:foo:bar:1.0:-:pro:*:*:windows:x64:*"


@pytest.mark.parametrize("bad", ["", "vsftpd 3.0.3", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", "cpe:/x:a:b",
                                 "cpe:/a:onlyvendor", None])
def test_cpe22_to_23_rejects_invalid(bad):
    assert cpe22_to_23(bad) is None


def test_parse_cpe23_roundtrip_and_escapes():
    s = "cpe:2.3:a:foo:bar:1.0\\+2:*:*:*:*:*:*:*"
    cpe = parse_cpe23(s)
    assert (cpe.vendor, cpe.product, cpe.version) == ("foo", "bar", "1.0+2")
    assert cpe.to_string() == s
    assert parse_cpe23("cpe:2.3:a:too:short") is None
    assert parse_cpe23("cpe:/a:vsftpd:vsftpd") is None


# --- version comparator ----------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("3.0.3", "3.0.3", 0),
    ("3.0.3", "3.0.4", -1),
    ("3.0.10", "3.0.9", 1),             # numeric, not lexical
    ("2.4.41", "2.4.7", 1),
    ("3.0", "3.0.0", 0),                # zero padding
    ("7.4p1", "7.4", 1),                # patch level sorts after the base release
    ("7.4p1", "7.5", -1),
    ("7.4p2", "7.4p1", 1),
    ("7.2p2", "7.2p2", 0),
    ("2.0rc1", "2.0", -1),              # pre-release sorts before the release
    ("2.0rc2", "2.0rc1", 1),
    ("2.0beta1", "2.0rc1", -1),
    ("v1.2.3", "1.2.3", 0),
    ("1.0-beta2", "1.0", -1),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected
    assert compare_versions(b, a) == -expected


@pytest.mark.parametrize("a,b", [
    ("", "1.0"), ("1.0", ""), (None, "1.0"), ("*", "1.0"), ("-", "1.0"),
    ("2.4.41-4ubuntu3", "2.4.41"), ("1.x", "1.0"), ("unknown", "1.0"), ("1.0.2k", "1.0.2h"),
])
def test_compare_versions_uncomparable(a, b):
    assert compare_versions(a, b) is None


def test_split_update():
    assert split_update("7.2p2") == ("7.2", "p2")
    assert split_update("7.2") == ("7.2", "")
    assert split_update("2.0rc1") == ("2.0", "rc1")


def test_target_version_folds_update_field():
    assert target_version(parse_cpe23("cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*")) == "7.2p2"
    assert target_version(parse_cpe23("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")) == ""


# --- range matching on saved NVD fixtures ------------------------------------

def test_openssh_ranges_with_update_field():
    got = run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:7.2p2")
    assert {k: m.confidence for k, m in got.items()} == {
        "CVE-2016-6210": "confirmed-range",    # openssh:*:p2, <= 7.2
        "CVE-2016-6515": "confirmed-range",
        "CVE-2016-10009": "confirmed-range",   # <= 7.3
        "CVE-2018-15473": "confirmed-range",   # <= 7.7
        "CVE-2023-38408": "confirmed-range",   # < 9.3
    }
    # CVE-2016-3115 is for openssh:*:p1 only, 2001-0144 lists old exact versions
    assert "CVE-2016-3115" not in got and "CVE-2001-0144" not in got


def test_version_just_outside_range_is_dropped():
    assert run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:9.4") == {}
    # 9.3 is outside "< 9.3", but the real record also lists openssh:9.3:- as an exact CPE
    got = run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:9.3")
    assert {k: m.confidence for k, m in got.items()} == {"CVE-2023-38408": "exact-cpe"}


def test_exact_cpe_match_and_platform_cap():
    got = run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:4.3p2")
    assert "CVE-2007-3102" in got
    m = got["CVE-2007-3102"]                   # exact CPE, but only on a listed platform (AND config)
    assert m.confidence == "unconfirmed" and "platform-dependent" in m.reason
    assert run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:4.0")["CVE-2008-3234"].confidence == "unconfirmed"


def test_vsftpd_real_vendor_gives_confirmed_and_exact():
    got = run_match("nvd_vsftpd_cpe.json", "cpe:/a:vsftpd_project:vsftpd:3.0.3")
    assert {k: m.confidence for k, m in got.items()} == {
        "CVE-2021-3618": "confirmed-range", "CVE-2021-30047": "exact-cpe"}
    # 3.0.2 and earlier / 2.3.4 backdoor / <2.3.3 are excluded by the version check
    for gone in ("CVE-2015-1419", "CVE-2011-2523", "CVE-2011-0762"):
        assert gone not in got


def test_boundaries_inclusive_and_exclusive():
    def conf(version):
        return {k: m.confidence for k, m in run_match("nvd_ranges_synthetic.json", f"cpe:/a:acme:widget:{version}").items()}
    assert conf("1.0")["CVE-9999-0001"] == "confirmed-range"       # startIncluding
    assert "CVE-9999-0002" not in conf("1.0")                      # startExcluding
    assert "CVE-9999-0001" not in conf("2.0")                      # endExcluding
    assert conf("2.0")["CVE-9999-0002"] == "confirmed-range"       # endIncluding
    assert "CVE-9999-0002" not in conf("2.0.1")


def test_synthetic_special_cases():
    got = run_match("nvd_ranges_synthetic.json", "cpe:/a:acme:widget:1.5.0")
    assert got["CVE-9999-0003"].confidence == "exact-cpe"
    assert got["CVE-9999-0004"].confidence == "unconfirmed"        # all versions affected
    assert "CVE-9999-0005" not in got                              # vulnerable: false
    assert "CVE-9999-0006" not in got                              # negated node
    assert got["CVE-9999-0007"].confidence == "unconfirmed"        # needs a specific platform
    assert got["CVE-9999-0008"].confidence == "unconfirmed"        # uncomparable bound
    assert "CVE-9999-0009" not in got                              # needs update p1, target has none
    assert run_match("nvd_ranges_synthetic.json", "cpe:/a:acme:widget:1.5p1")["CVE-9999-0009"].confidence == "confirmed-range"


def test_uncomparable_target_version_is_unconfirmed_not_dropped():
    target = parse_cpe23("cpe:2.3:a:acme:widget:1.x-custom:*:*:*:*:*:*:*")
    item = load("nvd_ranges_synthetic.json")["vulnerabilities"][0]["cve"]
    assert match_cve(item, target).confidence == "unconfirmed"


def test_missing_version_is_unconfirmed():
    target = parse_cpe23("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")
    item = load("nvd_ranges_synthetic.json")["vulnerabilities"][0]["cve"]
    assert match_cve(item, target).confidence == "unconfirmed"


def test_other_product_or_vendor_not_matched():
    assert run_match("nvd_ranges_synthetic.json", "cpe:/a:acme:gadget:1.5.0") == {}
    assert run_match("nvd_ranges_synthetic.json", "cpe:/a:other:widget:1.5.0") == {}


# --- vendor alias ---------------------------------------------------------------

def test_vendor_alias_is_never_better_than_unconfirmed():
    got = run_match("nvd_vsftpd_cpe.json", "cpe:/a:vsftpd:vsftpd:3.0.3", alias_note="vendor alias")
    assert {k: m.confidence for k, m in got.items()} == {
        "CVE-2021-3618": "unconfirmed", "CVE-2021-30047": "unconfirmed"}
    assert all(m.reason.startswith("vendor alias") for m in got.values())


def test_vendors_for_product():
    cves = [i["cve"] for i in load("nvd_vsftpd_cpe.json")["vulnerabilities"]]
    target = parse_cpe23("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*")
    assert vendors_for_product(cves, target) == {"beasts", "redhat", "vsftpd_project"}


# --- distro packages ------------------------------------------------------------

@pytest.mark.parametrize("text", ["Ubuntu 4ubuntu2.8", "7.9p1 Debian 10+deb10u2", "2.4.6 el7", "1.0.2k-fips CentOS",
                                  "8.0p1 Ubuntu Linux; protocol 2.0", "9.2p1 Debian 2+deb12u3", "1.14.1.el8_4"])
def test_distro_markers_detected(text):
    assert is_distro_package(text)


@pytest.mark.parametrize("text", ["", "3.0.3", "7.2p2", "OpenSSH for Windows", "protocol 2.0"])
def test_plain_versions_not_distro(text):
    assert not is_distro_package(text)


def test_distro_package_downgrades_confirmed_and_exact():
    got = run_match("nvd_vsftpd_cpe.json", "cpe:/a:vsftpd_project:vsftpd:3.0.3", distro=True)
    assert {m.confidence for m in got.values()} == {"unconfirmed"}
    assert all(DISTRO_NOTE in m.reason for m in got.values())
    ssh = run_match("nvd_openssh_cpe.json", "cpe:/a:openbsd:openssh:7.2p2", distro=True)
    assert ssh and {m.confidence for m in ssh.values()} == {"unconfirmed"}


# --- NVD client (no network) ------------------------------------------------------

class FakeNVD(NVDClient):
    """NVDClient whose HTTP layer serves canned payloads keyed by virtualMatchString."""

    def __init__(self, tmp_path, responses, cpe_responses=None, **kw):
        super().__init__(cache_dir=tmp_path, delay=0, **kw)
        self.responses = responses
        self.cpe_responses = cpe_responses or {}
        self.calls = []
        self.cpe_calls = []

    def _fetch_cpes(self, params):
        self.cpe_calls.append(params)
        return self.cpe_responses.get(params["cpeMatchString"], {"totalResults": 0, "products": []})

    def _fetch(self, params):
        self.calls.append(params)
        return self.responses.get(params.get("virtualMatchString") or params.get("keywordSearch"),
                                  {"totalResults": 0, "vulnerabilities": []})


def test_lookup_cpe_uses_vendor_product_prefix(tmp_path):
    ssh = load("nvd_openssh_cpe.json")
    client = FakeNVD(tmp_path, {"cpe:2.3:a:openbsd:openssh": ssh})
    cves = client.lookup_cpe("cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*")
    assert [c.confidence for c in cves] == ["confirmed-range"] * 5
    assert len(client.calls) == 1 and client.calls[0]["virtualMatchString"] == "cpe:2.3:a:openbsd:openssh"
    assert cves[0].severity in ("CRITICAL", "HIGH")       # strongest severity first within a confidence


def test_lookup_cpe_wildcard_fallback_ambiguous_vendor(tmp_path, monkeypatch):
    monkeypatch.setattr("reconforge.cve.apply_alias", lambda t: (t, ""))   # exercise the wildcard path
    client = FakeNVD(tmp_path, {"cpe:2.3:a:*:vsftpd": load("nvd_vsftpd_cpe.json")})
    cves = client.lookup_cpe("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*")
    assert {c.id for c in cves} == {"CVE-2021-30047", "CVE-2021-3618"}
    assert {c.confidence for c in cves} == {"unconfirmed"}
    assert all("vendor alias (ambiguous: beasts, redhat, vsftpd_project)" in c.reason for c in cves)
    assert [p["virtualMatchString"] for p in client.calls] == ["cpe:2.3:a:vsftpd:vsftpd", "cpe:2.3:a:*:vsftpd"]


def test_lookup_cpe_wildcard_fallback_single_vendor(tmp_path, monkeypatch):
    monkeypatch.setattr("reconforge.cve.apply_alias", lambda t: (t, ""))
    data = load("nvd_vsftpd_cpe.json")
    data["vulnerabilities"] = [v for v in data["vulnerabilities"] if "CVE-2021" in v["cve"]["id"]
                               or v["cve"]["id"] in ("CVE-2011-0762", "CVE-2015-1419", "CVE-2011-2523")]
    client = FakeNVD(tmp_path, {"cpe:2.3:a:*:vsftpd": data})
    cves = client.lookup_cpe("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*")
    assert {c.confidence for c in cves} == {"unconfirmed"}
    assert all(c.reason.startswith("vendor alias;") for c in cves)


def test_lookup_cpe_versionless_makes_no_query(tmp_path):
    client = FakeNVD(tmp_path, {})
    assert client.lookup_cpe("cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*") == []
    assert client.calls == []


def test_lookup_service_prefers_cpe_and_flags_distro(tmp_path):
    client = FakeNVD(tmp_path, {"cpe:2.3:a:openbsd:openssh": load("nvd_openssh_cpe.json")})
    svc = Service(port=22, protocol="tcp", name="ssh", product="OpenSSH", version="7.2p2",
                  extrainfo="Ubuntu 4ubuntu2.8", cpes=["cpe:/a:openbsd:openssh:7.2p2"])
    cves = client.lookup_service(svc)
    assert cves and {c.confidence for c in cves} == {"unconfirmed"}
    assert all(DISTRO_NOTE in c.reason for c in cves)


def test_lookup_service_keyword_fallback_without_cpe(tmp_path):
    kw = {"totalResults": 1, "vulnerabilities": [
        {"cve": {"id": "CVE-1999-0001", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {}}}]}
    client = FakeNVD(tmp_path, {"Apache httpd 2.4.18": kw})
    svc = Service(port=80, protocol="tcp", name="http", product="Apache httpd", version="2.4.18")
    cves = client.lookup_service(svc)
    assert [(c.id, c.confidence) for c in cves] == [("CVE-1999-0001", "keyword-guess")]
    nover = Service(port=80, protocol="tcp", name="http", product="nginx")
    assert client.lookup_service(nover) == []


def test_lookup_service_fills_missing_cpe_version_from_banner(tmp_path):
    client = FakeNVD(tmp_path, {"cpe:2.3:a:openbsd:openssh": load("nvd_openssh_cpe.json")})
    svc = Service(port=22, protocol="tcp", name="ssh", product="OpenSSH", version="7.2p2",
                  cpes=["cpe:/a:openbsd:openssh"])
    assert {c.confidence for c in client.lookup_service(svc)} == {"confirmed-range"}


def test_cache_ttl(tmp_path):
    client = FakeNVD(tmp_path, {"cpe:2.3:a:openbsd:openssh": load("nvd_openssh_cpe.json")}, ttl=3600)
    now = [1000.0]
    client._wall = lambda: now[0]
    cpe = "cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*"
    client.lookup_cpe(cpe)
    now[0] += 3000
    client.lookup_cpe(cpe)                      # still fresh
    assert len(client.calls) == 1
    now[0] += 1000                              # 4000 s old > ttl
    client.lookup_cpe(cpe)
    assert len(client.calls) == 2


def test_cache_survives_new_client_and_key_is_per_cpe(tmp_path):
    responses = {"cpe:2.3:a:openbsd:openssh": load("nvd_openssh_cpe.json")}
    FakeNVD(tmp_path, responses).lookup_cpe("cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*")
    second = FakeNVD(tmp_path, responses)
    second.lookup_cpe("cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*")   # same vendor:product -> same cache entry
    assert second.calls == []
    assert any(p.name.startswith("cpe_2_3_a_openbsd_openssh-") for p in tmp_path.iterdir())


def test_pagination_merges_pages(tmp_path):
    items = load("nvd_openssh_cpe.json")["vulnerabilities"]
    pages = {0: items[:4], 4: items[4:8], 8: items[8:]}

    class Paged(NVDClient):
        calls = 0

        def _fetch(self, params):
            self.calls += 1
            return {"totalResults": len(items), "vulnerabilities": pages[params["startIndex"]]}

    client = Paged(cache_dir=tmp_path, delay=0)
    payload = client._query({"virtualMatchString": "cpe:2.3:a:openbsd:openssh"}, per_page=4)
    assert client.calls == 3 and len(payload["vulnerabilities"]) == len(items)


def test_sliding_window_rate_limit(tmp_path, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    client = NVDClient(cache_dir=tmp_path)
    t, sleeps = [0.0], []
    client._mono = lambda: t[0]
    client._sleep = lambda s: (sleeps.append(s), t.__setitem__(0, t[0] + s))
    for _ in range(5):
        client._throttle()
    assert sleeps == []                          # 5 requests in the window are fine
    client._throttle()
    assert len(sleeps) == 1 and sleeps[0] >= 30  # the 6th waits for the window to slide
    keyed = NVDClient(cache_dir=tmp_path, api_key="k")
    assert keyed.limit == 50 and client.limit == 5


# --- vendor alias table -----------------------------------------------------------

def test_alias_table_contents_and_apply():
    assert VENDOR_ALIASES == {("a", "vsftpd", "vsftpd"): "vsftpd_project"}
    t, note = apply_alias(parse_cpe23("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*"))
    assert t.vendor == "vsftpd_project" and note == "vendor via alias table: vsftpd → vsftpd_project"
    same, none = apply_alias(parse_cpe23("cpe:2.3:a:openbsd:openssh:7.2:*:*:*:*:*:*:*"))
    assert same.vendor == "openbsd" and none == ""


def test_vsftpd_alias_reaches_exact_and_confirmed(tmp_path):
    client = FakeNVD(tmp_path, {"cpe:2.3:a:vsftpd_project:vsftpd": load("nvd_vsftpd_cpe.json")})
    cves = {c.id: c for c in client.lookup_cpe("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*")}
    assert cves["CVE-2021-3618"].confidence == "confirmed-range"
    assert cves["CVE-2021-30047"].confidence == "exact-cpe"
    assert all(c.reason.startswith("vendor via alias table: vsftpd → vsftpd_project;") for c in cves.values())
    assert [c["virtualMatchString"] for c in client.calls] == ["cpe:2.3:a:vsftpd_project:vsftpd"]


# --- NVD deprecation resolution ------------------------------------------------------

def rec(vendor, product, ver, dep_by=()):
    name = f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
    out = {"cpeName": name, "deprecated": bool(dep_by)}
    if dep_by:
        out["deprecatedBy"] = [{"cpeName": d} for d in dep_by]
    return {"cpe": out}


def cp(vendor, product, ver):
    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def tgt(vendor, product):
    return parse_cpe23(f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*")


def test_deprecation_nginx_two_hop_chain_from_real_data():
    r = resolve_replacement(load("nvd_cpes_nginx.json")["products"], tgt("igor_sysoev", "nginx"))
    assert (r.vendor, r.deprecated, r.total) == ("f5", 11, 11)      # igor_sysoev -> nginx -> f5


def test_deprecation_mysql_mixed_targets_from_real_data():
    r = resolve_replacement(load("nvd_cpes_mysql.json")["products"], tgt("mysql", "mysql"))
    assert r.vendor == "oracle" and r.deprecated >= 0.9 * r.total   # direct targets: oracle and mysql (renames)


def test_deprecation_not_applied_to_live_vendor():
    prods = load("nvd_cpes_nginx.json")["products"]
    assert resolve_replacement(prods, tgt("f5", "nginx")) is None
    assert resolve_replacement(prods, tgt("nobody", "nginx")) is None


def test_deprecation_threshold_is_90_percent():
    live = cp("f5", "w", "1")
    def build(n_dep, n_live):
        prods = [rec("f5", "w", "1")]
        prods += [rec("old", "w", f"d{i}", [cp("f5", "w", "1")]) for i in range(n_dep)]
        prods += [rec("old", "w", f"l{i}") for i in range(n_live)]
        return prods
    assert resolve_replacement(build(8, 2), tgt("old", "w")) is None              # 80%
    assert resolve_replacement(build(9, 1), tgt("old", "w")).vendor == "f5"       # 90%


def test_deprecation_cycle_and_hop_limit():
    cyc = [rec("old", "w", "1", [cp("old", "w", "2")]), rec("old", "w", "2", [cp("old", "w", "1")])]
    assert resolve_replacement(cyc, tgt("old", "w")) is None

    def chain(hops):
        prods = [rec("v0", "w", "1", [cp("v1", "w", "1")])]
        for i in range(1, hops):
            prods.append(rec(f"v{i}", "w", "1", [cp(f"v{i + 1}", "w", "1")]))
        prods.append(rec(f"v{hops}", "w", "1"))
        return prods
    assert resolve_replacement(chain(MAX_HOPS), tgt("v0", "w")).vendor == f"v{MAX_HOPS}"
    assert resolve_replacement(chain(MAX_HOPS + 1), tgt("v0", "w")) is None


def test_deprecation_ambiguous_unresolved_or_other_product_is_ignored():
    two = [rec("old", "w", "1", [cp("a", "w", "1")]), rec("old", "w", "2", [cp("b", "w", "2")]),
           rec("a", "w", "1"), rec("b", "w", "2")]
    assert resolve_replacement(two, tgt("old", "w")) is None                   # two live vendors
    missing = [rec("old", "w", "1", [cp("a", "w", "1")])]                      # target not in dictionary
    assert resolve_replacement(missing, tgt("old", "w")) is None
    other = [rec("old", "w", "1", [cp("a", "other", "1")]), rec("a", "other", "1")]
    assert resolve_replacement(other, tgt("old", "w")) is None                 # renamed product
    nodep = [{"cpe": {"cpeName": cp("old", "w", "1"), "deprecated": True}}]    # no deprecatedBy
    assert resolve_replacement(nodep, tgt("old", "w")) is None
    same = [rec("old", "w", "1", [cp("old", "w", "1.0")]), rec("old", "w", "1.0")]
    assert resolve_replacement(same, tgt("old", "w")) is None                  # live vendor == original


def nginx_client(tmp_path, **kw):
    return FakeNVD(tmp_path, {"cpe:2.3:a:f5:nginx": load("nvd_nginx_f5.json")},
                   {"cpe:2.3:a:*:nginx": load("nvd_cpes_nginx.json")}, **kw)


def test_nginx_via_deprecation_reaches_confirmed_range(tmp_path):
    client = nginx_client(tmp_path)
    cves = {c.id: c for c in client.lookup_cpe("cpe:2.3:a:igor_sysoev:nginx:1.0.5:*:*:*:*:*:*:*")}
    assert {"CVE-2011-4315", "CVE-2012-1180", "CVE-2021-23017", "CVE-2013-4547", "CVE-2017-7529"} <= set(cves)
    assert "CVE-2009-4487" not in cves                      # exact 0.7.64 only
    assert {c.confidence for c in cves.values()} == {"confirmed-range"}
    assert all(c.reason.startswith("vendor via NVD deprecation: igor_sysoev → f5; ") for c in cves.values())
    # both vendors queried; no wildcard retry because the replacement is known
    assert [c["virtualMatchString"] for c in client.calls] == ["cpe:2.3:a:igor_sysoev:nginx", "cpe:2.3:a:f5:nginx"]


def test_deprecation_matches_still_get_distro_downgrade(tmp_path):
    cves = nginx_client(tmp_path).lookup_cpe("cpe:2.3:a:igor_sysoev:nginx:1.0.5:*:*:*:*:*:*:*", distro=True)
    assert cves and {c.confidence for c in cves} == {"unconfirmed"}
    assert all(c.reason.startswith("vendor via NVD deprecation: igor_sysoev → f5; " + DISTRO_NOTE) for c in cves)


def test_deprecation_dedupes_by_id_keeping_strongest(tmp_path):
    # the same CVE comes back from both vendors; original-vendor hit is exact, replacement-vendor hit is a range
    cve_orig = {"cve": {"id": "CVE-9999-1", "descriptions": [{"lang": "en", "value": "x"}], "configurations": [
        {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:igor_sysoev:nginx:1.0.5:*:*:*:*:*:*:*"}]}]}]}}
    cve_repl = {"cve": {"id": "CVE-9999-1", "descriptions": [{"lang": "en", "value": "x"}], "configurations": [
        {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                  "versionEndExcluding": "2.0"}]}]}]}}
    client = FakeNVD(tmp_path, {"cpe:2.3:a:igor_sysoev:nginx": {"vulnerabilities": [cve_orig]},
                                "cpe:2.3:a:f5:nginx": {"vulnerabilities": [cve_repl]}},
                     {"cpe:2.3:a:*:nginx": load("nvd_cpes_nginx.json")})
    cves = client.lookup_cpe("cpe:2.3:a:igor_sysoev:nginx:1.0.5:*:*:*:*:*:*:*")
    assert [(c.id, c.confidence) for c in cves] == [("CVE-9999-1", "confirmed-range")]


def test_no_deprecation_keeps_wildcard_behaviour(tmp_path):
    # ambiguous chain: two live vendors -> rule ignored -> old wildcard/ambiguous path applies
    prods = [rec("old", "widget", "1", [cp("a", "widget", "1")]), rec("old", "widget", "2", [cp("b", "widget", "2")]),
             rec("a", "widget", "1"), rec("b", "widget", "2")]
    synthetic = load("nvd_ranges_synthetic.json")
    client = FakeNVD(tmp_path, {"cpe:2.3:a:*:widget": synthetic}, {"cpe:2.3:a:*:widget": {"products": prods, "totalResults": 4}})
    cves = client.lookup_cpe("cpe:2.3:a:old:widget:1.5.0:*:*:*:*:*:*:*")
    assert cves and {c.confidence for c in cves} == {"unconfirmed"}
    assert all(c.reason.startswith("vendor alias") for c in cves)


def test_deprecation_resolution_is_cached_with_ttl(tmp_path):
    client = nginx_client(tmp_path, ttl=3600)
    now = [1000.0]
    client._wall = lambda: now[0]
    cpe = "cpe:2.3:a:igor_sysoev:nginx:1.0.5:*:*:*:*:*:*:*"
    client.lookup_cpe(cpe)
    assert len(client.cpe_calls) == 1
    now[0] += 3000
    other = nginx_client(tmp_path, ttl=3600)               # new client, same cache dir
    other._wall = lambda: now[0]
    other.lookup_cpe("cpe:2.3:a:igor_sysoev:nginx:1.0.6:*:*:*:*:*:*:*")
    assert other.cpe_calls == []                           # resolution served from cache
    now[0] += 1000                                         # past the TTL
    client.lookup_cpe(cpe)
    assert len(client.cpe_calls) == 2


def test_negative_resolution_is_cached_too(tmp_path):
    client = FakeNVD(tmp_path, {"cpe:2.3:a:openbsd:openssh": load("nvd_openssh_cpe.json")})
    client.lookup_cpe("cpe:2.3:a:openbsd:openssh:7.2p2:*:*:*:*:*:*:*")
    client.lookup_cpe("cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*")
    assert len(client.cpe_calls) == 1


def test_cpe_dictionary_failure_degrades_to_wildcard(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("reconforge.cve.apply_alias", lambda t: (t, ""))
    client = FakeNVD(tmp_path, {"cpe:2.3:a:*:vsftpd": load("nvd_vsftpd_cpe.json")})
    client._fetch_cpes = lambda params: (_ for _ in ()).throw(OSError("boom"))
    cves = client.lookup_cpe("cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*")
    assert {c.confidence for c in cves} == {"unconfirmed"}
    assert "CPE dictionary lookup failed" in capsys.readouterr().err


# --- MySQL: deprecation and MariaDB -----------------------------------------------------

def mysql_client(tmp_path):
    return FakeNVD(tmp_path, {"cpe:2.3:a:mysql:mysql": load("nvd_mysql_legacy.json"),
                              "cpe:2.3:a:oracle:mysql": load("nvd_mysql_oracle.json")},
                   {"cpe:2.3:a:*:mysql": load("nvd_cpes_mysql.json")})


def test_mysql_queries_both_vendors_via_deprecation(tmp_path):
    client = mysql_client(tmp_path)
    svc = Service(port=3306, protocol="tcp", name="mysql", product="MySQL", version="5.5.5",
                  cpes=["cpe:/a:mysql:mysql:5.5.5"])
    cves = {c.id: c for c in client.lookup_service(svc)}
    assert [c["virtualMatchString"] for c in client.calls] == ["cpe:2.3:a:mysql:mysql", "cpe:2.3:a:oracle:mysql"]
    assert cves["CVE-2016-6662"].confidence == "confirmed-range"            # oracle:mysql 5.5.0 - 5.5.52
    assert cves["CVE-2016-6662"].reason.startswith("vendor via NVD deprecation: mysql → oracle; ")
    assert "CVE-2021-2307" not in cves                                      # 8.0.x only


@pytest.mark.parametrize("product,version,extrainfo,cpes", [
    ("MySQL", "5.5.5-10.3.23-MariaDB", "", ["cpe:/a:mysql:mysql:5.5.5-10.3.23-mariadb"]),   # junk CPE version
    ("MySQL", "5.5.5-10.3.23-MariaDB", "", ["cpe:/a:mysql:mysql"]),     # no CPE version -> banner prefix 5.5.5
    ("MySQL", "5.5.5", "MariaDB 10.3.23", ["cpe:/a:mysql:mysql:5.5.5"]),     # clean-looking CPE, MariaDB elsewhere
    ("MariaDB", "5.5.5-10.3.23-MariaDB", "", ["cpe:/a:mysql:mysql:5.5.5"]),
])
def test_mariadb_never_exact_or_confirmed_against_mysql(tmp_path, product, version, extrainfo, cpes):
    svc = Service(port=3306, protocol="tcp", name="mysql", product=product, version=version,
                  extrainfo=extrainfo, cpes=cpes)
    cves = mysql_client(tmp_path).lookup_service(svc)
    assert cves
    assert {c.confidence for c in cves} == {"unconfirmed"}
    assert all("MariaDB" in c.reason for c in cves)


def test_mariadb_with_its_own_cpe_is_not_capped_as_mysql(tmp_path):
    # a proper mariadb:mariadb CPE is a different product; the MySQL cap must not apply to it
    maria = {"cve": {"id": "CVE-9999-2", "descriptions": [{"lang": "en", "value": "x"}], "configurations": [
        {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*",
                                  "versionEndExcluding": "10.4.0"}]}]}]}}
    client = FakeNVD(tmp_path, {"cpe:2.3:a:mariadb:mariadb": {"vulnerabilities": [maria]}})
    svc = Service(port=3306, protocol="tcp", name="mysql", product="MariaDB", version="10.3.23",
                  cpes=["cpe:/a:mariadb:mariadb:10.3.23"])
    assert [c.confidence for c in client.lookup_service(svc)] == ["confirmed-range"]
