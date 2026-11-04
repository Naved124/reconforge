"""Look up known CVEs for a service via the NVD CVE API 2.0.

Matching is driven by the CPE that Nmap reports: NVD is queried with a
``virtualMatchString`` (vendor:product prefix) and the version check is done locally
against each CVE's configurations (see ``matching.py``). A keyword search on the
banner is kept only as a fallback for services that have no CPE, and its results
are labelled ``keyword-guess``.

Rate limits: NVD allows 5 requests per 30 seconds without an API key and 50 with
one (set NVD_API_KEY). Responses are cached on disk with a TTL.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

from .cpe import CPE, cpe22_to_23, meaningful, parse_cpe23
from .matching import CONFIDENCE_RANK, is_distro_package, match_cve, vendors_for_product
from .nmap import Service
from .vendors import Replacement, apply_alias, resolve_replacement

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
PAGE_SIZE = 2000
WINDOW_SECONDS = 30.0
RETRY_STATUS = {403, 429, 503}
DEFAULT_TTL = 24 * 3600


@dataclass
class CVE:
    id: str
    score: float | None
    severity: str
    summary: str
    confidence: str = "keyword-guess"
    reason: str = ""


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "reconforge" / "nvd"


def _parse_cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")
    if metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]
        return m["cvssData"].get("baseScore"), m.get("baseSeverity", "UNKNOWN")
    return None, "UNKNOWN"


def parse_cve(c: dict, confidence: str = "keyword-guess", reason: str = "") -> CVE:
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev = _parse_cvss(c.get("metrics", {}))
    return CVE(id=c.get("id", ""), score=score, severity=sev, summary=desc,
               confidence=confidence, reason=reason)


def sort_cves(cves: list[CVE]) -> list[CVE]:
    return sorted(cves, key=lambda v: (CONFIDENCE_RANK.get(v.confidence, 9),
                                       SEVERITY_ORDER.get(v.severity, 5), -(v.score or 0), v.id))


def parse_nvd_response(payload: dict) -> list[CVE]:
    out = [parse_cve(item.get("cve", {})) for item in payload.get("vulnerabilities", [])]
    out.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 5), -(v.score or 0)))
    return out


_MARIADB_RE = re.compile(r"mariadb", re.IGNORECASE)
MARIADB_NOTE = "MariaDB reported via the MySQL probe; its version numbering is not comparable with MySQL"


def _clean_version(text: str) -> str:
    """Leading numeric version of an Nmap version string, or '' if there is none."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*(?:p\d+)?)", text or "")
    return m.group(1) if m else ""


class NVDClient:
    def __init__(self, cache_dir: Path | None = None, api_key: str | None = None,
                 delay: float | None = None, ttl: float = DEFAULT_TTL):
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.delay = delay            # explicit minimum spacing; None = sliding window
        self.ttl = ttl
        self.limit = 50 if self.api_key else 5
        self._sent: deque[float] = deque()
        self._last = 0.0
        # injectable for tests
        self._sleep = time.sleep
        self._mono = time.monotonic
        self._wall = time.time

    # --- cache -----------------------------------------------------------
    def _cache_path(self, params: dict) -> Path:
        label = (params.get("virtualMatchString") or params.get("keywordSearch")
                 or params.get("deprecation") or "query")
        slug = "".join(ch if ch.isalnum() else "_" for ch in label)[:60]
        digest = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16]
        return self.cache_dir / f"{slug}-{digest}.json"

    def _read_cache(self, path: Path) -> dict | None:
        if self.ttl <= 0 or not path.exists():
            return None
        try:
            entry = json.loads(path.read_text())
            fetched = entry["fetched_at"]
            if self._wall() - fetched > self.ttl:
                return None
            return entry["payload"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write_cache(self, path: Path, payload: dict) -> None:
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"fetched_at": self._wall(), "payload": payload}))
            tmp.replace(path)
        except OSError:
            pass  # caching is best effort

    # --- network ---------------------------------------------------------
    def _throttle(self) -> None:
        now = self._mono()
        if self.delay is not None:
            wait = self.delay - (now - self._last)
        else:
            while self._sent and now - self._sent[0] >= WINDOW_SECONDS:
                self._sent.popleft()
            wait = (self._sent[0] + WINDOW_SECONDS + 0.5 - now) if len(self._sent) >= self.limit else 0
        if wait > 0:
            self._sleep(wait)
        self._last = self._mono()
        self._sent.append(self._last)

    def _fetch(self, params: dict) -> dict:
        return self._request(NVD_URL, params)

    def _fetch_cpes(self, params: dict) -> dict:
        return self._request(CPE_URL, params)

    def _request(self, endpoint: str, params: dict) -> dict:
        url = f"{endpoint}?{urllib.parse.urlencode(params)}"
        for attempt in range(4):
            self._throttle()
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "reconforge/0.3")
            if self.api_key:
                req.add_header("apiKey", self.api_key)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRY_STATUS or attempt == 3:
                    raise
                self._sleep(10 * 2 ** attempt)  # NVD signals throttling with 403/429/503
        raise RuntimeError("unreachable")

    def _query(self, params: dict, per_page: int = PAGE_SIZE, paginate: bool = True) -> dict:
        """Cached query; follows startIndex pagination and returns one merged payload."""
        key = self._cache_path({**params, "_per_page": per_page, "_paginate": paginate})
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        vulns, start = [], 0
        while True:
            page = self._fetch({**params, "resultsPerPage": per_page, "startIndex": start})
            got = page.get("vulnerabilities", [])
            vulns += got
            start += len(got)
            if not paginate or not got or start >= page.get("totalResults", 0):
                break
        payload = {"totalResults": len(vulns), "vulnerabilities": vulns}
        self._write_cache(key, payload)
        return payload

    # --- lookups ---------------------------------------------------------
    def lookup(self, product: str, version: str, limit: int = 20) -> list[CVE]:
        """Keyword search on product + version (labelled keyword-guess). Returns [] when
        there is no version info, since product-only searches return thousands of CVEs."""
        if not product or not version:
            return []
        payload = self._query({"keywordSearch": f"{product} {version}"}, per_page=limit, paginate=False)
        return parse_nvd_response(payload)[:limit]

    def _cpe_dictionary(self, part: str, product: str) -> list[dict]:
        """All NVD CPE dictionary records for a product, across vendors (paginated)."""
        products, start = [], 0
        match = CPE(part, "*", product).prefix()
        while True:
            page = self._fetch_cpes({"cpeMatchString": match, "resultsPerPage": 10000, "startIndex": start})
            got = page.get("products", [])
            products += got
            start += len(got)
            if not got or start >= page.get("totalResults", 0):
                return products

    def resolve_deprecation(self, target: CPE) -> Replacement | None:
        """Replacement vendor named by NVD's deprecatedBy chain, or None. The resolved result
        (not the large raw dictionary) is cached with the same TTL as CVE responses."""
        key = self._cache_path({"deprecation": f"{target.part}:{target.vendor}:{target.product}"})
        cached = self._read_cache(key)
        if cached is None:
            try:
                res = resolve_replacement(self._cpe_dictionary(target.part, target.product), target)
            except Exception as exc:  # degrade to the wildcard behaviour rather than lose the lookup
                print(f"[!] NVD CPE dictionary lookup failed for {target.vendor}:{target.product}: {exc}",
                      file=sys.stderr)
                return None
            cached = {"vendor": res.vendor, "deprecated": res.deprecated, "total": res.total} if res else {}
            self._write_cache(key, cached)
        return Replacement(cached["vendor"], cached["deprecated"], cached["total"]) if cached else None

    def _lookup_vendor(self, target: CPE, distro: bool, cap_notes: tuple[str, ...],
                       info_note: str = "", wildcard_fallback: bool = True) -> list[CVE]:
        """Query one vendor:product and version-check the results. If NVD knows nothing under
        that vendor, optionally retry with a wildcard vendor; those results are capped at
        'unconfirmed' (reason 'vendor alias')."""
        payload = self._query({"virtualMatchString": target.prefix()})
        alias = ""
        if not payload.get("vulnerabilities"):
            if not wildcard_fallback:
                return []
            wild = CPE(target.part, "*", target.product)
            payload = self._query({"virtualMatchString": wild.prefix()})
            vendors = sorted(vendors_for_product([v.get("cve", {}) for v in payload["vulnerabilities"]], target))
            if not vendors:
                return []
            alias = "vendor alias" if len(vendors) == 1 else f"vendor alias (ambiguous: {', '.join(vendors)})"
        out = []
        for item in payload["vulnerabilities"]:
            cve = item.get("cve", {})
            m = match_cve(cve, target, alias_note=alias, distro=distro, cap_notes=cap_notes,
                          info_note="" if alias else info_note)
            if m:
                out.append(parse_cve(cve, m.confidence, m.reason))
        return out

    def lookup_cpe(self, cpe23: str, distro: bool = False, cap_notes: tuple[str, ...] = ()) -> list[CVE]:
        """CVEs for a CPE 2.3 string, with the version checked locally.

        Vendor handling, in order: the static alias table (Nmap vs NVD naming), then NVD's own
        deprecation mapping (both the original and the replacement vendor are queried), and
        only if neither applies and NVD has nothing under the vendor, a wildcard-vendor retry
        that is capped at 'unconfirmed'.
        """
        target = parse_cpe23(cpe23)
        if target is None or not meaningful(target.version):
            return []
        target, alias_info = apply_alias(target)
        repl = self.resolve_deprecation(target)
        best: dict[str, CVE] = {}

        def add(cves: list[CVE]) -> None:
            for c in cves:
                old = best.get(c.id)
                if old is None or CONFIDENCE_RANK[c.confidence] < CONFIDENCE_RANK[old.confidence]:
                    best[c.id] = c

        add(self._lookup_vendor(target, distro, cap_notes, alias_info, wildcard_fallback=repl is None))
        if repl:
            add(self._lookup_vendor(replace(target, vendor=repl.vendor), distro, cap_notes,
                                    f"vendor via NVD deprecation: {target.vendor} → {repl.vendor}",
                                    wildcard_fallback=False))
        return sort_cves(list(best.values()))

    def lookup_service(self, s: Service) -> list[CVE]:
        """CPE-based lookup for a service; keyword fallback only when it has no usable CPE."""
        distro = is_distro_package(s.version, s.extrainfo)
        mariadb = bool(_MARIADB_RE.search(" ".join([s.product, s.version, s.extrainfo, *s.cpes])))
        targets = []
        for uri in s.cpes:
            c23 = cpe22_to_23(uri)
            t = parse_cpe23(c23) if c23 else None
            if t is None or t.part != "a":
                continue
            if not meaningful(t.version):
                t = t.with_version(_clean_version(s.version) or "*")
            targets.append(t)
        if not targets:
            return self.lookup(s.product, s.version)
        best: dict[str, CVE] = {}
        for t in targets:
            caps = (MARIADB_NOTE,) if mariadb and t.product == "mysql" else ()
            for c in self.lookup_cpe(t.to_string(), distro=distro, cap_notes=caps):
                old = best.get(c.id)
                if old is None or CONFIDENCE_RANK[c.confidence] < CONFIDENCE_RANK[old.confidence]:
                    best[c.id] = c
        return sort_cves(list(best.values()))
