"""Look up known CVEs for a service via the NVD CVE API 2.0, with a local cache.

Without an API key NVD allows roughly 5 requests per 30 seconds, so requests are
spaced out. Set NVD_API_KEY to raise the limit.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


@dataclass
class CVE:
    id: str
    score: float | None
    severity: str
    summary: str


def _parse_cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity", "UNKNOWN")
    if metrics.get("cvssMetricV2"):
        m = metrics["cvssMetricV2"][0]
        return m["cvssData"].get("baseScore"), m.get("baseSeverity", "UNKNOWN")
    return None, "UNKNOWN"


def parse_nvd_response(payload: dict) -> list[CVE]:
    out = []
    for item in payload.get("vulnerabilities", []):
        c = item.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, sev = _parse_cvss(c.get("metrics", {}))
        out.append(CVE(id=c.get("id", ""), score=score, severity=sev, summary=desc))
    out.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 5), -(v.score or 0)))
    return out


class NVDClient:
    def __init__(self, cache_dir: Path, api_key: str | None = None, delay: float | None = None):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.delay = delay if delay is not None else (0.7 if self.api_key else 6.5)
        self._last = 0.0

    def _cache_path(self, query: str) -> Path:
        safe = "".join(ch if ch.isalnum() else "_" for ch in query)[:120]
        return self.cache_dir / f"{safe}.json"

    def _fetch(self, params: dict) -> dict:
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(f"{NVD_URL}?{urllib.parse.urlencode(params)}")
        req.add_header("User-Agent", "reconforge/0.2")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        with urllib.request.urlopen(req, timeout=30) as resp:
            self._last = time.monotonic()
            return json.load(resp)

    def lookup(self, product: str, version: str, limit: int = 20) -> list[CVE]:
        """Keyword search on product + version. Returns [] when there is no version info,
        since product-only searches return thousands of irrelevant CVEs."""
        if not product or not version:
            return []
        query = f"{product} {version}"
        cache = self._cache_path(query)
        if cache.exists():
            payload = json.loads(cache.read_text())
        else:
            payload = self._fetch({"keywordSearch": query, "resultsPerPage": limit})
            cache.write_text(json.dumps(payload))
        return parse_nvd_response(payload)[:limit]
