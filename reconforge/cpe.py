"""CPE helpers: 2.2 -> 2.3 conversion, 2.3 parsing and a small version comparator.

Nmap reports CPE 2.2 URIs (``cpe:/a:vsftpd:vsftpd:3.0.3``). The NVD API 2.0 speaks
CPE 2.3 formatted strings (``cpe:2.3:a:vsftpd:vsftpd:3.0.3:*:*:*:*:*:*:*``).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, replace

FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
          "sw_edition", "target_sw", "target_hw", "other")


@dataclass(frozen=True)
class CPE:
    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_string(self) -> str:
        return "cpe:2.3:" + ":".join(_escape23(getattr(self, f)) for f in FIELDS)

    def prefix(self) -> str:
        """``cpe:2.3:<part>:<vendor>:<product>`` - the form used for NVD virtualMatchString."""
        return f"cpe:2.3:{self.part}:{_escape23(self.vendor)}:{_escape23(self.product)}"

    def with_version(self, version: str) -> "CPE":
        return replace(self, version=version)


def _escape23(value: str) -> str:
    if value in ("*", "-"):
        return value
    return "".join(ch if (ch.isalnum() or ch in "_-.") else "\\" + ch for ch in value)


def _unescape23(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def cpe22_to_23(uri: str) -> str | None:
    """Convert a CPE 2.2 URI to a CPE 2.3 formatted string, or None if it is not a valid CPE."""
    if not isinstance(uri, str):
        return None
    uri = uri.strip()
    if not uri.lower().startswith("cpe:/"):
        return None
    comps = uri[5:].split(":")
    part = comps[0].lower()
    if part not in ("a", "o", "h"):
        return None
    comps = (comps + [""] * 7)[:7]  # part vendor product version update edition language
    dec = [urllib.parse.unquote(c).lower() or "*" for c in comps]
    vendor, product, version, update, edition, language = dec[1:]
    if "*" in (vendor, product) or vendor == "-" or product == "-":
        return None
    sw_edition = target_sw = target_hw = other = "*"
    if comps[5].startswith("~"):  # packed edition: ~edition~sw_edition~target_sw~target_hw~other
        packed = (comps[5].split("~") + [""] * 6)[1:6]
        edition, sw_edition, target_sw, target_hw, other = (
            urllib.parse.unquote(p).lower() or "*" for p in packed)
    cpe = CPE(part, vendor, product, version, update, edition, language,
              sw_edition, target_sw, target_hw, other)
    return cpe.to_string()


def parse_cpe23(s: str) -> CPE | None:
    if not isinstance(s, str) or not s.lower().startswith("cpe:2.3:"):
        return None
    comps = re.split(r"(?<!\\):", s.strip())
    if len(comps) != 13:
        return None
    vals = [_unescape23(c).lower() for c in comps[2:]]
    return CPE(*vals)


def meaningful(value: str) -> bool:
    """False for the CPE wildcard '*', the 'not applicable' '-' and empty values."""
    return value not in ("*", "-", "")


# --- version comparison -------------------------------------------------------

_VERSION_RE = re.compile(
    r"^v?(?P<nums>\d+(?:\.\d+)*)(?:[-_.]?(?P<tag>alpha|beta|rc|pre|dev|pl|patch|p|a|b)\.?(?P<tagnum>\d*))?$",
    re.IGNORECASE)

# Pre-release tags sort before the plain release, patch levels after it.
_TAG_RANK = {"": 0, "dev": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "pre": -2, "rc": -1,
             "p": 1, "pl": 1, "patch": 1}


def _parse_version(v: str) -> tuple[tuple[int, ...], int, int] | None:
    m = _VERSION_RE.match((v or "").strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group("nums").split("."))
    tag = (m.group("tag") or "").lower()
    return nums, _TAG_RANK[tag], int(m.group("tagnum") or 0)


def compare_versions(a: str, b: str) -> int | None:
    """Return -1, 0 or 1, or None when either version cannot be compared reliably.

    Handles dotted numbers (``2.4.41``), patch suffixes (``7.4p1`` sorts after ``7.4``)
    and pre-release tags (``2.0rc1`` sorts before ``2.0``). Anything else - empty
    strings, wildcards, distro suffixes such as ``2.4.41-4ubuntu3`` - returns None.
    """
    pa, pb = _parse_version(a), _parse_version(b)
    if pa is None or pb is None:
        return None
    width = max(len(pa[0]), len(pb[0]))
    ka = (pa[0] + (0,) * (width - len(pa[0])), pa[1], pa[2])
    kb = (pb[0] + (0,) * (width - len(pb[0])), pb[1], pb[2])
    return (ka > kb) - (ka < kb)


_UPDATE_RE = re.compile(r"^(?P<base>.*?\d)(?P<upd>(?:p|pl|patch|rc|beta|alpha)\d+)$", re.IGNORECASE)


def split_update(version: str) -> tuple[str, str]:
    """Split ``7.2p2`` into (``7.2``, ``p2``); NVD stores such versions as version + update."""
    m = _UPDATE_RE.match(version or "")
    if not m:
        return version or "", ""
    return m.group("base"), m.group("upd").lower()
