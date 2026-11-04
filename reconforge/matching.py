"""Decide whether a detected service version is affected by a CVE, from NVD configurations.

Confidence levels:
    confirmed-range  the version falls inside an affected version range
    exact-cpe        the version equals a vulnerable CPE listed by NVD
    unconfirmed      no usable version, an uncomparable version, or a context
                     (vendor alias, distro package, platform) that limits trust
    keyword-guess    set elsewhere, for free-text fallback searches
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .cpe import CPE, compare_versions, meaningful, parse_cpe23, split_update

CONFIDENCE_RANK = {"confirmed-range": 0, "exact-cpe": 1, "unconfirmed": 2, "keyword-guess": 3}
DISTRO_NOTE = "distro package, fixes may be backported"
PLATFORM_NOTE = "platform-dependent configuration"

_BOUNDS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
_BOUND_TEXT = {"versionStartIncluding": ">=", "versionStartExcluding": ">",
               "versionEndIncluding": "<=", "versionEndExcluding": "<"}

_DISTRO_RE = re.compile(
    r"ubuntu|debian|raspbian|\+deb|~deb|\bdeb\d|\bdeb\b|\bel[5-9]\b|\.el\d|\bel\d+_\d|centos|"
    r"red\s?hat|rhel|fedora|alpine|suse|amzn|oracle linux|almalinux|rocky", re.IGNORECASE)
_UPDATE_TAG_RE = re.compile(r"(?:p|pl|patch|rc|beta|alpha)\d+", re.IGNORECASE)


@dataclass(frozen=True)
class Match:
    confidence: str
    reason: str


def is_distro_package(*texts: str) -> bool:
    """True when the banner text carries a distro package marker (Ubuntu, Debian, el7, ...)."""
    return any(t and _DISTRO_RE.search(t) for t in texts)


def target_version(target: CPE) -> str:
    """Detected version, with an NVD-style update field (``p2``) folded back in."""
    if not meaningful(target.version):
        return ""
    if _UPDATE_TAG_RE.fullmatch(target.update or ""):
        return target.version + target.update
    return target.version


def vendors_for_product(cves: list[dict], target: CPE) -> set[str]:
    """Distinct vendors NVD uses for the target's product across the given CVE records."""
    vendors = set()
    for cve in cves:
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for entry in node.get("cpeMatch", []):
                    c = parse_cpe23(entry.get("criteria", ""))
                    if c and c.part == target.part and c.product == target.product:
                        vendors.add(c.vendor)
    return vendors


def _entry_match(entry: dict, target: CPE, tv: str, check_vendor: bool) -> Match | None:
    crit = parse_cpe23(entry.get("criteria", ""))
    if crit is None or not entry.get("vulnerable"):
        return None
    if crit.part != target.part or crit.product != target.product:
        return None
    if check_vendor and crit.vendor != target.vendor:
        return None
    if not tv:
        return Match("unconfirmed", "no usable version detected")

    bounds = {k: entry[k] for k in _BOUNDS if entry.get(k)}
    if bounds and crit.version == "*":
        check_v = tv
        if meaningful(crit.update):  # e.g. openssh:*:p2 with versionEndIncluding 7.2
            check_v, upd = split_update(tv)
            if upd != crit.update:
                return None
        results = {k: compare_versions(check_v, b) for k, b in bounds.items()}
        tests = {"versionStartIncluding": lambda c: c >= 0, "versionStartExcluding": lambda c: c > 0,
                 "versionEndIncluding": lambda c: c <= 0, "versionEndExcluding": lambda c: c < 0}
        if any(c is not None and not tests[k](c) for k, c in results.items()):
            return None  # definitely outside the range
        text = ", ".join(f"{_BOUND_TEXT[k]} {b}" for k, b in bounds.items())
        if any(c is None for c in results.values()):
            return Match("unconfirmed", f"cannot compare {tv} with affected range {text}")
        return Match("confirmed-range", f"{tv} within affected range {text}")

    if crit.version == "*":
        return Match("unconfirmed", "NVD lists all versions as affected")
    if crit.version == "-":
        return None
    cv = crit.version + (crit.update if meaningful(crit.update) else "")
    c = compare_versions(tv, cv)
    if c == 0 or (c is None and tv.lower() == cv.lower()):
        return Match("exact-cpe", f"exact CPE version {cv}")
    if c is None:
        return Match("unconfirmed", f"cannot compare {tv} with {cv}")
    return None


def _cap(m: Match, notes: list[str]) -> Match:
    """Cap confidence at 'unconfirmed' and record why."""
    if not notes:
        return m
    return Match("unconfirmed", "; ".join(notes + [m.reason]))


def match_cve(cve: dict, target: CPE, alias_note: str = "", distro: bool = False,
              cap_notes: tuple[str, ...] = (), info_note: str = "") -> Match | None:
    """Best match of a CVE record against the target CPE, or None if it is not affected.

    alias_note: set when the vendor was wildcarded; the vendor is then ignored and the
        result can be at most 'unconfirmed'.
    distro: the detected version is a distro package, so fixes may be backported.
    cap_notes: further reasons that cap the result at 'unconfirmed' (e.g. MariaDB posing as MySQL).
    info_note: provenance of the vendor (alias table, NVD deprecation); prefixed to the reason
        but does not lower the confidence.
    """
    tv = target_version(target)
    best: Match | None = None
    for cfg in cve.get("configurations", []):
        nodes = cfg.get("nodes", [])
        platform = cfg.get("operator") == "AND" and any(
            not e.get("vulnerable") for n in nodes for e in n.get("cpeMatch", []))
        for node in nodes:
            if node.get("negate"):
                continue
            for entry in node.get("cpeMatch", []):
                m = _entry_match(entry, target, tv, check_vendor=not alias_note)
                if m is None:
                    continue
                notes = ([alias_note] if alias_note else []) + list(cap_notes) \
                    + ([DISTRO_NOTE] if distro else []) + ([PLATFORM_NOTE] if platform else [])
                m = _cap(m, notes)
                if info_note:
                    m = Match(m.confidence, f"{info_note}; {m.reason}")
                if best is None or CONFIDENCE_RANK[m.confidence] < CONFIDENCE_RANK[best.confidence]:
                    best = m
    return best
