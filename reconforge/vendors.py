"""Vendor naming differences between Nmap's CPEs and NVD's CPE dictionary.

Two mechanisms, both driven by NVD data rather than guesses:

* ``VENDOR_ALIASES`` - a short static table, built by comparing Nmap's CPE vendors
  (nmap-service-probes) with the NVD CPE dictionary. An entry exists only where the
  vendors differ AND NVD has exactly one vendor for the product.
* NVD deprecation - when (almost) all of a vendor's CPEs for a product are deprecated,
  the ``deprecatedBy`` field of the NVD CPE records names the replacement. The chain is
  followed to live CPEs and used only if it ends at exactly one live vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .cpe import CPE

# (part, nmap vendor, product) -> NVD vendor
VENDOR_ALIASES = {
    ("a", "vsftpd", "vsftpd"): "vsftpd_project",
}

MAX_HOPS = 6
DEPRECATED_THRESHOLD = 0.9


@dataclass(frozen=True)
class Replacement:
    vendor: str
    deprecated: int
    total: int


def apply_alias(target: CPE) -> tuple[CPE, str]:
    """Rewrite the vendor via the alias table. Returns (cpe, note); note is '' if unchanged."""
    new = VENDOR_ALIASES.get((target.part, target.vendor, target.product))
    if not new:
        return target, ""
    return replace(target, vendor=new), f"vendor via alias table: {target.vendor} → {new}"


def _live_vendors(idx: dict[str, dict], name: str, product: str, hops: int = 0,
                  path: tuple[str, ...] = ()) -> set[str] | None:
    """Vendors of the live CPEs a (possibly deprecated) CPE resolves to, or None if the chain
    breaks: unknown CPE, no deprecatedBy, a cycle, more than MAX_HOPS, or a different product."""
    cpe = idx.get(name)
    if cpe is None:
        return None
    parts = name.split(":")
    if not cpe.get("deprecated"):
        return {parts[3]} if parts[4] == product else None
    if hops >= MAX_HOPS or name in path:
        return None
    targets = [d.get("cpeName") for d in cpe.get("deprecatedBy", []) if d.get("cpeName")]
    if not targets:
        return None
    out: set[str] = set()
    for t in targets:
        r = _live_vendors(idx, t, product, hops + 1, path + (name,))
        if r is None:
            return None
        out |= r
    return out


def resolve_replacement(products: list[dict], target: CPE) -> Replacement | None:
    """Replacement vendor for target's vendor:product from NVD CPE API records, or None.

    Requires at least DEPRECATED_THRESHOLD of the vendor's CPEs for the product to be
    deprecated, and every deprecated CPE to resolve (within MAX_HOPS) to live CPEs of
    one single vendor that differs from the original.
    """
    idx = {p["cpe"]["cpeName"]: p["cpe"] for p in products if "cpe" in p}
    own = []
    for name, cpe in idx.items():
        parts = name.split(":")
        if len(parts) > 5 and (parts[2], parts[3], parts[4]) == (target.part, target.vendor, target.product):
            own.append((name, cpe))
    deprecated = [(n, c) for n, c in own if c.get("deprecated")]
    if not own or len(deprecated) / len(own) < DEPRECATED_THRESHOLD:
        return None
    vendors: set[str] = set()
    for name, _ in deprecated:
        r = _live_vendors(idx, name, target.product)
        if r is None:
            return None
        vendors |= r
    if len(vendors) != 1 or target.vendor in vendors:
        return None
    return Replacement(next(iter(vendors)), len(deprecated), len(own))
