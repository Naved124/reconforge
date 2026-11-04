"""Map CVEs to Metasploit modules using Metasploit's own module metadata file.

Metasploit ships db/modules_metadata_base.json, which lists every module with its
references (CVE IDs among them). reconforge only *suggests* modules: the generated
resource script is fully commented out, so nothing runs until a human reviews it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PATHS = [
    Path("/usr/share/metasploit-framework/db/modules_metadata_base.json"),
    Path("/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json"),
    Path("/opt/metasploit/db/modules_metadata_base.json"),
]


@dataclass
class Module:
    fullname: str
    name: str
    type: str
    rank: int | None


def find_metadata(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    return next((p for p in DEFAULT_PATHS if p.exists()), None)


class ModuleIndex:
    def __init__(self, by_cve: dict[str, list[Module]]):
        self.by_cve = by_cve

    @classmethod
    def load(cls, path: Path) -> "ModuleIndex":
        data = json.loads(path.read_text())
        by_cve: dict[str, list[Module]] = {}
        for entry in data.values():
            if entry.get("type") not in ("exploit", "auxiliary"):
                continue
            mod = Module(fullname=entry.get("fullname", ""), name=entry.get("name", ""),
                         type=entry.get("type", ""), rank=entry.get("rank"))
            for ref in entry.get("references", []):
                if ref.upper().startswith("CVE-"):
                    by_cve.setdefault(ref.upper(), []).append(mod)
        return cls(by_cve)

    @classmethod
    def empty(cls) -> "ModuleIndex":
        return cls({})

    def modules_for(self, cve_id: str) -> list[Module]:
        return self.by_cve.get(cve_id.upper(), [])


def resource_script(suggestions: list[tuple]) -> str:
    """Build a review-only msfconsole resource script. Every command is commented out."""
    lines = [
        "# reconforge suggested modules - REVIEW BEFORE USE",
        "# Every line is commented out on purpose. Confirm the target is in scope and the",
        "# module fits the exact service version, then uncomment what you intend to run.",
        "",
    ]
    for host, port, cve_id, mod, *rest in suggestions:
        conf = f" [{rest[0]}]" if rest else ""
        lines += [
            f"# {cve_id}{conf} -> {host}:{port} ({mod.type}: {mod.name})",
            f"# use {mod.fullname}",
            f"# set RHOSTS {host}",
            f"# set RPORT {port}",
            "# check",
            "",
        ]
    return "\n".join(lines)
