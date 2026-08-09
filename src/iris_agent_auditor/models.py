from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Advisory:
    package: str
    installed_version: str
    primary_id: str
    alias_ids: tuple[str, ...]
    cve_id: str
    severity: str
    title: str
    fixed_version: str
    source_records: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    asset: str
    evidence: str
    risk: str
    recommendation: str
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
