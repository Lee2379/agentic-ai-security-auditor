from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

from .models import Advisory


SEVERITY_RANK = {
    "unknown": 0,
    "informational": 1,
    "low": 2,
    "moderate": 3,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def normalize_severity(value: str) -> str:
    severity = value.strip().lower()
    if severity == "medium":
        return "moderate"
    if severity not in SEVERITY_RANK:
        return "unknown"
    return severity


def _title_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _group_key(record: dict[str, Any]) -> tuple[str, str, str]:
    cve = str(record.get("cve_id", "")).upper().strip()
    identity = cve or _title_key(str(record["title"]))
    return (str(record["package"]).casefold(), identity, str(record["fixed_version"]))


def deduplicate_advisories(records: Iterable[dict[str, Any]]) -> list[Advisory]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[_group_key(record)].append(record)

    advisories: list[Advisory] = []
    for items in groups.values():
        ranked = sorted(
            items,
            key=lambda item: (
                SEVERITY_RANK[normalize_severity(str(item.get("severity", "unknown")))],
                str(item.get("id", "")).startswith("GHSA-"),
            ),
            reverse=True,
        )
        selected = ranked[0]
        identifiers = tuple(sorted({str(item["id"]) for item in items}))
        ghsa = next((value for value in identifiers if value.startswith("GHSA-")), identifiers[0])
        advisories.append(
            Advisory(
                package=str(selected["package"]),
                installed_version=str(selected["installed_version"]),
                primary_id=ghsa,
                alias_ids=tuple(value for value in identifiers if value != ghsa),
                cve_id=str(selected.get("cve_id", "Not provided")),
                severity=normalize_severity(str(selected.get("severity", "unknown"))),
                title=str(selected["title"]),
                fixed_version=str(selected["fixed_version"]),
                source_records=len(items),
            )
        )

    return sorted(
        advisories,
        key=lambda item: (-SEVERITY_RANK[item.severity], item.package, item.primary_id),
    )
