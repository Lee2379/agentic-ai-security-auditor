from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .controls import evaluate_controls
from .deduplicate import SEVERITY_RANK, deduplicate_advisories
from .loader import load_evidence
from .models import Advisory, Finding
from .report import render_report


RISK_TEXT = {
    "GHSA-cq5v-8q36-5273": "A malformed or malicious HTTP response could trigger memory-safety behavior or denial of service in an affected parser path; reachability in this deployment was not verified.",
    "GHSA-g6cj-pr64-35w5": "If attacker-controlled PKCS#7 EnvelopedData is decrypted and distinguishable outcomes are exposed, an adaptive attacker may derive protected information; feature use was not verified.",
    "GHSA-jwv3-5hgf-82ww": "Crafted certificate chains could cause excessive path-building work and service degradation where untrusted chains are validated; reachability was not verified.",
    "GHSA-mfx4-hv73-q22v": "Affected server or proxy arrangements may interpret WebSocket upgrades inconsistently and permit request smuggling; deployment topology was not collected.",
    "GHSA-mq44-7p77-q5h7": "A malicious WebSocket peer could cause processing of unsolicited compressed frames and additional resource consumption; WebSocket use was not verified.",
    "GHSA-m2h6-j472-rp4c": "Certificate validation may accept identities outside an intended permitted subtree; affected verification workflows were not verified.",
}


def _advisory_finding(index: int, advisory: Advisory) -> Finding:
    aliases = ", ".join(advisory.alias_ids) if advisory.alias_ids else "none"
    return Finding(
        finding_id=f"IRIS-DEP-{index:03d}",
        severity=advisory.severity,
        asset=f"{advisory.package} {advisory.installed_version}",
        evidence=f"{advisory.primary_id}; aliases: {aliases}; fixed in {advisory.fixed_version}",
        risk=RISK_TEXT.get(advisory.primary_id, f"Known vulnerability in {advisory.package}; exploitability was not verified."),
        recommendation=f"Upgrade {advisory.package} to {advisory.fixed_version} or later through the controlled build process, then run compatibility and regression tests.",
    )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_audit(input_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    evidence = load_evidence(input_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    advisories = deduplicate_advisories(evidence["advisories_raw"])
    dependency_findings = [_advisory_finding(index, item) for index, item in enumerate(advisories, start=1)]
    passed_controls, control_findings, not_verified = evaluate_controls(evidence)
    findings = sorted(
        dependency_findings + control_findings,
        key=lambda item: (-SEVERITY_RANK[item.severity], item.finding_id),
    )

    severity_counts = Counter(item.severity for item in findings)
    raw_count = len(evidence["advisories_raw"])
    unique_count = len(advisories)
    metrics = {
        "raw_advisory_records": raw_count,
        "unique_dependency_vulnerabilities": unique_count,
        "alias_records_removed": raw_count - unique_count,
        "deduplication_reduction_pct": round(100 * (raw_count - unique_count) / raw_count, 2) if raw_count else 0.0,
        "findings_total": len(findings),
        "findings_by_severity": {
            severity: severity_counts[severity]
            for severity in ("critical", "high", "moderate", "low", "informational", "unknown")
            if severity_counts[severity]
        },
        "passed_controls": len(passed_controls),
        "not_verified_items": len(not_verified),
        "automatic_remediation_performed": False,
    }

    normalized = dict(evidence)
    normalized["advisories_unique"] = [item.to_dict() for item in advisories]
    normalized.pop("advisories_raw")
    _write_json(output / "normalized_evidence.json", normalized)
    _write_json(output / "findings.json", [item.to_dict() for item in findings])
    _write_json(output / "metrics.json", metrics)
    (output / "audit_report.md").write_text(
        render_report(evidence, findings, passed_controls, not_verified, metrics),
        encoding="utf-8",
    )
    return metrics
