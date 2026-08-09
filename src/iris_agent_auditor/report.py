from __future__ import annotations

from typing import Any, Iterable

from .models import Finding


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def render_report(
    evidence: dict[str, Any],
    findings: Iterable[Finding],
    passed_controls: list[str],
    not_verified: list[str],
    metrics: dict[str, Any],
) -> str:
    items = list(findings)
    counts = metrics["findings_by_severity"]
    severity_summary = ", ".join(f"{count} {name.title()}" for name, count in counts.items())
    rows = "\n".join(
        f"| {item.finding_id} | {item.severity.title()} | {_escape(item.asset)} | {_escape(item.evidence)} | {_escape(item.risk)} | {_escape(item.recommendation)} |"
        for item in items
    )
    passed = "\n".join(f"- {item}" for item in passed_controls)
    limitations = "\n".join(f"- {item}" for item in not_verified)
    timestamp = evidence["metadata"]["timestamp_utc"]

    return f"""# Iris Security Audit

## Executive Summary

The evidence-grounded audit identified **{metrics['findings_total']} open findings**: **{severity_summary}**. The dependency scanner emitted {metrics['raw_advisory_records']} records; GHSA/PYSEC aliases were consolidated into {metrics['unique_dependency_vulnerabilities']} unique dependency vulnerabilities, a {metrics['deduplication_reduction_pct']:.0f}% reduction in duplicate records.

The runtime is non-root, has a zero effective capability mask, uses seccomp filtering, does not mount the Docker socket, protects sensitive profile files with mode `0600`, and enforces multiple fail-closed approval controls. `NoNewPrivs` is not enabled, leaving a defense-in-depth gap. Exploitability and vulnerable-code reachability were **Not Verified**.

No system modification or automatic remediation was performed. All findings remain open until human-approved changes are deployed and re-tested.

## Scope and Timestamp

- **Audit timestamp:** {timestamp}
- **Subject:** Hermes `iris` security-auditor profile and its runtime container
- **Method:** deterministic, read-only evidence collection followed by structured classification and report generation
- **Included:** runtime identity, capability mask, seccomp state, Docker-socket exposure, sensitive-file metadata, selected approval controls, tool/MCP exposure, and dependency advisories
- **Excluded:** active exploitation, secret values, package upgrades, network probing, configuration changes, and automatic remediation

## Findings

| ID | Severity | Asset | Evidence | Risk | Recommendation |
|---|---|---|---|---|---|
{rows}

## Passed Controls

{passed}

## Limitations and Not-Verified Items

{limitations}

- Controls lacking evidence are **Not Verified**, not passed.
- Scanner presence does not establish runtime reachability or exploitability.
- Advisory aliases were deduplicated; the report does not count one underlying vulnerability twice.

## Risk Treatment

1. **Priority 1 — dependency remediation:** upgrade `aiohttp` to at least `3.14.3` and `cryptography` to at least `50.0.0` through the normal lockfile, build, review, and deployment process.
2. Execute HTTP/WebSocket, certificate-path, name-constraint, and PKCS#7 regression tests before release.
3. Rebuild from trusted sources, record the immutable image digest and software bill of materials, and require deployment approval.
4. **Priority 2 — runtime hardening:** enable `no-new-privileges` after confirming that no workflow depends on set-user-ID, set-group-ID, or file capabilities.
5. Until validated upgrades are deployed, reduce exposure to untrusted HTTP/WebSocket peers, certificate chains, and PKCS#7 input where operationally feasible.

## Remediation Verification Plan

1. Collect a fresh package inventory after the approved rebuild.
2. Confirm `aiohttp >= 3.14.3` and `cryptography >= 50.0.0`.
3. Re-run the same scanner and verify that all six canonical advisories are absent; version inspection alone is insufficient.
4. Run regression tests for malformed HTTP responses, WebSocket upgrades/compression, certificate path construction, DNS name constraints, and PKCS#7 decryption.
5. Verify `NoNewPrivs=1`, `CapEff=0000000000000000`, seccomp remains active, and the Docker socket remains unmounted.
6. Re-run file-permission, approval-control, tool, MCP, and gateway checks to detect control regressions.
7. Record build provenance, test results, deployment approval, and verification timestamp as remediation evidence.
"""
