# Iris Security Audit

## Executive Summary

The evidence-grounded audit identified **7 open findings**: **3 High, 3 Moderate, 1 Low**. The dependency scanner emitted 12 records; GHSA/PYSEC aliases were consolidated into 6 unique dependency vulnerabilities, a 50% reduction in duplicate records.

The runtime is non-root, has a zero effective capability mask, uses seccomp filtering, does not mount the Docker socket, protects sensitive profile files with mode `0600`, and enforces multiple fail-closed approval controls. `NoNewPrivs` is not enabled, leaving a defense-in-depth gap. Exploitability and vulnerable-code reachability were **Not Verified**.

No system modification or automatic remediation was performed. All findings remain open until human-approved changes are deployed and re-tested.

## Scope and Timestamp

- **Audit timestamp:** 2026-08-09T03:40:33Z
- **Subject:** Hermes `iris` security-auditor profile and its runtime container
- **Method:** deterministic, read-only evidence collection followed by structured classification and report generation
- **Included:** runtime identity, capability mask, seccomp state, Docker-socket exposure, sensitive-file metadata, selected approval controls, tool/MCP exposure, and dependency advisories
- **Excluded:** active exploitation, secret values, package upgrades, network probing, configuration changes, and automatic remediation

## Findings

| ID | Severity | Asset | Evidence | Risk | Recommendation |
|---|---|---|---|---|---|
| IRIS-DEP-001 | High | aiohttp 3.14.1 | GHSA-cq5v-8q36-5273; aliases: PYSEC-2026-3545; fixed in 3.14.3 | A malformed or malicious HTTP response could trigger memory-safety behavior or denial of service in an affected parser path; reachability in this deployment was not verified. | Upgrade aiohttp to 3.14.3 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-DEP-002 | High | cryptography 48.0.1 | GHSA-g6cj-pr64-35w5; aliases: PYSEC-2026-3552; fixed in 50.0.0 | If attacker-controlled PKCS#7 EnvelopedData is decrypted and distinguishable outcomes are exposed, an adaptive attacker may derive protected information; feature use was not verified. | Upgrade cryptography to 50.0.0 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-DEP-003 | High | cryptography 48.0.1 | GHSA-jwv3-5hgf-82ww; aliases: PYSEC-2026-3553; fixed in 49.0.0 | Crafted certificate chains could cause excessive path-building work and service degradation where untrusted chains are validated; reachability was not verified. | Upgrade cryptography to 49.0.0 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-DEP-004 | Moderate | aiohttp 3.14.1 | GHSA-mfx4-hv73-q22v; aliases: PYSEC-2026-3546; fixed in 3.14.2 | Affected server or proxy arrangements may interpret WebSocket upgrades inconsistently and permit request smuggling; deployment topology was not collected. | Upgrade aiohttp to 3.14.2 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-DEP-005 | Moderate | aiohttp 3.14.1 | GHSA-mq44-7p77-q5h7; aliases: PYSEC-2026-3547; fixed in 3.14.2 | A malicious WebSocket peer could cause processing of unsolicited compressed frames and additional resource consumption; WebSocket use was not verified. | Upgrade aiohttp to 3.14.2 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-DEP-006 | Moderate | cryptography 48.0.1 | GHSA-m2h6-j472-rp4c; aliases: PYSEC-2026-3554; fixed in 49.0.0 | Certificate validation may accept identities outside an intended permitted subtree; affected verification workflows were not verified. | Upgrade cryptography to 49.0.0 or later through the controlled build process, then run compatibility and regression tests. |
| IRIS-RUNTIME-005 | Low | runtime container | NoNewPrivs=0 | A future executable or configuration change could acquire privilege through set-user-ID, set-group-ID, or file capabilities. | Enable no-new-privileges after compatibility testing and retain capability dropping and seccomp filtering. |

## Passed Controls

- Runtime executes as non-root UID 1000.
- Effective Linux capability mask is zero.
- The host Docker socket is not mounted.
- Seccomp filtering is active.
- Sensitive profile files are mode 0600 and owned by hermes:hermes.
- State-changing actions require human approval.
- Unattended cron approvals are denied.
- MCP reload requires confirmation.
- Destructive slash commands require confirmation.
- Tirith security enforcement is enabled.
- Tirith enforcement is configured fail-closed.
- Private URL access is disabled.
- Lazy package installation is disabled.
- The Iris profile exposes no interactive CLI tools.
- The Iris profile has no configured MCP servers.

## Limitations and Not-Verified Items

- Dependency reachability and vulnerable code paths were not tested.
- Credential values, validity, rotation dates, and external secret-store use were not inspected.
- Parent-directory ACLs, backup copies, filesystem encryption, and host isolation were not assessed.
- Network listeners, firewall policy, egress restrictions, TLS, and external exposure were not collected.
- Container image provenance, immutable digest, signature, namespaces, resource limits, and read-only-root status were not collected.
- Audit-log retention, alert delivery, and cron-definition change control were not independently verified.

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
