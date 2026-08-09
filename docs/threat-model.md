# Threat Model

## Protected assets

- Agent credentials and provider tokens
- Profile configuration and persona policy
- Host/container separation
- Approval and scheduler policy
- Audit evidence integrity
- Accuracy and traceability of security findings

## Trust boundaries

| Boundary | Trusted inputs | Untrusted or constrained inputs |
|---|---|---|
| Hermes runtime | Kernel-reported process metadata and approved configuration keys | Agent-generated prose, third-party skill content, external network content |
| Evidence collector | Explicit read-only commands and file metadata | Credential values and unrelated user data are out of scope |
| Iris analysis | Validated collector output | Missing evidence cannot be inferred; tool calls are prohibited for scheduled analysis |
| Change process | Human-reviewed rebuild, tests, and deployment approval | Autonomous remediation and live package mutation are prohibited |
| Public repository | Synthetic fixtures and sanitized derivatives | Live `.env`, private endpoints, identifiers, and token fingerprints are prohibited |

## Threats and mitigations

| Threat | Primary mitigation | Residual risk / next evidence |
|---|---|---|
| Agent compromise reaches host Docker daemon | Docker socket is not mounted | Validate all mounts and host isolation independently |
| Container process gains excessive privilege | Non-root UID, zero effective capabilities, seccomp | Operational runtime still reports `NoNewPrivs=0`; enable and verify after compatibility testing |
| Unattended job approves a state-changing action | Manual approval mode and cron approval denial | Review approval-log retention and policy-change controls |
| Tool/MCP expands the auditor's authority | Zero bundled skills, empty CLI exposure, no MCP servers | Detect future configuration drift on every run |
| Secret leakage through audit evidence | Collector does not read values; repository privacy scanner; sanitized screenshots | Validate external log retention and access controls |
| Duplicate advisories inflate risk counts | CVE-aware GHSA/PYSEC consolidation | Source metadata can be incomplete; review ambiguous groups manually |
| LLM invents a passed control | Deterministic evaluator and Not-Verified policy | Human review remains required for report release |
| Vulnerable dependency is present but unreachable | Report separates presence from exploitability | Add application-specific reachability and regression testing |
| Malicious third-party dependency or skill | Zero Iris skills; lazy installs disabled; controlled rebuild | Add signed provenance, SBOM, and artifact attestation |

## Explicit non-goals

- Exploit development or active penetration testing
- Secret-value inspection
- Autonomous package upgrades or container deployment
- Host-forensics coverage
- Compliance certification

The report is an engineering control assessment. It does not by itself establish legal or regulatory compliance.
