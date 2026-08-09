# Audit Methodology

## Objective

Iris produces an evidence-grounded security assessment of a containerized AI-agent profile without reading credential values, altering the target, or performing automatic remediation. The method separates deterministic collection from agent interpretation so that each conclusion can be traced to a recorded observation.

## Processing stages

1. **Collect:** record a bounded set of runtime, file-metadata, policy, tool, MCP, and dependency observations.
2. **Validate:** reject incomplete evidence documents and any collector declaration indicating credential reads, system modification, or automatic remediation.
3. **Normalize:** convert the evidence into stable JSON types and canonical records.
4. **Deduplicate:** group GHSA/PYSEC aliases by package, CVE identity, and fixed version; retain the highest known severity and prefer the GHSA identifier as the canonical ID.
5. **Evaluate controls:** compare observations with explicit expected states. A positive test produces a passed-control statement; a negative test produces a finding. An uncollected observation becomes Not Verified.
6. **Classify:** sort findings by severity and stable ID. No opaque aggregate score is used.
7. **Report:** emit machine-readable findings and metrics plus a structured Markdown report.
8. **Verify remediation:** re-collect evidence after a human-approved change, re-run regression tests and the scanner, and compare the new result with the prior baseline.

## Evidence contract

The public JSON schema is represented by the sample fixture and enforced in `loader.py`. Required top-level sections are:

- `metadata`
- `profile`
- `runtime`
- `security_files`
- `controls`
- `tools`
- `mcp_servers`
- `advisories_raw`
- `collector_guarantees`

The collector guarantees must state:

```json
{
  "credential_values_read": false,
  "system_modifications_performed": false,
  "automatic_remediation_performed": false
}
```

Any contradictory value causes validation to fail before report generation.

## Severity model

| Severity | Interpretation |
|---|---|
| Critical | Direct compromise path or control failure with potentially systemic impact |
| High | Serious vulnerability or privilege/isolation failure requiring priority treatment |
| Moderate | Meaningful exposure whose impact depends on topology, feature use, or attacker access |
| Low | Defense-in-depth gap with limited immediate impact under the observed controls |
| Informational | Relevant observation without a demonstrated security defect |
| Unknown | Upstream source did not supply a mappable severity |

Upstream dependency severity is preserved after alias consolidation. Runtime-control severity is assigned by an explicit rule in the control evaluator.

## Advisory alias handling

Multiple vulnerability databases can describe the same underlying issue. Counting both the GHSA and PYSEC record would inflate the finding total. Iris groups records using:

```text
(normalized package, CVE identity or normalized title, fixed version)
```

The output retains all source identifiers but emits one finding per underlying vulnerability. In the reference fixture, 12 raw records become six canonical dependency findings.

## Confidence language

- **Confirmed:** directly supported by collector evidence.
- **Not Verified:** evidence was absent or the relevant active test was outside scope.
- **Open:** remediation has not been deployed and re-tested.

Scanner detection alone does not prove exploitability. Likewise, an unobserved control is never described as effective.

## Human approval boundary

Iris may recommend a target version or hardening change, but it may not install packages, edit policy, restart services, or deploy a container. A reviewer must approve the change, preserve the normal build/release process, run compatibility tests, and supply fresh evidence for closure.

## Determinism and reviewability

The public pipeline performs no network request and makes no LLM call. Given the same JSON input and package version, its four outputs are byte-identical. CI regenerates the artifacts and compares them with the committed reference output to detect logic or report drift.
