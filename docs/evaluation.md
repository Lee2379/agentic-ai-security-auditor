# Evaluation Framework

## 1. Evaluation objective

The evaluation determines whether the audit method is reproducible, evidence-grounded, internally consistent, and safe to run against the defined scope. It does not estimate penetration-testing coverage or certify the security of the upstream Hermes platform.

## 2. Current reference dataset

The committed fixture is synthetic but structurally representative of the reviewed operational audit. It contains:

- one Iris profile record;
- one least-privilege runtime observation with an open `NoNewPrivs` hardening gap;
- three sensitive-file metadata records;
- nine selected policy values, including the approval timeout;
- explicit empty CLI-tool and MCP-server states;
- 12 raw dependency advisory records representing six underlying CVEs; and
- three negative collector-safety declarations.

Using a synthetic fixture prevents credentials and private infrastructure details from entering Git while retaining the data shapes and edge cases needed for regression testing.

## 3. Metric definitions

### 3.1 Advisory alias reduction

```text
alias_records_removed = raw_advisory_records - unique_dependency_vulnerabilities
deduplication_reduction_pct = 100 * alias_records_removed / raw_advisory_records
```

Reference result:

```text
raw records       = 12
canonical records = 6
aliases removed   = 6
reduction         = 50%
```

This is a data-quality metric, not a risk-reduction metric. The underlying vulnerabilities remain open after their duplicate representations are removed.

### 3.2 Finding count

```text
findings_total = canonical dependency findings + failed control predicates
```

The reference result is seven: six canonical dependency findings and one Low runtime-control finding.

### 3.3 Passed-control count

A passed control is counted only when an implemented predicate has direct evidence and the observed value matches the expected state. Not Verified domains are excluded from the numerator rather than treated as negative or positive results.

### 3.4 Artifact determinism

CI regenerates and byte-compares:

1. `normalized_evidence.json`
2. `findings.json`
3. `metrics.json`
4. `audit_report.md`

Any difference fails the golden-master comparison and requires review of the input, rule, ordering, or renderer change.

## 4. Test coverage matrix

| Evaluation area | Test behavior | Failure detected |
|---|---|---|
| Evidence schema | Remove a required section | Incomplete collector output accepted |
| Collector safety | Load fixture guarantees | Credential read or mutation incorrectly allowed |
| Runtime classification | Set UID to zero | Root execution not classified High |
| Least privilege | Evaluate hardened fixture | Confirmed controls not recognized |
| Missing evidence | Remove/alter observations | Unknown state incorrectly reported as passed |
| CLI exposure | Enable an interactive terminal fixture | Added authority not reported as a finding |
| MCP exposure | Add an MCP server fixture | External capability path not reported as a finding |
| Alias grouping | Process 12 GHSA/PYSEC records | Duplicate vulnerabilities inflate totals |
| CVE identity | Use different titles for one CVE | Text variation prevents correct grouping |
| Severity selection | Pair known and unknown severities | Lower-confidence alias overrides known severity |
| Output contract | Run full pipeline | Required artifacts missing |
| Report governance | Inspect rendered headings | Required review sections omitted |
| Normalized shape | Inspect normalized evidence | Raw duplicate advisory list leaks downstream |
| Repository privacy | Scan committed text | Common credential or personal infrastructure pattern published |

## 5. Reference results

| Result | Value |
|---|---:|
| Unit and integration tests | 14 passed |
| Raw advisory records | 12 |
| Canonical dependency vulnerabilities | 6 |
| Alias records removed | 6 |
| Deduplication reduction | 50% |
| Total findings | 7 |
| Severity distribution | 3 High, 3 Moderate, 1 Low |
| Confirmed passed controls | 15 |
| Not Verified domains | 6 |
| Deterministic artifact comparison | 4/4 equal |
| Reviewed evidence images | 8/8 hash-verified |
| Automatic remediation | 0 |

## 6. Statistical and analytical interpretation

The sample is a regression fixture, not an independently sampled security population. Consequently:

- the 50% alias reduction describes this fixture and must not be generalized to other scanners or environments;
- finding severity is an ordinal upstream/policy classification, not a calibrated probability of compromise;
- the passed-control count is meaningful only with the explicit 16-control catalog and six Not Verified domains beside it; and
- no precision, recall, false-positive rate, or exploitability rate is reported because no labeled vulnerability-reachability corpus was used.

Avoiding unsupported aggregate metrics is part of the evaluation design. Transparent counts preserve information that would be hidden by an arbitrary weighted risk score.

## 7. Agent-output evaluation

The public reference uses a deterministic renderer. If an LLM renderer is introduced, it should be evaluated separately from collection and control logic using a frozen evidence corpus.

Recommended measures:

| Measure | Definition |
|---|---|
| Evidence attribution coverage | Material report claims linked to one or more evidence fields / all material claims |
| Unsupported-claim rate | Material claims without supporting evidence / all material claims |
| Severity consistency | Findings whose rendered severity matches the deterministic record / all findings |
| Finding completeness | Deterministic findings represented in the report / deterministic findings |
| Not-Verified preservation | Required limitation items retained without being rewritten as passes |
| Remediation-boundary compliance | Reports that recommend but do not claim unauthorized remediation |
| Format compliance | Reports containing all seven required governance sections |

Agent evaluation should use exact evidence IDs and structured outputs rather than judging prose style alone.

## 8. Production validation plan

### Phase 1 — rule truth tables

Create fixtures for every implemented control in passing, failing, missing, and malformed states. Verify stable IDs, severity, and no cross-control interference.

### Phase 2 — advisory identity benchmark

Build a labeled set containing alias pairs, unrelated records with similar titles, missing CVEs, conflicting severities, and different fixed versions. Measure pairwise precision and recall for the deduplication decision.

### Phase 3 — operational replay

Replay sanitized collector snapshots from multiple runtime versions. Measure schema compatibility, rule drift, artifact stability, and execution latency.

### Phase 4 — agent renderer evaluation

Generate reports from a frozen evidence set across model and prompt versions. Measure attribution, unsupported claims, omission, severity consistency, and governance-format compliance.

### Phase 5 — remediation closure tests

For approved changes, compare before/after evidence, verify scanner absence, run feature-specific regression tests, and detect regressions in capability, socket, seccomp, approval, tool, and MCP controls.

## 9. Known evaluation gaps

- No external labeled corpus for vulnerability reachability.
- No adversarial prompt-injection benchmark for the operational scheduled agent.
- No measured inter-reviewer agreement for severity or report acceptance.
- No long-term alert-delivery, retention, or scheduler-reliability dataset.
- No performance benchmark across large SBOMs or multi-container fleets.

These gaps define the next measurement work; they are not silently absorbed into the current results.
