# Operational Evidence Register

## Publication controls

Only the minimum evidence required to substantiate the design is published. Every image is a deterministic derivative of a user-provided capture and was reviewed at original resolution. Solid masks cover personal shell prompts or transient identifiers; no generative reconstruction was used. The derivative byte size and SHA-256 digest are committed in `assets/evidence/manifest.json` and verified in CI.

| ID | Public artifact | Control or claim supported | Sanitization |
|---|---|---|---|
| E-01 | `01-iris-policy-boundary-sanitized.png` | Iris mission, trust boundary, prohibited actions, severity model, and report contract | None required |
| E-02 | `02-iris-profile-isolation-sanitized.png` | Dedicated profile, alias, zero skills, separation from business agents | Personal prompt cropped/masked if present |
| E-03 | `03-least-privilege-controls-sanitized.png` | Non-root execution, zero capabilities, seccomp, no Docker socket, file modes, approval/security controls, empty CLI exposure | None required |
| E-04 | `04-cron-run-success-sanitized.png` | On-demand scheduler execution and retained next-run state | Personal shell prompts masked |
| E-05 | `05-scheduled-audit-evidence-sanitized.png` | Scheduled read-only prompt and injected runtime evidence | Job identifier masked |
| E-06 | `06-structured-audit-report-sanitized.png` | Finding schema, alias consolidation, risk/recommendation, passed-control separation | None required |
| E-07 | `07-gateway-cron-status-sanitized.png` | Running gateway, active cron service, coexistence with business-agent profiles | Personal shell prompts and transient PIDs masked |
| E-08 | `08-scheduled-job-registry-sanitized.png` | Weekly job registration, collector binding, last-run and next-run state | Job/execution identifiers and personal prompt masked |

## Excluded captures

| Capture | Reason for exclusion |
|---|---|
| Initial collector execution as root | Superseded by the hardened non-root re-audit; publishing it without the full transition narrative could misrepresent the final control state |
| Token-fingerprint verification | Although raw tokens were not printed, stable token fingerprints are operational identifiers and unnecessary for the public proof set |
| Temporary-directory approval setup | The capture shows only directory creation and does not demonstrate an approval decision; it is incomplete evidence |
| Duplicate profile-list captures | Redundant with E-02 and add no independent control evidence |

## Evidence interpretation

Screenshots demonstrate that the operational workflow was exercised. They do not replace executable validation. The repository therefore includes a synthetic evidence fixture, deterministic audit implementation, tests, and reference artifacts so reviewers can inspect the method and reproduce its output without access to the private environment.
