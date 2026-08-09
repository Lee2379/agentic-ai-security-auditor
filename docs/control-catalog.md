# Control Catalog

## Interpretation

The catalog maps every implemented control predicate to its evidence field, expected state, failure severity, and reference-fixture outcome. A pass requires direct evidence. Missing evidence is not converted into a pass.

| ID | Control | Evidence | Expected state | Failure severity | Reference outcome |
|---|---|---|---|---|---|
| RT-01 | Non-root execution | `runtime.uid` | not `0` | High | Pass: UID 1000 |
| RT-02 | Effective capabilities | `runtime.cap_eff` | all zeros | High | Pass |
| RT-03 | Docker socket isolation | `runtime.docker_socket_mounted` | `false` | Critical | Pass |
| RT-04 | Seccomp filtering | `runtime.seccomp` | `2` | Moderate | Pass |
| RT-05 | Privilege-escalation prevention | `runtime.no_new_privs` | `1` | Low | **Finding: observed 0** |
| FS-01 | Sensitive profile-file protection | `security_files[*].mode`, `.owner` | mode `0600`, owner `hermes:hermes` | High | Pass |
| AP-01 | Human approval | `controls.approvals.mode` | `manual` | Moderate | Pass |
| AP-02 | Unattended cron approval | `controls.approvals.cron_mode` | `deny` | Moderate | Pass |
| AP-03 | MCP reload confirmation | `controls.approvals.mcp_reload_confirm` | `true` | Moderate | Pass |
| AP-04 | Destructive command confirmation | `controls.approvals.destructive_slash_confirm` | `true` | Moderate | Pass |
| SE-01 | Security enforcement | `controls.security.tirith_enabled` | `true` | Moderate | Pass |
| SE-02 | Fail-closed enforcement | `controls.security.tirith_fail_open` | `false` | Moderate | Pass |
| SE-03 | Private URL restriction | `controls.security.allow_private_urls` | `false` | Moderate | Pass |
| SE-04 | Lazy-install restriction | `controls.security.allow_lazy_installs` | `false` | Moderate | Pass |
| EX-01 | Interactive CLI exposure | `tools.cli` | empty | Moderate | Pass |
| EX-02 | MCP server exposure | `mcp_servers` | empty | Moderate | Pass |

## Result accounting

The reference fixture evaluates 16 implemented predicates:

- 15 confirmed passes;
- one Low runtime finding for `NoNewPrivs=0`;
- no inferred passes from missing evidence.

Dependency vulnerabilities are evaluated separately from this control catalog because their severity and remediation metadata originate in upstream advisory records rather than a local configuration predicate.

## Not Verified domains

The following assessment domains are material but lack sufficient evidence in the current collector:

1. vulnerable-code reachability and dependency feature use;
2. credential validity, rotation, and external secret-store controls;
3. parent-directory ACLs, backups, encryption, and host isolation;
4. listeners, firewall, egress, TLS, and external exposure;
5. image digest, signature, provenance, namespaces, resource limits, and read-only-root state in the operational Hermes container; and
6. audit-log retention, alert delivery, and cron-definition change control.

These domains remain explicit limitations. The hardened public Compose profile demonstrates additional controls for the reference runner, but those controls are not used to overstate the captured Hermes runtime.

## Control-change procedure

A failed control is not closed by editing the report or changing the expected value. Closure requires:

1. an approved configuration or deployment change;
2. compatibility and regression testing;
3. fresh evidence from the same predicate;
4. confirmation that adjacent controls did not regress; and
5. a recorded reviewer and verification timestamp.
