# Hermes Deployment Notes

This directory documents the integration contract used by the operational Iris profile without publishing a live Hermes configuration.

## Profile contract

- Profile name: `iris`
- Purpose: independent, read-only security inspection
- Bundled skills: none
- State-changing actions: human approval required
- Scheduled approval mode: deny
- Automatic remediation: prohibited
- Report delivery: local scheduler output

## Collector placement

In the private deployment, the collector is installed under the Iris profile's script directory and is executed before the scheduled agent analysis. A publishable reference is available at [`../../scripts/collect_security_evidence.sh`](../../scripts/collect_security_evidence.sh).

The collector must:

1. emit stable, timestamped evidence;
2. avoid credential values;
3. avoid package installation, service control, and configuration mutation;
4. continue through a non-zero vulnerability-scanner exit status while recording that status;
5. end with explicit collection guarantees.

## Scheduled analysis contract

The agent receives collector output as bounded context and is instructed to call no tools. Its final response must include the seven required governance sections and must deduplicate database aliases for the same underlying vulnerability. A missing observation is labeled Not Verified.

## Public/private boundary

The repository intentionally omits:

- `.env` and authentication material;
- gateway/channel identifiers;
- live provider configuration;
- private endpoints and network topology;
- agent session history and raw logs;
- stable token fingerprints.

The checked-in JSON fixture is synthetic and should be used for public reproduction.
