#!/usr/bin/env bash
set -eu

# Public reference collector. It performs read-only checks and never prints
# credential values. Run it inside the Hermes container as the hermes user.
profile_name="${IRIS_PROFILE:-iris}"
profile_root="${HERMES_DATA_ROOT:-/opt/data/profiles}/${profile_name}"

printf '%s\n' '=== AUDIT METADATA ==='
date -u '+Timestamp (UTC): %Y-%m-%dT%H:%M:%SZ'
hermes --version

printf '\n%s\n' '=== IRIS PROFILE ISOLATION ==='
hermes profile show "${profile_name}"

printf '\n%s\n' '=== RUNTIME IDENTITY ==='
id
if [ -f /.dockerenv ]; then
  printf '%s\n' 'Container environment: detected'
else
  printf '%s\n' 'Container environment: not detected'
fi
if [ -S /var/run/docker.sock ]; then
  printf '%s\n' 'Docker socket: mounted'
else
  printf '%s\n' 'Docker socket: not mounted'
fi
sed -n -E '/^(CapEff|NoNewPrivs|Seccomp):/p' /proc/self/status

printf '\n%s\n' '=== SECURITY FILE METADATA ==='
for relative_path in .env config.yaml SOUL.md; do
  target="${profile_root}/${relative_path}"
  if [ -e "${target}" ]; then
    stat -c '%n | mode=%a | owner=%U:%G' "${target}"
  else
    printf '%s\n' "${target} | missing"
  fi
done

printf '\n%s\n' '=== SELECTED SECURITY CONTROLS ==='
for key in \
  approvals.mode \
  approvals.timeout \
  approvals.cron_mode \
  approvals.mcp_reload_confirm \
  approvals.destructive_slash_confirm \
  security.tirith_enabled \
  security.tirith_fail_open \
  security.allow_private_urls \
  security.allow_lazy_installs
do
  value="$(hermes -p "${profile_name}" config get "${key}")"
  printf '%s = %s\n' "${key}" "${value}"
done

printf '\n%s\n' '=== MCP SERVERS ==='
hermes -p "${profile_name}" mcp list

printf '\n%s\n' '=== SUPPLY-CHAIN AUDIT ==='
if command -v pip-audit >/dev/null 2>&1; then
  audit_exit=0
  pip-audit || audit_exit=$?
  printf 'Supply-chain audit exit code: %s\n' "${audit_exit}"
else
  printf '%s\n' 'Not Collected: pip-audit is not installed; the collector will not install packages.'
fi

printf '\n%s\n' '=== COLLECTOR GUARANTEES ==='
printf '%s\n' 'Credential values read: no'
printf '%s\n' 'System modifications performed: no'
printf '%s\n' 'Automatic remediation performed: no'
printf '%s\n' 'Evidence collection completed'
