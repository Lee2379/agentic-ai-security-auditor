from __future__ import annotations

from typing import Any

from .models import Finding


def evaluate_controls(evidence: dict[str, Any]) -> tuple[list[str], list[Finding], list[str]]:
    runtime = evidence["runtime"]
    controls = evidence["controls"]
    files = evidence["security_files"]
    tools = evidence["tools"]
    passed: list[str] = []
    findings: list[Finding] = []

    if runtime["uid"] != 0:
        passed.append(f"Runtime executes as non-root UID {runtime['uid']}.")
    else:
        findings.append(Finding("IRIS-RUNTIME-001", "high", "runtime container", "uid=0", "A compromised process would execute with root privileges inside the container.", "Run the workload as a dedicated non-root user and verify the effective UID at runtime."))

    if str(runtime["cap_eff"]).strip("0") == "":
        passed.append("Effective Linux capability mask is zero.")
    else:
        findings.append(Finding("IRIS-RUNTIME-002", "high", "runtime container", f"CapEff={runtime['cap_eff']}", "Retained Linux capabilities expand the impact of process compromise.", "Drop all capabilities and add back only a documented minimum after compatibility testing."))

    if not runtime["docker_socket_mounted"]:
        passed.append("The host Docker socket is not mounted.")
    else:
        findings.append(Finding("IRIS-RUNTIME-003", "critical", "runtime container", "Docker socket mounted", "Docker socket access can provide control over the host container runtime.", "Remove the Docker socket mount and use a narrow, authenticated control plane if orchestration is required."))

    if runtime["seccomp"] == 2:
        passed.append("Seccomp filtering is active.")
    else:
        findings.append(Finding("IRIS-RUNTIME-004", "moderate", "runtime container", f"Seccomp={runtime['seccomp']}", "Missing syscall filtering increases kernel attack surface.", "Apply and test an explicit seccomp profile."))

    if runtime["no_new_privs"] == 1:
        passed.append("NoNewPrivileges is enabled.")
    else:
        findings.append(Finding("IRIS-RUNTIME-005", "low", "runtime container", "NoNewPrivs=0", "A future executable or configuration change could acquire privilege through set-user-ID, set-group-ID, or file capabilities.", "Enable no-new-privileges after compatibility testing and retain capability dropping and seccomp filtering."))

    insecure_files = [item for item in files if str(item["mode"]) != "600" or item["owner"] != "hermes:hermes"]
    if not insecure_files:
        passed.append("Sensitive profile files are mode 0600 and owned by hermes:hermes.")
    else:
        details = ", ".join(item["path"] for item in insecure_files)
        findings.append(Finding("IRIS-FILE-001", "high", "profile files", details, "Overbroad permissions can expose configuration or credentials to other principals.", "Set owner-only permissions and verify owner/group after deployment."))

    expected_controls = {
        "approvals.mode": ("manual", "State-changing actions require human approval."),
        "approvals.cron_mode": ("deny", "Unattended cron approvals are denied."),
        "approvals.mcp_reload_confirm": (True, "MCP reload requires confirmation."),
        "approvals.destructive_slash_confirm": (True, "Destructive slash commands require confirmation."),
        "security.tirith_enabled": (True, "Tirith security enforcement is enabled."),
        "security.tirith_fail_open": (False, "Tirith enforcement is configured fail-closed."),
        "security.allow_private_urls": (False, "Private URL access is disabled."),
        "security.allow_lazy_installs": (False, "Lazy package installation is disabled."),
    }
    for key, (expected, statement) in expected_controls.items():
        if controls.get(key) == expected:
            passed.append(statement)
        else:
            findings.append(Finding(f"IRIS-CONTROL-{len(findings)+1:03d}", "moderate", key, f"observed={controls.get(key)!r}; expected={expected!r}", "The observed policy does not match the auditor's fail-closed baseline.", f"Set {key} to {expected!r} under change control and re-run the audit."))

    cli_tools = tools.get("cli") or []
    if not cli_tools:
        passed.append("The Iris profile exposes no interactive CLI tools.")
    else:
        findings.append(Finding(
            "IRIS-EXPOSURE-001",
            "moderate",
            "Iris profile",
            f"{len(cli_tools)} interactive CLI tool(s) enabled",
            "Interactive command or file capabilities expand the auditor's authority and can invalidate the read-only trust boundary.",
            "Disable interactive CLI tools for the auditor profile, then re-run the exposure and report-contract tests.",
        ))

    mcp_servers = evidence["mcp_servers"]
    if not mcp_servers:
        passed.append("The Iris profile has no configured MCP servers.")
    else:
        findings.append(Finding(
            "IRIS-EXPOSURE-002",
            "moderate",
            "Iris profile",
            f"{len(mcp_servers)} MCP server(s) configured",
            "An MCP connection adds an external capability and data path that is outside the zero-integration auditor baseline.",
            "Remove MCP servers from the auditor profile or document and approve a narrowly scoped exception before re-audit.",
        ))

    not_verified = [
        "Dependency reachability and vulnerable code paths were not tested.",
        "Credential values, validity, rotation dates, and external secret-store use were not inspected.",
        "Parent-directory ACLs, backup copies, filesystem encryption, and host isolation were not assessed.",
        "Network listeners, firewall policy, egress restrictions, TLS, and external exposure were not collected.",
        "Container image provenance, immutable digest, signature, namespaces, resource limits, and read-only-root status were not collected.",
        "Audit-log retention, alert delivery, and cron-definition change control were not independently verified.",
    ]
    return passed, findings, not_verified
