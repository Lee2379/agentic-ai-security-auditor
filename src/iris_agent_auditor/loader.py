from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REQUIRED_TOP_LEVEL = {
    "metadata",
    "profile",
    "runtime",
    "security_files",
    "controls",
    "tools",
    "mcp_servers",
    "advisories_raw",
    "collector_guarantees",
}


def load_evidence(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("collector evidence must be a JSON object")

    missing = sorted(REQUIRED_TOP_LEVEL - set(payload))
    if missing:
        raise ValueError(f"missing evidence sections: {', '.join(missing)}")

    runtime = payload["runtime"]
    for key in ("uid", "gid", "container_detected", "docker_socket_mounted", "cap_eff", "no_new_privs", "seccomp"):
        if key not in runtime:
            raise ValueError(f"runtime evidence missing: {key}")

    if not isinstance(payload["security_files"], list) or not payload["security_files"]:
        raise ValueError("security_files must contain at least one metadata record")
    if not isinstance(payload["advisories_raw"], list):
        raise ValueError("advisories_raw must be a list")

    guarantees = payload["collector_guarantees"]
    required_guarantees = {
        "credential_values_read": False,
        "system_modifications_performed": False,
        "automatic_remediation_performed": False,
    }
    for key, expected in required_guarantees.items():
        if guarantees.get(key) is not expected:
            raise ValueError(f"collector guarantee violated: {key}")
    return payload
