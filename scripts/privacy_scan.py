#!/usr/bin/env python3
"""Fail when common secrets or personal infrastructure markers enter the repository."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]


RULES = (
    Rule("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    Rule("credential-in-url", re.compile(r"[?&](?:token|api[_-]?key|access[_-]?token)=[A-Za-z0-9._~-]{8,}", re.I)),
    Rule("email-address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    Rule("windows-user-path", re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s]+", re.I)),
    Rule("personal-unix-home", re.compile(r"/home/(?!user(?:/|\b)|demo(?:/|\b)|hermes(?:/|\b))[A-Za-z0-9._-]+", re.I)),
    Rule("personal-shell-prompt", re.compile(r"\b(?!user@|demo@|hermes@)[a-z0-9._-]+@[a-z0-9._-]+:[~/$]", re.I)),
    Rule("private-network-address", re.compile(r"(?<!\d)(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2})(?!\d)")),
)

TEXT_SUFFIXES = {".cfg", ".csv", ".dockerignore", ".example", ".gitignore", ".json", ".md", ".py", ".sh", ".toml", ".txt", ".yaml", ".yml"}
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}
SKIP_FILES = {"privacy_scan.py"}


def scan(root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", "LICENSE"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            for rule in RULES:
                if rule.pattern.search(line):
                    findings.append((path.relative_to(root), line_number, rule.name))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    findings = scan(root)
    if findings:
        print(f"privacy scan failed: {len(findings)} finding(s)")
        for path, line, rule in findings:
            print(f"- {path}:{line}: {rule}")
        print("Matched values are intentionally not printed.")
        return 1
    print("privacy scan passed: no configured secret or personal-data patterns found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
