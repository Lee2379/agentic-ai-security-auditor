#!/usr/bin/env python3
"""Compare deterministic CI output with the committed reference artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path


FILES = ("normalized_evidence.json", "findings.json", "metrics.json", "audit_report.md")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("actual", type=Path)
    args = parser.parse_args()
    failures = []
    for name in FILES:
        expected = (args.expected / name).read_bytes()
        actual = (args.actual / name).read_bytes()
        if expected != actual:
            failures.append(name)
    if failures:
        print("artifact comparison failed: " + ", ".join(failures))
        return 1
    print(f"artifact comparison passed: {len(FILES)} deterministic files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
