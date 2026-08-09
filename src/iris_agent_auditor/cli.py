from __future__ import annotations

import argparse
from pathlib import Path

from .pipeline import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iris-audit",
        description="Evaluate deterministic security evidence and generate an audit report.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate", help="validate, deduplicate, classify, and report")
    evaluate.add_argument("--input", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        metrics = run_audit(args.input, args.output)
        print("Iris security audit: completed")
        print(f"raw advisories: {metrics['raw_advisory_records']}")
        print(f"unique dependency vulnerabilities: {metrics['unique_dependency_vulnerabilities']}")
        print(f"findings: {metrics['findings_total']}")
        print(f"passed controls: {metrics['passed_controls']}")
        print("automatic remediation: no")
        print(f"artifacts: {args.output}")
        return 0
    return 2
