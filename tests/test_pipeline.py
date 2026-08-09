import json
from pathlib import Path
import tempfile
import unittest

from iris_agent_auditor.pipeline import run_audit


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def test_pipeline_emits_reviewable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            metrics = run_audit(ROOT / "evidence" / "sample" / "collector.json", output)
            self.assertEqual(metrics["raw_advisory_records"], 12)
            self.assertEqual(metrics["unique_dependency_vulnerabilities"], 6)
            self.assertEqual(metrics["findings_total"], 7)
            self.assertEqual(metrics["findings_by_severity"], {"high": 3, "low": 1, "moderate": 3})
            self.assertEqual(metrics["passed_controls"], 15)
            self.assertFalse(metrics["automatic_remediation_performed"])
            for name in ("normalized_evidence.json", "findings.json", "metrics.json", "audit_report.md"):
                self.assertTrue((output / name).is_file(), name)

    def test_report_has_required_governance_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            run_audit(ROOT / "evidence" / "sample" / "collector.json", output)
            report = (output / "audit_report.md").read_text(encoding="utf-8")
            for heading in (
                "## Executive Summary",
                "## Scope and Timestamp",
                "## Findings",
                "## Passed Controls",
                "## Limitations and Not-Verified Items",
                "## Risk Treatment",
                "## Remediation Verification Plan",
            ):
                self.assertIn(heading, report)
            self.assertIn("No system modification or automatic remediation was performed", report)

    def test_normalized_evidence_contains_no_duplicate_advisory_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            run_audit(ROOT / "evidence" / "sample" / "collector.json", output)
            normalized = json.loads((output / "normalized_evidence.json").read_text(encoding="utf-8"))
            self.assertNotIn("advisories_raw", normalized)
            self.assertEqual(len(normalized["advisories_unique"]), 6)


if __name__ == "__main__":
    unittest.main()
