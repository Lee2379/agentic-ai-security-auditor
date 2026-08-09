from copy import deepcopy
from pathlib import Path
import unittest

from iris_agent_auditor.controls import evaluate_controls
from iris_agent_auditor.loader import load_evidence


ROOT = Path(__file__).resolve().parents[1]


class ControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence = load_evidence(ROOT / "evidence" / "sample" / "collector.json")

    def test_least_privilege_controls_are_recognized(self) -> None:
        passed, findings, _ = evaluate_controls(self.evidence)
        self.assertIn("Effective Linux capability mask is zero.", passed)
        self.assertIn("The host Docker socket is not mounted.", passed)
        self.assertIn("Seccomp filtering is active.", passed)
        self.assertEqual([item.finding_id for item in findings], ["IRIS-RUNTIME-005"])

    def test_root_runtime_is_a_high_finding(self) -> None:
        modified = deepcopy(self.evidence)
        modified["runtime"]["uid"] = 0
        _, findings, _ = evaluate_controls(modified)
        root = next(item for item in findings if item.finding_id == "IRIS-RUNTIME-001")
        self.assertEqual(root.severity, "high")

    def test_collector_never_marks_missing_evidence_as_passed(self) -> None:
        _, _, not_verified = evaluate_controls(self.evidence)
        self.assertTrue(any("Network listeners" in item for item in not_verified))


if __name__ == "__main__":
    unittest.main()
