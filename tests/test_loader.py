from pathlib import Path
import unittest

from iris_agent_auditor.loader import load_evidence


ROOT = Path(__file__).resolve().parents[1]


class LoaderTests(unittest.TestCase):
    def test_sample_evidence_satisfies_contract(self) -> None:
        evidence = load_evidence(ROOT / "evidence" / "sample" / "collector.json")
        self.assertEqual(evidence["profile"]["name"], "iris")
        self.assertEqual(evidence["runtime"]["uid"], 1000)
        self.assertFalse(evidence["collector_guarantees"]["credential_values_read"])

    def test_missing_sections_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            load_evidence(ROOT / "config" / "iris-policy.json")


if __name__ == "__main__":
    unittest.main()
