from pathlib import Path
import unittest

from iris_agent_auditor.deduplicate import deduplicate_advisories
from iris_agent_auditor.loader import load_evidence


ROOT = Path(__file__).resolve().parents[1]


class DeduplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.records = load_evidence(ROOT / "evidence" / "sample" / "collector.json")["advisories_raw"]

    def test_alias_records_reduce_from_twelve_to_six(self) -> None:
        unique = deduplicate_advisories(self.records)
        self.assertEqual(len(self.records), 12)
        self.assertEqual(len(unique), 6)
        self.assertTrue(all(item.source_records == 2 for item in unique))

    def test_known_ghsa_severity_wins_over_unknown_alias(self) -> None:
        unique = deduplicate_advisories(self.records)
        out_of_bounds = next(item for item in unique if item.primary_id == "GHSA-cq5v-8q36-5273")
        self.assertEqual(out_of_bounds.severity, "high")
        self.assertEqual(out_of_bounds.alias_ids, ("PYSEC-2026-3545",))

    def test_cve_identity_is_used_when_titles_differ(self) -> None:
        records = [dict(self.records[0]), dict(self.records[1])]
        records[1]["title"] = "Alternate database wording"
        self.assertEqual(len(deduplicate_advisories(records)), 1)


if __name__ == "__main__":
    unittest.main()
