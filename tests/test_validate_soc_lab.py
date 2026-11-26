"""Unit tests for Wazuh XML configs, FIM regex filtering, and pfSense rule matching."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import validate_soc_lab  # noqa: E402


class TestSOCLabArtifacts(unittest.TestCase):
    def setUp(self) -> None:
        self.ossec_xml = REPO_ROOT / "configs" / "wazuh" / "ossec-fim-syslog.xml"
        self.rules_xml = REPO_ROOT / "configs" / "wazuh" / "local-rules-pfsense.xml"

    def test_fim_regex_suppresses_tmp_and_log_only(self) -> None:
        patterns = validate_soc_lab.parse_fim_ignore_patterns(self.ossec_xml)
        self.assertTrue(validate_soc_lab.should_suppress_fim_event("noise.tmp", patterns))
        self.assertTrue(validate_soc_lab.should_suppress_fim_event("app.LOG", patterns))
        self.assertFalse(validate_soc_lab.should_suppress_fim_event("2nd_file.txt", patterns))
        self.assertFalse(validate_soc_lab.should_suppress_fim_event("tmp_payload.exe", patterns))

    def test_pfsense_rules_correlate_blocked_ioc_to_level_12(self) -> None:
        rules = validate_soc_lab.parse_wazuh_rules(self.rules_xml)
        self.assertEqual(rules["100901"]["level"], 5)
        self.assertEqual(rules["100903"]["level"], 12)

        blocked_eicar = {"action": "block", "dstip": "89.238.73.97"}
        self.assertEqual(
            validate_soc_lab.evaluate_pfsense_event(blocked_eicar, rules),
            ["100901", "100903"],
        )

        blocked_other = {"action": "block", "dstip": "1.1.1.1"}
        self.assertEqual(
            validate_soc_lab.evaluate_pfsense_event(blocked_other, rules),
            ["100901"],
        )

        allowed_traffic = {"action": "pass", "dstip": "89.238.73.97"}
        self.assertEqual(
            validate_soc_lab.evaluate_pfsense_event(allowed_traffic, rules),
            [],
        )

    def test_full_repo_validation_passes(self) -> None:
        summary = validate_soc_lab.run_validation(REPO_ROOT)
        self.assertEqual(summary.xml_files_checked, 2)
        self.assertIn("100903", summary.triggered_rules)


if __name__ == "__main__":
    unittest.main()
