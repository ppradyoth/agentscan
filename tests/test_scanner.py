import os
import unittest

from agentscan.scanner import scan_path
from agentscan.model import SEV_RANK

HERE = os.path.dirname(__file__)
EX = os.path.join(HERE, "..", "examples")


def rule_ids(report):
    return {f.rule_id for f in report.findings}


class TestVulnSample(unittest.TestCase):
    def setUp(self):
        self.r = scan_path(os.path.join(EX, "vuln-sample"))

    def test_finds_critical_bypass_and_shell(self):
        ids = rule_ids(self.r)
        self.assertIn("AS001", ids)
        self.assertIn("AS004", ids)  # leaked key
        self.assertIn("AS002", ids)  # broad filesystem root
        self.assertIn("AS003", ids)  # hook shell
        self.assertIn("AS005", ids)  # no-confirm instructions
        self.assertIn("AS006", ids)  # injection boundary
        self.assertIn("AS007", ids)  # unpinned npx

    def test_has_critical(self):
        self.assertGreaterEqual(self.r.max_rank(), SEV_RANK["CRITICAL"])

    def test_secret_is_redacted(self):
        secrets = [f for f in self.r.findings if f.rule_id == "AS004"]
        self.assertTrue(secrets)
        for f in secrets:
            self.assertNotIn("FAKEKEYtestonly", f.evidence)


class TestCleanSample(unittest.TestCase):
    def test_clean_has_no_findings(self):
        r = scan_path(os.path.join(EX, "clean-sample"))
        self.assertEqual(len(r.findings), 0, [f.title for f in r.findings])


class TestPinnedNpxNotFlagged(unittest.TestCase):
    def test_pinned_package_ok(self):
        r = scan_path(os.path.join(EX, "clean-sample", ".mcp.json"))
        self.assertNotIn("AS007", rule_ids(r))


if __name__ == "__main__":
    unittest.main()
