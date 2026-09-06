from __future__ import annotations

import unittest
from pathlib import Path

from mcp_guard.reporting import build_json_report, build_sarif_report, should_fail


class ReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = [
            {
                "severity": "error",
                "rule": "secret-detected",
                "message": "Secret found",
                "location": "config.json",
                "line": 3,
            },
            {
                "severity": "warning",
                "rule": "unpinned-package",
                "message": "Package is unpinned",
                "location": "README.md",
            },
        ]

    def test_json_report_contains_summary(self) -> None:
        report = build_json_report(Path("."), self.findings)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["summary"]["warnings"], 1)

    def test_sarif_report_is_sarif_21(self) -> None:
        report = build_sarif_report(self.findings)
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "MCP Guard")
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            3,
        )

    def test_failure_threshold(self) -> None:
        self.assertTrue(should_fail(self.findings, "warning"))
        self.assertFalse(should_fail(self.findings, "error"))
        self.assertTrue(should_fail(self.findings, "info"))


if __name__ == "__main__":
    unittest.main()
