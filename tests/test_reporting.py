from __future__ import annotations

import unittest
from pathlib import Path

from mcp_guard.reporting import should_fail, summarize, to_sarif


class ReportingTests(unittest.TestCase):
    def test_summary_and_failure_thresholds(self) -> None:
        findings = [
            {"severity": "warning", "rule": "one", "message": "warning", "location": "a.json"},
            {"severity": "info", "rule": "two", "message": "info", "location": "b.json"},
        ]

        self.assertEqual(
            summarize(findings),
            {"error": 0, "warning": 1, "info": 1, "total": 2},
        )
        self.assertFalse(should_fail(findings, "error"))
        self.assertTrue(should_fail(findings, "warning"))
        self.assertTrue(should_fail(findings, "info"))
        self.assertFalse(should_fail(findings, "never"))

    def test_sarif_preserves_windows_drive_and_strips_structural_trail(self) -> None:
        findings = [
            {
                "severity": "error",
                "rule": "forbidden-tool",
                "message": "Dangerous tool declared: exec",
                "location": r"C:\repo\mcp.json:mcpServers.demo.tools",
                "line": 12,
                "hint": "Remove it.",
            }
        ]

        sarif = to_sarif(findings, Path("."))
        result = sarif["runs"][0]["results"][0]
        physical = result["locations"][0]["physicalLocation"]

        self.assertEqual(physical["artifactLocation"]["uri"], "C:/repo/mcp.json")
        self.assertEqual(physical["region"]["startLine"], 12)
        self.assertEqual(result["level"], "error")


if __name__ == "__main__":
    unittest.main()
