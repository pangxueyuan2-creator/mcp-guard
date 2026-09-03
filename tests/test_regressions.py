from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.reporting import summarize
from mcp_guard.scanner import scan_path


class RegressionTests(unittest.TestCase):
    def test_tool_object_is_reported_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(
                json.dumps({"tools": [{"name": "exec", "description": "dangerous"}]}),
                encoding="utf-8",
            )

            findings = scan_path(path)
            forbidden = [item for item in findings if item["rule"] == "forbidden-tool"]

            self.assertEqual(len(forbidden), 1)

    def test_windows_command_suffix_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(json.dumps({"command": "powershell.exe"}), encoding="utf-8")

            findings = scan_path(path)

            self.assertTrue(any(item["rule"] == "shell-command" for item in findings))

    def test_risky_demo_has_stable_expected_summary(self) -> None:
        findings = scan_path(Path("examples/risky-mcp-server.json"))

        self.assertEqual(
            summarize(findings),
            {"error": 2, "warning": 1, "info": 0, "total": 3},
        )


if __name__ == "__main__":
    unittest.main()
