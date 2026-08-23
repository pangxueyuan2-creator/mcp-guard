from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class PolicyTests(unittest.TestCase):
    def test_default_policy_detects_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "server.json"
            target.write_text('{"tools": [{"name": "exec"}]}', encoding="utf-8")

            findings = scan_path(target)

            self.assertTrue(
                any(
                    finding["rule"] == "forbidden-tool"
                    and "exec" in finding["message"].lower()
                    for finding in findings
                )
            )

    def test_custom_forbidden_tool_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "server.json"
            policy = root / ".mcp-guard.toml"

            target.write_text(
                '{"tools": [{"name": "delete_everything"}]}',
                encoding="utf-8",
            )
            policy.write_text(
                '[policy]\nforbidden_tools = ["delete_everything"]\n',
                encoding="utf-8",
            )

            findings = scan_path(target, policy_path=policy)

            self.assertTrue(
                any(
                    finding["rule"] == "forbidden-tool"
                    and "delete_everything" in finding["message"]
                    for finding in findings
                )
            )

    def test_custom_secret_pattern_is_honored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "config.toml"
            policy = root / ".mcp-guard.toml"

            target.write_text('token = "CUSTOM-SECRET-1234"\n', encoding="utf-8")
            policy.write_text(
                '[secrets]\npatterns = ["CUSTOM-SECRET-[0-9]+"]\n',
                encoding="utf-8",
            )

            findings = scan_path(target, policy_path=policy)

            self.assertTrue(
                any(finding["rule"] == "secret-detected" for finding in findings)
            )

    def test_missing_policy_is_a_failing_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "server.json"
            target.write_text('{"tools": []}', encoding="utf-8")

            findings = scan_path(target, policy_path=root / "missing.toml")

            self.assertTrue(
                any(finding["rule"] == "policy-not-found" for finding in findings)
            )


if __name__ == "__main__":
    unittest.main()
