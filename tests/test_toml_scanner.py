from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class TomlScannerTests(unittest.TestCase):
    def test_nested_toml_sensitive_literal_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "mcp.toml"
            target.write_text(
                '[mcp_servers.demo]\napi_key = "literal-value-without-token-shape"\n',
                encoding="utf-8",
            )
            findings = scan_path(target)

        sensitive = [f for f in findings if f["rule"] == "sensitive-value"]
        self.assertEqual(len(sensitive), 1)
        self.assertIn("api_key", sensitive[0]["message"])
        self.assertIn("$.mcp_servers.demo.api_key", sensitive[0]["location"])

    def test_toml_placeholder_sensitive_value_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "mcp.toml"
            target.write_text(
                '[mcp_servers.demo]\nclient_secret = "${CLIENT_SECRET}"\n',
                encoding="utf-8",
            )
            findings = scan_path(target)

        self.assertFalse(any(f["rule"] == "sensitive-value" for f in findings))

    def test_array_of_tables_is_walked_structurally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "agents.toml"
            target.write_text(
                '[[agents]]\nname = "safe"\ncredentials = "literal-credential"\n'
                '[[agents]]\nname = "also-safe"\nrefresh_token = "<REFRESH_TOKEN>"\n',
                encoding="utf-8",
            )
            findings = scan_path(target)

        sensitive = [f for f in findings if f["rule"] == "sensitive-value"]
        self.assertEqual(len(sensitive), 1)
        self.assertIn("credentials", sensitive[0]["message"])
        self.assertIn("$.agents[0].credentials", sensitive[0]["location"])

    def test_toml_declared_forbidden_tool_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "agent.toml"
            target.write_text('tools = ["shell", "read_file"]\n', encoding="utf-8")
            findings = scan_path(target)

        self.assertTrue(any(f["rule"] == "forbidden-tool" for f in findings))

    def test_invalid_toml_falls_back_to_text_scan_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "broken.toml"
            target.write_text('[server\napi_key = "ordinary-literal"\n', encoding="utf-8")
            findings = scan_path(target)

        self.assertFalse(any(f["rule"] == "sensitive-value" for f in findings))


if __name__ == "__main__":
    unittest.main()
