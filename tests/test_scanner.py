from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def test_detects_secret_and_forbidden_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "server.json"
            target.write_text(
                '{"tools":[{"name":"shell"}],"token":"ghp_abcdefghijklmnopqrstuvwxyz1234567890"}',
                encoding="utf-8",
            )
            findings = scan_path(target)

        rules = {finding["rule"] for finding in findings}
        self.assertIn("secret-detected", rules)
        self.assertIn("forbidden-tool", rules)

    def test_allowed_host_policy_flags_only_outside_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "skill.md"
            target.write_text(
                "Allowed https://api.example.com/v1 and blocked https://evil.invalid/x",
                encoding="utf-8",
            )
            policy = root / "policy.toml"
            policy.write_text(
                '[scope]\nallowed_hosts = ["example.com"]\n',
                encoding="utf-8",
            )
            findings = scan_path(target, policy)

        host_findings = [f for f in findings if f["rule"] == "host-outside-policy"]
        self.assertEqual(len(host_findings), 1)
        self.assertIn("evil.invalid", host_findings[0]["message"])

    def test_excluded_directory_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            node_modules = root / "node_modules"
            node_modules.mkdir()
            (node_modules / "bad.js").write_text('const token = "sk-abcdefghijklmnopqrstuvwxyz";', encoding="utf-8")
            (root / "safe.json").write_text('{"name":"safe"}', encoding="utf-8")
            findings = scan_path(root)

        self.assertFalse(any("node_modules" in str(f.get("location", "")) for f in findings))

    def test_unpinned_package_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text("Run: npx some-package", encoding="utf-8")
            findings = scan_path(target)

        self.assertTrue(any(f["rule"] == "unpinned-package" for f in findings))

    def test_sensitive_literal_field_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text('{"api_key":"literal-value"}', encoding="utf-8")
            findings = scan_path(target)

        self.assertTrue(any(f["rule"] == "sensitive-value" for f in findings))

    def test_placeholder_sensitive_field_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text('{"api_key":"${API_KEY}"}', encoding="utf-8")
            findings = scan_path(target)

        self.assertFalse(any(f["rule"] == "sensitive-value" for f in findings))


if __name__ == "__main__":
    unittest.main()
