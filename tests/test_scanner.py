from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.policy import Policy, load_policy
from mcp_guard.scanner import scan_findings, scan_path


class ScannerTests(unittest.TestCase):
    def test_secret_detection_reports_line_without_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text('{\n  "token": "sk-abcdefghijklmnopqrstuvwxyz123456"\n}\n', encoding="utf-8")

            findings = scan_path(path)

            secret = next(item for item in findings if item["rule"] == "secret-detected")
            self.assertEqual(secret["line"], 2)
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", secret["message"])

    def test_custom_policy_forbidden_tool_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "server.json"
            target.write_text(json.dumps({"tools": ["browser"]}), encoding="utf-8")
            policy = root / "policy.toml"
            policy.write_text('[policy]\nforbidden_tools = ["browser"]\n', encoding="utf-8")

            findings = scan_path(target, policy)

            self.assertTrue(any(item["rule"] == "forbidden-tool" for item in findings))

    def test_ignored_directory_is_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ignored = root / "node_modules"
            ignored.mkdir()
            (ignored / "leak.js").write_text('const token = "sk-abcdefghijklmnopqrstuvwxyz123456";', encoding="utf-8")

            findings = scan_path(root)

            self.assertEqual(findings, [])

    def test_unpinned_npx_package_is_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(
                json.dumps({"mcpServers": {"demo": {"command": "npx", "args": ["-y", "@example/server"]}}}),
                encoding="utf-8",
            )

            findings = scan_path(path)

            self.assertTrue(any(item["rule"] == "unpinned-package" and item["severity"] == "warning" for item in findings))

    def test_pinned_scoped_npm_package_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(
                json.dumps({"mcpServers": {"demo": {"command": "npx", "args": ["-y", "@example/server@1.2.3"]}}}),
                encoding="utf-8",
            )

            findings = scan_path(path)

            self.assertFalse(any(item["rule"] == "unpinned-package" for item in findings))

    def test_shell_command_is_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(json.dumps({"command": "bash", "args": ["-c", "echo ok"]}), encoding="utf-8")

            findings = scan_path(path)

            self.assertTrue(any(item["rule"] == "shell-command" and item["severity"] == "error" for item in findings))

    def test_sensitive_env_literal_warns_but_placeholder_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(
                json.dumps({"env": {"API_KEY": "literal-value", "AUTH_TOKEN": "${AUTH_TOKEN}"}}),
                encoding="utf-8",
            )

            findings = scan_path(path)
            inline = [item for item in findings if item["rule"] == "inline-sensitive-env"]

            self.assertEqual(len(inline), 1)
            self.assertIn("API_KEY", inline[0]["message"])

    def test_remote_plaintext_http_warns_localhost_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "mcp.json"
            path.write_text(
                json.dumps({"endpoint": "http://example.com/mcp", "health_url": "http://localhost:8080/health"}),
                encoding="utf-8",
            )

            findings = scan_path(path)

            self.assertEqual(sum(item["rule"] == "plaintext-remote-url" for item in findings), 1)

    def test_large_file_creates_coverage_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large.json"
            path.write_text("x" * 32, encoding="utf-8")
            policy = Policy().with_max_file_size(8)

            findings = scan_findings(path, policy)

            self.assertEqual(findings[0].rule, "file-too-large")
            self.assertEqual(findings[0].severity, "warning")

    def test_policy_normalizes_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.toml"
            path.write_text('[policy]\nextensions = ["json", ".toml"]\n', encoding="utf-8")

            policy = load_policy(path)

            self.assertEqual(policy.extensions, frozenset({".json", ".toml"}))


if __name__ == "__main__":
    unittest.main()
