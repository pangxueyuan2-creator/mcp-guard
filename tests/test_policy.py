from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.policy import load_policy


class PolicyTests(unittest.TestCase):
    def test_custom_policy_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.toml"
            policy_path.write_text(
                '''
[policy]
forbidden_tools = ["danger"]
allowed_tools = ["safe"]
max_severity = "info"
max_file_bytes = 1234

[scope]
allowed_hosts = ["example.com"]
exclude_dirs = ["generated"]
extensions = ["json", ".py"]
''',
                encoding="utf-8",
            )

            policy = load_policy(policy_path)

        self.assertEqual(policy.forbidden_tools, {"danger"})
        self.assertEqual(policy.allowed_tools, {"safe"})
        self.assertEqual(policy.max_severity, "info")
        self.assertEqual(policy.max_file_bytes, 1234)
        self.assertEqual(policy.allowed_hosts, {"example.com"})
        self.assertIn("generated", policy.excluded_dirs)
        self.assertEqual(policy.scan_extensions, {".json", ".py"})

    def test_invalid_severity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.toml"
            policy_path.write_text('[policy]\nmax_severity = "critical"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(policy_path)


if __name__ == "__main__":
    unittest.main()
