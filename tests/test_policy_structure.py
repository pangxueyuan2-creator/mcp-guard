from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.policy import load_policy


class PolicyStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = self.root / "policy.toml"
        self.target = self.root / "safe.json"
        self.target.write_text("{}", encoding="utf-8")

    def write_policy(self, content: str) -> None:
        self.policy.write_text(content, encoding="utf-8")

    def test_known_sections_must_be_tables(self) -> None:
        for section in ("policy", "scope", "secrets"):
            for value in ('"private-policy-canary"', "[]", "[1]", "42", "true"):
                with self.subTest(section=section, value=value):
                    self.write_policy(f"{section} = {value}\n")
                    with self.assertRaisesRegex(ValueError, f"{section} must be a TOML table"):
                        load_policy(self.policy)

    def test_empty_and_omitted_tables_preserve_defaults(self) -> None:
        for content in ("", "[policy]\n[scope]\n[secrets]\n"):
            with self.subTest(content=content):
                self.write_policy(content)
                policy = load_policy(self.policy)
                self.assertEqual(policy.max_file_bytes, 2_000_000)
                self.assertEqual(policy.allowed_hosts, set())

    def test_max_file_bytes_requires_a_positive_integer(self) -> None:
        for value in ("true", "false", "1.5", "nan", "inf", "-inf", '"100"', "[]", "{limit = 4}", "0", "-1"):
            with self.subTest(value=value):
                self.write_policy(f"[policy]\nmax_file_bytes = {value}\n")
                with self.assertRaisesRegex(ValueError, "policy.max_file_bytes must be a positive integer"):
                    load_policy(self.policy)

    def test_positive_integer_limits_are_preserved(self) -> None:
        for value in (1, 100, 2_000_000):
            with self.subTest(value=value):
                self.write_policy(f"[policy]\nmax_file_bytes = {value}\n")
                self.assertEqual(load_policy(self.policy).max_file_bytes, value)

    def test_cli_rejects_invalid_policy_before_emitting_a_report(self) -> None:
        invalid_policies = (
            'scope = []\n',
            'secrets = "private-policy-canary"\n',
            '[policy]\nmax_file_bytes = inf\n',
        )
        for index, content in enumerate(invalid_policies):
            for output_format in ("human", "json", "sarif"):
                with self.subTest(content=content, output_format=output_format):
                    self.write_policy(content)
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    output = self.root / f"report-{index}-{output_format}.txt"
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = main([
                            "scan", str(self.target), "--policy", str(self.policy),
                            "--strict", "--format", output_format, "--output", str(output),
                        ])
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("Policy error:", stderr.getvalue())
                    self.assertNotIn("private-policy-canary", stderr.getvalue())
                    self.assertNotIn("Traceback", stderr.getvalue())
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
