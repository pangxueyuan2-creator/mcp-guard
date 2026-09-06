from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main


class CliTests(unittest.TestCase):
    def test_clean_json_scan_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "safe.json"
            target.write_text('{"name":"safe"}', encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["scan", str(target), "--format", "json"])

        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["summary"]["total"], 0)

    def test_error_finding_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bad.json"
            target.write_text('{"tools":["shell"]}', encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["scan", str(target)])

        self.assertEqual(code, 1)
        self.assertIn("FAIL", stdout.getvalue())

    def test_invalid_policy_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "safe.json"
            target.write_text('{"name":"safe"}', encoding="utf-8")
            policy = root / "bad.toml"
            policy.write_text('[policy]\nmax_severity = "critical"\n', encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(["scan", str(target), "--policy", str(policy)])

        self.assertEqual(code, 2)
        self.assertIn("Policy error", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
