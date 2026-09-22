from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.scanner import scan_path


class UrlScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "README.md"
        self.policy = self.root / "policy.toml"
        self.policy.write_text(
            '[scope]\nallowed_hosts = ["example.test", "::1"]\n',
            encoding="utf-8",
        )

    def test_malformed_urls_warn_without_disclosing_input(self) -> None:
        for url in (
            "https://[broken",
            "https://synthetic-user:synthetic-password@[not-ip]/path",
            "https://synthetic-user:synthetic-password@bad\uff0fhost/path",
            "https:///no-host",
            "https://synthetic-user@",
            "https://]",
        ):
            with self.subTest(url=url):
                self.target.write_text(f"Reference:\n{url}\n", encoding="utf-8")
                findings = scan_path(self.target, self.policy)
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding["rule"], "url-parse-error")
                self.assertEqual(finding["severity"], "warning")
                self.assertEqual(finding["location"], str(self.target))
                self.assertEqual(finding["line"], 2)
                self.assertEqual(
                    finding["message"],
                    "Could not parse URL; its network host was not checked against policy.",
                )
                self.assertNotIn(url, json.dumps(findings))
                self.assertNotIn("synthetic-password", json.dumps(findings))

    def test_malformed_url_preserves_other_findings_and_files(self) -> None:
        self.target.write_text(
            '"shell"\nhttps://[broken\nhttps://outside.invalid/path\n',
            encoding="utf-8",
        )
        other = self.root / "other.json"
        other.write_text('{"tools": ["bash"]}', encoding="utf-8")
        findings = scan_path(self.root, self.policy)
        rules = {finding["rule"] for finding in findings}
        self.assertTrue(
            {"forbidden-tool", "url-parse-error", "host-outside-policy"} <= rules
        )
        self.assertTrue(any(f["location"] == str(other) for f in findings))
        host = next(f for f in findings if f["rule"] == "host-outside-policy")
        self.assertEqual(host["line"], 3)

    def test_valid_hosts_ipv6_and_markdown_delimiters(self) -> None:
        self.target.write_text(
            "https://example.test\n"
            "https://API.EXAMPLE.TEST/path\n"
            "https://example.test/path).\n"
            "[https://example.test]\n"
            "[https://example.test.] [https://example.test,] [https://example.test)]\n"
            "https://[::1]\n"
            "[https://[::1]]\n"
            "(https://[::1]).\n"
            "[https://[::1].]\n"
            "https://[::1]:443/path\n"
            "https://[2001:db8::1]\n"
            "https://outside.invalid/path\n",
            encoding="utf-8",
        )
        findings = scan_path(self.target, self.policy)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["rule"] == "host-outside-policy" for f in findings))
        self.assertEqual({f["line"] for f in findings}, {11, 12})

    def test_empty_allowlist_still_disables_host_checks(self) -> None:
        self.target.write_text("https://[broken\n", encoding="utf-8")
        self.assertEqual(scan_path(self.target), [])

    def test_cli_warning_formats_and_strict_exit_status(self) -> None:
        self.target.write_text(
            "Reference:\nhttps://synthetic-user:synthetic-password@bad\uff0fhost/path\n",
            encoding="utf-8",
        )
        for report_format in ("human", "json", "sarif"):
            for strict in (False, True):
                with self.subTest(report_format=report_format, strict=strict):
                    args = [
                        "scan", str(self.target), "--policy", str(self.policy),
                        "--format", report_format,
                    ]
                    if strict:
                        args.append("--strict")
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = main(args)
                    output = stdout.getvalue()
                    self.assertEqual(code, 1 if strict else 0)
                    self.assertEqual(stderr.getvalue(), "")
                    self.assertIn("url-parse-error", output)
                    self.assertNotIn("synthetic-user", output)
                    self.assertNotIn("synthetic-password", output)
                    self.assertNotIn("bad\\uff0fhost", output)
                    if report_format == "human":
                        self.assertTrue(output.startswith("WARN"))
                    elif report_format == "json":
                        report = json.loads(output)
                        self.assertEqual(report["summary"]["warnings"], 1)
                        self.assertEqual(report["findings"][0]["line"], 2)
                    else:
                        result = json.loads(output)["runs"][0]["results"][0]
                        self.assertEqual(result["level"], "warning")
                        location = result["locations"][0]["physicalLocation"]
                        self.assertEqual(location["region"]["startLine"], 2)


if __name__ == "__main__":
    unittest.main()
