from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.scanner import scan_path


class ConfigParseDiagnosticTests(unittest.TestCase):
    def test_malformed_configs_report_incomplete_structured_checks(self) -> None:
        samples = {
            "broken.json": '{"api_key":"synthetic-ordinary-value",',
            "broken.toml": '[server\napi_key = "synthetic-ordinary-value"\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in samples.items():
                with self.subTest(name=name):
                    target = Path(tmp) / name
                    target.write_text(text, encoding="utf-8")
                    findings = scan_path(target)
                    self.assertEqual(len(findings), 1)
                    self.assertEqual(findings[0]["rule"], "config-parse-error")
                    self.assertEqual(findings[0]["severity"], "warning")
                    self.assertEqual(findings[0]["location"], str(target))
                    self.assertIn("incomplete", findings[0]["message"])
                    self.assertNotIn("synthetic-ordinary-value", str(findings))

    def test_parse_warning_reaches_all_cli_formats_and_respects_severity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for suffix, text in (("json", '{"name":'), ("toml", "[server")):
                target = Path(tmp) / f"broken.{suffix}"
                target.write_text(text, encoding="utf-8")
                for report_format in ("human", "json", "sarif"):
                    for strict in (False, True):
                        with self.subTest(suffix=suffix, format=report_format, strict=strict):
                            output = io.StringIO()
                            args = ["scan", str(target), "--format", report_format]
                            if strict:
                                args.append("--strict")
                            with contextlib.redirect_stdout(output):
                                code = main(args)
                            self.assertEqual(code, 1 if strict else 0)
                            rendered = output.getvalue()
                            if report_format == "human":
                                self.assertIn("WARN", rendered)
                                self.assertNotIn("PASS", rendered)
                                self.assertIn("config-parse-error", rendered)
                            elif report_format == "json":
                                report = json.loads(rendered)
                                self.assertEqual(report["summary"]["warnings"], 1)
                                self.assertEqual(report["findings"][0]["rule"], "config-parse-error")
                            else:
                                report = json.loads(rendered)
                                result = report["runs"][0]["results"][0]
                                self.assertEqual(result["ruleId"], "config-parse-error")
                                self.assertEqual(result["level"], "warning")

    def test_parse_diagnostics_do_not_echo_toml_exception_fragments(self) -> None:
        marker = "SYNTHETIC_DIAGNOSTIC_CANARY"
        text = f'["{marker}"]\n["{marker}"]\n'
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "duplicate.toml"
            target.write_text(text, encoding="utf-8")
            for report_format in ("human", "json", "sarif"):
                with self.subTest(format=report_format):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main(["scan", str(target), "--strict", "--format", report_format])
                    self.assertEqual(code, 1)
                    self.assertIn("config-parse-error", output.getvalue())
                    self.assertNotIn(marker, output.getvalue())

    def test_text_findings_survive_invalid_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for suffix in ("json", "toml"):
                with self.subTest(suffix=suffix):
                    target = Path(tmp) / f"broken.{suffix}"
                    target.write_text('broken [\n"shell"\nnpx review-only-tool\n', encoding="utf-8")
                    rules = {finding["rule"] for finding in scan_path(target)}
                    self.assertTrue({"config-parse-error", "forbidden-tool", "unpinned-package"} <= rules)

    def test_deep_decoding_produces_an_incomplete_diagnostic_not_a_crash(self) -> None:
        depth = sys.getrecursionlimit() + 100
        array = "[" * depth + "0" + "]" * depth
        with tempfile.TemporaryDirectory() as tmp:
            for suffix, text in (("json", array), ("toml", "value = " + array)):
                with self.subTest(suffix=suffix):
                    target = Path(tmp) / f"deep.{suffix}"
                    target.write_text(text, encoding="utf-8")
                    findings = scan_path(target)
                    self.assertEqual(len(findings), 1)
                    self.assertEqual(findings[0]["rule"], "config-scan-incomplete")
                    self.assertEqual(findings[0]["severity"], "warning")
                    self.assertIn("nesting", findings[0]["message"])
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main(["scan", str(target), "--strict", "--format", "json"])
                    self.assertEqual(code, 1)

    def test_successful_parse_with_excessive_structural_depth_is_reported(self) -> None:
        # tomllib can decode a dotted key without recursively walking its value.
        text = ".".join(["a"] * 999) + " = 1\n"
        self.assertIsInstance(tomllib.loads(text), dict)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "deep-walk.toml"
            target.write_text(text, encoding="utf-8")
            findings = scan_path(target)
        self.assertEqual([finding["rule"] for finding in findings], ["config-scan-incomplete"])

    def test_valid_empty_scalar_and_text_inputs_do_not_get_parse_warnings(self) -> None:
        samples = [
            ("safe.json", "{}"),
            ("safe.json", "[]"),
            ("safe.json", "null"),
            ("safe.json", "42"),
            ("safe.json", '{"api_key":"${API_KEY}"}'),
            ("safe.toml", ""),
            ("safe.toml", '[server]\nname = "safe"\n'),
            ("safe.md", "Ordinary prose with unmatched [ punctuation."),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in samples:
                with self.subTest(name=name, text=text):
                    target = Path(tmp) / name
                    target.write_text(text, encoding="utf-8")
                    self.assertEqual(scan_path(target), [])

    def test_launch_credentials_stay_redacted_when_structured_checks_fail(self) -> None:
        marker = "SYNTHETIC_CREDENTIAL_CANARY"
        package = f"--package=https://user:{marker}@example.invalid/tool.tgz?token={marker}"
        launch = {"command": "npx", "args": [package, "serve"]}
        valid_json = json.dumps({"mcpServers": {"demo": launch}})
        valid_toml = f'mcp_servers.demo = {{ command = "npx", args = ["{package}", "serve"] }}\n'
        depth = sys.getrecursionlimit() + 100
        array = "[" * depth + "0" + "]" * depth
        samples = (
            ("valid.json", valid_json, None),
            ("valid.toml", valid_toml, None),
            ("broken.json", valid_json[:-1], "config-parse-error"),
            ("broken.toml", valid_toml * 2, "config-parse-error"),
            ("deep.json", valid_json[:-1] + ', "deep": ' + array + "}", "config-scan-incomplete"),
            ("deep.toml", valid_toml + "deep = " + array + "\n", "config-scan-incomplete"),
            ("deep-walk.toml", valid_toml + ".".join(["a"] * 999) + " = 1\n", "config-scan-incomplete"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for name, text, diagnostic in samples:
                target = Path(tmp) / name
                target.write_text(text, encoding="utf-8")
                findings = scan_path(target)
                expected_rules = {"unpinned-package"} | ({diagnostic} if diagnostic else set())
                with self.subTest(name=name, surface="findings"):
                    self.assertEqual({finding["rule"] for finding in findings}, expected_rules)
                    self.assertNotIn(marker, json.dumps(findings))
                    packages = [finding for finding in findings if finding["rule"] == "unpinned-package"]
                    self.assertTrue(packages)
                    for finding in packages:
                        if diagnostic:
                            self.assertEqual(finding["location"], str(target))
                            self.assertIsInstance(finding["line"], int)
                        else:
                            self.assertTrue(finding["location"].endswith(".demo.args[0]"))
                            self.assertNotIn("line", finding)
                for report_format in ("human", "json", "sarif"):
                    with self.subTest(name=name, format=report_format):
                        stdout = io.StringIO()
                        stderr = io.StringIO()
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            code = main(["scan", str(target), "--strict", "--format", report_format])
                        self.assertEqual(code, 1)
                        self.assertEqual(stderr.getvalue(), "")
                        self.assertNotIn(marker, stdout.getvalue())
                        for rule in expected_rules:
                            self.assertIn(rule, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
