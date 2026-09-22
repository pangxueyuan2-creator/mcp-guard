from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.scanner import scan_path


class TextReportPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="mcp-guard-text-privacy-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "policy.toml"
        self.policy.write_text('[scope]\nallowed_hosts = ["public.example"]\n', encoding="utf-8")
        self.markers = ("SYNTH_USERINFO_CANARY", "SYNTH_QUERY_CANARY", "SYNTH_FRAGMENT_CANARY")
        self.url = (
            "https://user:SYNTH_USERINFO_CANARY@packages.example/pkg.whl"
            "?token=SYNTH_QUERY_CANARY#SYNTH_FRAGMENT_CANARY"
        )

    def render(self, target: Path, report_format: str) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["scan", str(target), "--policy", str(self.policy), "--strict", "--format", report_format])
        self.assertEqual(code, 1)
        return output.getvalue()

    def test_text_install_urls_are_safe_in_every_report_format(self) -> None:
        cases = {
            "install.md": f"# Setup\n\npip install {self.url}\n",
            "bootstrap.sh": f"#!/bin/sh\nnpx --package={self.url} public-runner\n",
            "job.yaml": f"steps:\n  - run: npm install {self.url}\n",
            "windows-cache.ps1": f"pip install C:\\cache\\pkg.whl --index-url {self.url} public-package\n",
        }
        for filename, content in cases.items():
            target = self.root / filename
            target.write_text(content, encoding="utf-8")
            for report_format in ("human", "json", "sarif"):
                with self.subTest(filename=filename, report_format=report_format):
                    output = self.render(target, report_format)
                    for marker in self.markers:
                        self.assertNotIn(marker, output)
                    self.assertIn("packages.example", output)
                    self.assertIn("unpinned-package", output)
            findings = scan_path(target)
            if filename == "windows-cache.ps1":
                finding = next(item for item in findings if item["rule"] == "absolute-path-reference")
                self.assertIn("C:\\cache\\pkg.whl", finding["message"])
            else:
                finding = next(item for item in findings if item["rule"] == "unpinned-package")
                self.assertIn("/pkg.whl", finding["message"])
            self.assertEqual(finding["location"], str(target))
            self.assertEqual(finding["line"], 3 if filename == "install.md" else 1 if filename.endswith("ps1") else 2)

    def test_existing_package_matchers_and_git_url_schemes_are_redacted(self) -> None:
        for command in (
            f"pip install --upgrade {self.url}",
            f"npm install --save-dev {self.url}",
            f"uvx --from {self.url} public-runner",
            f"npm install public-package@latest {self.url}",
            f"pip install git+{self.url}",
            f"pip install {self.url.replace('https://', 'git+ssh://')}",
        ):
            with self.subTest(command=command):
                target = self.root / "README.md"
                target.write_text(command, encoding="utf-8")
                findings = scan_path(target)
                packages = [item for item in findings if item["rule"] == "unpinned-package"]
                self.assertTrue(packages)
                self.assertTrue(any("packages.example/pkg.whl" in item["message"] for item in packages))
                for marker in self.markers:
                    self.assertNotIn(marker, json.dumps(findings))

    def test_public_package_names_and_source_lines_are_preserved(self) -> None:
        target = self.root / "public.md"
        target.write_text("# Public packages\nnpx @public/server@latest\npip install public-package\n", encoding="utf-8")
        findings = scan_path(target)
        self.assertEqual([item["line"] for item in findings], [2, 3])
        self.assertTrue(all(item["rule"] == "unpinned-package" and item["location"] == str(target) for item in findings))
        for report_format in ("human", "json", "sarif"):
            output = self.render(target, report_format)
            self.assertIn("@public/server@latest", output)
            self.assertIn("public-package", output)

    def test_query_fragment_and_userinfo_are_redacted_independently(self) -> None:
        for url in (
            "https://packages.example/pkg.whl?arbitrary=SYNTH_QUERY_CANARY",
            "https://packages.example/pkg.whl#SYNTH_FRAGMENT_CANARY",
            "https://SYNTH_USERINFO_CANARY@packages.example/pkg.whl",
        ):
            with self.subTest(url=url):
                target = self.root / "install.md"
                target.write_text(f"pip install {url}", encoding="utf-8")
                for report_format in ("human", "json", "sarif"):
                    output = self.render(target, report_format)
                    self.assertIn("packages.example/pkg.whl", output)
                    for marker in self.markers:
                        self.assertNotIn(marker, output)

    def test_url_host_check_already_keeps_credentials_private(self) -> None:
        target = self.root / "urls-only.md"
        target.write_text(f"# Documentation\nSource: {self.url}\n", encoding="utf-8")
        findings = scan_path(target, self.policy)
        self.assertEqual([item["rule"] for item in findings], ["host-outside-policy"])
        self.assertEqual(findings[0]["line"], 2)
        for report_format in ("human", "json", "sarif"):
            output = self.render(target, report_format)
            for marker in self.markers:
                self.assertNotIn(marker, output)


if __name__ == "__main__":
    unittest.main()
