from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class SupplyChainScannerTests(unittest.TestCase):
    def _scan(self, command: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text(command, encoding="utf-8")
            return scan_path(target)

    def test_npx_yes_flag_does_not_hide_unpinned_package(self) -> None:
        for command in ("npx -y some-package", "npx --yes some-package"):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)
                self.assertIn("some-package", str(warnings[0]["message"]))

    def test_npx_yes_flag_keeps_pinned_package_clean(self) -> None:
        for command in (
            "npx -y some-package@1.2.3",
            "npx --yes @scope/tool@2.0.0",
            "npx some-package@1.2.3-beta.1+build.7",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_npx_package_flags_report_unpinned_packages(self) -> None:
        for command in (
            "npx --package some-package tool",
            "npx --package=some-package@latest tool",
            "npx -p @scope/tool command",
            "npx -p=@scope/tool@^2.0.0 command",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)

    def test_npx_package_flags_accept_exact_pins(self) -> None:
        for command in (
            "npx --package some-package@1.2.3 tool",
            "npx --package=@scope/tool@2.0.0 command",
            "npx -p some-package@1.2.3-beta.1+build.7 tool",
            "npx -p=@scope/tool@2.0.0 command",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_npx_multiple_package_flags_are_all_scanned(self) -> None:
        findings = self._scan(
            "npx --package first-package@latest -p second-package@^2.0.0 tool"
        )
        warnings = [f for f in findings if f["rule"] == "unpinned-package"]
        self.assertEqual(len(warnings), 2)
        messages = {str(f["message"]) for f in warnings}
        self.assertTrue(any("first-package@latest" in message for message in messages))
        self.assertTrue(any("second-package@^2.0.0" in message for message in messages))

    def test_package_flag_without_npx_is_not_treated_as_npx_dependency(self) -> None:
        findings = self._scan("python tool.py --package some-package")
        self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_npm_floating_versions_are_reported(self) -> None:
        for command in (
            "npx some-package@latest",
            "npx some-package@next",
            "npm install some-package@^1.2.3",
            "npm i some-package@~1.2.3",
            "npm install some-package@>=1.2.3",
            "npx some-package@1.2",
            "npx @scope/tool@latest",
            "npm install @scope/tool@^2.0.0",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)

    def test_pip_floating_versions_are_reported(self) -> None:
        for command in (
            "pip install some-package>=1.2.3",
            "pip3 install some-package~=1.2",
            "pip install some-package<=2.0.0",
            "pip install some-package!=1.5.0",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)

    def test_pip_exact_versions_stay_clean(self) -> None:
        for command in (
            "pip install some-package==1.2.3",
            "pip3 install some-package===1.2.3",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_uvx_from_flag_scans_source_package(self) -> None:
        for command in (
            "uvx --from some-package tool",
            "uvx --from=some-package@latest tool",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)
                self.assertIn("some-package", str(warnings[0]["message"]))

    def test_uvx_from_flag_accepts_exact_pin(self) -> None:
        for command in (
            "uvx --from some-package@1.2.3 tool",
            "uvx --from=@scope/tool@2.0.0 command",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))


if __name__ == "__main__":
    unittest.main()
