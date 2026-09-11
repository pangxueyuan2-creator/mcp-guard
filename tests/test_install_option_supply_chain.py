from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class InstallOptionSupplyChainTests(unittest.TestCase):
    def _scan(self, command: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text(command, encoding="utf-8")
            return scan_path(target)

    def test_pip_leading_options_do_not_hide_unpinned_package(self) -> None:
        for command in (
            "pip install --upgrade some-package",
            "pip3 install -U --pre some-package",
            "python -m pip install --user some-package",
            "py -3.14 -m pip install --no-deps some-package",
            "pip install --index-url=mirror.example.invalid/simple some-package",
        ):
            with self.subTest(command=command):
                warnings = [
                    finding
                    for finding in self._scan(command)
                    if finding["rule"] == "unpinned-package"
                ]
                self.assertEqual(len(warnings), 1)
                self.assertIn("some-package", str(warnings[0]["message"]))

    def test_npm_leading_options_do_not_hide_unpinned_package(self) -> None:
        for command in (
            "npm install --save-dev some-package",
            "npm i -D --dry-run some-package",
            "npm install --global some-package",
            "npm install --registry=registry.example.invalid some-package",
        ):
            with self.subTest(command=command):
                warnings = [
                    finding
                    for finding in self._scan(command)
                    if finding["rule"] == "unpinned-package"
                ]
                self.assertEqual(len(warnings), 1)
                self.assertIn("some-package", str(warnings[0]["message"]))

    def test_leading_options_keep_exact_pins_clean(self) -> None:
        for command in (
            "pip install --upgrade some-package==1.2.3",
            "python -m pip install --user some-package===1.2.3",
            "npm install --save-dev some-package@1.2.3",
            "npm i -D @scope/tool@2.0.0",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(
                    any(finding["rule"] == "unpinned-package" for finding in findings)
                )


if __name__ == "__main__":
    unittest.main()
