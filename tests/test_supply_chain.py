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

    def test_npm_floating_versions_are_reported(self) -> None:
        for command in (
            "npx some-package@latest",
            "npx some-package@next",
            "npm install some-package@^1.2.3",
            "npm i some-package@~1.2.3",
            "npx some-package@1.2",
            "npx @scope/tool@latest",
            "npm install @scope/tool@^2.0.0",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
