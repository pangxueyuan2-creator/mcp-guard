from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class RemoteUrlSupplyChainScannerTests(unittest.TestCase):
    def _scan(self, command: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text(command, encoding="utf-8")
            return scan_path(target)

    def test_remote_package_urls_are_reported_as_unpinned(self) -> None:
        for command in (
            "pip install https://downloads.example.com/tool-1.2.3-py3-none-any.whl",
            "python -m pip install https://downloads.example.com/tool.tar.gz",
            "npm install https://downloads.example.com/tool.tgz",
            f"pip install https://downloads.example.com/tool.whl#sha256={'a' * 64}",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)
                self.assertIn("https://", str(warnings[0]["message"]))

    def test_http_package_urls_are_also_reported(self) -> None:
        findings = self._scan("pip install http://downloads.example.com/tool.whl")
        warnings = [f for f in findings if f["rule"] == "unpinned-package"]
        self.assertEqual(len(warnings), 1)

    def test_local_paths_remain_ignored_by_supply_chain_pin_check(self) -> None:
        for command in (
            "pip install ./dist/tool.whl",
            "pip install /tmp/tool.whl",
            "npm install ../tool.tgz",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))


if __name__ == "__main__":
    unittest.main()
