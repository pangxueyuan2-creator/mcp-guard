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

    def test_remote_package_urls_without_digest_are_reported(self) -> None:
        for command in (
            "pip install https://downloads.example.com/tool-1.2.3-py3-none-any.whl",
            "python -m pip install https://downloads.example.com/tool.tar.gz",
            "npm install https://downloads.example.com/tool.tgz",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)
                self.assertIn("https://", str(warnings[0]["message"]))

    def test_remote_package_urls_accept_strong_digest_fragments(self) -> None:
        sha256 = "a" * 64
        sha384 = "b" * 96
        sha512 = "c" * 128
        for command in (
            f"pip install https://downloads.example.com/tool.whl#sha256={sha256}",
            f"python -m pip install https://downloads.example.com/tool.tar.gz#sha384={sha384}",
            f"npm install https://downloads.example.com/tool.tgz#sha512={sha512}",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_remote_package_urls_reject_invalid_digest_fragments(self) -> None:
        for command in (
            "pip install https://downloads.example.com/tool.whl#sha256=abcd",
            f"pip install https://downloads.example.com/tool.whl#md5={'a' * 32}",
            f"pip install https://downloads.example.com/tool.whl#sha256={'z' * 64}",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
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
