from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class VcsSupplyChainScannerTests(unittest.TestCase):
    def _scan(self, command: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text(command, encoding="utf-8")
            return scan_path(target)

    def test_git_vcs_dependencies_without_immutable_commit_are_reported(self) -> None:
        for command in (
            "pip install git+https://github.com/example/tool.git",
            "pip install git+https://github.com/example/tool.git@main",
            "pip install git+https://github.com/example/tool.git@v1.2.3",
            "python -m pip install git+ssh://git@github.com/example/tool.git@release",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)
                self.assertIn("git+", str(warnings[0]["message"]))

    def test_git_vcs_dependencies_accept_full_commit_sha(self) -> None:
        sha1 = "0123456789abcdef0123456789abcdef01234567"
        sha256 = (
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )
        for command in (
            f"pip install git+https://github.com/example/tool.git@{sha1}",
            f"pip install git+https://github.com/example/tool.git@{sha1}#subdirectory=python",
            f"python -m pip install git+ssh://git@github.com/example/tool.git@{sha1}",
            f"pip install git+https://example.com/tool.git@{sha256}",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_short_commit_sha_is_still_reported(self) -> None:
        findings = self._scan(
            "pip install git+https://github.com/example/tool.git@0123456789ab"
        )
        warnings = [f for f in findings if f["rule"] == "unpinned-package"]
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
