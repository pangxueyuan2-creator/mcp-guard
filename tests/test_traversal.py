from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import subprocess
import tempfile
import unittest
from itertools import islice
from pathlib import Path
from unittest import mock

from mcp_guard.cli import main
from mcp_guard.policy import Policy
from mcp_guard.scanner import _iter_scannable_files, scan_path


class TraversalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="mcp-guard-traversal-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        self.root.mkdir()

    def directory_alias(self, target: Path, alias: Path) -> None:
        if os.name == "nt":
            # Directory junctions require no symlink privilege on Windows.
            # This fixture setup command never runs in the scanner itself.
            script = (
                "New-Item -ItemType Junction -Path $env:MCP_GUARD_TEST_LINK "
                "-Target $env:MCP_GUARD_TEST_TARGET | Out-Null"
            )
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                env={**os.environ, "MCP_GUARD_TEST_LINK": str(alias), "MCP_GUARD_TEST_TARGET": str(target)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            alias.symlink_to(target, target_is_directory=True)

    def outside(self) -> Path:
        target = self.base / "outside"
        target.mkdir()
        (target / "canary.md").write_text("npx external-canary", encoding="utf-8")
        return target

    def test_nested_directory_alias_does_not_scan_outside_files(self) -> None:
        target = self.outside()
        nested = self.root / "nested"
        nested.mkdir()
        alias = nested / "bridge"
        self.directory_alias(target, alias)

        findings = scan_path(self.root)

        self.assertFalse(any("external-canary" in item["message"] for item in findings))
        self.assertEqual([item["rule"] for item in findings], ["skipped-link"])
        self.assertEqual(findings[0]["location"], str(alias))

    def test_directory_cycle_is_pruned_before_enumerating_descendants(self) -> None:
        local = self.root / "local.json"
        local.write_text("{}", encoding="utf-8")
        self.directory_alias(self.root, self.root / "cycle")

        # Bound the pre-fix regression itself; a junction cycle must not hang tests.
        selected = list(islice(_iter_scannable_files(self.root, Policy()), 3))

        self.assertEqual(selected, [local])

    def test_directly_selected_root_alias_remains_supported(self) -> None:
        (self.root / "local.md").write_text("npx selected-root-canary", encoding="utf-8")
        alias = self.base / "selected-root"
        self.directory_alias(self.root, alias)

        findings = scan_path(alias)

        self.assertEqual([item["rule"] for item in findings], ["unpinned-package"])
        self.assertIn("selected-root-canary", findings[0]["message"])
        self.assertEqual(findings[0]["location"], str(alias / "local.md"))

    def test_internal_alias_is_skipped_without_duplicate_scanning(self) -> None:
        target = self.root / "actual"
        target.mkdir()
        local = target / "local.json"
        local.write_text("{}", encoding="utf-8")
        self.directory_alias(target, self.root / "alias")

        self.assertEqual(list(_iter_scannable_files(self.root, Policy())), [local])
        self.assertEqual([item["rule"] for item in scan_path(self.root)], ["skipped-link"])

    def test_excluded_directory_alias_is_not_scanned_or_reported(self) -> None:
        self.directory_alias(self.outside(), self.root / "node_modules")
        (self.root / "safe.json").write_text("{}", encoding="utf-8")

        self.assertEqual(scan_path(self.root), [])

    def test_regular_files_extensions_and_nested_directories_are_preserved(self) -> None:
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "README.MD").write_text("npx local-canary", encoding="utf-8")
        (nested / "ignored.txt").write_text("npx excluded-extension-canary", encoding="utf-8")

        findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["unpinned-package"])
        self.assertIn("local-canary", findings[0]["message"])

    def test_broken_directory_alias_is_reported_without_following_it(self) -> None:
        target = self.base / "empty-target"
        target.mkdir()
        alias = self.root / "broken.json"
        self.directory_alias(target, alias)
        target.rmdir()

        findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["skipped-link"])
        self.assertEqual(findings[0]["location"], str(alias))

    def test_broken_alias_without_extension_is_reported_when_classified_as_file(self) -> None:
        target = self.base / "empty-target"
        target.mkdir()
        alias = self.root / "broken"
        self.directory_alias(target, alias)
        target.rmdir()

        # POSIX os.walk classifies dangling directory symlinks as files. Windows
        # may retain a dangling junction in dirs, so exercise both classifications.
        self.assertEqual([item["rule"] for item in scan_path(self.root)], ["skipped-link"])
        with mock.patch("mcp_guard.scanner.os.walk", return_value=[(self.root, [], [alias.name])]):
            findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["skipped-link"])
        self.assertEqual(findings[0]["location"], str(alias))

    def test_file_symlink_is_not_read(self) -> None:
        target = self.outside() / "canary.md"
        alias = self.root / "alias.md"
        try:
            alias.symlink_to(target)
        except OSError as error:
            if os.name == "nt" and (
                error.errno in {errno.EPERM, errno.EACCES} or getattr(error, "winerror", None) == 1314
            ):
                self.skipTest("Windows file symlink privilege is unavailable; junction cases still run.")
            raise

        findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["skipped-link"])
        self.assertNotIn("external-canary", json.dumps(findings))

    def test_directory_enumeration_failure_is_a_finding(self) -> None:
        failure = PermissionError(errno.EACCES, "Synthetic enumeration denied", str(self.root))
        with mock.patch("mcp_guard.scanner.os.scandir", side_effect=failure):
            findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["walk-error"])
        self.assertEqual(findings[0]["location"], str(self.root))

    def test_entry_metadata_failure_is_reported_and_pruned(self) -> None:
        child = self.root / "uninspectable"
        child.mkdir()
        (child / "canary.md").write_text("npx unread-canary", encoding="utf-8")
        original_lstat = Path.lstat

        def lstat(path: Path):
            if path == child:
                raise PermissionError(errno.EACCES, "Synthetic metadata denied", str(child))
            return original_lstat(path)

        with mock.patch.object(Path, "lstat", lstat):
            findings = scan_path(self.root)

        self.assertEqual([item["rule"] for item in findings], ["stat-error"])
        self.assertEqual(findings[0]["location"], str(child))

    def test_junction_check_does_not_require_python_312_path_method(self) -> None:
        self.directory_alias(self.outside(), self.root / "bridge")
        with mock.patch.object(Path, "is_junction", None, create=True):
            self.assertEqual(list(_iter_scannable_files(self.root, Policy())), [])

    def test_cli_strict_mode_reports_incomplete_traversal_without_target_contents(self) -> None:
        self.directory_alias(self.outside(), self.root / "bridge")
        for report_format in ("human", "json", "sarif"):
            with self.subTest(report_format=report_format):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(["scan", str(self.root), "--strict", "--format", report_format])
                self.assertEqual(code, 1)
                self.assertIn("skipped-link", output.getvalue())
                self.assertNotIn("external-canary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
