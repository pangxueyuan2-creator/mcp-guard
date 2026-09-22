from __future__ import annotations

import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp_guard.cli import main
from mcp_guard.policy import Policy
from mcp_guard.scanner import _scan_file, scan_path


class SpecialFileTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="mcp-guard-special-file-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "events.json"

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "Requires a real POSIX FIFO")
    def test_real_fifo_is_reported_without_opening_it(self) -> None:
        os.mkfifo(self.target)
        self.assertTrue(stat.S_ISFIFO(self.target.stat().st_mode))
        # Do not wait on a writer: fail immediately if the scanner tries to read.
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("FIFO content read attempted")) as reader:
            findings = scan_path(self.root)
            # Directly selected special roots keep the existing entry-point rule.
            self.assertEqual([item["rule"] for item in scan_path(self.target)], ["path-not-found"])
        reader.assert_not_called()
        self.assertEqual([item["rule"] for item in findings], ["unsupported-file-type"])
        self.assertEqual(findings[0]["location"], str(self.target))

    def special_metadata(self, mode: int):
        self.target.write_text("{}", encoding="utf-8")
        original_stat = Path.stat
        fields = list(self.target.stat())
        fields[0] = mode | 0o600
        fields[6] = 0
        metadata = os.stat_result(fields)

        def inspect(path: Path, *args, **kwargs):
            return metadata if path == self.target else original_stat(path, *args, **kwargs)

        return mock.patch.object(Path, "stat", inspect)

    def test_injected_fifo_socket_and_device_metadata_never_reaches_reader(self) -> None:
        # This is metadata injection, not an assertion that Windows has POSIX FIFOs.
        for mode in (stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK):
            with self.subTest(mode=mode), self.special_metadata(mode):
                with mock.patch.object(Path, "read_text", side_effect=AssertionError("Special file read attempted")) as reader:
                    findings = scan_path(self.root)
                reader.assert_not_called()
                self.assertEqual([item["rule"] for item in findings], ["unsupported-file-type"])
                self.assertEqual(findings[0]["severity"], "warning")

    def test_cli_reports_skips_in_all_formats_and_preserves_warning_threshold(self) -> None:
        with self.special_metadata(stat.S_IFIFO):
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("Special file read attempted")):
                for report_format in ("human", "json", "sarif"):
                    for strict in (False, True):
                        with self.subTest(report_format=report_format, strict=strict):
                            output = io.StringIO()
                            arguments = ["scan", str(self.root), "--format", report_format]
                            if strict:
                                arguments.append("--strict")
                            with contextlib.redirect_stdout(output):
                                code = main(arguments)
                            self.assertEqual(code, 1 if strict else 0)
                            self.assertIn("unsupported-file-type", output.getvalue())

    def test_regular_file_scanning_and_size_limit_are_preserved(self) -> None:
        self.target.write_text('{"notes": "npx public-package"}', encoding="utf-8")
        self.assertEqual([item["rule"] for item in scan_path(self.root)], ["unpinned-package"])
        with mock.patch.object(Path, "read_text", side_effect=AssertionError("Oversized file read attempted")):
            findings = _scan_file(self.target, Policy(max_file_bytes=1))
        self.assertEqual([item["rule"] for item in findings], ["file-too-large"])

    def test_metadata_and_regular_file_read_errors_keep_existing_rules(self) -> None:
        self.target.write_text("{}", encoding="utf-8")
        with mock.patch.object(Path, "stat", side_effect=PermissionError("Synthetic stat denied")):
            self.assertEqual([item["rule"] for item in _scan_file(self.target, Policy())], ["stat-error"])
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("Synthetic read denied")):
            self.assertEqual([item["rule"] for item in _scan_file(self.target, Policy())], ["read-error"])


if __name__ == "__main__":
    unittest.main()
