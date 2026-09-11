from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_guard.scanner import scan_path


class PythonModulePipSupplyChainTests(unittest.TestCase):
    def _scan(self, command: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "README.md"
            target.write_text(command, encoding="utf-8")
            return scan_path(target)

    def test_python_module_pip_reports_unpinned_packages(self) -> None:
        for command in (
            "python -m pip install some-package",
            "python3 -m pip install some-package>=1.2.3",
            "python3.14 -m pip install some-package",
            "python.exe -m pip install some-package@latest",
            "py -m pip install some-package~=1.2",
            "py -3.14 -m pip install some-package",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                warnings = [f for f in findings if f["rule"] == "unpinned-package"]
                self.assertEqual(len(warnings), 1)

    def test_python_module_pip_accepts_exact_pins(self) -> None:
        for command in (
            "python -m pip install some-package==1.2.3",
            "python3.14 -m pip install some-package===1.2.3",
            "py -3 -m pip install some-package==2.0.0",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))

    def test_python_module_pip_scans_later_package_specs(self) -> None:
        findings = self._scan(
            "python -m pip install stable-package==1.2.3 floating-package>=2.0"
        )
        warnings = [f for f in findings if f["rule"] == "unpinned-package"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("floating-package>=2.0", str(warnings[0]["message"]))

    def test_python_module_pip_non_install_commands_stay_clean(self) -> None:
        for command in (
            "python -m pip list",
            "python -m pip check",
            "py -3.14 -m pip --version",
        ):
            with self.subTest(command=command):
                findings = self._scan(command)
                self.assertFalse(any(f["rule"] == "unpinned-package" for f in findings))


if __name__ == "__main__":
    unittest.main()
