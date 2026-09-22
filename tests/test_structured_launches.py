from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main
from mcp_guard.reporting import build_sarif_report
from mcp_guard.scanner import scan_path


class StructuredLaunchTests(unittest.TestCase):
    def _scan(self, command: object, args: object, *, container: str = "mcpServers") -> list[dict]:
        server = {"command": command, "args": args}
        data = {"mcp": {"servers": {"demo": server}}} if container == "mcp.servers" else {container: {"demo": server}}
        return self._scan_text(json.dumps(data), ".json")

    def _scan_text(self, content: str, suffix: str) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ("config" + suffix)
            target.write_text(content, encoding="utf-8")
            return scan_path(target)

    def _packages(self, findings: list[dict]) -> list[dict]:
        return [item for item in findings if item["rule"] == "unpinned-package"]

    def test_supported_json_containers_find_unpinned_npx(self) -> None:
        for container in ("mcpServers", "mcp_servers", "servers", "mcp.servers"):
            with self.subTest(container=container):
                packages = self._packages(self._scan("npx", ["-y", "demo@latest"], container=container))
                self.assertEqual(len(packages), 1)
                self.assertTrue(packages[0]["location"].endswith(".demo.args[1]"))

    def test_toml_launch_arguments_are_scanned(self) -> None:
        findings = self._scan_text(
            '[mcp_servers.demo]\ncommand = "uvx"\nargs = ["--from", "demo", "serve"]\n',
            ".toml",
        )
        packages = self._packages(findings)
        self.assertEqual(len(packages), 1)
        self.assertTrue(packages[0]["location"].endswith("$.mcp_servers.demo.args[1]"))

    def test_direct_installers_and_python_module_invocations(self) -> None:
        cases = [
            ("npm", ["install", "demo"]),
            ("pip", ["install", "demo"]),
            ("pip3", ["install", "demo"]),
            ("python", ["-m", "pip", "install", "demo"]),
            ("python3.14", ["-I", "-m", "pip", "install", "demo"]),
            ("python", ["-W", "ignore", "-X", "dev", "-m", "pip", "install", "demo"]),
            ("py.exe", ["-3.14", "-m", "pip", "install", "demo"]),
            ("uvx", ["demo"]),
            (r"C:\tools\npx.cmd", ["--yes", "demo"]),
            ("/opt/bin/uvx", ["demo"]),
        ]
        for command, args in cases:
            with self.subTest(command=command):
                self.assertEqual(len(self._packages(self._scan(command, args))), 1)

    def test_exact_versions_do_not_produce_supply_chain_warnings(self) -> None:
        cases = [
            ("npx", ["-y", "@scope/demo@1.2.3"]),
            ("npx", ["--package", "demo@1.2.3", "serve"]),
            ("uvx", ["--from", "demo==1.2.3", "serve"]),
            ("uvx", ["demo@1.2.3"]),
            ("npm", ["install", "demo@1.2.3", "@scope/other@2.0.0-beta.1"]),
            ("python", ["-m", "pip", "install", "demo==1.2.3", "other===2.0.0"]),
            ("pip", ["install", "git+https://example.invalid/tool.git@" + "a" * 40]),
            ("pip", ["install", "demo @ git+https://example.invalid/tool.git@" + "a" * 40]),
            ("npm", ["install", "git+https://example.invalid/tool.git#" + "a" * 40]),
        ]
        for command, args in cases:
            with self.subTest(command=command, args=args):
                self.assertEqual(self._scan(command, args), [])

    def test_all_install_package_arguments_are_checked(self) -> None:
        cases = [
            ("npm", ["install", "first@1.2.3", "second", "third@latest"], [2, 3]),
            ("pip", ["install", "first==1.2.3", "second", "third>=2"], [2, 3]),
            ("npx", ["--package", "first", "-p", "second@latest", "serve"], [1, 3]),
            ("uvx", ["--from", "first", "--with", "second", "serve"], [1, 3]),
        ]
        for command, args, indexes in cases:
            with self.subTest(command=command):
                packages = self._packages(self._scan(command, args))
                self.assertEqual(len(packages), len(indexes))
                for finding, index in zip(packages, indexes):
                    self.assertTrue(finding["location"].endswith(f".args[{index}]"))

    def test_option_values_are_not_mistaken_for_packages(self) -> None:
        cases = [
            ("npx", ["--registry", "https://mirror.invalid", "demo@1.2.3"]),
            ("npm", ["--registry", "https://mirror.invalid", "install", "-D", "demo@1.2.3"]),
            ("npm", ["install", "--workspace", "packages/app", "demo@1.2.3"]),
            ("pip", ["--isolated", "install", "--index-url", "https://mirror.invalid", "demo==1.2.3"]),
            ("pip", ["install", "--timeout=20", "demo==1.2.3"]),
            ("uvx", ["--python", "3.12", "--from", "demo==1.2.3", "serve"]),
        ]
        for command, args in cases:
            with self.subTest(command=command, args=args):
                self.assertEqual(self._scan(command, args), [])

    def test_server_arguments_are_not_parsed_as_installer_options(self) -> None:
        cases = [
            ("npx", ["demo@1.2.3", "--package=unrelated@latest"]),
            ("npx", ["--package", "demo@1.2.3", "serve", "-p", "unrelated"]),
            ("uvx", ["--from", "demo==1.2.3", "serve", "--with", "unrelated"]),
        ]
        for command, args in cases:
            with self.subTest(command=command):
                self.assertEqual(self._scan(command, args), [])

    def test_joining_argument_strings_cannot_create_an_installer(self) -> None:
        findings = self._scan("python", ["-m pip install demo"])
        self.assertEqual(self._packages(findings), [])
        self.assertEqual(findings[0]["rule"], "unresolved-mcp-command")
        self.assertEqual(self._scan("node", ["server.js", "--package", "demo"]), [])

    def test_unknown_options_and_external_requirements_are_unresolved(self) -> None:
        cases = [
            ("npx", ["--unrecognized", "demo"]),
            ("npx", ["--package"]),
            ("pip", ["install", "-r", "requirements.txt"]),
            ("pip", ["install", "--constraint=constraints.txt", "demo==1.2.3"]),
            ("uvx", ["--from"]),
        ]
        for command, args in cases:
            with self.subTest(command=command, args=args):
                findings = self._scan(command, args)
                self.assertTrue(any(item["rule"] == "unresolved-mcp-command" for item in findings))

    def test_malformed_arguments_have_a_review_finding(self) -> None:
        for command, args in (("npx", "demo"), ("npx", [True]), ("npx", None), (42, ["demo"])):
            with self.subTest(command=command, args=args):
                findings = self._scan(command, args)
                self.assertTrue(any(item["rule"] == "unresolved-mcp-command" for item in findings))

    def test_non_launch_objects_and_remote_servers_stay_clean(self) -> None:
        for data in (
            {"command": "npx", "args": ["demo"]},
            {"task": {"command": "npx", "args": ["demo"]}},
            {"mcpServers": {"remote": {"url": "https://example.invalid/mcp"}}},
            {"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}},
        ):
            with self.subTest(data=data):
                self.assertEqual(self._scan_text(json.dumps(data), ".json"), [])

    def test_messages_never_echo_package_credentials_or_other_argv_values(self) -> None:
        marker = "synthetic-private-value"
        args = ["install", f"https://user:{marker}@example.invalid/tool.whl?token={marker}"]
        findings = self._scan("pip", args)
        self.assertEqual(len(self._packages(findings)), 1)
        self.assertNotIn(marker, json.dumps(findings))
        self.assertNotIn(marker, json.dumps(build_sarif_report(findings)))

    def test_attached_package_flag_has_one_structured_finding(self) -> None:
        packages = self._packages(self._scan("npx", ["--package=demo@latest", "serve"]))
        self.assertEqual(len(packages), 1)
        self.assertTrue(packages[0]["location"].endswith(".args[0]"))

    def test_attached_short_options_and_option_terminators(self) -> None:
        cases = [
            ("npx", ["-pdemo@latest", "serve"], 0),
            ("npx", ["--", "demo"], 1),
            ("pip", ["install", "-ihttps://mirror.invalid", "demo"], 2),
            ("pip", ["install", "--", "demo"], 2),
        ]
        for command, args, index in cases:
            with self.subTest(command=command, args=args):
                packages = self._packages(self._scan(command, args))
                self.assertEqual(len(packages), 1)
                self.assertTrue(packages[0]["location"].endswith(f".args[{index}]"))

    def test_dynamic_versions_and_named_urls_are_not_treated_as_pins(self) -> None:
        cases = [
            ("pip", ["install", "demo==${VERSION}"]),
            ("pip", ["install", "demo==="]),
            ("pip", ["install", "demo @ https://example.invalid/tool@1.2.3"]),
            ("npm", ["install", "git+https://example.invalid/tool.git#main"]),
            ("uvx", ["--from", "demo==1.*", "serve"]),
        ]
        for command, args in cases:
            with self.subTest(command=command, args=args):
                self.assertEqual(len(self._packages(self._scan(command, args))), 1)

    def test_shell_and_inline_code_wrappers_require_review(self) -> None:
        cases = [
            ("cmd.exe", ["/c", "npx demo"]),
            ("bash", ["-c", "npx demo"]),
            ("env", ["npx", "demo"]),
            ("python", ["-c", "import os; os.system('pip install demo')"]),
            ("node", ["--eval", "require('child_process').execSync('npx demo')"]),
        ]
        for command, args in cases:
            with self.subTest(command=command):
                findings = self._scan(command, args)
                self.assertTrue(any(item["rule"] == "unresolved-mcp-command" for item in findings))

    def test_interpreter_inline_code_aliases_require_review_before_script(self) -> None:
        cases = [
            ("node", ["--eval=require(1)"]),
            ("node", ["-erequire(1)"]),
            ("node", ["--no-warnings", "--eval", "require(1)"]),
            ("node", ["--input-type", "module", "--eval", "import('demo')"]),
            ("node", ["--print=1"]),
            ("python", ["-cprint(1)"]),
            ("python", ["-bb", "-m", "pip", "install", "demo"]),
            ("python", ["-Icprint(1)"]),
        ]
        for command, args in cases:
            with self.subTest(command=command, args=args):
                findings = self._scan(command, args)
                self.assertTrue(any(item["rule"] == "unresolved-mcp-command" for item in findings))
        for command, args in (
            ("node", ["server.js", "--eval=literal"]),
            ("node", ["--no-warnings", "server.js", "-e", "literal"]),
            ("node", ["--", "server.js", "--eval=literal"]),
            ("python", ["server.py", "-cprint(1)"]),
            ("python", ["--help"]),
            ("python", ["-m", "http.server"]),
        ):
            with self.subTest(command=command, args=args):
                self.assertEqual(self._scan(command, args), [])

    def test_generic_servers_map_requires_a_launch_shape(self) -> None:
        content = json.dumps({"servers": {
            "web": {"host": "example.invalid", "port": 80},
            "demo": {"command": "npx", "args": ["demo"]},
        }})
        findings = self._scan_text(content, ".json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "unpinned-package")

    def test_missing_launch_arguments_and_malformed_containers_require_review(self) -> None:
        for data in (
            {"mcpServers": {"demo": {"command": "npx"}}},
            {"mcpServers": []},
            {"mcp_servers": {"demo": None}},
        ):
            with self.subTest(data=data):
                findings = self._scan_text(json.dumps(data), ".json")
                self.assertTrue(any(item["rule"] == "unresolved-mcp-command" for item in findings))

    def test_ordinary_structured_text_fields_keep_command_checks(self) -> None:
        for content, suffix in (
            (json.dumps({"notes": "Run npx demo", "mcpServers": {"demo": {"command": "npx", "args": ["demo@1.2.3"]}}}), ".json"),
            ('notes = "Run npx demo"\n[mcp_servers.demo]\ncommand = "npx"\nargs = ["demo@1.2.3"]\n', ".toml"),
        ):
            with self.subTest(suffix=suffix):
                packages = self._packages(self._scan_text(content, suffix))
                self.assertEqual(len(packages), 1)
                self.assertTrue(packages[0]["location"].endswith("$.notes"))
                self.assertNotIn("line", packages[0])

    def test_non_install_commands_do_not_require_package_pins(self) -> None:
        for command, args in (("npm", ["run", "serve"]), ("pip", ["list"]), ("npx", ["--version"]), ("uvx", ["--help"])):
            with self.subTest(command=command, args=args):
                self.assertEqual(self._scan(command, args), [])

    def test_launch_credentials_are_redacted_in_every_cli_format(self) -> None:
        marker = "synthetic-private-value"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text(json.dumps({"mcpServers": {"demo": {
                "command": "npx", "args": [f"--package=https://user:{marker}@example.invalid/tool.tgz?token={marker}", "serve"],
            }}}), encoding="utf-8")
            for report_format in ("human", "json", "sarif"):
                with self.subTest(report_format=report_format):
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        code = main(["scan", str(target), "--strict", "--format", report_format])
                    self.assertEqual(code, 1)
                    self.assertNotIn(marker, stream.getvalue())

    def test_cli_strict_mode_fails_and_sarif_preserves_argument_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.json"
            target.write_text(json.dumps({"mcpServers": {"demo": {"command": "npx", "args": ["demo"]}}}), encoding="utf-8")
            for report_format in ("human", "json", "sarif"):
                with self.subTest(report_format=report_format):
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        code = main(["scan", str(target), "--strict", "--format", report_format])
                    self.assertEqual(code, 1)
                    rendered = stream.getvalue()
                    self.assertIn("unpinned-package", rendered)
                    if report_format == "sarif":
                        location = json.loads(rendered)["runs"][0]["results"][0]["locations"][0]
                        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"], target.as_posix())
                        self.assertEqual(location["logicalLocations"][0]["fullyQualifiedName"], "$.mcpServers.demo.args[0]")


if __name__ == "__main__":
    unittest.main()
