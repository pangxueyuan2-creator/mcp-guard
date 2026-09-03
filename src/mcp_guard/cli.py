"""Command-line interface for MCP Guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp_guard import __version__
from mcp_guard.models import SEVERITY_RANK
from mcp_guard.policy import PolicyError
from mcp_guard.reporting import should_fail, summarize, to_sarif
from mcp_guard.scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Local-first security auditor for MCP servers and AI agent skills",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan an MCP config, skill package or directory")
    scan_p.add_argument("path", type=Path, help="File or directory to scan")
    scan_p.add_argument("--policy", type=Path, default=None, help="Optional TOML policy file")
    scan_p.add_argument(
        "--format",
        choices=("human", "json", "sarif"),
        default="human",
        help="Report format (default: human)",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=("info", "warning", "error", "never"),
        default="error",
        help="Lowest severity that produces exit code 1 (default: error)",
    )
    scan_p.add_argument("--strict", action="store_true", help="Compatibility alias for --fail-on warning")
    scan_p.add_argument("--json", dest="legacy_json", action="store_true", help=argparse.SUPPRESS)

    init_p = sub.add_parser("init", help="Write a starter policy file")
    init_p.add_argument("--path", type=Path, default=Path(".mcp-guard.toml"), help="Policy path to create")
    init_p.add_argument("--force", action="store_true", help="Overwrite an existing policy file")

    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "scan":
        return _cmd_scan(args)
    return 2


def _cmd_init(args: argparse.Namespace) -> int:
    target: Path = args.path
    if target.exists() and not args.force:
        print(f"{target} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    content = '''# MCP Guard policy
# Keep this file in version control so local scans and CI use the same rules.

[policy]
# Tool/capability names that should fail a scan when declared.
forbidden_tools = [
  "exec",
  "shell",
  "run_command",
  "bash",
  "powershell",
  "cmd",
]

# Directories pruned during recursive scans.
ignored_dirs = [
  ".git",
  ".venv",
  "venv",
  "node_modules",
  "build",
  "dist",
  "__pycache__",
]

# Text-like files considered by recursive scans.
extensions = [".json", ".jsonc", ".toml", ".yaml", ".yml", ".md", ".py", ".js", ".ts", ".jsx", ".tsx"]

# Large files are skipped and reported as coverage warnings.
max_file_size_bytes = 2097152

[secrets]
# Replacing `patterns` disables the built-in secret patterns. Prefer [[secrets.rules]]
# when you want a fully custom ruleset with descriptions.
# patterns = ["your-regex-here"]
'''
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(f"Could not write {target}: {exc}", file=sys.stderr)
        return 2

    print(f"Wrote starter policy → {target}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    path: Path = args.path
    if not path.exists():
        print(f"Path not found: {path}", file=sys.stderr)
        return 2

    report_format = "json" if args.legacy_json else args.format
    fail_on = "warning" if args.strict else args.fail_on

    try:
        findings = scan_path(path, policy_path=args.policy)
    except PolicyError as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2

    if report_format == "json":
        print(
            json.dumps(
                {
                    "path": str(path),
                    "policy": str(args.policy) if args.policy else None,
                    "summary": summarize(findings),
                    "findings": findings,
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif report_format == "sarif":
        print(json.dumps(to_sarif(findings, path), indent=2, sort_keys=True))
    else:
        _print_human(findings, path)

    return 1 if should_fail(findings, fail_on) else 0


def _print_human(findings: list[dict[str, Any]], path: Path) -> None:
    summary = summarize(findings)
    if not findings:
        print(f"PASS  {path}")
        print("  No issues found.")
        return

    status = "FAIL" if summary["error"] else "WARN" if summary["warning"] else "PASS"
    print(f"{status}  {path}")
    print(
        f"  {summary['error']} error(s), {summary['warning']} warning(s), "
        f"{summary['info']} info finding(s)"
    )
    print()

    ordered = sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity", "info")), 0),
            str(item.get("location", "")),
            int(item.get("line") or 0),
            str(item.get("rule", "")),
        ),
    )
    for finding in ordered:
        severity = str(finding.get("severity", "info")).upper()
        print(f"  [{severity}] {finding.get('rule', 'unknown')}")
        print(f"         {finding.get('message', '')}")
        location = finding.get("location")
        line = finding.get("line")
        if location:
            suffix = f":{line}" if isinstance(line, int) and line > 0 else ""
            print(f"         at {location}{suffix}")
        if finding.get("hint"):
            print(f"         fix: {finding['hint']}")
        print()
