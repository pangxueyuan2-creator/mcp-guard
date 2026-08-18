"""Command-line interface for MCP Guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp_guard import __version__
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
    scan_p.add_argument("--policy", type=Path, default=None, help="Optional policy file")
    scan_p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    scan_p.add_argument("--strict", action="store_true", help="Treat warnings as failures")

    init_p = sub.add_parser("init", help="Write a starter policy file")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing file")

    args = parser.parse_args(argv)

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "scan":
        return _cmd_scan(args)

    return 2


def _cmd_init(args: argparse.Namespace) -> int:
    target = Path(".mcp-guard.toml")
    if target.exists() and not args.force:
        print(f"{target} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    content = '''# MCP Guard policy (starter)
# Edit this file to match your risk tolerance.

[policy]
# Fail the scan if any of these tool names appear
forbidden_tools = ["exec", "shell", "run_command", "bash", "powershell"]

# Maximum severity that is still allowed (info | warning | error)
max_severity = "warning"

[secrets]
# Patterns that should never appear in plain text
patterns = [
    "sk-[a-zA-Z0-9]{20,}",
    "ghp_[a-zA-Z0-9]{30,}",
    "-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
]
'''
    target.write_text(content, encoding="utf-8")
    print(f"Wrote starter policy → {target}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    path: Path = args.path
    if not path.exists():
        print(f"Path not found: {path}", file=sys.stderr)
        return 2

    findings = scan_path(path, policy_path=args.policy)

    if args.json:
        print(json.dumps({"findings": findings, "path": str(path)}, indent=2))
    else:
        _print_human(findings, path)

    has_error = any(f.get("severity") == "error" for f in findings)
    has_warning = any(f.get("severity") == "warning" for f in findings)

    if has_error or (args.strict and has_warning):
        return 1
    return 0


def _print_human(findings: list[dict[str, Any]], path: Path) -> None:
    if not findings:
        print(f"PASS  {path}")
        print("  No issues found.")
        return

    errors = [f for f in findings if f.get("severity") == "error"]
    warnings = [f for f in findings if f.get("severity") == "warning"]
    infos = [f for f in findings if f.get("severity") == "info"]

    status = "FAIL" if errors else "WARN" if warnings else "PASS"
    print(f"{status}  {path}")
    print()

    for f in findings:
        sev = f.get("severity", "info").upper()
        print(f"  [{sev}] {f.get('rule', 'unknown')}")
        print(f"         {f.get('message', '')}")
        if f.get("location"):
            print(f"         at {f['location']}")
        print()
