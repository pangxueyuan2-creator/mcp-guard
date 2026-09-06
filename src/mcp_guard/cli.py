"""Command-line interface for MCP Guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mcp_guard import __version__
from mcp_guard.policy import load_policy
from mcp_guard.reporting import build_json_report, build_sarif_report, should_fail
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
    scan_p.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    scan_p.add_argument("--output", type=Path, default=None, help="Write report to a file")
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

    content = '''# MCP Guard policy
# Runtime remains stdlib-only; this file uses Python's built-in TOML parser.

[policy]
# A finding above this severity fails the scan: info | warning | error
# warning means errors fail, while warnings are allowed.
max_severity = "warning"
max_file_bytes = 2000000

# Tool names that are denied unless explicitly placed in allowed_tools.
forbidden_tools = [
    "exec",
    "shell",
    "run_command",
    "bash",
    "powershell",
    "system",
    "subprocess",
    "os.system",
]
allowed_tools = []

[scope]
# Leave empty to permit any network host. When populated, subdomains are allowed.
allowed_hosts = []
exclude_dirs = ["vendor"]
extensions = ["json", "toml", "yaml", "yml", "md", "py", "js", "ts", "mjs", "cjs", "sh", "ps1"]

[secrets]
# Additional regular expressions. Built-in secret rules remain enabled.
patterns = []
'''
    target.write_text(content, encoding="utf-8")
    print(f"Wrote starter policy → {target}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    path: Path = args.path
    if not path.exists():
        print(f"Path not found: {path}", file=sys.stderr)
        return 2

    try:
        policy = load_policy(args.policy)
        findings = scan_path(path, policy_path=args.policy)
    except ValueError as exc:
        print(f"Policy error: {exc}", file=sys.stderr)
        return 2

    report_format = "json" if args.json else args.format

    if report_format == "json":
        rendered = json.dumps(build_json_report(path, findings), indent=2)
    elif report_format == "sarif":
        rendered = json.dumps(build_sarif_report(findings), indent=2)
    else:
        rendered = _render_human(findings, path)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
        print(f"Wrote {report_format} report → {args.output}")
    else:
        print(rendered)

    max_allowed = "info" if args.strict else policy.max_severity
    return 1 if should_fail(findings, max_allowed) else 0


def _render_human(findings: list[dict[str, Any]], path: Path) -> str:
    if not findings:
        return f"PASS  {path}\n  No issues found."

    errors = [f for f in findings if f.get("severity") == "error"]
    warnings = [f for f in findings if f.get("severity") == "warning"]

    status = "FAIL" if errors else "WARN" if warnings else "PASS"
    lines = [f"{status}  {path}", ""]

    for finding in findings:
        severity = str(finding.get("severity", "info")).upper()
        lines.append(f"  [{severity}] {finding.get('rule', 'unknown')}")
        lines.append(f"         {finding.get('message', '')}")
        if finding.get("location"):
            location = str(finding["location"])
            if finding.get("line"):
                location = f"{location}:{finding['line']}"
            lines.append(f"         at {location}")
        lines.append("")

    lines.append(
        f"Summary: {len(errors)} error(s), {len(warnings)} warning(s), "
        f"{len(findings) - len(errors) - len(warnings)} info finding(s)"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
