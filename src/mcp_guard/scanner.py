"""Core scanning logic for MCP Guard."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern


@dataclass(frozen=True)
class ScanPolicy:
    """Resolved scanner policy."""

    forbidden_tools: frozenset[str]
    secret_patterns: tuple[tuple[Pattern[str], str], ...]


DEFAULT_FORBIDDEN_TOOLS = frozenset(
    {
        "exec",
        "shell",
        "run_command",
        "bash",
        "powershell",
        "system",
        "subprocess",
        "os.system",
    }
)

DEFAULT_SECRET_PATTERNS: tuple[tuple[Pattern[str], str], ...] = (
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "Possible OpenAI-style API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{30,}"), "Possible GitHub personal access token"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"), "Private key material"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"), "Possible Slack token"),
)

DEFAULT_POLICY = ScanPolicy(
    forbidden_tools=DEFAULT_FORBIDDEN_TOOLS,
    secret_patterns=DEFAULT_SECRET_PATTERNS,
)


def scan_path(path: Path, policy_path: Path | None = None) -> list[dict[str, Any]]:
    """Scan a file or directory and return a list of findings."""
    policy, policy_findings = _load_policy(policy_path)
    findings: list[dict[str, Any]] = list(policy_findings)

    if path.is_file():
        findings.extend(_scan_file(path, policy))
    elif path.is_dir():
        for p in path.rglob("*"):
            if p.is_file() and p.suffix in {".json", ".toml", ".yaml", ".yml", ".md", ".py", ".js", ".ts"}:
                findings.extend(_scan_file(p, policy))
    else:
        findings.append(
            {
                "severity": "error",
                "rule": "path-not-found",
                "message": f"Path does not exist or is not accessible: {path}",
                "location": str(path),
            }
        )

    return findings


def _load_policy(policy_path: Path | None) -> tuple[ScanPolicy, list[dict[str, Any]]]:
    """Load an optional TOML policy while falling back to safe built-in defaults."""
    if policy_path is None:
        return DEFAULT_POLICY, []

    if not policy_path.is_file():
        return DEFAULT_POLICY, [
            {
                "severity": "error",
                "rule": "policy-not-found",
                "message": f"Policy file does not exist or is not accessible: {policy_path}",
                "location": str(policy_path),
            }
        ]

    try:
        data = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return DEFAULT_POLICY, [
            {
                "severity": "error",
                "rule": "policy-invalid",
                "message": f"Could not load policy: {exc}",
                "location": str(policy_path),
            }
        ]

    findings: list[dict[str, Any]] = []
    policy_data = data.get("policy", {})
    secrets_data = data.get("secrets", {})

    forbidden_tools = set(DEFAULT_FORBIDDEN_TOOLS)
    raw_tools = policy_data.get("forbidden_tools")
    if raw_tools is not None:
        if isinstance(raw_tools, list) and all(isinstance(item, str) for item in raw_tools):
            forbidden_tools = {item.strip().lower() for item in raw_tools if item.strip()}
        else:
            findings.append(
                {
                    "severity": "error",
                    "rule": "policy-invalid",
                    "message": "policy.forbidden_tools must be a list of strings",
                    "location": str(policy_path),
                }
            )

    secret_patterns = list(DEFAULT_SECRET_PATTERNS)
    raw_patterns = secrets_data.get("patterns")
    if raw_patterns is not None:
        if isinstance(raw_patterns, list) and all(isinstance(item, str) for item in raw_patterns):
            secret_patterns = []
            for raw_pattern in raw_patterns:
                try:
                    secret_patterns.append(
                        (re.compile(raw_pattern), f"Custom secret pattern matched: {raw_pattern}")
                    )
                except re.error as exc:
                    findings.append(
                        {
                            "severity": "error",
                            "rule": "policy-invalid-regex",
                            "message": f"Invalid secret regex {raw_pattern!r}: {exc}",
                            "location": str(policy_path),
                        }
                    )
        else:
            findings.append(
                {
                    "severity": "error",
                    "rule": "policy-invalid",
                    "message": "secrets.patterns must be a list of regex strings",
                    "location": str(policy_path),
                }
            )

    return (
        ScanPolicy(
            forbidden_tools=frozenset(forbidden_tools),
            secret_patterns=tuple(secret_patterns),
        ),
        findings,
    )


def _scan_file(path: Path, policy: ScanPolicy) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        findings.append(
            {
                "severity": "warning",
                "rule": "read-error",
                "message": f"Could not read file: {exc}",
                "location": str(path),
            }
        )
        return findings

    # Secret scanning
    for pattern, description in policy.secret_patterns:
        if pattern.search(text):
            findings.append(
                {
                    "severity": "error",
                    "rule": "secret-detected",
                    "message": description,
                    "location": str(path),
                }
            )

    # JSON-specific checks (MCP configs often live here)
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            findings.extend(_scan_json(data, path, policy.forbidden_tools))
        except json.JSONDecodeError:
            pass  # not every .json is a config we care about

    # Simple keyword heuristics for tool definitions
    lower = text.lower()
    for tool in policy.forbidden_tools:
        if f'"{tool}"' in lower or f"'{tool}'" in lower or f'name\\": \\"{tool}\\"' in lower:
            findings.append(
                {
                    "severity": "error",
                    "rule": "forbidden-tool",
                    "message": f"Potentially dangerous tool name detected: {tool}",
                    "location": str(path),
                }
            )

    return findings


def _scan_json(
    data: Any,
    path: Path,
    forbidden_tools: frozenset[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if not isinstance(data, dict):
        return findings

    # Look for tools / capabilities lists common in MCP and agent skill formats
    for key in ("tools", "capabilities", "functions", "allowed_tools"):
        if key in data and isinstance(data[key], list):
            for item in data[key]:
                name = None
                if isinstance(item, str):
                    name = item
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("tool") or item.get("id")
                if name and str(name).lower() in forbidden_tools:
                    findings.append(
                        {
                            "severity": "error",
                            "rule": "forbidden-tool",
                            "message": f"Dangerous tool declared: {name}",
                            "location": f"{path}:{key}",
                        }
                    )

    return findings
