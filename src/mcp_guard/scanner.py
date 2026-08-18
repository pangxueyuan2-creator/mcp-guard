"""Core scanning logic for MCP Guard."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Minimal built-in rules. Keep this file readable and dependency-free.

FORBIDDEN_TOOLS = {
    "exec", "shell", "run_command", "bash", "powershell",
    "system", "subprocess", "os.system",
}

SECRET_PATTERNS = [
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "Possible OpenAI-style API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{30,}"), "Possible GitHub personal access token"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"), "Private key material"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"), "Possible Slack token"),
]


def scan_path(path: Path, policy_path: Path | None = None) -> list[dict[str, Any]]:
    """Scan a file or directory and return a list of findings."""
    findings: list[dict[str, Any]] = []

    if path.is_file():
        findings.extend(_scan_file(path))
    elif path.is_dir():
        for p in path.rglob("*"):
            if p.is_file() and p.suffix in {".json", ".toml", ".yaml", ".yml", ".md", ".py", ".js", ".ts"}:
                findings.extend(_scan_file(p))
    else:
        findings.append({
            "severity": "error",
            "rule": "path-not-found",
            "message": f"Path does not exist or is not accessible: {path}",
            "location": str(path),
        })

    return findings


def _scan_file(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        findings.append({
            "severity": "warning",
            "rule": "read-error",
            "message": f"Could not read file: {exc}",
            "location": str(path),
        })
        return findings

    # Secret scanning
    for pattern, description in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append({
                "severity": "error",
                "rule": "secret-detected",
                "message": description,
                "location": str(path),
            })

    # JSON-specific checks (MCP configs often live here)
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            findings.extend(_scan_json(data, path))
        except json.JSONDecodeError:
            pass  # not every .json is a config we care about

    # Simple keyword heuristics for tool definitions
    lower = text.lower()
    for tool in FORBIDDEN_TOOLS:
        if f'"{tool}"' in lower or f"'{tool}'" in lower or f"name\": \"{tool}\"" in lower:
            findings.append({
                "severity": "error",
                "rule": "forbidden-tool",
                "message": f"Potentially dangerous tool name detected: {tool}",
                "location": str(path),
            })

    return findings


def _scan_json(data: Any, path: Path) -> list[dict[str, Any]]:
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
                if name and str(name).lower() in FORBIDDEN_TOOLS:
                    findings.append({
                        "severity": "error",
                        "rule": "forbidden-tool",
                        "message": f"Dangerous tool declared: {name}",
                        "location": f"{path}:{key}",
                    })

    return findings
