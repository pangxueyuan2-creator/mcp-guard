"""Policy loading for MCP Guard.

The policy format intentionally stays small and stdlib-only so the scanner can be
used in bootstrap and CI environments without pulling additional dependencies.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Pattern

DEFAULT_FORBIDDEN_TOOLS = {
    "exec",
    "shell",
    "run_command",
    "bash",
    "powershell",
    "system",
    "subprocess",
    "os.system",
}

DEFAULT_EXTENSIONS = {
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".md",
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".sh",
    ".ps1",
}

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

DEFAULT_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "Possible OpenAI-style API key"),
    (r"gh[pousr]_[a-zA-Z0-9]{20,}", "Possible GitHub token"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key material"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Possible Slack token"),
    (r"AKIA[0-9A-Z]{16}", "Possible AWS access key ID"),
]


@dataclass(slots=True)
class Policy:
    forbidden_tools: set[str] = field(default_factory=lambda: set(DEFAULT_FORBIDDEN_TOOLS))
    allowed_tools: set[str] = field(default_factory=set)
    max_severity: str = "warning"
    allowed_hosts: set[str] = field(default_factory=set)
    scan_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    excluded_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_DIRS))
    max_file_bytes: int = 2_000_000
    secret_patterns: list[tuple[Pattern[str], str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.secret_patterns:
            self.secret_patterns = [
                (re.compile(pattern), description)
                for pattern, description in DEFAULT_SECRET_PATTERNS
            ]

    @property
    def effective_forbidden_tools(self) -> set[str]:
        return {tool.lower() for tool in self.forbidden_tools - self.allowed_tools}


def load_policy(path: Path | None) -> Policy:
    """Load a TOML policy, falling back to safe built-in defaults."""
    policy = Policy()
    if path is None:
        return policy

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Policy file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML policy {path}: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"Could not read policy {path}: {exc}") from exc

    policy_section = data.get("policy", {})
    scope_section = data.get("scope", {})
    secrets_section = data.get("secrets", {})

    if "forbidden_tools" in policy_section:
        policy.forbidden_tools = _string_set(policy_section["forbidden_tools"], "policy.forbidden_tools")
    if "allowed_tools" in policy_section:
        policy.allowed_tools = _string_set(policy_section["allowed_tools"], "policy.allowed_tools")
    if "max_severity" in policy_section:
        severity = str(policy_section["max_severity"]).lower()
        if severity not in {"info", "warning", "error"}:
            raise ValueError("policy.max_severity must be one of: info, warning, error")
        policy.max_severity = severity
    if "max_file_bytes" in policy_section:
        value = int(policy_section["max_file_bytes"])
        if value < 1:
            raise ValueError("policy.max_file_bytes must be positive")
        policy.max_file_bytes = value

    if "allowed_hosts" in scope_section:
        policy.allowed_hosts = {host.lower() for host in _string_set(scope_section["allowed_hosts"], "scope.allowed_hosts")}
    if "exclude_dirs" in scope_section:
        policy.excluded_dirs |= _string_set(scope_section["exclude_dirs"], "scope.exclude_dirs")
    if "extensions" in scope_section:
        extensions = _string_set(scope_section["extensions"], "scope.extensions")
        policy.scan_extensions = {ext if ext.startswith(".") else f".{ext}" for ext in extensions}

    custom_patterns = secrets_section.get("patterns")
    if custom_patterns is not None:
        if not isinstance(custom_patterns, list) or not all(isinstance(item, str) for item in custom_patterns):
            raise ValueError("secrets.patterns must be an array of regular-expression strings")
        try:
            policy.secret_patterns.extend(
                (re.compile(pattern), "Custom policy secret pattern") for pattern in custom_patterns
            )
        except re.error as exc:
            raise ValueError(f"Invalid regular expression in secrets.patterns: {exc}") from exc

    return policy


def _string_set(value: object, field_name: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be an array of strings")
    return {item.strip() for item in value if item.strip()}
