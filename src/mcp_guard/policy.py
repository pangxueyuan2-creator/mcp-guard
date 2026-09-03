"""Policy loading and validation for MCP Guard."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

DEFAULT_FORBIDDEN_TOOLS = frozenset(
    {
        "bash",
        "cmd",
        "exec",
        "os.system",
        "powershell",
        "run_command",
        "shell",
        "subprocess",
        "system",
    }
)

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)

DEFAULT_EXTENSIONS = frozenset(
    {
        ".json",
        ".jsonc",
        ".md",
        ".py",
        ".toml",
        ".ts",
        ".tsx",
        ".yaml",
        ".yml",
        ".js",
        ".jsx",
    }
)

# Patterns intentionally match only well-known high-confidence credential shapes.
DEFAULT_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"sk-[A-Za-z0-9_-]{20,}", "Possible OpenAI-style API key"),
    (r"gh[pousr]_[A-Za-z0-9]{30,}", "Possible GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{30,}", "Possible GitHub fine-grained token"),
    (r"xox[baprs]-[0-9A-Za-z-]{10,}", "Possible Slack token"),
    (r"AKIA[0-9A-Z]{16}", "Possible AWS access key ID"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key material"),
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    pattern: str
    description: str

    def compile(self) -> re.Pattern[str]:
        try:
            return re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"Invalid secret regex {self.pattern!r}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class Policy:
    """Runtime policy controlling what the scanner considers risky."""

    forbidden_tools: frozenset[str] = DEFAULT_FORBIDDEN_TOOLS
    ignored_dirs: frozenset[str] = DEFAULT_IGNORED_DIRS
    extensions: frozenset[str] = DEFAULT_EXTENSIONS
    max_file_size_bytes: int = 2 * 1024 * 1024
    secret_rules: tuple[SecretRule, ...] = field(
        default_factory=lambda: tuple(SecretRule(pattern, label) for pattern, label in DEFAULT_SECRET_PATTERNS)
    )

    def with_max_file_size(self, value: int) -> "Policy":
        if value <= 0:
            raise ValueError("max_file_size_bytes must be greater than zero")
        return replace(self, max_file_size_bytes=value)


class PolicyError(ValueError):
    """Raised when a policy file is invalid or unsafe to interpret."""


def load_policy(path: Path | None) -> Policy:
    """Load a TOML policy, or return secure defaults when no file is given."""
    base = Policy()
    if path is None:
        return base

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"Policy file not found: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise PolicyError(f"Could not read policy file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"Invalid TOML in {path}: {exc}") from exc

    policy_table = raw.get("policy", {})
    if not isinstance(policy_table, dict):
        raise PolicyError("[policy] must be a TOML table")

    forbidden_tools = _string_set(
        policy_table.get("forbidden_tools", base.forbidden_tools),
        "policy.forbidden_tools",
        normalize=True,
    )
    ignored_dirs = _string_set(
        policy_table.get("ignored_dirs", base.ignored_dirs),
        "policy.ignored_dirs",
    )
    extensions = _string_set(
        policy_table.get("extensions", base.extensions),
        "policy.extensions",
    )
    extensions = frozenset(_normalize_extension(value) for value in extensions)

    max_file_size_bytes = policy_table.get("max_file_size_bytes", base.max_file_size_bytes)
    if not isinstance(max_file_size_bytes, int) or isinstance(max_file_size_bytes, bool) or max_file_size_bytes <= 0:
        raise PolicyError("policy.max_file_size_bytes must be a positive integer")

    secret_rules = list(base.secret_rules)
    secrets_table = raw.get("secrets", {})
    if not isinstance(secrets_table, dict):
        raise PolicyError("[secrets] must be a TOML table")

    # Backward-compatible format: patterns = ["regex", ...]
    custom_patterns = secrets_table.get("patterns")
    if custom_patterns is not None:
        patterns = _string_list(custom_patterns, "secrets.patterns")
        secret_rules = [SecretRule(pattern, "Custom policy secret pattern") for pattern in patterns]

    # Richer format: [[secrets.rules]] pattern = "..." description = "..."
    rich_rules = secrets_table.get("rules")
    if rich_rules is not None:
        if not isinstance(rich_rules, list) or not all(isinstance(item, dict) for item in rich_rules):
            raise PolicyError("secrets.rules must be an array of tables")
        parsed: list[SecretRule] = []
        for index, item in enumerate(rich_rules):
            pattern = item.get("pattern")
            description = item.get("description", "Custom policy secret pattern")
            if not isinstance(pattern, str) or not pattern:
                raise PolicyError(f"secrets.rules[{index}].pattern must be a non-empty string")
            if not isinstance(description, str) or not description:
                raise PolicyError(f"secrets.rules[{index}].description must be a non-empty string")
            parsed.append(SecretRule(pattern, description))
        secret_rules = parsed

    for rule in secret_rules:
        try:
            rule.compile()
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc

    return Policy(
        forbidden_tools=forbidden_tools,
        ignored_dirs=ignored_dirs,
        extensions=extensions,
        max_file_size_bytes=max_file_size_bytes,
        secret_rules=tuple(secret_rules),
    )


def _string_set(value: object, name: str, *, normalize: bool = False) -> frozenset[str]:
    values = _string_list(value, name)
    if normalize:
        values = [item.lower() for item in values]
    return frozenset(values)


def _string_list(value: object, name: str) -> list[str]:
    if isinstance(value, (tuple, frozenset, set)):
        value = list(value)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PolicyError(f"{name} must be an array of non-empty strings")
    return list(value)


def _normalize_extension(value: str) -> str:
    return value if value.startswith(".") else f".{value}"
