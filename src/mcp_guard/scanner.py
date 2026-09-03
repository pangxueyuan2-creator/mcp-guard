"""Core scanning engine for MCP Guard."""

from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from mcp_guard.models import Finding
from mcp_guard.policy import Policy, load_policy

SENSITIVE_ENV_RE = re.compile(r"(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY|CREDENTIAL)", re.I)
PLACEHOLDER_RE = re.compile(r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%|<[^>]+>|\{\{[^}]+\}\})$")
SHELL_COMMANDS = frozenset({"bash", "sh", "zsh", "fish", "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe"})
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx", "yarn", "uvx", "pipx"})
TOOL_LIST_KEYS = frozenset({"tools", "capabilities", "functions", "allowed_tools", "allowed-tools"})
URL_KEYS = frozenset({"url", "endpoint", "base_url", "baseurl", "server_url", "serverurl"})


def scan_path(path: Path, policy_path: Path | None = None) -> list[dict[str, Any]]:
    """Scan a file or directory and return JSON-serializable findings.

    This function keeps the original public API while the internal engine uses
    structured :class:`Finding` objects.
    """
    policy = load_policy(policy_path)
    findings = scan_findings(path, policy)
    return [finding.to_dict() for finding in findings]


def scan_findings(path: Path, policy: Policy | None = None) -> list[Finding]:
    """Scan ``path`` using ``policy`` and return de-duplicated findings."""
    policy = policy or Policy()

    if not path.exists():
        return [
            Finding(
                severity="error",
                rule="path-not-found",
                message=f"Path does not exist or is not accessible: {path}",
                location=str(path),
                hint="Check the path and filesystem permissions.",
            )
        ]

    candidates = [path] if path.is_file() else list(_iter_files(path, policy))
    findings: list[Finding] = []
    for candidate in candidates:
        findings.extend(_scan_file(candidate, policy))

    return _dedupe(findings)


def _iter_files(root: Path, policy: Policy) -> Iterable[Path]:
    """Walk a tree without descending into ignored or symlinked directories."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in policy.ignored_dirs and not (Path(dirpath) / name).is_symlink()
        ]
        base = Path(dirpath)
        for filename in filenames:
            path = base / filename
            if path.is_symlink():
                continue
            if path.suffix.lower() in policy.extensions:
                yield path


def _scan_file(path: Path, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []

    try:
        size = path.stat().st_size
    except OSError as exc:
        return [
            Finding(
                severity="warning",
                rule="stat-error",
                message=f"Could not inspect file metadata: {exc}",
                location=str(path),
            )
        ]

    if size > policy.max_file_size_bytes:
        return [
            Finding(
                severity="warning",
                rule="file-too-large",
                message=f"Skipped file larger than policy limit ({size} bytes > {policy.max_file_size_bytes} bytes)",
                location=str(path),
                hint="Raise policy.max_file_size_bytes if this file should be scanned.",
            )
        ]

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            Finding(
                severity="warning",
                rule="read-error",
                message=f"Could not read file: {exc}",
                location=str(path),
            )
        ]

    findings.extend(_scan_secrets(text, path, policy))

    suffix = path.suffix.lower()
    if suffix == ".json":
        findings.extend(_scan_json_text(text, path, policy))
    elif suffix == ".toml":
        findings.extend(_scan_toml_text(text, path, policy))
    elif suffix in {".yaml", ".yml", ".md"}:
        findings.extend(_scan_lightweight_manifest(text, path, policy))

    return findings


def _scan_secrets(text: str, path: Path, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for rule in policy.secret_rules:
        pattern = rule.compile()
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    severity="error",
                    rule="secret-detected",
                    message=rule.description,
                    location=str(path),
                    line=_line_number(text, match.start()),
                    hint="Remove the credential from source and rotate it if it was real.",
                )
            )
    return findings


def _scan_json_text(text: str, path: Path, policy: Policy) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Invalid JSON is only security-relevant when the file looks like an MCP config.
        if _looks_like_mcp_manifest(text, path):
            return [
                Finding(
                    severity="warning",
                    rule="invalid-json",
                    message=f"MCP-like JSON could not be parsed: {exc.msg}",
                    location=str(path),
                    line=exc.lineno,
                    hint="Fix the JSON so semantic security checks can run.",
                )
            ]
        return []
    return _scan_structure(data, path, policy, text=text)


def _scan_toml_text(text: str, path: Path, policy: Policy) -> list[Finding]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    return _scan_structure(data, path, policy, text=text)


def _scan_structure(data: Any, path: Path, policy: Policy, *, text: str) -> list[Finding]:
    findings: list[Finding] = []

    def visit(value: Any, trail: tuple[str, ...]) -> None:
        if isinstance(value, dict):
            lowered = {str(key).lower(): item for key, item in value.items()}

            for key, item in value.items():
                key_text = str(key)
                key_lower = key_text.lower()
                current = trail + (key_text,)

                if key_lower in TOOL_LIST_KEYS:
                    findings.extend(_check_tool_declarations(item, path, policy, text, current))

                if key_lower == "command" and isinstance(item, str):
                    findings.extend(_check_command(item, value, path, text, current))

                if key_lower == "env" and isinstance(item, dict):
                    findings.extend(_check_env(item, path, text, current))

                if key_lower in URL_KEYS and isinstance(item, str):
                    finding = _check_url(item, path, text, current)
                    if finding:
                        findings.append(finding)

                visit(item, current)

            # Some manifests express a tool as {"name": "shell"} outside a list.
            name = lowered.get("name") or lowered.get("tool") or lowered.get("id")
            if isinstance(name, str) and name.lower() in policy.forbidden_tools:
                findings.append(
                    Finding(
                        severity="error",
                        rule="forbidden-tool",
                        message=f"Dangerous tool declared: {name}",
                        location=_trail_location(path, trail),
                        line=_find_value_line(text, name),
                        hint="Remove the tool or explicitly allow it in a reviewed policy.",
                    )
                )

        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, trail + (str(index),))

    visit(data, ())
    return findings


def _check_tool_declarations(
    value: Any,
    path: Path,
    policy: Policy,
    text: str,
    trail: tuple[str, ...],
) -> list[Finding]:
    if not isinstance(value, list):
        return []

    findings: list[Finding] = []
    for item in value:
        name: str | None = None
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            candidate = item.get("name") or item.get("tool") or item.get("id")
            if candidate is not None:
                name = str(candidate)
        if name and name.lower() in policy.forbidden_tools:
            findings.append(
                Finding(
                    severity="error",
                    rule="forbidden-tool",
                    message=f"Dangerous tool declared: {name}",
                    location=_trail_location(path, trail),
                    line=_find_value_line(text, name),
                    hint="Remove the capability or narrow it behind an explicit policy boundary.",
                )
            )
    return findings


def _check_command(
    command: str,
    container: dict[Any, Any],
    path: Path,
    text: str,
    trail: tuple[str, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    executable = Path(command).name.lower()

    if executable in SHELL_COMMANDS:
        findings.append(
            Finding(
                severity="error",
                rule="shell-command",
                message=f"MCP server launches through a general-purpose shell: {command}",
                location=_trail_location(path, trail),
                line=_find_value_line(text, command),
                hint="Launch a fixed executable directly and avoid shell interpretation.",
            )
        )

    if executable in PACKAGE_RUNNERS:
        args = container.get("args", [])
        if isinstance(args, list):
            package = _first_package_arg(executable, args)
            if package and not _is_pinned_package(package):
                findings.append(
                    Finding(
                        severity="warning",
                        rule="unpinned-package",
                        message=f"Runtime package runner uses an unpinned package: {package}",
                        location=_trail_location(path, trail),
                        line=_find_value_line(text, package),
                        hint="Pin an exact package version or immutable source revision.",
                    )
                )
    return findings


def _check_env(env: dict[Any, Any], path: Path, text: str, trail: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in env.items():
        key_text = str(key)
        if not SENSITIVE_ENV_RE.search(key_text) or not isinstance(value, str):
            continue
        stripped = value.strip()
        if not stripped or PLACEHOLDER_RE.match(stripped):
            continue
        findings.append(
            Finding(
                severity="warning",
                rule="inline-sensitive-env",
                message=f"Sensitive environment variable appears to contain an inline literal: {key_text}",
                location=_trail_location(path, trail + (key_text,)),
                line=_find_key_line(text, key_text),
                hint="Reference the value from the process environment or a secret manager instead.",
            )
        )
    return findings


def _check_url(url: str, path: Path, text: str, trail: tuple[str, ...]) -> Finding | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme.lower() != "http":
        return None
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return None
    return Finding(
        severity="warning",
        rule="plaintext-remote-url",
        message=f"Remote endpoint uses plaintext HTTP: {url}",
        location=_trail_location(path, trail),
        line=_find_value_line(text, url),
        hint="Use HTTPS for non-local endpoints.",
    )


def _scan_lightweight_manifest(text: str, path: Path, policy: Policy) -> list[Finding]:
    """Conservative checks for frontmatter / simple YAML without dependencies."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^\s*(?:allowed[_-]?tools|tools)\s*:\s*\[?([^\]#]+)\]?\s*$", line, re.I)
        if match:
            names = [part.strip().strip("'\"") for part in match.group(1).split(",")]
            for name in names:
                if name.lower() in policy.forbidden_tools:
                    findings.append(
                        Finding(
                            severity="error",
                            rule="forbidden-tool",
                            message=f"Dangerous tool declared: {name}",
                            location=str(path),
                            line=index,
                            hint="Remove the capability or narrow it behind an explicit policy boundary.",
                        )
                    )

        command_match = re.match(r"^\s*command\s*:\s*['\"]?([^'\"\s#]+)", line, re.I)
        if command_match and Path(command_match.group(1)).name.lower() in SHELL_COMMANDS:
            command = command_match.group(1)
            findings.append(
                Finding(
                    severity="error",
                    rule="shell-command",
                    message=f"Manifest launches through a general-purpose shell: {command}",
                    location=str(path),
                    line=index,
                    hint="Launch a fixed executable directly.",
                )
            )
    return findings


def _first_package_arg(executable: str, args: list[Any]) -> str | None:
    strings = [str(item) for item in args if isinstance(item, (str, int, float))]
    if executable in {"npx", "bunx", "pnpx"}:
        skip_next = False
        for arg in strings:
            if skip_next:
                skip_next = False
                continue
            if arg in {"-p", "--package"}:
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            return arg
    elif executable == "yarn":
        # Only treat `yarn dlx package` as a runtime package fetch.
        if strings and strings[0] == "dlx":
            return next((arg for arg in strings[1:] if not arg.startswith("-")), None)
    else:
        return next((arg for arg in strings if not arg.startswith("-")), None)
    return None


def _is_pinned_package(package: str) -> bool:
    if package.startswith(("git+", "http://", "https://")):
        # URLs are considered pinned only when they visibly include an immutable-ish revision.
        return bool(re.search(r"(?:@|#)[0-9a-f]{7,40}(?:$|[/?#])", package, re.I))
    if package.startswith("@"):
        # Scoped npm package: @scope/name@1.2.3
        return package.count("@") >= 2 and not package.endswith("@latest")
    return "@" in package and not package.endswith("@latest")


def _looks_like_mcp_manifest(text: str, path: Path) -> bool:
    name = path.name.lower()
    return "mcp" in name or any(token in text for token in ('"mcpServers"', '"mcp_servers"', '"tools"'))


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _find_value_line(text: str, value: str) -> int | None:
    index = text.find(value)
    return _line_number(text, index) if index >= 0 else None


def _find_key_line(text: str, key: str) -> int | None:
    match = re.search(rf"[\"']?{re.escape(key)}[\"']?\s*[:=]", text)
    return _line_number(text, match.start()) if match else None


def _trail_location(path: Path, trail: tuple[str, ...]) -> str:
    if not trail:
        return str(path)
    return f"{path}:{'.'.join(trail)}"


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    result: list[Finding] = []
    seen: set[tuple[str, str, str, int | None]] = set()
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        result.append(finding)
    return result
