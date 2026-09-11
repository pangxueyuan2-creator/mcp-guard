"""Core scanning logic for MCP Guard."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from mcp_guard.policy import Policy, load_policy

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PYTHON_PIP_PREFIX = (
    r"(?:python(?:3(?:\.\d+)?)?(?:\.exe)?|py(?:\.exe)?(?:\s+-\d+(?:\.\d+)?)?)"
    r"\s+-m\s+pip"
)
PACKAGE_COMMAND_PATTERN = re.compile(
    rf"(?im)\b(?:npx(?:\s+(?:-y|--yes))?|npm\s+(?:install|i)|"
    rf"pip(?:3)?\s+install|{PYTHON_PIP_PREFIX}\s+install|uvx)\s+([^\s\\]+)"
)
PIP_VALUE_INSTALL_FLAG = (
    r"(?:-i|--index-url|--extra-index-url|-f|--find-links|--trusted-host|"
    r"--proxy|--cert|--client-cert|--timeout|--retries|--cache-dir|--src|"
    r"-t|--target|--root|--prefix|--platform|--python-version|"
    r"--implementation|--abi|-C|--config-settings)\s+[^\s\\]+"
)
PIP_LEADING_INSTALL_FLAG = (
    rf"(?:{PIP_VALUE_INSTALL_FLAG}|-U|--upgrade|--pre|--user|--no-deps|"
    r"--ignore-installed|--force-reinstall|--no-build-isolation|"
    r"--[A-Za-z0-9_-]+=[^\s]+)"
)
PIP_OPTION_PACKAGE_PATTERN = re.compile(
    rf"(?im)\b(?:pip(?:3)?|{PYTHON_PIP_PREFIX})\s+install\s+"
    rf"(?:{PIP_LEADING_INSTALL_FLAG}\s+)+([^\s\\]+)"
)
NPM_VALUE_INSTALL_FLAG = (
    r"(?:--registry|--prefix|--cache|--userconfig|--workspace|-w|--tag|"
    r"--omit|--include|--install-strategy|--save-prefix|--loglevel)\s+[^\s\\]+"
)
NPM_LEADING_INSTALL_FLAG = (
    rf"(?:{NPM_VALUE_INSTALL_FLAG}|-D|-O|-P|-S|-g|--save-dev|--save-optional|"
    r"--save-peer|--save-prod|--save|--no-save|--global|--dry-run|"
    r"--[A-Za-z0-9_-]+=[^\s]+)"
)
NPM_OPTION_PACKAGE_PATTERN = re.compile(
    rf"(?im)\bnpm\s+(?:install|i)\s+"
    rf"(?:{NPM_LEADING_INSTALL_FLAG}\s+)+([^\s\\]+)"
)
INSTALL_COMMAND_PATTERN = re.compile(
    rf"(?im)\b(?:npm\s+(?:install|i)|pip(?:3)?\s+install|"
    rf"{PYTHON_PIP_PREFIX}\s+install)\s+([^\r\n;&|]+)"
)
EXPLICIT_PACKAGE_SPEC_PATTERN = re.compile(r"(?:@|===?|~=|!=|<=|>=|<|>)")
UVX_FROM_PATTERN = re.compile(r"(?im)\buvx\s+--from(?:=|\s+)([^\s\\]+)")
NPX_COMMAND_PATTERN = re.compile(r"(?im)\bnpx\b[^\r\n]*")
NPX_PACKAGE_FLAG_PATTERN = re.compile(
    r"(?i)(?:--package|-p)(?:=|\s+)([^\s\\]+)"
)
NPM_EXACT_VERSION_PATTERN = re.compile(
    r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
GIT_COMMIT_SHA_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"bearer[_-]?token|client[_-]?secret|refresh[_-]?token|session[_-]?token|"
    r"secret|password|passwd|private[_-]?key|credentials?)(?:$|[_-])"
)
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?i)(?:^|[\"'\s:=])((?:/[A-Za-z0-9._-]+){2,}|[A-Z]:\\(?:[^\\\r\n]+\\?)+)"
)


def scan_path(path: Path, policy_path: Path | None = None) -> list[dict[str, Any]]:
    """Scan a file or directory and return normalized findings.

    The scanner is intentionally stdlib-only and does not execute the target.
    """
    policy = load_policy(policy_path)
    findings: list[dict[str, Any]] = []

    if path.is_file():
        findings.extend(_scan_file(path, policy))
    elif path.is_dir():
        for candidate in _iter_scannable_files(path, policy):
            findings.extend(_scan_file(candidate, policy))
    else:
        findings.append(
            _finding(
                "error",
                "path-not-found",
                f"Path does not exist or is not accessible: {path}",
                path,
            )
        )

    return _deduplicate(findings)


def _iter_scannable_files(root: Path, policy: Policy) -> Iterable[Path]:
    """Yield supported files while pruning dependency/build directories."""
    for current_root, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [
            name
            for name in dirs
            if name not in policy.excluded_dirs
            and not Path(current_root, name).is_symlink()
        ]
        for name in files:
            candidate = Path(current_root, name)
            if candidate.is_symlink():
                continue
            if candidate.suffix.lower() in policy.scan_extensions:
                yield candidate


def _scan_file(path: Path, policy: Policy) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    try:
        size = path.stat().st_size
    except OSError as exc:
        return [
            _finding(
                "warning",
                "stat-error",
                f"Could not inspect file metadata: {exc}",
                path,
            )
        ]

    if size > policy.max_file_bytes:
        return [
            _finding(
                "warning",
                "file-too-large",
                f"Skipped file larger than policy.max_file_bytes ({size} bytes)",
                path,
            )
        ]

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [
            _finding(
                "warning",
                "read-error",
                f"Could not read file: {exc}",
                path,
            )
        ]

    findings.extend(_scan_secrets(text, path, policy))
    findings.extend(_scan_tool_names(text, path, policy))
    findings.extend(_scan_urls(text, path, policy))
    findings.extend(_scan_supply_chain(text, path))
    findings.extend(_scan_absolute_paths(text, path))

    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            findings.extend(_scan_json(data, path, policy))

    return findings


def _scan_secrets(text: str, path: Path, policy: Policy) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern, description in policy.secret_patterns:
        for match in pattern.finditer(text):
            findings.append(
                _finding(
                    "error",
                    "secret-detected",
                    description,
                    path,
                    line=_line_number(text, match.start()),
                )
            )
    return findings


def _scan_tool_names(text: str, path: Path, policy: Policy) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lower = text.lower()
    for tool in sorted(policy.effective_forbidden_tools):
        escaped = re.escape(tool.lower())
        pattern = re.compile(
            rf"[\"']{escaped}[\"']|\bname\s*[\"']?\s*:\s*[\"']{escaped}[\"']",
            re.IGNORECASE,
        )
        for match in pattern.finditer(lower):
            findings.append(
                _finding(
                    "error",
                    "forbidden-tool",
                    f"Potentially dangerous tool name detected: {tool}",
                    path,
                    line=_line_number(text, match.start()),
                )
            )
    return findings


def _scan_urls(text: str, path: Path, policy: Policy) -> list[dict[str, Any]]:
    if not policy.allowed_hosts:
        return []

    findings: list[dict[str, Any]] = []
    for match in URL_PATTERN.finditer(text):
        raw_url = match.group(0).rstrip(".,);]}")
        host = (urlparse(raw_url).hostname or "").lower()
        if host and not _host_allowed(host, policy.allowed_hosts):
            findings.append(
                _finding(
                    "warning",
                    "host-outside-policy",
                    f"Network host is not allowed by policy: {host}",
                    path,
                    line=_line_number(text, match.start()),
                )
            )
    return findings


def _scan_supply_chain(text: str, path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern in (
        PACKAGE_COMMAND_PATTERN,
        PIP_OPTION_PACKAGE_PATTERN,
        NPM_OPTION_PACKAGE_PATTERN,
        UVX_FROM_PATTERN,
    ):
        for match in pattern.finditer(text):
            spec = match.group(1).strip("\"',[]()")
            if spec and _looks_unpinned(spec):
                findings.append(
                    _finding(
                        "warning",
                        "unpinned-package",
                        f"Package/install command appears unpinned: {spec}",
                        path,
                        line=_line_number(text, match.start()),
                    )
                )

    # npm/pip install can accept several package specs in one command. The
    # generic matcher above only sees the first argument, so inspect later
    # arguments when they are explicitly package-shaped (for example @latest
    # or >=2.0). Requiring version/package syntax avoids treating prose after an
    # inline README command as additional packages.
    for command_match in INSTALL_COMMAND_PATTERN.finditer(text):
        arguments = command_match.group(1).split()
        for raw_spec in arguments[1:]:
            spec = raw_spec.strip("\"',[]()")
            if not spec or spec.startswith(("-", "#", ">", "<")):
                break
            if not EXPLICIT_PACKAGE_SPEC_PATTERN.search(spec):
                break
            if _looks_unpinned(spec):
                findings.append(
                    _finding(
                        "warning",
                        "unpinned-package",
                        f"Package/install command appears unpinned: {spec}",
                        path,
                        line=_line_number(text, command_match.start()),
                    )
                )

    # npx can fetch extra packages through --package/-p before invoking a binary.
    # Those package specs are supply-chain inputs too and must be pinned just like
    # the direct package argument handled above.
    for command_match in NPX_COMMAND_PATTERN.finditer(text):
        command = command_match.group(0)
        for package_match in NPX_PACKAGE_FLAG_PATTERN.finditer(command):
            spec = package_match.group(1).strip("\"',[]()")
            if spec and _looks_unpinned(spec):
                findings.append(
                    _finding(
                        "warning",
                        "unpinned-package",
                        f"Package/install command appears unpinned: {spec}",
                        path,
                        line=_line_number(
                            text, command_match.start() + package_match.start()
                        ),
                    )
                )
    return findings


def _scan_absolute_paths(text: str, path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in ABSOLUTE_PATH_PATTERN.finditer(text):
        candidate = match.group(1)
        if candidate.startswith(
            ("/usr/", "/opt/", "/etc/", "/var/", "/home/", "/root/")
        ) or re.match(r"^[A-Z]:\\", candidate, re.IGNORECASE):
            findings.append(
                _finding(
                    "warning",
                    "absolute-path-reference",
                    f"Absolute filesystem path may escape an intended workspace scope: {candidate}",
                    path,
                    line=_line_number(text, match.start(1)),
                )
            )
    return findings


def _scan_json(data: Any, path: Path, policy: Policy) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    _walk_json(data, path, policy, findings, pointer="$")
    return findings


def _walk_json(
    value: Any,
    path: Path,
    policy: Policy,
    findings: list[dict[str, Any]],
    pointer: str,
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = f"{pointer}.{key}"
            key_lower = str(key).lower()

            if key_lower in {
                "tools",
                "capabilities",
                "functions",
                "allowed_tools",
            } and isinstance(child, list):
                for item in child:
                    name: str | None = None
                    if isinstance(item, str):
                        name = item
                    elif isinstance(item, dict):
                        candidate = item.get("name") or item.get("tool") or item.get("id")
                        if candidate is not None:
                            name = str(candidate)
                    if name and name.lower() in policy.effective_forbidden_tools:
                        findings.append(
                            _finding(
                                "error",
                                "forbidden-tool",
                                f"Dangerous tool declared: {name}",
                                f"{path}:{child_pointer}",
                            )
                        )

            if (
                SENSITIVE_NAME_PATTERN.search(key_lower)
                and isinstance(child, str)
                and child.strip()
            ):
                if not _looks_like_placeholder(child):
                    findings.append(
                        _finding(
                            "warning",
                            "sensitive-value",
                            f"Sensitive field contains a literal value: {key}",
                            f"{path}:{child_pointer}",
                        )
                    )

            _walk_json(child, path, policy, findings, child_pointer)
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk_json(child, path, policy, findings, f"{pointer}[{index}]")


def _host_allowed(host: str, allowed_hosts: set[str]) -> bool:
    for allowed in allowed_hosts:
        allowed = allowed.lstrip(".")
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


def _looks_unpinned(spec: str) -> bool:
    if spec.startswith("git+"):
        return _git_vcs_ref_is_unpinned(spec)
    if spec.startswith(("http://", "https://")):
        # A URL can keep serving different bytes over time. Without installer-
        # specific integrity metadata in the command, the scanner cannot prove
        # the artifact is immutable, so fail closed rather than trusting the path.
        return True
    if spec.startswith((".", "/", "-")):
        return False
    if "===" in spec:
        return False
    if "==" in spec:
        version = spec.split("==", 1)[1]
        return not version or "*" in version

    if spec.startswith("@"):
        # Scoped npm package: the first @ begins the scope; the last one begins
        # the version only when another @ is present.
        if spec.count("@") < 2:
            return True
        version = spec.rsplit("@", 1)[1]
        return NPM_EXACT_VERSION_PATTERN.fullmatch(version) is None

    if "@" in spec:
        version = spec.rsplit("@", 1)[1]
        return NPM_EXACT_VERSION_PATTERN.fullmatch(version) is None

    return True


def _git_vcs_ref_is_unpinned(spec: str) -> bool:
    """Return whether a pip-style git+ URL lacks an immutable full commit ref."""
    target = spec.split("#", 1)[0]
    scheme_end = target.find("://")
    if scheme_end < 0:
        return True

    path_start = target.find("/", scheme_end + 3)
    if path_start < 0:
        return True

    ref_separator = target.rfind("@")
    if ref_separator <= path_start:
        return True

    ref = target[ref_separator + 1 :]
    return GIT_COMMIT_SHA_PATTERN.fullmatch(ref) is None


def _looks_like_placeholder(value: str) -> bool:
    stripped = value.strip()
    upper = stripped.upper()
    return (
        stripped.startswith(("${", "{{", "$", "<"))
        or upper
        in {
            "REDACTED",
            "CHANGEME",
            "PLACEHOLDER",
            "YOUR_TOKEN",
            "YOUR_API_KEY",
        }
    )


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _finding(
    severity: str,
    rule: str,
    message: str,
    location: Path | str,
    *,
    line: int | None = None,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "severity": severity,
        "rule": rule,
        "message": message,
        "location": str(location),
    }
    if line is not None:
        finding["line"] = line
    return finding


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        key = (
            finding.get("severity"),
            finding.get("rule"),
            finding.get("message"),
            finding.get("location"),
            finding.get("line"),
        )
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
