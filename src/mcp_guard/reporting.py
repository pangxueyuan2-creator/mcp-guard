"""Output helpers for MCP Guard CLI and CI integrations."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from mcp_guard.models import SEVERITY_RANK

_FILE_LOCATION_RE = re.compile(
    r"^(.*\.(?:jsonc?|toml|ya?ml|md|py|jsx?|tsx?))(?::.*)?$",
    re.I,
)


def summarize(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity", "info")) for item in findings)
    return {
        "error": counts["error"],
        "warning": counts["warning"],
        "info": counts["info"],
        "total": sum(counts.values()),
    }


def should_fail(findings: Iterable[dict[str, Any]], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK[fail_on]
    return any(
        SEVERITY_RANK.get(str(item.get("severity", "info")), 0) >= threshold
        for item in findings
    )


def to_sarif(findings: list[dict[str, Any]], scanned_path: Path) -> dict[str, Any]:
    """Render findings as SARIF 2.1.0 with one rule descriptor per rule id."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("rule", "unknown"))
        severity = str(finding.get("severity", "info"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": _title(rule_id)},
                "help": {
                    "text": str(
                        finding.get("hint")
                        or finding.get("message")
                        or rule_id
                    )
                },
            },
        )

        location = str(finding.get("location") or scanned_path)
        file_location = _artifact_location(location, scanned_path)
        region: dict[str, Any] = {}
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            region["startLine"] = line

        physical: dict[str, Any] = {
            "artifactLocation": {"uri": file_location.replace("\\", "/")}
        }
        if region:
            physical["region"] = region

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": {
                "error": "error",
                "warning": "warning",
                "info": "note",
            }.get(severity, "note"),
            "message": {"text": str(finding.get("message", ""))},
            "locations": [{"physicalLocation": physical}],
        }
        if finding.get("hint"):
            result["properties"] = {
                "hint": str(finding["hint"]),
                "mcpGuardSeverity": severity,
            }
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Guard",
                        "informationUri": "https://github.com/pangxueyuan2-creator/mcp-guard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _artifact_location(location: str, scanned_path: Path) -> str:
    """Strip our structural `:trail` suffix without breaking Windows drives."""
    match = _FILE_LOCATION_RE.match(location)
    if match:
        return match.group(1)
    return location or str(scanned_path)


def _title(rule_id: str) -> str:
    return rule_id.replace("-", " ").replace("_", " ").strip().title()
