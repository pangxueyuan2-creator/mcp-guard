"""Report generation helpers for MCP Guard."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_LEVELS = {"info": 0, "warning": 1, "error": 2}
SARIF_LEVELS = {"info": "note", "warning": "warning", "error": "error"}


def build_json_report(path: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a stable machine-readable report envelope."""
    counts = Counter(str(f.get("severity", "info")) for f in findings)
    return {
        "schema_version": 1,
        "path": str(path),
        "summary": {
            "total": len(findings),
            "errors": counts.get("error", 0),
            "warnings": counts.get("warning", 0),
            "infos": counts.get("info", 0),
        },
        "findings": findings,
    }


def build_sarif_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert findings to a minimal SARIF 2.1.0 document."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = str(finding.get("rule", "unknown"))
        severity = str(finding.get("severity", "info")).lower()
        message = str(finding.get("message", ""))
        location = str(finding.get("location", ""))

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("-", " ").title()},
                "defaultConfiguration": {"level": SARIF_LEVELS.get(severity, "note")},
            },
        )

        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": _artifact_uri(location)}
        }
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            physical_location["region"] = {"startLine": line}

        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVELS.get(severity, "note"),
                "message": {"text": message},
                "locations": [{"physicalLocation": physical_location}],
            }
        )

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


def should_fail(findings: list[dict[str, Any]], max_allowed: str) -> bool:
    """Return True when a finding exceeds the configured allowed severity."""
    allowed_rank = SEVERITY_LEVELS[max_allowed]
    return any(
        SEVERITY_LEVELS.get(str(f.get("severity", "info")).lower(), 0) > allowed_rank
        for f in findings
    )


def _artifact_uri(location: str) -> str:
    # JSON-pointer style locations are encoded as `file:$....`; SARIF wants the file.
    if ":$" in location:
        location = location.split(":$", 1)[0]
    return location.replace("\\", "/")
