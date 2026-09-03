"""Shared data models used by MCP Guard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Severity = Literal["info", "warning", "error"]

SEVERITY_RANK: dict[str, int] = {"info": 0, "warning": 1, "error": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    """One actionable security finding produced by the scanner."""

    severity: Severity
    rule: str
    message: str
    location: str
    line: int | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "severity": self.severity,
            "rule": self.rule,
            "message": self.message,
            "location": self.location,
        }
        if self.line is not None:
            data["line"] = self.line
        if self.hint:
            data["hint"] = self.hint
        return data

    @property
    def fingerprint(self) -> tuple[str, str, str, int | None]:
        """Stable tuple used to suppress duplicate findings."""
        return (self.rule, self.message, self.location, self.line)
