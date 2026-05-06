"""Versioned JSON report model for AgentVeil Posture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json


REPORT_VERSION = "0.1"
SEVERITIES = ("critical", "high", "medium", "low", "info")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str
    remediation: str


@dataclass(frozen=True)
class Summary:
    by_severity: dict[str, int]
    total: int


@dataclass(frozen=True)
class PostureReport:
    report_version: str
    scanned_at: str
    scanned_path: str
    findings: list[Finding] = field(default_factory=list)
    summary: Summary = field(default_factory=lambda: empty_summary())

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


def empty_summary() -> Summary:
    return Summary(by_severity={severity: 0 for severity in SEVERITIES}, total=0)


def empty_report(scanned_path: str) -> PostureReport:
    return PostureReport(
        report_version=REPORT_VERSION,
        scanned_at=utc_now_iso(),
        scanned_path=scanned_path,
        findings=[],
        summary=empty_summary(),
    )

