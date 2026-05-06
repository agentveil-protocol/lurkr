"""Versioned JSON report model for AgentVeil Posture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json


REPORT_VERSION = "0.1"
SCANNER_VERSION = "agentveil-posture/0.1.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")
        category, separator, name = self.rule_id.partition(".")
        if not category or separator != "." or not name:
            raise ValueError(f"invalid rule_id: {self.rule_id}")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_")
        if not set(category) <= allowed or not set(name) <= allowed:
            raise ValueError(f"invalid rule_id: {self.rule_id}")
        if (
            self.file.startswith("/")
            or self.file.startswith("\\\\")
            or (len(self.file) >= 2 and self.file[1] == ":")
        ):
            raise ValueError("finding file must be repository-relative")


@dataclass(frozen=True)
class Summary:
    by_severity: dict[str, int]
    total: int


@dataclass(frozen=True)
class PostureReport:
    report_version: str
    scanner_version: str
    scanned_at: str
    scanned_path: str
    findings: list[Finding] = field(default_factory=list)
    summary: Summary = field(default_factory=lambda: empty_summary())

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"


def empty_summary() -> Summary:
    return Summary(by_severity={severity: 0 for severity in SEVERITIES}, total=0)


def empty_report(scanned_path: str) -> PostureReport:
    return build_report(scanned_path, [])


def build_report(scanned_path: str, findings: list[Finding]) -> PostureReport:
    by_severity = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        by_severity[finding.severity] += 1
    return PostureReport(
        report_version=REPORT_VERSION,
        scanner_version=SCANNER_VERSION,
        scanned_at=utc_now_iso(),
        scanned_path=scanned_path,
        findings=findings,
        summary=Summary(by_severity=by_severity, total=len(findings)),
    )
