"""Baseline file helpers for suppressing known Lurkr findings."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

from lurkr import __version__
from lurkr.report import Finding, utc_now_iso


BASELINE_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class BaselineEntry:
    """Single fingerprinted finding in a baseline file."""

    fingerprint: str
    rule_id: str
    file: str


def fingerprint_finding(rule_id: str, file: str, message: str) -> str:
    """Compute a stable finding fingerprint.

    The fingerprint intentionally omits line numbers so findings survive line
    shifts. It drifts when the rule id, relative path, or message changes.
    """
    relative_file = _normalize_file(file)
    normalized = f"{rule_id}|{relative_file}|{message}".encode("utf-8")
    return sha256(normalized).hexdigest()


def load_baseline(path: Path) -> set[str]:
    """Load a baseline file and return its finding fingerprints."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"cannot read baseline file: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed JSON: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object")
    if data.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported baseline schema version: {data.get('schema_version')!r}"
        )
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("baseline entries must be a list")

    fingerprints: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"baseline entry {index} must be an object")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise ValueError(f"baseline entry {index} is missing fingerprint")
        fingerprints.add(fingerprint)
    return fingerprints


def save_baseline(path: Path, findings: list[dict[str, Any] | Finding]) -> None:
    """Write a baseline file with fingerprints for the supplied findings."""
    entries_by_fingerprint: dict[str, BaselineEntry] = {}
    for finding in findings:
        rule_id, file, message = _finding_identity(finding)
        fingerprint = fingerprint_finding(rule_id, file, message)
        entries_by_fingerprint.setdefault(
            fingerprint,
            BaselineEntry(fingerprint=fingerprint, rule_id=rule_id, file=file),
        )

    entries = [
        {
            "fingerprint": entry.fingerprint,
            "rule_id": entry.rule_id,
            "file": entry.file,
        }
        for entry in sorted(
            entries_by_fingerprint.values(), key=lambda entry: entry.fingerprint
        )
    ]
    data = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "created": utc_now_iso(),
        "lurkr_version": __version__,
        "entries": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def filter_findings_by_baseline(
    findings: list[dict[str, Any] | Finding], baseline: set[str]
) -> tuple[list[dict[str, Any] | Finding], int]:
    """Return findings whose fingerprints are not present in the baseline."""
    filtered: list[dict[str, Any] | Finding] = []
    suppressed_count = 0
    for finding in findings:
        rule_id, file, message = _finding_identity(finding)
        fingerprint = fingerprint_finding(rule_id, file, message)
        if fingerprint in baseline:
            suppressed_count += 1
        else:
            filtered.append(finding)
    return filtered, suppressed_count


def _finding_identity(finding: dict[str, Any] | Finding) -> tuple[str, str, str]:
    if isinstance(finding, Finding):
        return finding.rule_id, _normalize_file(finding.file), finding.message
    return (
        str(finding["rule_id"]),
        _normalize_file(str(finding["file"])),
        str(finding["message"]),
    )


def _normalize_file(file: str) -> str:
    normalized = file.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized
