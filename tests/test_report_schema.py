from __future__ import annotations

import json
import re

import pytest

from agentveil_posture.report import Finding, build_report, empty_report


def test_empty_report_schema_contains_scanner_version_and_whole_second_time(tmp_path):
    report = empty_report(str(tmp_path))
    data = json.loads(report.to_json())

    assert set(data) == {
        "report_version",
        "scanner_version",
        "scanned_at",
        "scanned_path",
        "findings",
        "summary",
    }
    assert data["scanner_version"] == "agentveil-posture/0.1.0"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["scanned_at"])
    assert data["summary"]["by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert data["summary"]["total"] == 0


def test_non_empty_report_summary_matches_findings(tmp_path):
    finding = Finding(
        rule_id="identity.private_key_unencrypted",
        severity="high",
        file="id_rsa",
        line=1,
        message="message",
        remediation="remediation",
    )

    data = json.loads(build_report(str(tmp_path), [finding]).to_json())

    assert data["summary"]["total"] == len(data["findings"]) == 1
    assert data["summary"]["by_severity"]["high"] == 1


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="unknown severity"):
        Finding(
            rule_id="identity.private_key_unencrypted",
            severity="severe",
            file="id_rsa",
            line=1,
            message="message",
            remediation="remediation",
        )


def test_finding_rejects_invalid_rule_id():
    with pytest.raises(ValueError, match="invalid rule_id"):
        Finding(
            rule_id="Identity.PrivateKey",
            severity="high",
            file="id_rsa",
            line=1,
            message="message",
            remediation="remediation",
        )


def test_finding_rejects_absolute_file_path():
    with pytest.raises(ValueError, match="repository-relative"):
        Finding(
            rule_id="identity.private_key_unencrypted",
            severity="high",
            file="/tmp/id_rsa",
            line=1,
            message="message",
            remediation="remediation",
        )


def test_finding_rejects_windows_absolute_file_path():
    for absolute_path in ("C:\\Users\\me\\id_rsa", "\\\\server\\share\\id_rsa"):
        with pytest.raises(ValueError, match="repository-relative"):
            Finding(
                rule_id="identity.private_key_unencrypted",
                severity="high",
                file=absolute_path,
                line=1,
                message="message",
                remediation="remediation",
            )
