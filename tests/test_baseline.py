from __future__ import annotations

import json
from pathlib import Path

import pytest

from lurkr import __version__
from lurkr.baseline import (
    fingerprint_finding,
    filter_findings_by_baseline,
    load_baseline,
    save_baseline,
)


FIXTURES = Path(__file__).resolve().parent / "baseline_fixtures"


def finding(rule_id: str = "agent.python_tool_without_approval") -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "severity": "high",
        "file": "tools.py",
        "line": 12,
        "message": "Tool 'run_command' is registered without approval.",
        "remediation": "Require approval.",
    }


def test_fingerprint_finding_is_deterministic():
    first = fingerprint_finding("agent.python_tool_without_approval", "tools.py", "msg")
    second = fingerprint_finding("agent.python_tool_without_approval", "tools.py", "msg")

    assert first == second


def test_fingerprint_finding_changes_for_rule_file_or_message():
    base = fingerprint_finding("agent.python_tool_without_approval", "tools.py", "msg")

    assert fingerprint_finding("agent.python_api_key_hardcoded", "tools.py", "msg") != base
    assert fingerprint_finding("agent.python_tool_without_approval", "other.py", "msg") != base
    assert fingerprint_finding("agent.python_tool_without_approval", "tools.py", "other") != base


def test_fingerprint_finding_normalizes_relative_path_prefix():
    assert fingerprint_finding("agent.python_tool_without_approval", "./tools.py", "msg") == (
        fingerprint_finding("agent.python_tool_without_approval", "tools.py", "msg")
    )


def test_save_baseline_writes_valid_json_with_sorted_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("lurkr.baseline.utc_now_iso", lambda: "2026-05-13T00:00:00Z")
    output = tmp_path / "baseline.json"
    findings = [
        finding("workflow.deploy_without_approval"),
        finding("agent.python_tool_without_approval"),
    ]

    save_baseline(output, findings)

    data = json.loads(output.read_text(encoding="utf-8"))
    fingerprints = [entry["fingerprint"] for entry in data["entries"]]
    assert data["schema_version"] == "1.0"
    assert data["created"] == "2026-05-13T00:00:00Z"
    assert data["lurkr_version"] == __version__
    assert fingerprints == sorted(fingerprints)


def test_save_baseline_creates_parent_directories(tmp_path):
    output = tmp_path / "nested" / "baseline.json"

    save_baseline(output, [finding()])

    assert output.exists()


def test_save_baseline_deduplicates_matching_fingerprints(tmp_path):
    output = tmp_path / "baseline.json"

    save_baseline(output, [finding(), finding()])

    data = json.loads(output.read_text(encoding="utf-8"))
    assert len(data["entries"]) == 1


def test_load_baseline_returns_fingerprints():
    assert load_baseline(FIXTURES / "valid-baseline.json") == {"abc123"}


def test_load_baseline_raises_for_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_baseline(tmp_path / "missing.json")


def test_load_baseline_raises_for_malformed_json():
    with pytest.raises(ValueError, match="malformed JSON"):
        load_baseline(FIXTURES / "malformed-baseline.json")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": "2.0", "entries": []},
        {"schema_version": "1.0"},
        {"schema_version": "1.0", "entries": {}},
        {"schema_version": "1.0", "entries": [None]},
        {"schema_version": "1.0", "entries": [{}]},
    ],
)
def test_load_baseline_raises_for_schema_mismatch(tmp_path, payload):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        load_baseline(path)


def test_filter_findings_by_baseline_returns_only_new_findings():
    old = finding("agent.python_tool_without_approval")
    new = finding("workflow.deploy_without_approval")
    baseline = {
        fingerprint_finding(
            str(old["rule_id"]),
            str(old["file"]),
            str(old["message"]),
        )
    }

    filtered, suppressed_count = filter_findings_by_baseline([old, new], baseline)

    assert filtered == [new]
    assert suppressed_count == 1


def test_filter_findings_by_baseline_empty_baseline_keeps_all_findings():
    findings = [finding(), finding("workflow.deploy_without_approval")]

    filtered, suppressed_count = filter_findings_by_baseline(findings, set())

    assert filtered == findings
    assert suppressed_count == 0


def test_filter_findings_by_baseline_all_suppressed():
    findings = [finding(), finding("workflow.deploy_without_approval")]
    baseline = {
        fingerprint_finding(str(item["rule_id"]), str(item["file"]), str(item["message"]))
        for item in findings
    }

    filtered, suppressed_count = filter_findings_by_baseline(findings, baseline)

    assert filtered == []
    assert suppressed_count == 2
