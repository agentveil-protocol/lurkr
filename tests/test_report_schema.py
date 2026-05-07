from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from agentveil_posture.report import Finding, RULE_DESCRIPTORS, build_report, empty_report
from agentveil_posture.scanner import scan_path


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


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
    assert data["scanner_version"] == "agentveil-posture/0.2.0"
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


def test_sarif_schema_version_and_rules_are_defined(tmp_path):
    sarif = empty_report(str(tmp_path)).to_sarif()

    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {rule["id"] for rule in rules}
    assert rule_ids == {
        "bypass.direct_github_token",
        "workflow.deploy_without_approval",
        "workflow.pull_request_target_secrets_risk",
        "tool.shell_without_approval",
        "identity.private_key_unencrypted",
        "agent.python_tool_without_approval",
        "agent.python_subprocess_in_tool",
        "agent.python_eval_exec_in_tool",
        "agent.python_unrestricted_file_access",
        "agent.python_api_key_hardcoded",
    }
    for rule in rules:
        assert rule["defaultConfiguration"]["level"] == "error"
        security_severity = rule["properties"]["security-severity"]
        assert isinstance(security_severity, str)
        assert 7.0 <= float(security_severity) <= 8.9
        assert rule["helpUri"].endswith(f"/docs/rules/{rule['id']}.md")


def test_every_rule_has_a_documentation_page():
    docs_root = Path(__file__).resolve().parents[1] / "docs" / "rules"

    for rule_id, descriptor in RULE_DESCRIPTORS.items():
        doc_path = docs_root / f"{rule_id}.md"
        assert doc_path.exists(), rule_id
        assert descriptor["help"].endswith(f"/docs/rules/{rule_id}.md")


def test_sarif_result_has_code_scanning_fields_and_posix_artifact_uri(tmp_path):
    finding = Finding(
        rule_id="workflow.deploy_without_approval",
        severity="high",
        file=".github/workflows/deploy.yml",
        line=12,
        message="Deployment workflow appears to run without an approval gate.",
        remediation="Add approval before production deploy steps.",
    )

    result = build_report(str(tmp_path), [finding]).to_sarif()["runs"][0]["results"][0]

    assert result["level"] == "error"
    assert result["partialFingerprints"]["primaryLocationLineHash"]
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == ".github/workflows/deploy.yml"
    assert physical_location["region"]["startLine"] == 12
    assert not physical_location["artifactLocation"]["uri"].startswith("/")
    assert "file://" not in physical_location["artifactLocation"]["uri"]
    assert "\\" not in physical_location["artifactLocation"]["uri"]


def test_sarif_preserves_redaction_contract_for_dangerous_fixture():
    report = scan_path(FIXTURES / "dangerous_github_project")
    sarif_json = json.dumps(report.to_sarif(), sort_keys=True)

    assert any(
        finding.rule_id == "identity.private_key_unencrypted"
        for finding in report.findings
    )
    assert "secrets.GITHUB_TOKEN" not in sarif_json
    assert "GITHUB_TOKEN:" not in sarif_json
    assert "terraform apply" not in sarif_json
    assert "SYNTHETIC_FIXTURE_NOT_A_REAL_PRIVATE_KEY" not in sarif_json
    assert "BEGIN PRIVATE KEY" not in sarif_json
    assert "snippet" not in sarif_json
    assert "contextRegion" not in sarif_json
