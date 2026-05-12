from __future__ import annotations

from pathlib import Path

from lurkr.scanner import scan_path


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_clean_fixture_has_no_findings():
    report = scan_path(FIXTURES / "clean_github_project")

    assert report.findings == []


def test_dangerous_fixture_covers_all_v0_1_rules_with_synthetic_values_only():
    report = scan_path(FIXTURES / "dangerous_github_project")

    assert sorted(finding.rule_id for finding in report.findings) == sorted(
        [
            "bypass.direct_github_token",
            "workflow.deploy_without_approval",
            "workflow.pull_request_target_secrets_risk",
            "tool.shell_without_approval",
            "identity.private_key_unencrypted",
        ]
    )
    report_json = report.to_json()
    assert "secrets.GITHUB_TOKEN" not in report_json
    assert "SYNTHETIC_FIXTURE_NOT_A_REAL_PRIVATE_KEY" not in report_json
    assert "terraform apply" not in report_json


def test_clean_declared_match_fixture_has_no_findings():
    report = scan_path(FIXTURES / "clean_declared_match")

    assert report.findings == []


def test_dangerous_shadow_capabilities_fixture_finds_declared_delta_only():
    report = scan_path(FIXTURES / "dangerous_shadow_capabilities")

    findings = [
        finding
        for finding in report.findings
        if finding.rule_id == "agent.declared_vs_imported_delta"
    ]
    assert len(findings) == 2
    assert {finding.file for finding in findings} == {"agent.py"}
    assert {finding.line for finding in findings} == {9, 14}
    assert sorted(finding.message for finding in findings) == [
        "Tool 'delete_files' is registered in Python code but not declared in any agent manifest.",
        "Tool 'run_command' is registered in Python code but not declared in any agent manifest.",
    ]
    assert [finding.rule_id for finding in report.findings] == [
        "agent.declared_vs_imported_delta",
        "agent.declared_vs_imported_delta",
    ]


def test_dangerous_crewai_shadow_fixture_finds_declared_delta_only():
    report = scan_path(FIXTURES / "dangerous_crewai_shadow")

    findings = [
        finding
        for finding in report.findings
        if finding.rule_id == "agent.declared_vs_imported_delta"
    ]
    assert len(findings) == 1
    assert findings[0].file == "agent.py"
    assert findings[0].line == 19
    assert "export_records" in findings[0].message
    assert [finding.rule_id for finding in report.findings] == [
        "agent.declared_vs_imported_delta"
    ]
