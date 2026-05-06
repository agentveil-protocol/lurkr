from __future__ import annotations

from pathlib import Path

from agentveil_posture.scanner import scan_path


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
