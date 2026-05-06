from __future__ import annotations

import json

from agentveil_posture.rules import parsing
from agentveil_posture.rules import workflow
from agentveil_posture.scanner import scan_path


def test_deploy_without_approval_fires_without_raw_command_or_secret(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "jobs:",
                "  deploy:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        run: echo ${{ secrets.PROD_TOKEN }} && terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]
    finding = report.findings[0]
    assert finding.severity == "high"
    assert finding.file == ".github/workflows/deploy.yml"
    assert finding.line == 1
    report_json = report.to_json()
    assert "PROD_TOKEN" not in report_json
    assert "terraform apply" not in report_json


def test_deploy_with_environment_approval_signal_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "jobs:",
                "  deploy:",
                "    environment: production",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_deploy_markers_do_not_match_prod_or_produce_substrings(tmp_path):
    workflow_path = _workflow_path(tmp_path, "build.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: produce artifacts",
                "on: push",
                "jobs:",
                "  build:",
                "    production: false",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: produce-artifacts",
                "        run: echo productivity-tools",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_pull_request_target_risk_fires_with_checkout(tmp_path):
    workflow_path = _workflow_path(tmp_path, "pr.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "on:",
                "  pull_request_target:",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.pull_request_target_secrets_risk"
    ]
    assert report.findings[0].file == ".github/workflows/pr.yml"
    assert report.findings[0].line == 3


def test_pull_request_target_without_risky_step_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "pr.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "on: [pull_request_target]",
                "jobs:",
                "  label:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Metadata only",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_comment_only_pull_request_target_reference_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "pr.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "# pull_request_target:",
                "on: pull_request",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_crlf_workflow_parses_like_lf(tmp_path):
    workflow_path = _workflow_path(tmp_path, "pr.yml")
    workflow_path.write_bytes(
        b"name: pr\r\n"
        b"on:\r\n"
        b"  pull_request_target:\r\n"
        b"jobs:\r\n"
        b"  test:\r\n"
        b"    runs-on: ubuntu-latest\r\n"
        b"    steps:\r\n"
        b"      - run: echo safe\r\n"
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.pull_request_target_secrets_risk"
    ]


def test_symlinked_workflow_file_is_skipped(tmp_path):
    outside = tmp_path / "outside.yml"
    outside.write_text(
        "name: deploy\non: push\njobs:\n  deploy:\n    steps:\n      - run: terraform apply\n",
        encoding="utf-8",
    )
    workflows_dir = tmp_path / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    (workflows_dir / "deploy.yml").symlink_to(outside)

    report = scan_path(tmp_path)

    assert report.findings == []


def test_large_workflow_is_skipped_before_yaml_parse(monkeypatch, tmp_path):
    def blocked_safe_load(text):
        raise AssertionError("safe_load should not run for oversized YAML")

    monkeypatch.setattr(parsing.yaml, "safe_load", blocked_safe_load)
    workflow_path = _workflow_path(tmp_path, "large.yml")
    workflow_path.write_text(
        "name: deploy\n"
        + ("# padding\n" * 120_000)
        + "jobs:\n  deploy:\n    steps:\n      - run: terraform apply\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_alias_heavy_workflow_is_rejected_before_safe_load(monkeypatch, tmp_path):
    def blocked_safe_load(text):
        raise AssertionError("safe_load should not run for alias-heavy YAML")

    monkeypatch.setattr(parsing.yaml, "safe_load", blocked_safe_load)
    aliases = ", ".join("*base" for _ in range(workflow.MAX_YAML_ALIAS_TOKENS + 1))
    workflow_path = _workflow_path(tmp_path, "aliases.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "base: &base terraform",
                f"aliases: [{aliases}]",
                "jobs:",
                "  deploy:",
                "    steps:",
                "      - run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_anchor_without_alias_is_allowed(tmp_path):
    workflow_path = _workflow_path(tmp_path, "anchor.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: anchor",
                "base: &base value",
                "on:",
                "  pull_request_target:",
                "jobs:",
                "  test:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: echo safe",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.pull_request_target_secrets_risk"
    ]


def test_empty_workflow_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "empty.yml")
    workflow_path.write_text("name: empty\n", encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_workflow_outside_root_github_workflows_dir_is_ignored(tmp_path):
    nested = tmp_path / "subproject" / ".github" / "workflows"
    nested.mkdir(parents=True)
    (nested / "deploy.yml").write_text(
        "name: deploy\non: push\njobs:\n  deploy:\n    steps:\n      - run: terraform apply\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_utf8_bom_workflow_parses_without_crash(tmp_path):
    workflow_path = _workflow_path(tmp_path, "bom.yml")
    workflow_path.write_text(
        "\ufeffname: deploy\non: push\njobs:\n  deploy:\n    steps:\n      - run: terraform apply\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


def test_workflow_direct_github_token_fires_without_secret_value(tmp_path):
    workflow_path = _workflow_path(tmp_path, "token.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: token",
                "on: push",
                "jobs:",
                "  check:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Use token",
                "        env:",
                "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
                "        run: echo masked",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "bypass.direct_github_token"
    ]
    report_json = report.to_json()
    assert "secrets.GITHUB_TOKEN" not in report_json
    assert "GITHUB_TOKEN:" not in report_json


def test_deeply_nested_yaml_is_rejected_without_traceback(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deep.yml")
    nested = "a:\n" + "\n".join(f"{'  ' * depth}a:" for depth in range(1, 1500))
    workflow_path.write_text(nested, encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_workflow_report_summary_counts_two_rules(tmp_path):
    workflow_path = _workflow_path(tmp_path, "risky.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: risky",
                "on:",
                "  pull_request_target:",
                "jobs:",
                "  deploy:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/checkout@v4",
                "      - run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    data = json.loads(scan_path(tmp_path).to_json())

    assert data["summary"]["total"] == 2
    assert data["summary"]["by_severity"]["high"] == 2


def _workflow_path(root, name: str):
    workflows_dir = root / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    return workflows_dir / name
