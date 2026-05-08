from __future__ import annotations

import json

import pytest

from agentveil_posture.rules import parsing
from agentveil_posture.rules import workflow
from agentveil_posture.scanner import scan_path


NEW_DEPLOY_MARKERS = (
    "gh release create v1.0.0",
    "docker push ghcr.io/acme/app:latest",
    "helm upgrade app ./chart",
    "pulumi up --yes",
    "sam deploy --no-confirm-changeset",
    "gcloud run deploy app",
    "firebase deploy --only hosting",
    "vercel deploy --prod",
    "netlify deploy --prod",
    "fly deploy",
    "wrangler deploy",
    "aws ecs update-service --cluster prod --service web",
)

NEW_DEPLOY_NON_MATCHES = (
    "gh release list",
    "docker pushed to registry",
    "helm upgraded yesterday",
    "pulumi upsert stack metadata",
    "sam deployment package",
    "gcloud run deployments list",
    "firebase deployment preview",
    "vercel deployment of v2",
    "netlify deployment summary",
    "fly deployment notes",
    "wrangler deployments list",
    "aws ecs service status",
)

DEPLOY_EXCLUSIONS = (
    "docker build .",
    "helm template app ./chart",
    "helm lint ./chart",
    "pulumi preview",
    "terraform plan",
    "vercel pull",
    "vercel build",
    "npm pack",
)

DEPLOY_EXCLUSION_WITH_MARKER = (
    "docker build . && docker push ghcr.io/acme/app:latest",
    "helm template app ./chart > out.yaml; helm upgrade app ./chart",
    "helm lint ./chart && helm upgrade app ./chart",
    "pulumi preview && pulumi up --yes",
    "terraform plan && terraform apply -auto-approve",
    "vercel pull && vercel deploy --prod",
    "vercel build && vercel deploy --prod",
    "npm pack && npm publish",
)

LEGACY_DEPLOY_MARKERS = (
    "kubectl apply -f k8s.yaml",
    "terraform apply -auto-approve",
    "cloudformation deploy --stack-name app",
    "serverless deploy",
    "npm publish",
    "twine publish dist/*",
)


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
    assert finding.line == 8
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


def test_deploy_with_environment_dict_approval_signal_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "jobs:",
                "  deploy:",
                "    environment:",
                "      name: production",
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


def test_deploy_with_upstream_environment_job_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "jobs:",
                "  approve:",
                "    environment: production",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: echo approved",
                "  deploy:",
                "    needs: approve",
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


def test_deploy_step_if_approval_output_does_not_fire(tmp_path):
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
                "        if: needs.review.outputs.approved == 'true'",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_deploy_with_unrelated_review_step_still_fires(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "jobs:",
                "  lint:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Review spelling",
                "        run: echo safe",
                "  deploy:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


def test_deploy_with_unrelated_approval_env_and_comment_still_fires(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on: push",
                "# manual approval happens in another system",
                "jobs:",
                "  deploy:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        if: env.APPROVAL_REQUIRED == 'true'",
                "        env:",
                "          APPROVAL_REQUIRED: 'true'",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


def test_deploy_with_workflow_dispatch_trigger_still_fires(tmp_path):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: deploy",
                "on:",
                "  workflow_dispatch:",
                "jobs:",
                "  deploy:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


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


def test_deploy_names_without_run_marker_do_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "named-deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: Deploy website",
                "on: push",
                "jobs:",
                "  deploy-website:",
                "    name: Deploy website",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Deploy production",
                "        run: echo preparing",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


@pytest.mark.parametrize("command", NEW_DEPLOY_MARKERS)
def test_new_deploy_markers_fire_without_approval(tmp_path, command):
    workflow_path = _workflow_path(tmp_path, "deploy.yml")
    workflow_path.write_text(
        _workflow_with_run(command),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


@pytest.mark.parametrize("command", NEW_DEPLOY_NON_MATCHES)
def test_new_deploy_markers_do_not_substring_match(tmp_path, command):
    workflow_path = _workflow_path(tmp_path, "not-deploy.yml")
    workflow_path.write_text(
        _workflow_with_run(f"echo {command!r}"),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


@pytest.mark.parametrize("command", DEPLOY_EXCLUSIONS)
def test_deploy_exclusion_without_marker_does_not_fire(tmp_path, command):
    workflow_path = _workflow_path(tmp_path, "excluded.yml")
    workflow_path.write_text(
        _workflow_with_run(command),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


@pytest.mark.parametrize("command", DEPLOY_EXCLUSION_WITH_MARKER)
def test_deploy_marker_wins_over_exclusion_in_same_step(tmp_path, command):
    workflow_path = _workflow_path(tmp_path, "excluded-then-deploy.yml")
    workflow_path.write_text(
        _workflow_with_run(command),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


@pytest.mark.parametrize("command", LEGACY_DEPLOY_MARKERS)
def test_existing_deploy_markers_still_fire(tmp_path, command):
    workflow_path = _workflow_path(tmp_path, "legacy.yml")
    workflow_path.write_text(
        _workflow_with_run(command),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


def test_comment_only_deploy_line_does_not_fire(tmp_path):
    workflow_path = _workflow_path(tmp_path, "comment.yml")
    workflow_path.write_text(
        _workflow_with_run("# docker push ghcr.io/acme/app:latest"),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_multiline_run_block_deploy_marker_fires(tmp_path):
    workflow_path = _workflow_path(tmp_path, "multiline.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: multiline",
                "on: push",
                "jobs:",
                "  ship:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - name: Ship",
                "        run: |",
                "          echo preparing",
                "          # docker push ghcr.io/acme/commented:latest",
                "          docker push ghcr.io/acme/app:latest",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.deploy_without_approval"
    ]


def test_new_marker_report_redacts_command_body_in_json_and_sarif(tmp_path):
    command = "docker push ghcr.io/acme/app:latest"
    workflow_path = _workflow_path(tmp_path, "redacted.yml")
    workflow_path.write_text(
        _workflow_with_run(command),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    report_json = report.to_json()
    report_sarif = json.dumps(report.to_sarif(), sort_keys=True)

    assert "workflow.deploy_without_approval" in report_json
    assert command not in report_json
    assert command not in report_sarif


def test_dotnet_build_release_configuration_does_not_fire_deploy(tmp_path):
    workflow_path = _workflow_path(tmp_path, "build.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: build",
                "on: push",
                "jobs:",
                "  build:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: dotnet restore",
                "      - run: dotnet build --no-restore --configuration Release -bl",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_release_notes_phrase_does_not_fire_deploy(tmp_path):
    workflow_path = _workflow_path(tmp_path, "notes.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: release notes",
                "on: push",
                "jobs:",
                "  docs:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: echo Generating Release Notes for changelog",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_build_config_skipped_then_real_deploy_step_fires(tmp_path):
    workflow_path = _workflow_path(tmp_path, "build-and-deploy.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: build-and-deploy",
                "on: push",
                "jobs:",
                "  ship:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - run: dotnet build --configuration Release",
                "      - name: Deploy production",
                "        run: terraform apply",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    rule_ids = sorted(f.rule_id for f in report.findings)
    assert "workflow.deploy_without_approval" in rule_ids


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


@pytest.mark.parametrize(
    "uses_value",
    (
        "actions/github-script@v7",
        "actions/github-script@main",
        "actions/github-script@v7.0.1",
        "actions/github-script@0123456789abcdef0123456789abcdef01234567",
    ),
)
def test_pull_request_target_github_script_action_fires_for_any_pin(tmp_path, uses_value):
    workflow_path = _workflow_path(tmp_path, "github-script.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "on:",
                "  pull_request_target:",
                "jobs:",
                "  script:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                f"      - uses: {uses_value}",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "workflow.pull_request_target_secrets_risk"
    ]


def test_pull_request_github_script_action_does_not_fire_without_privileged_trigger(tmp_path):
    workflow_path = _workflow_path(tmp_path, "github-script-pr.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "on: pull_request",
                "jobs:",
                "  script:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/github-script@v7",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_pull_request_target_github_script_suffix_does_not_match(tmp_path):
    workflow_path = _workflow_path(tmp_path, "github-script-foo.yml")
    workflow_path.write_text(
        "\n".join(
            [
                "name: pr",
                "on:",
                "  pull_request_target:",
                "jobs:",
                "  script:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - uses: actions/github-script-foo@v7",
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


def _workflow_with_run(command: str) -> str:
    return "\n".join(
        [
            "name: ci",
            "on: push",
            "jobs:",
            "  ship:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: Maybe ship",
            f"        run: {command}",
        ]
    )
