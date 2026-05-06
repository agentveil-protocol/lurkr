from __future__ import annotations

import json

from agentveil_posture.rules import parsing
from agentveil_posture.scanner import scan_path


def test_manifest_direct_github_token_fires_without_secret_value(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "github",
                        "env": {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "bypass.direct_github_token"
    ]
    report_json = report.to_json()
    assert "secrets.GITHUB_TOKEN" not in report_json
    assert "GITHUB_TOKEN" not in report_json


def test_manifest_direct_github_token_fires_in_minified_json(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text('{"env":{"GITHUB_TOKEN":"synthetic-token"}}', encoding="utf-8")

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "bypass.direct_github_token"
    ]
    assert "synthetic-token" not in report.to_json()


def test_manifest_shell_without_approval_fires(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps({"tools": [{"name": "shell", "shell": "bash"}]}),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "tool.shell_without_approval"
    ]
    assert report.findings[0].file == "mcp.json"
    assert report.findings[0].line == 1


def test_manifest_shell_with_approval_does_not_fire(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "shell",
                        "shell": "bash",
                        "approval_required": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_manifest_shell_string_value_human_does_not_silence_rule(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps({"tools": [{"name": "shell", "shell": "bash"}], "owner": "human"}),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "tool.shell_without_approval"
    ]


def test_yaml_manifest_shell_without_approval_fires(tmp_path):
    manifest = tmp_path / "crew-tools.yaml"
    manifest.write_text(
        "tools:\n  - name: local_shell\n    command: bash\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "tool.shell_without_approval"
    ]
    assert report.findings[0].line == 3


def test_crewai_agents_yaml_in_crews_config_path_is_scanned(tmp_path):
    config_dir = tmp_path / "crews" / "researcher" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "agents.yaml").write_text(
        "researcher:\n"
        "  role: Senior Researcher\n"
        "  shell: bash\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert "tool.shell_without_approval" in [
        finding.rule_id for finding in report.findings
    ]


def test_crewai_tasks_yaml_in_crews_config_path_is_scanned(tmp_path):
    config_dir = tmp_path / "crews" / "writer" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "tasks.yaml").write_text(
        "task:\n  env:\n    GITHUB_TOKEN: synthetic\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert "bypass.direct_github_token" in [
        finding.rule_id for finding in report.findings
    ]


def test_random_agents_yaml_not_in_crews_structure_is_ignored(tmp_path):
    (tmp_path / "agents.yaml").write_text(
        "shell: bash\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_crewai_yml_extension_recognized_in_crews_config(tmp_path):
    config_dir = tmp_path / "crews" / "writer" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "agents.yml").write_text(
        "writer:\n"
        "  shell: bash\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert "tool.shell_without_approval" in [
        finding.rule_id for finding in report.findings
    ]


def test_non_candidate_manifest_name_is_ignored(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps({"scripts": {"deploy": "terraform apply"}, "GITHUB_TOKEN": "synthetic"}),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_empty_manifest_files_do_not_fire(tmp_path):
    for name, content in (("mcp.json", "{}"), ("crew-tools.yaml", ""), ("autogen.yml", "[]")):
        (tmp_path / name).write_text(content, encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_unsupported_manifest_extension_is_ignored(tmp_path):
    manifest = tmp_path / "mcp.toml"
    manifest.write_text('shell = "bash"\nGITHUB_TOKEN = "synthetic"\n', encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_cursor_mcp_json_exact_path_is_scanned(tmp_path):
    manifest = tmp_path / ".cursor" / "mcp.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"tools": [{"shell": "bash"}]}), encoding="utf-8")

    report = scan_path(tmp_path)

    assert [finding.rule_id for finding in report.findings] == [
        "tool.shell_without_approval"
    ]


def test_large_yaml_manifest_is_skipped_before_yaml_parse(monkeypatch, tmp_path):
    def blocked_safe_load(text):
        raise AssertionError("safe_load should not run for oversized manifest YAML")

    monkeypatch.setattr(parsing.yaml, "safe_load", blocked_safe_load)
    manifest = tmp_path / "crew-tools.yaml"
    manifest.write_text("tools:\n" + ("# padding\n" * 120_000), encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_alias_heavy_manifest_is_rejected_before_safe_load(monkeypatch, tmp_path):
    def blocked_safe_load(text):
        raise AssertionError("safe_load should not run for alias-heavy manifest YAML")

    monkeypatch.setattr(parsing.yaml, "safe_load", blocked_safe_load)
    aliases = ", ".join("*base" for _ in range(parsing.MAX_YAML_ALIAS_TOKENS + 1))
    manifest = tmp_path / "crew-tools.yaml"
    manifest.write_text(
        f"base: &base bash\ntools: [{aliases}]\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_large_json_manifest_is_skipped_before_json_parse(monkeypatch, tmp_path):
    def blocked_loads(text):
        raise AssertionError("json.loads should not run for oversized manifest JSON")

    monkeypatch.setattr(parsing.json, "loads", blocked_loads)
    manifest = tmp_path / "mcp.json"
    manifest.write_text('{"tools": []' + (" " * 1_100_000) + "}", encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def test_deeply_nested_json_manifest_is_rejected_without_traceback(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text("[" * 1500 + "]" * 1500, encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []
