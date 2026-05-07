from __future__ import annotations

import json
from pathlib import Path

import agentveil_posture.report as report_module
from agentveil_posture.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_cli_scan_writes_json_report(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(["posture", "scan", "--path", str(tmp_path), "--output", str(output)])

    assert exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["report_version"] == "0.1"
    assert data["scanner_version"] == "agentveil-posture/0.1.0"


def test_cli_default_and_format_json_match_existing_json_output(tmp_path, monkeypatch):
    monkeypatch.setattr(report_module, "utc_now_iso", lambda: "2026-05-07T00:00:00Z")
    scan_root = FIXTURES / "dangerous_github_project"
    default_output = tmp_path / "default.json"
    explicit_output = tmp_path / "explicit.json"

    default_exit = main(["posture", "scan", "--path", str(scan_root), "--output", str(default_output)])
    explicit_exit = main(
        [
            "posture",
            "scan",
            "--path",
            str(scan_root),
            "--output",
            str(explicit_output),
            "--format",
            "json",
        ]
    )

    expected_json = f"""{{
  "findings": [
    {{
      "file": ".github/workflows/dangerous.yml",
      "line": 11,
      "message": "Workflow appears to expose direct GitHub token access.",
      "remediation": "Restrict GitHub token permissions, avoid passing direct write tokens to agent-controlled steps, and require approval for GitHub write or deploy paths.",
      "rule_id": "bypass.direct_github_token",
      "severity": "high"
    }},
    {{
      "file": ".github/workflows/dangerous.yml",
      "line": 5,
      "message": "Deployment workflow appears to run without an approval gate.",
      "remediation": "Add a protected GitHub environment or explicit manual approval before production deploy, release, or publish steps.",
      "rule_id": "workflow.deploy_without_approval",
      "severity": "high"
    }},
    {{
      "file": ".github/workflows/dangerous.yml",
      "line": 3,
      "message": "pull_request_target workflow appears to combine privileged PR context with checkout, shell execution, or secrets access.",
      "remediation": "Use pull_request for untrusted checks, avoid checking out fork code in privileged workflows, and isolate any secret-bearing jobs.",
      "rule_id": "workflow.pull_request_target_secrets_risk",
      "severity": "high"
    }},
    {{
      "file": "keys/synthetic_unencrypted_private_key.pem",
      "line": 1,
      "message": "Unencrypted private key file appears present.",
      "remediation": "Remove the key from the repository, rotate it if exposed, store it in a secret manager, and use encrypted private key material when local keys are unavoidable.",
      "rule_id": "identity.private_key_unencrypted",
      "severity": "high"
    }},
    {{
      "file": "mcp.json",
      "line": 5,
      "message": "Agent/tool manifest appears to enable shell execution without approval.",
      "remediation": "Require explicit approval or a narrow allowlist before enabling shell, terminal, command, bash, or subprocess tools.",
      "rule_id": "tool.shell_without_approval",
      "severity": "high"
    }}
  ],
  "report_version": "0.1",
  "scanned_at": "2026-05-07T00:00:00Z",
  "scanned_path": "{scan_root.resolve()}",
  "scanner_version": "agentveil-posture/0.1.0",
  "summary": {{
    "by_severity": {{
      "critical": 0,
      "high": 5,
      "info": 0,
      "low": 0,
      "medium": 0
    }},
    "total": 5
  }}
}}
"""
    assert default_exit == explicit_exit == 0
    assert default_output.read_text(encoding="utf-8") == expected_json
    assert explicit_output.read_text(encoding="utf-8") == expected_json


def test_cli_scan_writes_sarif_report(tmp_path):
    output = tmp_path / "report.sarif"

    exit_code = main(
        ["posture", "scan", "--path", str(tmp_path), "--output", str(output), "--format", "sarif"]
    )

    assert exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"


def test_cli_without_fail_on_returns_0_for_high_findings(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "posture",
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["by_severity"]["high"] == 5


def test_cli_fail_on_high_returns_1_for_high_findings(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "posture",
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--output",
            str(output),
            "--fail-on",
            "high",
        ]
    )

    assert exit_code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["by_severity"]["high"] == 5


def test_cli_fail_on_high_returns_0_without_high_findings(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "posture",
            "scan",
            "--path",
            str(FIXTURES / "clean_github_project"),
            "--output",
            str(output),
            "--fail-on",
            "high",
        ]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["total"] == 0


def test_cli_fail_on_critical_returns_0_for_only_high_findings(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "posture",
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--output",
            str(output),
            "--fail-on",
            "critical",
        ]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["summary"]["by_severity"]["high"] == 5


def test_cli_missing_path_exits_1(tmp_path, capsys):
    output = tmp_path / "report.json"

    exit_code = main(
        ["posture", "scan", "--path", str(tmp_path / "missing"), "--output", str(output)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "does not exist" in captured.err
    assert not output.exists()


def test_cli_file_path_exits_1(tmp_path, capsys):
    scan_file = tmp_path / "file.txt"
    scan_file.write_text("content", encoding="utf-8")
    output = tmp_path / "report.json"

    exit_code = main(["posture", "scan", "--path", str(scan_file), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not a directory" in captured.err
    assert not output.exists()


def test_cli_uncreatable_output_exits_1(tmp_path, capsys):
    output = tmp_path / "missing" / "report.json"

    exit_code = main(["posture", "scan", "--path", str(tmp_path), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "No such file or directory" in captured.err
