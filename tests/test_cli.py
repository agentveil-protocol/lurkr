from __future__ import annotations

import json
from pathlib import Path
import shutil

from lurkr import __version__
import lurkr.report as report_module
from lurkr.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_cli_scan_writes_json_report(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(["scan", "--path", str(tmp_path), "--output", str(output)])

    assert exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["report_version"] == "0.1"
    assert data["scanner_version"] == f"lurkr/{__version__}"


def test_cli_default_and_format_json_match_existing_json_output(tmp_path, monkeypatch):
    monkeypatch.setattr(report_module, "utc_now_iso", lambda: "2026-05-07T00:00:00Z")
    scan_root = FIXTURES / "dangerous_github_project"
    default_output = tmp_path / "default.json"
    explicit_output = tmp_path / "explicit.json"

    default_exit = main(["scan", "--path", str(scan_root), "--output", str(default_output)])
    explicit_exit = main(
        [
            "scan",
            "--path",
            str(scan_root),
            "--output",
            str(explicit_output),
            "--format",
            "json",
        ]
    )

    expected = {
        "findings": [
            {
                "file": ".github/workflows/dangerous.yml",
                "line": 11,
                "message": "Workflow appears to expose direct GitHub token access.",
                "remediation": (
                    "Restrict GitHub token permissions, avoid passing direct write tokens to "
                    "agent-controlled steps, and require approval for GitHub write or deploy paths."
                ),
                "rule_id": "bypass.direct_github_token",
                "severity": "high",
            },
            {
                "file": ".github/workflows/dangerous.yml",
                "line": 12,
                "message": "Deployment workflow appears to run without an approval gate.",
                "remediation": (
                    "Add a protected GitHub environment or explicit manual approval before "
                    "production deploy, release, or publish steps."
                ),
                "rule_id": "workflow.deploy_without_approval",
                "severity": "high",
            },
            {
                "file": ".github/workflows/dangerous.yml",
                "line": 3,
                "message": (
                    "pull_request_target workflow appears to combine privileged PR context with "
                    "checkout, shell execution, or secrets access."
                ),
                "remediation": (
                    "Use pull_request for untrusted checks, avoid checking out fork code in "
                    "privileged workflows, and isolate any secret-bearing jobs."
                ),
                "rule_id": "workflow.pull_request_target_secrets_risk",
                "severity": "high",
            },
            {
                "file": "keys/synthetic_unencrypted_private_key.pem",
                "line": 1,
                "message": "Unencrypted private key file appears present.",
                "remediation": (
                    "Remove the key from the repository, rotate it if exposed, store it in a "
                    "secret manager, and use encrypted private key material when local keys are "
                    "unavoidable."
                ),
                "rule_id": "identity.private_key_unencrypted",
                "severity": "high",
            },
            {
                "file": "mcp.json",
                "line": 5,
                "message": "Agent/tool manifest appears to enable shell execution without approval.",
                "remediation": (
                    "Require explicit approval or a narrow allowlist before enabling shell, "
                    "terminal, command, bash, or subprocess tools."
                ),
                "rule_id": "tool.shell_without_approval",
                "severity": "high",
            },
        ],
        "report_version": "0.1",
        "scanned_at": "2026-05-07T00:00:00Z",
        "scanned_path": str(scan_root.resolve()),
        "scanner_version": f"lurkr/{__version__}",
        "summary": {
            "by_severity": {
                "critical": 0,
                "high": 5,
                "info": 0,
                "low": 0,
                "medium": 0,
            },
            "total": 5,
        },
    }
    assert default_exit == explicit_exit == 0
    assert json.loads(default_output.read_text(encoding="utf-8")) == expected
    assert json.loads(explicit_output.read_text(encoding="utf-8")) == expected


def test_cli_scan_writes_sarif_report(tmp_path):
    output = tmp_path / "report.sarif"

    exit_code = main(
        ["scan", "--path", str(tmp_path), "--output", str(output), "--format", "sarif"]
    )

    assert exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"


def test_cli_without_fail_on_returns_0_for_high_findings(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(
        [
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
        ["scan", "--path", str(tmp_path / "missing"), "--output", str(output)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "does not exist" in captured.err
    assert not output.exists()


def test_cli_file_path_exits_1(tmp_path, capsys):
    scan_file = tmp_path / "file.txt"
    scan_file.write_text("content", encoding="utf-8")
    output = tmp_path / "report.json"

    exit_code = main(["scan", "--path", str(scan_file), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not a directory" in captured.err
    assert not output.exists()


def test_cli_uncreatable_output_exits_1(tmp_path, capsys):
    output = tmp_path / "missing" / "report.json"

    exit_code = main(["scan", "--path", str(tmp_path), "--output", str(output)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "No such file or directory" in captured.err


def test_cli_scan_without_output_requires_output_unless_baseline_mode(tmp_path, capsys):
    exit_code = main(["scan", "--path", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--output is required" in captured.err


def test_cli_save_baseline_writes_baseline_without_report(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"

    exit_code = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--save-baseline",
            str(baseline),
        ]
    )

    captured = capsys.readouterr()
    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "Saved 5 fingerprints" in captured.out
    assert data["schema_version"] == "1.0"
    assert len(data["entries"]) == 5


def test_cli_save_baseline_also_writes_report_when_output_provided(tmp_path):
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--save-baseline",
            str(baseline),
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["summary"]["total"] == 5
    assert len(baseline_data["entries"]) == 5


def test_cli_baseline_filters_findings(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "filtered.json"
    assert (
        main(
            [
                "scan",
                "--path",
                str(FIXTURES / "dangerous_github_project"),
                "--save-baseline",
                str(baseline),
            ]
        )
        == 0
    )

    exit_code = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--baseline",
            str(baseline),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "Baseline applied: 0 new findings (5 suppressed)" in captured.out
    assert report["summary"]["total"] == 0


def test_cli_baseline_without_value_uses_scan_root_default(tmp_path, capsys):
    scan_root = tmp_path / "project"
    shutil.copytree(FIXTURES / "dangerous_github_project", scan_root)
    assert (
        main(
            [
                "scan",
                "--path",
                str(scan_root),
                "--save-baseline",
                str(scan_root / ".lurkr-baseline.json"),
            ]
        )
        == 0
    )

    exit_code = main(["scan", "--path", str(scan_root), "--baseline"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Baseline applied: 0 new findings (5 suppressed)" in captured.out


def test_cli_baseline_and_save_baseline_are_mutually_exclusive(tmp_path, capsys):
    exit_code = main(
        [
            "scan",
            "--path",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--save-baseline",
            str(tmp_path / "new-baseline.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Cannot use --baseline and --save-baseline together" in captured.err


def test_cli_baseline_missing_file_exits_2(tmp_path, capsys):
    exit_code = main(
        [
            "scan",
            "--path",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "missing.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Baseline file not found" in captured.err


def test_cli_baseline_malformed_file_exits_2(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{", encoding="utf-8")

    exit_code = main(["scan", "--path", str(tmp_path), "--baseline", str(baseline)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Baseline file is malformed" in captured.err


def test_cli_empty_baseline_matches_scan_without_baseline(tmp_path):
    baseline = tmp_path / "empty-baseline.json"
    baseline.write_text(
        json.dumps({"schema_version": "1.0", "created": "now", "entries": []}),
        encoding="utf-8",
    )
    baseline_output = tmp_path / "baseline.json"
    normal_output = tmp_path / "normal.json"

    baseline_exit = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--baseline",
            str(baseline),
            "--output",
            str(baseline_output),
        ]
    )
    normal_exit = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--output",
            str(normal_output),
        ]
    )

    baseline_report = json.loads(baseline_output.read_text(encoding="utf-8"))
    normal_report = json.loads(normal_output.read_text(encoding="utf-8"))
    assert baseline_exit == normal_exit == 0
    assert baseline_report["findings"] == normal_report["findings"]
    assert baseline_report["summary"] == normal_report["summary"]


def test_cli_baseline_fail_on_uses_only_new_findings(tmp_path):
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "filtered.json"
    assert (
        main(
            [
                "scan",
                "--path",
                str(FIXTURES / "dangerous_github_project"),
                "--save-baseline",
                str(baseline),
            ]
        )
        == 0
    )

    exit_code = main(
        [
            "scan",
            "--path",
            str(FIXTURES / "dangerous_github_project"),
            "--baseline",
            str(baseline),
            "--output",
            str(output),
            "--fail-on",
            "high",
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["summary"]["total"] == 0


def test_cli_outdated_baseline_fail_on_high_returns_1_for_new_findings(tmp_path):
    scan_root = tmp_path / "project"
    shutil.copytree(FIXTURES / "dangerous_github_project", scan_root)
    baseline = tmp_path / "baseline.json"
    output = tmp_path / "filtered.json"
    assert (
        main(
            [
                "scan",
                "--path",
                str(scan_root),
                "--save-baseline",
                str(baseline),
            ]
        )
        == 0
    )
    (scan_root / "new_key.py").write_text(
        'OPENAI_API_KEY = "sk-newnewnewnewnewnewnewnewnewnewnewnewnewnewnewnew"\n',
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "--path",
            str(scan_root),
            "--baseline",
            str(baseline),
            "--output",
            str(output),
            "--fail-on",
            "high",
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert report["summary"]["total"] == 1
    assert report["findings"][0]["rule_id"] == "agent.python_api_key_hardcoded"
