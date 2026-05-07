from __future__ import annotations

import json
from pathlib import Path
import subprocess

from validation import phase10e


def write_fixture(root: Path, *, observed: list[dict[str, object]] | None = None) -> Path:
    fixture = root / "example"
    fixture.mkdir()
    (fixture / "requirements.txt").write_text("example-framework>=1,<2\n", encoding="utf-8")
    (fixture / "agent.py").write_text("def tool():\n    return 'ok'\n", encoding="utf-8")
    (fixture / "expected_findings.json").write_text(
        json.dumps(
            {
                "framework": "example",
                "framework_version_constraint": "example-framework>=1,<2",
                "import_checks": ["example_framework"],
                "expected_findings": [
                    {"rule_id": "agent.python_tool_without_approval", "file": "agent.py", "line": 10}
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "observed.json").write_text(
        json.dumps(
            {
                "findings": observed
                if observed is not None
                else [
                    {
                        "rule_id": "agent.python_tool_without_approval",
                        "file": "agent.py",
                        "line": 10,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return fixture


def test_compare_findings_reports_extra_and_missing():
    expected = {
        phase10e.FindingKey("agent.python_tool_without_approval", "agent.py", 10),
        phase10e.FindingKey("agent.python_subprocess_in_tool", "agent.py", 12),
    }
    observed = {
        phase10e.FindingKey("agent.python_tool_without_approval", "agent.py", 10),
        phase10e.FindingKey("agent.python_eval_exec_in_tool", "agent.py", 14),
    }

    extra, missing = phase10e.compare_findings(expected, observed)

    assert extra == [phase10e.FindingKey("agent.python_eval_exec_in_tool", "agent.py", 14)]
    assert missing == [phase10e.FindingKey("agent.python_subprocess_in_tool", "agent.py", 12)]


def test_run_fixture_invokes_venv_install_import_check_and_scan(tmp_path, monkeypatch):
    fixture = write_fixture(tmp_path)
    commands: list[list[str]] = []

    def fake_run(command, check, text, capture_output):
        commands.append([str(part) for part in command])
        if "agentveil" in str(command[0]):
            output = Path(command[command.index("--output") + 1])
            output.write_text((tmp_path / "observed.json").read_text(encoding="utf-8"), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(phase10e.subprocess, "run", fake_run)

    result = phase10e.run_fixture(
        fixture,
        venv_root=tmp_path / "venvs",
        no_cache=True,
        python_executable="/usr/bin/python3",
    )

    assert result.passed
    assert commands[0][:3] == ["/usr/bin/python3", "-m", "venv"]
    assert any(command[-2:] == ["-r", str(fixture / "requirements.txt")] for command in commands)
    assert any(command[-2:] == ["-e", str(phase10e.REPO_ROOT)] for command in commands)
    assert any("importlib.util.find_spec" in " ".join(command) for command in commands)
    assert any("posture" in command and "scan" in command for command in commands)


def test_run_fixture_fails_on_extra_and_missing_findings(tmp_path, monkeypatch):
    fixture = write_fixture(
        tmp_path,
        observed=[
            {"rule_id": "agent.python_eval_exec_in_tool", "file": "agent.py", "line": 14},
        ],
    )

    def fake_run(command, check, text, capture_output):
        if "agentveil" in str(command[0]):
            output = Path(command[command.index("--output") + 1])
            output.write_text((tmp_path / "observed.json").read_text(encoding="utf-8"), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(phase10e.subprocess, "run", fake_run)

    result = phase10e.run_fixture(
        fixture,
        venv_root=tmp_path / "venvs",
        no_cache=True,
        python_executable="/usr/bin/python3",
    )

    assert not result.passed
    assert result.extra == [phase10e.FindingKey("agent.python_eval_exec_in_tool", "agent.py", 14)]
    assert result.missing == [phase10e.FindingKey("agent.python_tool_without_approval", "agent.py", 10)]


def test_main_returns_failure_when_any_fixture_fails(tmp_path, monkeypatch, capsys):
    ok = phase10e.FixtureResult("ok", 1, 1, [], [], True)
    bad = phase10e.FixtureResult(
        "bad",
        1,
        0,
        [],
        [phase10e.FindingKey("agent.python_tool_without_approval", "agent.py", 10)],
        False,
    )
    monkeypatch.setattr(phase10e, "discover_fixture_dirs", lambda framework=None: [tmp_path / "ok", tmp_path / "bad"])
    monkeypatch.setattr(phase10e, "run_fixture", lambda fixture, **kwargs: ok if fixture.name == "ok" else bad)

    exit_code = phase10e.main([])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "ok,1,1,0,0,PASS" in output
    assert "bad,1,0,0,1,FAIL" in output
