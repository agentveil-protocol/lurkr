from __future__ import annotations

import json

from agentveil_posture.cli import main


def test_cli_scan_writes_json_report(tmp_path):
    output = tmp_path / "report.json"

    exit_code = main(["posture", "scan", "--path", str(tmp_path), "--output", str(output)])

    assert exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["report_version"] == "0.1"
    assert data["scanner_version"] == "agentveil-posture/0.1.0"


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
