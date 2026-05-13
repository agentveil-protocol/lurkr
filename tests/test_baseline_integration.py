from __future__ import annotations

import json
from pathlib import Path
import shutil

from lurkr.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_baseline_workflow_suppresses_known_findings_and_reports_new(tmp_path):
    scan_root = tmp_path / "project"
    shutil.copytree(FIXTURES / "dangerous_github_project", scan_root)
    baseline = tmp_path / "baseline.json"
    filtered = tmp_path / "filtered.json"

    save_exit = main(
        [
            "scan",
            "--path",
            str(scan_root),
            "--save-baseline",
            str(baseline),
        ]
    )
    baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
    assert save_exit == 0
    assert len(baseline_data["entries"]) == 5

    filtered_exit = main(
        [
            "scan",
            "--path",
            str(scan_root),
            "--baseline",
            str(baseline),
            "--output",
            str(filtered),
        ]
    )
    filtered_report = json.loads(filtered.read_text(encoding="utf-8"))
    assert filtered_exit == 0
    assert filtered_report["summary"]["total"] == 0

    (scan_root / "new_key.py").write_text(
        'OPENAI_API_KEY = "sk-newnewnewnewnewnewnewnewnewnewnewnewnewnewnewnew"\n',
        encoding="utf-8",
    )

    new_exit = main(
        [
            "scan",
            "--path",
            str(scan_root),
            "--baseline",
            str(baseline),
            "--output",
            str(filtered),
            "--fail-on",
            "high",
        ]
    )
    new_report = json.loads(filtered.read_text(encoding="utf-8"))
    assert new_exit == 1
    assert new_report["summary"]["total"] == 1
    assert new_report["findings"][0]["rule_id"] == "agent.python_api_key_hardcoded"
