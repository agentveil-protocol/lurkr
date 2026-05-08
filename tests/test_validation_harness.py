from __future__ import annotations

import json

from validation.run import run_validation


def test_validation_harness_passes_exact_label(tmp_path):
    checkout = tmp_path / "repo"
    scan_root = checkout / "scan"
    scan_root.mkdir(parents=True)
    (scan_root / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "shell"}]}),
        encoding="utf-8",
    )
    label = tmp_path / "label.json"
    label.write_text(
        json.dumps(
            {
                "repo": "local/test",
                "commit": "WORKTREE",
                "checkout_path": str(checkout),
                "scan_path": "scan",
                "expected_findings": [
                    {
                        "rule_id": "tool.shell_without_approval",
                        "file": "mcp.json",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_validation(
        [label],
        workdir=tmp_path / "work",
        require_all_rules=False,
        repo_root=tmp_path,
    )

    assert result.exit_code == 0
    assert result.stats["tool.shell_without_approval"].precision == 1.0
    assert result.stats["tool.shell_without_approval"].recall == 1.0


def test_validation_harness_fails_on_unexpected_finding(tmp_path):
    checkout = tmp_path / "repo"
    scan_root = checkout / "scan"
    scan_root.mkdir(parents=True)
    (scan_root / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "shell"}]}),
        encoding="utf-8",
    )
    label = tmp_path / "label.json"
    label.write_text(
        json.dumps(
            {
                "repo": "local/test",
                "commit": "WORKTREE",
                "checkout_path": str(checkout),
                "scan_path": "scan",
                "expected_findings": [],
            }
        ),
        encoding="utf-8",
    )

    result = run_validation(
        [label],
        workdir=tmp_path / "work",
        precision_threshold=1.0,
        require_all_rules=False,
        repo_root=tmp_path,
    )

    assert result.exit_code == 1
    assert result.stats["tool.shell_without_approval"].false_positive == 1
