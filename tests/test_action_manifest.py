from __future__ import annotations

from pathlib import Path

import yaml


def test_action_manifest_wires_report_output():
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["outputs"]["report"]["value"] == "${{ steps.scan.outputs.report }}"
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    install_step = next(
        step for step in action["runs"]["steps"] if step["name"] == "Install agentveil-posture"
    )
    assert install_step["working-directory"] == "${{ github.action_path }}"
    assert "agentveil posture scan" in scan_step["run"]
    assert 'echo "report=${{ inputs.output }}" >> "$GITHUB_OUTPUT"' in scan_step["run"]
