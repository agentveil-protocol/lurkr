from __future__ import annotations

from pathlib import Path

import yaml


def test_action_manifest_wires_report_output():
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["format"]["default"] == "json"
    assert "json or sarif" in action["inputs"]["format"]["description"]
    assert action["inputs"]["fail-on"]["default"] == ""
    assert action["outputs"]["report"]["value"] == "${{ steps.scan.outputs.report }}"
    assert action["outputs"]["report"]["description"] == "Path to the generated report"
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    install_step = next(
        step for step in action["runs"]["steps"] if step["name"] == "Install agentveil-posture"
    )
    assert install_step["working-directory"] == "${{ github.action_path }}"
    assert scan_step["env"]["AGENTVEIL_POSTURE_FAIL_ON"] == "${{ inputs.fail-on }}"
    assert "agentveil posture scan" in scan_step["run"]
    assert '--format "${{ inputs.format }}"' in scan_step["run"]
    assert '--fail-on "$AGENTVEIL_POSTURE_FAIL_ON"' in scan_step["run"]
    assert 'echo "report=${{ inputs.output }}" >> "$GITHUB_OUTPUT"' in scan_step["run"]
    assert scan_step["run"].index('echo "report=') < scan_step["run"].index(
        "agentveil posture scan"
    )
