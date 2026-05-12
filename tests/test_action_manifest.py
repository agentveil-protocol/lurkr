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
    install_step = next(step for step in action["runs"]["steps"] if step["name"] == "Install lurkr")
    assert install_step["working-directory"] == "${{ github.action_path }}"
    assert scan_step["env"]["LURKR_FAIL_ON"] == "${{ inputs.fail-on }}"
    assert "lurkr scan" in scan_step["run"]
    assert '--format "${{ inputs.format }}"' in scan_step["run"]
    assert '--fail-on "$LURKR_FAIL_ON"' in scan_step["run"]
    assert 'echo "report=${{ inputs.output }}" >> "$GITHUB_OUTPUT"' in scan_step["run"]
    assert scan_step["run"].index('echo "report=') < scan_step["run"].index("lurkr scan")


def test_action_smoke_workflow_exercises_review_and_fail_on_modes():
    workflow = yaml.safe_load(
        Path(".github/workflows/action-smoke-test.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["local-action-smoke"]
    steps = job["steps"]

    assert workflow["permissions"] == {"contents": "read"}
    assert job["runs-on"] == "ubuntu-latest"

    review = next(step for step in steps if step.get("id") == "review")
    assert review["uses"] == "./"
    assert review["with"]["path"] == "fixtures/dangerous_github_project"
    assert review["with"]["output"] == "action-smoke-review.json"
    assert "fail-on" not in review["with"]

    fail_on = next(step for step in steps if step.get("id") == "fail_on")
    assert fail_on["uses"] == "./"
    assert fail_on["continue-on-error"] is True
    assert fail_on["with"]["path"] == "fixtures/dangerous_github_project"
    assert fail_on["with"]["output"] == "action-smoke-fail-on.json"
    assert fail_on["with"]["fail-on"] == "high"

    verify = next(step for step in steps if step["name"] == "Verify fail-on behavior")
    assert 'steps.fail_on.outcome }}" = "failure"' in verify["run"]
    assert "action-smoke-fail-on.json" in verify["run"]
