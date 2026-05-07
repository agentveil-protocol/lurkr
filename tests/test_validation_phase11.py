from __future__ import annotations

from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_docker_publish_workflow_runs_only_on_tags_or_dispatch():
    workflow = yaml.load(
        (REPO_ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(),
        Loader=yaml.BaseLoader,
    )

    assert workflow["on"]["push"]["tags"] == ["v*"]
    assert "workflow_dispatch" in workflow["on"]
    assert workflow["permissions"] == {"contents": "read", "packages": "write"}


def test_docker_publish_workflow_uses_ghcr_tag_and_latest():
    workflow = yaml.load(
        (REPO_ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    build_step = workflow["jobs"]["docker-publish"]["steps"][-1]
    tags = build_step["with"]["tags"]

    assert "ghcr.io/agentveil-protocol/agentveil-posture:${{ github.ref_name }}" in tags
    assert "ghcr.io/agentveil-protocol/agentveil-posture:latest" in tags
    assert build_step["with"]["push"] == "true"


def test_phase11_release_dry_run_script_builds_checks_and_smokes_wheel():
    script = (REPO_ROOT / "validation" / "phase11_release_dry_run.sh").read_text()

    assert "-m build --sdist --wheel" in script
    assert "twine check" in script
    assert "sha256=" in script
    assert "--format sarif" in script
    assert "PASS: release dry-run smoke" in script
