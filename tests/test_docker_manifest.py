from __future__ import annotations

from pathlib import Path


def test_dockerfile_runs_posture_scan_against_workspace():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.13-slim" in dockerfile
    assert "COPY src ./src" in dockerfile
    assert "python -m pip install --no-cache-dir ." in dockerfile
    assert "useradd --create-home --uid 1000 lurkr" in dockerfile
    assert "USER lurkr" in dockerfile
    assert 'WORKDIR /workspace' in dockerfile
    assert 'ENTRYPOINT ["lurkr", "scan", "--path", "/workspace"]' in dockerfile
    assert 'CMD ["--output", "/workspace/lurkr-report.json"]' in dockerfile


def test_dockerignore_excludes_build_and_git_context():
    ignored = set(Path(".dockerignore").read_text(encoding="utf-8").splitlines())

    assert ".git" in ignored
    assert "build" in ignored
    assert "dist" in ignored
    assert "*.egg-info" in ignored
    assert "__pycache__" in ignored
