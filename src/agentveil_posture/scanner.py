"""Static scan orchestrator for AgentVeil Posture."""

from __future__ import annotations

from pathlib import Path

from agentveil_posture.report import PostureReport, empty_report


def scan_path(path: Path) -> PostureReport:
    """Return an empty v0.1 report until Day 2 rule detection is implemented."""
    return empty_report(str(path.resolve()))

