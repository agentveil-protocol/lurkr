"""Static scan orchestrator for AgentVeil Posture."""

from __future__ import annotations

import os
from pathlib import Path

from agentveil_posture.report import Finding, PostureReport, build_report
from agentveil_posture.rules import (
    scan_identity_private_key_unencrypted,
    scan_workflow_deploy_without_approval,
    scan_workflow_pull_request_target_secrets_risk,
)


class ScanError(Exception):
    """Raised when the requested scan path cannot be scanned safely."""


def scan_path(path: Path) -> PostureReport:
    """Run a static, read-only scan for the currently implemented v0.1 rules."""
    root = path.resolve()
    if not root.exists():
        raise ScanError(f"scan path does not exist: {path}")
    if not root.is_dir():
        raise ScanError(f"scan path is not a directory: {path}")

    findings: list[Finding] = []
    for candidate in _iter_regular_files(root):
        finding = scan_identity_private_key_unencrypted(root, candidate)
        if finding is not None:
            findings.append(finding)
        if _is_github_workflow(root, candidate):
            findings.extend(scan_workflow_deploy_without_approval(root, candidate))
            findings.extend(scan_workflow_pull_request_target_secrets_risk(root, candidate))

    return build_report(str(root), findings)


def _iter_regular_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(str(root), followlinks=False):
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.is_symlink():
                continue
            if path.is_file():
                paths.append(path)
    return sorted(paths)


def _is_github_workflow(root: Path, path: Path) -> bool:
    relative = path.relative_to(root)
    return (
        len(relative.parts) >= 3
        and relative.parts[0] == ".github"
        and relative.parts[1] == "workflows"
        and path.suffix.lower() in {".yml", ".yaml"}
    )
