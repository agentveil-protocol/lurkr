"""Static scan orchestrator for Lurkr."""

from __future__ import annotations

import os
from pathlib import Path

from lurkr.js_ast import is_js_or_ts_source
from lurkr.paths import prune_excluded_dirnames
from lurkr.report import Finding, PostureReport, build_report
from lurkr.rules import (
    is_agent_manifest,
    scan_credential_to_llm_context,
    scan_declared_vs_imported_delta,
    scan_dynamic_prompt_from_user_input,
    scan_identity_private_key_unencrypted,
    scan_js_agent_rules,
    scan_manifest_rules,
    scan_python_agent_rules,
    scan_unverified_mcp_endpoint,
    scan_workflow_rules,
)


class ScanError(Exception):
    """Raised when the requested scan path cannot be scanned safely."""


def scan_path(path: Path) -> PostureReport:
    """Run a static, read-only scan for the currently implemented rules."""
    root = path.resolve()
    if not root.exists():
        raise ScanError(f"scan path does not exist: {path}")
    if not root.is_dir():
        raise ScanError(f"scan path is not a directory: {path}")

    findings: list[Finding] = []
    python_files: list[Path] = []
    js_files: list[Path] = []
    for candidate in _iter_regular_files(root):
        finding = scan_identity_private_key_unencrypted(root, candidate)
        if finding is not None:
            findings.append(finding)
        if _is_github_workflow(root, candidate):
            findings.extend(scan_workflow_rules(root, candidate))
        if is_agent_manifest(root, candidate):
            findings.extend(scan_manifest_rules(root, candidate))
            findings.extend(scan_unverified_mcp_endpoint(root, candidate))
        if _is_python_source(candidate):
            python_files.append(candidate)
            findings.extend(scan_python_agent_rules(root, candidate))
            findings.extend(scan_credential_to_llm_context(root, candidate))
            findings.extend(scan_dynamic_prompt_from_user_input(root, candidate))
        if is_js_or_ts_source(candidate):
            js_files.append(candidate)
            findings.extend(scan_js_agent_rules(root, candidate))
    findings.extend(scan_declared_vs_imported_delta(root, python_files, js_files))

    return build_report(str(root), findings)


def _iter_regular_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        prune_excluded_dirnames(dirnames)
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


def _is_python_source(path: Path) -> bool:
    return path.suffix.lower() == ".py"
