"""GitHub workflow posture rules."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml

from agentveil_posture.report import Finding


MAX_WORKFLOW_BYTES = 1_000_000
MAX_YAML_ALIAS_TOKENS = 25
DEPLOY_MARKER_RE = re.compile(
    r"\b(deploy|deployment|release|kubectl)\b"
    r"|\b(npm|pnpm|yarn|pypi|twine|poetry)\s+publish\b"
    r"|\bterraform\s+apply\b"
    r"|\bcloudformation\s+deploy\b"
    r"|\bserverless\s+deploy\b",
    re.IGNORECASE,
)
APPROVAL_MARKERS = ("approval", "manual approval", "review", "protected environment")
PULL_REQUEST_TARGET_RE = re.compile(r"(^|\s)pull_request_target\s*:", re.MULTILINE)
PULL_REQUEST_TARGET_INLINE_RE = re.compile(
    r"^\s*on\s*:\s*(\[.*pull_request_target.*\]|pull_request_target)\s*$",
    re.MULTILINE,
)
PULL_REQUEST_TARGET_LIST_RE = re.compile(r"^\s*-\s*pull_request_target\s*$", re.MULTILINE)


def scan_workflow_deploy_without_approval(root: Path, path: Path) -> list[Finding]:
    parsed = _load_workflow(path)
    if parsed is None:
        return []
    _data, text, lines = parsed
    deploy_line = _first_deploy_line(lines)
    if deploy_line is None or _has_approval_signal(text):
        return []
    return [
        Finding(
            rule_id="workflow.deploy_without_approval",
            severity="high",
            file=path.relative_to(root).as_posix(),
            line=deploy_line,
            message="Deployment workflow appears to run without an approval gate.",
            remediation=(
                "Add a protected GitHub environment or explicit manual approval "
                "before production deploy, release, or publish steps."
            ),
        )
    ]


def scan_workflow_pull_request_target_secrets_risk(root: Path, path: Path) -> list[Finding]:
    parsed = _load_workflow(path)
    if parsed is None:
        return []
    _data, text, lines = parsed
    trigger_line = _pull_request_target_line(lines)
    if trigger_line is None or not _has_pull_request_target_risk(text):
        return []
    return [
        Finding(
            rule_id="workflow.pull_request_target_secrets_risk",
            severity="high",
            file=path.relative_to(root).as_posix(),
            line=trigger_line,
            message=(
                "pull_request_target workflow appears to combine privileged PR "
                "context with checkout, shell execution, or secrets access."
            ),
            remediation=(
                "Use pull_request for untrusted checks, avoid checking out fork "
                "code in privileged workflows, and isolate any secret-bearing jobs."
            ),
        )
    ]


def _load_workflow(path: Path) -> tuple[Any, str, list[str]] | None:
    try:
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            return None
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if _has_excessive_yaml_aliases(text):
        return None
    try:
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        return None
    return data, text, text.splitlines()


def _has_excessive_yaml_aliases(text: str) -> bool:
    aliases = 0
    try:
        for token in yaml.scan(text):
            if isinstance(token, yaml.AliasToken):
                aliases += 1
                if aliases > MAX_YAML_ALIAS_TOKENS:
                    return True
    except yaml.YAMLError:
        return True
    return False


def _first_deploy_line(lines: list[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if DEPLOY_MARKER_RE.search(line):
            return line_number
    return None


def _has_approval_signal(text: str) -> bool:
    normalized = text.lower()
    if re.search(r"^\s*environment\s*:", text, flags=re.MULTILINE):
        return True
    return any(marker in normalized for marker in APPROVAL_MARKERS)


def _pull_request_target_line(lines: list[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if "pull_request_target" in line:
            return line_number
    return None


def _has_pull_request_target_risk(text: str) -> bool:
    if not _has_pull_request_target_trigger(text):
        return False
    normalized = text.lower()
    return (
        "actions/checkout" in normalized
        or "${{ secrets." in normalized
        or re.search(r"^\s*-?\s*run\s*:", text, flags=re.MULTILINE) is not None
        or "github.event.pull_request.head" in normalized
    )


def _has_pull_request_target_trigger(text: str) -> bool:
    return (
        PULL_REQUEST_TARGET_RE.search(text) is not None
        or PULL_REQUEST_TARGET_INLINE_RE.search(text) is not None
        or PULL_REQUEST_TARGET_LIST_RE.search(text) is not None
    )
