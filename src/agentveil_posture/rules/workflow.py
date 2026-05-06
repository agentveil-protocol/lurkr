"""GitHub workflow posture rules."""

from __future__ import annotations

from pathlib import Path
import re

from agentveil_posture.report import Finding
from agentveil_posture.rules.parsing import (
    MAX_TEXT_BYTES as MAX_WORKFLOW_BYTES,
    MAX_YAML_ALIAS_TOKENS,
    ParsedDocument,
    load_yaml_document,
)


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
DIRECT_GITHUB_TOKEN_RE = re.compile(
    r"\bsecrets\.(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)\b"
    r"|^\s*(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|github-token)\s*:",
    re.IGNORECASE | re.MULTILINE,
)


def scan_workflow_rules(root: Path, path: Path) -> list[Finding]:
    document = load_workflow(path)
    if document is None:
        return []
    findings: list[Finding] = []
    findings.extend(scan_workflow_direct_github_token(root, path, document))
    findings.extend(scan_workflow_deploy_without_approval(root, path, document))
    findings.extend(scan_workflow_pull_request_target_secrets_risk(root, path, document))
    return findings


def scan_workflow_direct_github_token(
    root: Path, path: Path, document: ParsedDocument
) -> list[Finding]:
    line = _first_matching_line(document.lines, DIRECT_GITHUB_TOKEN_RE)
    if line is None:
        return []
    return [
        Finding(
            rule_id="bypass.direct_github_token",
            severity="high",
            file=path.relative_to(root).as_posix(),
            line=line,
            message="Workflow appears to expose direct GitHub token access.",
            remediation=(
                "Restrict GitHub token permissions, avoid passing direct write "
                "tokens to agent-controlled steps, and require approval for "
                "GitHub write or deploy paths."
            ),
        )
    ]


def scan_workflow_deploy_without_approval(
    root: Path, path: Path, document: ParsedDocument
) -> list[Finding]:
    deploy_line = _first_deploy_line(document.lines)
    if deploy_line is None or _has_approval_signal(document.text):
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


def scan_workflow_pull_request_target_secrets_risk(
    root: Path, path: Path, document: ParsedDocument
) -> list[Finding]:
    trigger_line = _pull_request_target_line(document.lines)
    if trigger_line is None or not _has_pull_request_target_risk(document.text):
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


def load_workflow(path: Path) -> ParsedDocument | None:
    return load_yaml_document(path, max_bytes=MAX_WORKFLOW_BYTES)


def _first_deploy_line(lines: list[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if DEPLOY_MARKER_RE.search(line):
            return line_number
    return None


def _first_matching_line(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return line_number
    return None


def _has_approval_signal(text: str) -> bool:
    normalized = text.lower()
    if re.search(r"^\s*environment\s*:", text, flags=re.MULTILINE):
        return True
    return any(marker in normalized for marker in APPROVAL_MARKERS)


def _pull_request_target_line(lines: list[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
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
    text = _without_comment_lines(text)
    return (
        PULL_REQUEST_TARGET_RE.search(text) is not None
        or PULL_REQUEST_TARGET_INLINE_RE.search(text) is not None
        or PULL_REQUEST_TARGET_LIST_RE.search(text) is not None
    )


def _without_comment_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
