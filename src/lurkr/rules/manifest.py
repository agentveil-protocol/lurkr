"""Agent/tool manifest posture rules."""

from __future__ import annotations

import fnmatch
from pathlib import Path
import re
from typing import Any

from lurkr.report import Finding
from lurkr.rules.parsing import ParsedDocument, load_json_document, load_yaml_document


EXACT_MANIFEST_PATHS = {
    ".mcp.json",
    ".cursor/mcp.json",
    "mcp.json",
    "mcp_config.json",
}
MANIFEST_NAME_PATTERNS = (
    "crew*.yaml",
    "crew*.yml",
    "autogen*.json",
    "autogen*.yaml",
    "autogen*.yml",
    "langchain*.json",
    "langchain*.yaml",
    "langchain*.yml",
)
CREWAI_PATH_REGEX = re.compile(r"(^|/)crews/[^/]+/config/(agents|tasks)\.ya?ml$")
DIRECT_GITHUB_TOKEN_RE = re.compile(
    r"\bsecrets\.(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)\b"
    r"|^\s*[\"']?(GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|github-token)[\"']?\s*[:=]"
    r"|[\"'](GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|github-token)[\"']\s*:",
    re.IGNORECASE | re.MULTILINE,
)
SHELL_KEY_RE = re.compile(r"(^|[_-])(shell|bash|command|terminal|subprocess)([_-]|$)", re.I)
SHELL_LINE_RE = re.compile(
    r"(^|[\s,{])[\"']?(shell|bash|command|terminal|subprocess)[\"']?\s*[:=]",
    re.I,
)
SHELL_TOOL_NAMES = {"shell", "bash", "terminal", "subprocess", "command"}
TOOL_NAME_KEYS = {"name", "tool", "tool_name", "type"}
APPROVAL_KEY_RE = re.compile(r"(approval|approve|human)", re.I)
MAX_MANIFEST_SCAN_DEPTH = 100


def is_agent_manifest(root: Path, path: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    if relative in EXACT_MANIFEST_PATHS:
        return True
    if CREWAI_PATH_REGEX.search(relative):
        return True
    name = path.name.lower()
    return any(fnmatch.fnmatch(name, pattern) for pattern in MANIFEST_NAME_PATTERNS)


def scan_manifest_rules(root: Path, path: Path) -> list[Finding]:
    document = load_manifest(path)
    if document is None:
        return []
    findings: list[Finding] = []
    findings.extend(scan_manifest_direct_github_token(root, path, document))
    findings.extend(scan_manifest_shell_without_approval(root, path, document))
    return findings


def load_manifest(path: Path) -> ParsedDocument | None:
    if path.suffix.lower() == ".json":
        return load_json_document(path)
    if path.suffix.lower() in {".yaml", ".yml"}:
        return load_yaml_document(path)
    return None


def scan_manifest_direct_github_token(
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
            message="Agent/tool manifest appears to expose direct GitHub token access.",
            remediation=(
                "Remove direct GitHub tokens from agent manifests, restrict token "
                "permissions, and require approval for GitHub write or deploy paths."
            ),
        )
    ]


def scan_manifest_shell_without_approval(
    root: Path, path: Path, document: ParsedDocument
) -> list[Finding]:
    try:
        has_shell = _has_shell_capability(document.data)
        has_approval = _has_approval_signal(document.data)
    except RecursionError:
        return []
    if not has_shell or has_approval:
        return []
    return [
        Finding(
            rule_id="tool.shell_without_approval",
            severity="high",
            file=path.relative_to(root).as_posix(),
            line=_first_shell_line(document.lines),
            message="Agent/tool manifest appears to enable shell execution without approval.",
            remediation=(
                "Require explicit approval or a narrow allowlist before enabling "
                "shell, terminal, command, bash, or subprocess tools."
            ),
        )
    ]


def _has_shell_capability(value: Any, depth: int = 0) -> bool:
    if depth > MAX_MANIFEST_SCAN_DEPTH:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            if _is_tool_name_key(key) and _is_exact_shell_tool_name(child):
                return True
            if SHELL_KEY_RE.search(str(key)) and _value_enabled(child):
                return True
            if _has_shell_capability(child, depth + 1):
                return True
    if isinstance(value, list):
        return any(
            _is_exact_shell_tool_name(item) or _has_shell_capability(item, depth + 1)
            for item in value
        )
    return False


def _has_approval_signal(value: Any, depth: int = 0) -> bool:
    if depth > MAX_MANIFEST_SCAN_DEPTH:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            if APPROVAL_KEY_RE.search(str(key)) and _value_enabled(child):
                return True
            if _has_approval_signal(child, depth + 1):
                return True
    if isinstance(value, list):
        return any(_has_approval_signal(item, depth + 1) for item in value)
    return False


def _value_enabled(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "false", "no", "off", "none"}
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _is_tool_name_key(key: Any) -> bool:
    return str(key).strip().lower() in TOOL_NAME_KEYS


def _is_exact_shell_tool_name(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() in SHELL_TOOL_NAMES


def _first_shell_line(lines: list[str]) -> int | None:
    return _first_matching_line(lines, SHELL_LINE_RE)


def _first_matching_line(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return line_number
    return None
