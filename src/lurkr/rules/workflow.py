"""GitHub workflow posture rules."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from lurkr.report import Finding
from lurkr.rules.parsing import (
    MAX_TEXT_BYTES as MAX_WORKFLOW_BYTES,
    MAX_YAML_ALIAS_TOKENS,
    ParsedDocument,
    load_yaml_document,
)


STRONG_DEPLOY_RE = re.compile(
    r"\b(deploy|kubectl)\b"
    r"|\b(npm|pnpm|yarn|pypi|twine|poetry)\s+publish\b"
    r"|\bterraform\s+apply\b"
    r"|\bcloudformation\s+deploy\b"
    r"|\bserverless\s+deploy\b",
    re.IGNORECASE,
)
DEPLOY_PHRASE_MARKERS = (
    "gh release create",
    "docker push",
    "helm upgrade",
    "pulumi up",
    "sam deploy",
    "gcloud run deploy",
    "firebase deploy",
    "vercel deploy",
    "netlify deploy",
    "fly deploy",
    "wrangler deploy",
    "aws ecs update-service",
)
DEPLOY_PHRASE_RE = re.compile(
    r"(?<![\w-])("
    + "|".join(re.escape(marker).replace(r"\ ", r"\s+") for marker in DEPLOY_PHRASE_MARKERS)
    + r")(?![\w-])",
    re.IGNORECASE,
)
LEGACY_DEPLOY_MARKER_RE = re.compile(r"\b(deployment|release)\b", re.IGNORECASE)
BUILD_CONFIG_EXCLUSIONS = re.compile(
    r"--configuration\s+\w+"
    r"|--framework\s+\w+"
    r"|\brelease\s+notes\b"
    r"|\brelease\s+candidate\b",
    re.IGNORECASE,
)
DEPLOY_EXCLUSION_RE = re.compile(
    r"(?<![\w-])("
    r"docker\s+build"
    r"|helm\s+template"
    r"|helm\s+lint"
    r"|pulumi\s+preview"
    r"|terraform\s+plan"
    r"|vercel\s+pull"
    r"|vercel\s+build"
    r"|vercel\s+deployment"
    r"|gh\s+release\s+list"
    r"|sam\s+deployment\s+package"
    r"|firebase\s+deployment\s+preview"
    r"|netlify\s+deployment\s+summary"
    r"|fly\s+deployment\s+notes"
    r"|npm\s+pack"
    r")(?![\w-])",
    re.IGNORECASE,
)
STEP_APPROVAL_IF_RE = re.compile(
    r"\b(?:needs|steps)\.[\w-]+\.outputs\."
    r"(?:approved|approval_required|manual_approval|review_approved|reviewed)\b"
    r"|\bgithub\.event\.review\.",
    re.IGNORECASE,
)
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
    if deploy_line is None or _has_approval_signal(document.data):
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
    if trigger_line is None or not _has_pull_request_target_risk(document.text, document.data):
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
    in_run_block = False
    run_indent = 0

    for line_number, line in enumerate(lines, start=1):
        if in_run_block:
            if line.strip() and _indent(line) <= run_indent:
                in_run_block = False
            else:
                executable = _strip_inline_comment(line)
                if executable and _has_deploy_marker(executable):
                    return line_number
                continue

        run_value = _run_value(line)
        if run_value is None:
            continue
        executable = _strip_inline_comment(run_value)
        if _is_block_scalar(executable):
            in_run_block = True
            run_indent = _indent(line)
            continue

        if executable and _has_deploy_marker(executable):
            return line_number
    return None


def _first_matching_line(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return line_number
    return None


def _has_approval_signal(data: Any) -> bool:
    jobs = _workflow_jobs(data)
    deploy_sites = _deploy_job_sites(jobs)
    if not deploy_sites:
        return False
    return all(
        _job_has_environment(job)
        or _needs_environment_job(job_id, jobs, seen=set())
        or _step_has_approval_if(step)
        for job_id, job, step in deploy_sites
    )


def _pull_request_target_line(lines: list[str]) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#"):
            continue
        if "pull_request_target" in line:
            return line_number
    return None


def _has_pull_request_target_risk(text: str, data: Any) -> bool:
    if not _has_pull_request_target_trigger(text):
        return False
    if _contains_github_script_step(data):
        return True
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


def _strip_inline_comment(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("#"):
        return ""
    return stripped.split("#", 1)[0].strip()


def _run_value(line: str) -> str | None:
    match = re.match(r"^\s*(?:-\s*)?run\s*:\s*(.*)$", line)
    if match is None:
        return None
    return match.group(1).strip()


def _is_block_scalar(value: str) -> bool:
    return value in {"|", "|-", "|+", ">", ">-", ">+"}


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _has_deploy_marker(line: str) -> bool:
    normalized = " ".join(line.split())
    if STRONG_DEPLOY_RE.search(normalized) or DEPLOY_PHRASE_RE.search(normalized):
        return True
    if BUILD_CONFIG_EXCLUSIONS.search(normalized) or DEPLOY_EXCLUSION_RE.search(normalized):
        return False
    return LEGACY_DEPLOY_MARKER_RE.search(normalized) is not None


def _workflow_jobs(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    jobs = data.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _deploy_job_sites(
    jobs: dict[str, Any],
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    sites: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for job_id, job in jobs.items():
        if not isinstance(job_id, str) or not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict) and _step_has_deploy_marker(step):
                sites.append((job_id, job, step))
    return sites


def _step_has_deploy_marker(step: dict[str, Any]) -> bool:
    run = step.get("run")
    if not isinstance(run, str):
        return False
    for line in run.splitlines() or [run]:
        executable = _strip_inline_comment(line)
        if executable and _has_deploy_marker(executable):
            return True
    return False


def _job_has_environment(job: dict[str, Any]) -> bool:
    environment = job.get("environment")
    if isinstance(environment, str):
        return bool(environment.strip())
    if isinstance(environment, dict):
        name = environment.get("name")
        return isinstance(name, str) and bool(name.strip())
    return False


def _needs_environment_job(
    job_id: str, jobs: dict[str, Any], *, seen: set[str]
) -> bool:
    if job_id in seen:
        return False
    seen.add(job_id)
    job = jobs.get(job_id)
    if not isinstance(job, dict):
        return False
    for upstream_id in _needs_job_ids(job.get("needs")):
        upstream = jobs.get(upstream_id)
        if not isinstance(upstream, dict):
            continue
        if _job_has_environment(upstream) or _needs_environment_job(
            upstream_id, jobs, seen=seen
        ):
            return True
    return False


def _needs_job_ids(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _step_has_approval_if(step: dict[str, Any]) -> bool:
    condition = step.get("if")
    return isinstance(condition, str) and STEP_APPROVAL_IF_RE.search(condition) is not None


def _contains_github_script_step(value: Any) -> bool:
    if isinstance(value, dict):
        uses = value.get("uses")
        if isinstance(uses, str) and re.match(r"^actions/github-script@.+$", uses, flags=re.I):
            return True
        return any(_contains_github_script_step(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_github_script_step(item) for item in value)
    return False
