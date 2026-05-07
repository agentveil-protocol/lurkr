"""Versioned JSON report model for AgentVeil Posture."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json


REPORT_VERSION = "0.1"
SCANNER_VERSION = "agentveil-posture/0.2.0"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "0.0",
}
RULE_DOC_BASE_URL = "https://github.com/agentveil-protocol/agentveil-posture/blob/main/docs/rules"


def _rule_doc_url(rule_id: str) -> str:
    return f"{RULE_DOC_BASE_URL}/{rule_id}.md"


RULE_DESCRIPTORS = {
    "bypass.direct_github_token": {
        "short": "Direct GitHub token capability",
        "full": "Flags direct GitHub token references in workflows or agent manifests.",
        "help": _rule_doc_url("bypass.direct_github_token"),
    },
    "workflow.deploy_without_approval": {
        "short": "Deployment without approval gate",
        "full": "Flags deploy, release, or publish workflow steps without an approval signal.",
        "help": _rule_doc_url("workflow.deploy_without_approval"),
    },
    "workflow.pull_request_target_secrets_risk": {
        "short": "Privileged pull_request_target risk",
        "full": "Flags pull_request_target workflows that combine privileged context with checkout, run, or secrets.",
        "help": _rule_doc_url("workflow.pull_request_target_secrets_risk"),
    },
    "tool.shell_without_approval": {
        "short": "Shell-capable tool without approval",
        "full": "Flags agent tool manifests that expose shell execution without an approval flag.",
        "help": _rule_doc_url("tool.shell_without_approval"),
    },
    "identity.private_key_unencrypted": {
        "short": "Unencrypted private key file",
        "full": "Flags committed PEM private key files that appear to be unencrypted.",
        "help": _rule_doc_url("identity.private_key_unencrypted"),
    },
    "agent.python_tool_without_approval": {
        "short": "Python agent tool without approval",
        "full": "Flags Python agent tool decorators or constructors without an approval marker.",
        "help": _rule_doc_url("agent.python_tool_without_approval"),
    },
    "agent.python_subprocess_in_tool": {
        "short": "Python agent tool subprocess use",
        "full": "Flags subprocess or shell calls inside Python agent tool functions.",
        "help": _rule_doc_url("agent.python_subprocess_in_tool"),
    },
    "agent.python_eval_exec_in_tool": {
        "short": "Python agent tool dynamic execution",
        "full": "Flags eval, exec, compile, or dynamic import calls inside Python agent tool functions.",
        "help": _rule_doc_url("agent.python_eval_exec_in_tool"),
    },
    "agent.python_unrestricted_file_access": {
        "short": "Python agent tool file mutation",
        "full": "Flags file write or delete calls inside Python agent tool functions.",
        "help": _rule_doc_url("agent.python_unrestricted_file_access"),
    },
    "agent.python_api_key_hardcoded": {
        "short": "Python hardcoded API key",
        "full": "Flags API-key-shaped string literals in Python source.",
        "help": _rule_doc_url("agent.python_api_key_hardcoded"),
    },
}


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int | None
    message: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")
        category, separator, name = self.rule_id.partition(".")
        if not category or separator != "." or not name:
            raise ValueError(f"invalid rule_id: {self.rule_id}")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_")
        if not set(category) <= allowed or not set(name) <= allowed:
            raise ValueError(f"invalid rule_id: {self.rule_id}")
        if (
            self.file.startswith("/")
            or self.file.startswith("\\\\")
            or (len(self.file) >= 2 and self.file[1] == ":")
        ):
            raise ValueError("finding file must be repository-relative")


@dataclass(frozen=True)
class Summary:
    by_severity: dict[str, int]
    total: int


@dataclass(frozen=True)
class PostureReport:
    report_version: str
    scanner_version: str
    scanned_at: str
    scanned_path: str
    findings: list[Finding] = field(default_factory=list)
    summary: Summary = field(default_factory=lambda: empty_summary())

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def to_sarif(self) -> dict[str, object]:
        rule_ids = sorted(RULE_DESCRIPTORS)
        rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentVeil Posture",
                            "informationUri": "https://github.com/agentveil-protocol/agentveil-posture",
                            "semanticVersion": "0.2.0",
                            "rules": [_sarif_rule(rule_id) for rule_id in rule_ids],
                        }
                    },
                    "results": [
                        _sarif_result(finding, rule_index[finding.rule_id])
                        for finding in self.findings
                    ],
                }
            ],
        }


def empty_summary() -> Summary:
    return Summary(by_severity={severity: 0 for severity in SEVERITIES}, total=0)


def empty_report(scanned_path: str) -> PostureReport:
    return build_report(scanned_path, [])


def build_report(scanned_path: str, findings: list[Finding]) -> PostureReport:
    by_severity = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        by_severity[finding.severity] += 1
    return PostureReport(
        report_version=REPORT_VERSION,
        scanner_version=SCANNER_VERSION,
        scanned_at=utc_now_iso(),
        scanned_path=scanned_path,
        findings=findings,
        summary=Summary(by_severity=by_severity, total=len(findings)),
    )


def _sarif_rule(rule_id: str) -> dict[str, object]:
    descriptor = RULE_DESCRIPTORS[rule_id]
    return {
        "id": rule_id,
        "shortDescription": {"text": descriptor["short"]},
        "fullDescription": {"text": descriptor["full"]},
        "helpUri": descriptor["help"],
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF_LEVEL["high"],
        },
        "properties": {
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY["high"],
        },
    }


def _sarif_result(finding: Finding, rule_index: int) -> dict[str, object]:
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": finding.file.replace("\\", "/")}
    }
    if finding.line is not None:
        physical_location["region"] = {"startLine": finding.line}

    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": SEVERITY_TO_SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": physical_location,
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _sarif_fingerprint(finding),
        },
        "properties": {
            "severity": finding.severity,
            "remediation": finding.remediation,
        },
    }


def _sarif_fingerprint(finding: Finding) -> str:
    source = "\0".join(
        [
            finding.rule_id,
            finding.file.replace("\\", "/"),
            "" if finding.line is None else str(finding.line),
        ]
    )
    return hashlib.sha256(source.encode("utf-8")).hexdigest()
