"""Rule registry stubs for AgentVeil Posture v0.1."""

from __future__ import annotations

from agentveil_posture.rules.identity import scan_identity_private_key_unencrypted
from agentveil_posture.rules.workflow import (
    scan_workflow_deploy_without_approval,
    scan_workflow_pull_request_target_secrets_risk,
)

RULES = (
    scan_identity_private_key_unencrypted,
    scan_workflow_deploy_without_approval,
    scan_workflow_pull_request_target_secrets_risk,
)

__all__ = [
    "RULES",
    "scan_identity_private_key_unencrypted",
    "scan_workflow_deploy_without_approval",
    "scan_workflow_pull_request_target_secrets_risk",
]
