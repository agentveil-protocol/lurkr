"""Rule registry stubs for AgentVeil Posture v0.1."""

from __future__ import annotations

from agentveil_posture.rules.identity import scan_identity_private_key_unencrypted
from agentveil_posture.rules.manifest import is_agent_manifest, scan_manifest_rules
from agentveil_posture.rules.python_agent import scan_python_agent_rules
from agentveil_posture.rules.workflow import scan_workflow_rules

RULES = (
    scan_identity_private_key_unencrypted,
    scan_workflow_rules,
    scan_manifest_rules,
    scan_python_agent_rules,
)

__all__ = [
    "RULES",
    "is_agent_manifest",
    "scan_identity_private_key_unencrypted",
    "scan_manifest_rules",
    "scan_python_agent_rules",
    "scan_workflow_rules",
]
