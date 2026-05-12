"""Rule registry stubs for Lurkr v0.1."""

from __future__ import annotations

from lurkr.rules.credential_to_llm_context import scan_credential_to_llm_context
from lurkr.rules.declared_vs_imported import scan_declared_vs_imported_delta
from lurkr.rules.identity import scan_identity_private_key_unencrypted
from lurkr.rules.manifest import is_agent_manifest, scan_manifest_rules
from lurkr.rules.python_agent import scan_python_agent_rules
from lurkr.rules.workflow import scan_workflow_rules

RULES = (
    scan_identity_private_key_unencrypted,
    scan_workflow_rules,
    scan_manifest_rules,
    scan_python_agent_rules,
    scan_credential_to_llm_context,
    scan_declared_vs_imported_delta,
)

__all__ = [
    "RULES",
    "is_agent_manifest",
    "scan_credential_to_llm_context",
    "scan_declared_vs_imported_delta",
    "scan_identity_private_key_unencrypted",
    "scan_manifest_rules",
    "scan_python_agent_rules",
    "scan_workflow_rules",
]
