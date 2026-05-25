"""Rule registry stubs for Lurkr v0.1."""

from __future__ import annotations

from lurkr.rules.credential_to_llm_context import scan_credential_to_llm_context
from lurkr.rules.declared_vs_imported import scan_declared_vs_imported_delta
from lurkr.rules.dynamic_prompt_from_user_input import scan_dynamic_prompt_from_user_input
from lurkr.rules.identity import scan_identity_private_key_unencrypted
from lurkr.rules.js_agent import scan_js_agent_rules
from lurkr.rules.manifest import is_agent_manifest, scan_manifest_rules
from lurkr.rules.python_agent import scan_python_agent_rules
from lurkr.rules.unverified_mcp_endpoint import scan_unverified_mcp_endpoint
from lurkr.rules.workflow import scan_workflow_rules

RULES = (
    scan_identity_private_key_unencrypted,
    scan_workflow_rules,
    scan_manifest_rules,
    scan_unverified_mcp_endpoint,
    scan_python_agent_rules,
    scan_js_agent_rules,
    scan_credential_to_llm_context,
    scan_dynamic_prompt_from_user_input,
    scan_declared_vs_imported_delta,
)

__all__ = [
    "RULES",
    "is_agent_manifest",
    "scan_credential_to_llm_context",
    "scan_declared_vs_imported_delta",
    "scan_dynamic_prompt_from_user_input",
    "scan_identity_private_key_unencrypted",
    "scan_js_agent_rules",
    "scan_manifest_rules",
    "scan_python_agent_rules",
    "scan_unverified_mcp_endpoint",
    "scan_workflow_rules",
]
