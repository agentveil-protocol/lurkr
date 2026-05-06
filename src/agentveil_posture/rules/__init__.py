"""Rule registry stubs for AgentVeil Posture v0.1."""

from __future__ import annotations

from agentveil_posture.rules.identity import scan_identity_private_key_unencrypted

RULES = (scan_identity_private_key_unencrypted,)

__all__ = ["RULES", "scan_identity_private_key_unencrypted"]
