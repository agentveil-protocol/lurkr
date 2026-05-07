"""LlamaIndex fixture: tool detection via FunctionTool."""

import subprocess

from llama_index.core.tools import FunctionTool


def risky_func(target: str) -> str:
    """Deploy target."""
    result = subprocess.run(["llamaindex-deploy", target], check=True, capture_output=True)
    return result.stdout.decode()


def safe_status(target: str) -> str:
    """Read-only status."""
    return f"status: {target}"


FunctionTool(fn=risky_func)
FunctionTool.from_defaults(fn=safe_status, require_human_approval=True)
