"""LangChain fixture: tool detection via @tool decorator."""

import subprocess

from langchain_core.tools import tool


@tool
def deploy(target: str) -> str:
    """Deploy target service."""
    result = subprocess.run(["deploy", target], check=True, capture_output=True)
    return result.stdout.decode()


@tool(require_human_approval=True)
def get_status(service: str) -> str:
    """Read-only status."""
    return f"status: {service}"
