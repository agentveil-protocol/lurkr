"""LangGraph fixture: tool detection via LangChain @tool decorator."""

import subprocess

from langchain_core.tools import tool


@tool
def publish_graph(target: str) -> str:
    """Publish graph deployment."""
    result = subprocess.run(["publish-graph", target], check=True, capture_output=True)
    return result.stdout.decode()


@tool(require_human_approval=True)
def graph_status(name: str) -> str:
    """Read-only graph status."""
    return f"graph status: {name}"
