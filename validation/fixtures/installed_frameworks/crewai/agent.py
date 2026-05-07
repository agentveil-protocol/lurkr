"""CrewAI fixture: tool detection via @tool decorator."""

import subprocess

from crewai.tools import tool


@tool
def ship_release(version: str) -> str:
    """Ship a release."""
    result = subprocess.run(["ship-release", version], check=True, capture_output=True)
    return result.stdout.decode()


@tool(require_human_approval=True)
def release_notes(version: str) -> str:
    """Read-only release notes."""
    return f"notes for {version}"
