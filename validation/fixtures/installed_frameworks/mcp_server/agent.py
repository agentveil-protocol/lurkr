"""MCP Server fixture: tool detection via @server.call_tool()."""

import subprocess

from mcp.server import Server

server = Server("posture-fixture")


@server.call_tool()
def run_backup(name: str) -> str:
    """Run a backup."""
    result = subprocess.run(["run-backup", name], check=True, capture_output=True)
    return result.stdout.decode()


@server.call_tool(require_human_approval=True)
def backup_status(name: str) -> str:
    """Read-only backup status."""
    return f"backup status: {name}"
