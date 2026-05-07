"""FastMCP fixture: tool detection via @app.tool()."""

import subprocess

from mcp.server.fastmcp import FastMCP

app = FastMCP("posture-fixture")


@app.tool()
def rotate_secret(name: str) -> str:
    """Rotate a secret."""
    result = subprocess.run(["rotate-secret", name], check=True, capture_output=True)
    return result.stdout.decode()


@app.tool(require_human_approval=True)
def describe_secret(name: str) -> str:
    """Read-only secret metadata."""
    return f"secret metadata: {name}"
