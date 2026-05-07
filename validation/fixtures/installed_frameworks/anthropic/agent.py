"""Anthropic fixture: tool detection via messages tools list."""

import subprocess

from anthropic import Anthropic

client = Anthropic(api_key="placeholder")


def risky_func(target: str) -> str:
    """Deploy target."""
    result = subprocess.run(["anthropic-deploy", target], check=True, capture_output=True)
    return result.stdout.decode()


def safe_status(target: str) -> str:
    """Read-only status helper not exposed as a tool."""
    return f"status: {target}"


client.messages.create(
    model="claude-3-5-sonnet-latest",
    max_tokens=32,
    messages=[{"role": "user", "content": "run"}],
    tools=[
        {
            "name": "risky_func",
            "description": "Risky deploy",
            "input_schema": {"type": "object", "properties": {}},
        }
    ],
)
