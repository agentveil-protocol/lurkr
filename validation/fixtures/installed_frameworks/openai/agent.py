"""OpenAI fixture: tool detection via chat completions tools list."""

import subprocess

from openai import OpenAI

client = OpenAI(api_key="placeholder")


def risky_func(target: str) -> str:
    """Deploy target."""
    result = subprocess.run(["openai-deploy", target], check=True, capture_output=True)
    return result.stdout.decode()


def safe_status(target: str) -> str:
    """Read-only status helper not exposed as a tool."""
    return f"status: {target}"


client.chat.completions.create(
    model="gpt-4.1-mini",
    messages=[{"role": "user", "content": "run"}],
    tools=[
        {
            "type": "function",
            "function": {"name": "risky_func", "description": "Risky deploy"},
        }
    ],
)
