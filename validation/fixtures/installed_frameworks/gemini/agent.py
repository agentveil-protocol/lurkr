"""Gemini fixture: tool detection via function_declarations."""

import subprocess

from google import genai

client = genai.Client(api_key="placeholder")


def risky_func(target: str) -> str:
    """Deploy target."""
    result = subprocess.run(["gemini-deploy", target], check=True, capture_output=True)
    return result.stdout.decode()


def safe_status(target: str) -> str:
    """Read-only status helper not exposed as a tool."""
    return f"status: {target}"


client.models.generate_content(
    model="gemini-2.0-flash",
    contents="run",
    config={
        "tools": [
            {"function_declarations": [{"name": "risky_func"}]},
        ]
    },
)
