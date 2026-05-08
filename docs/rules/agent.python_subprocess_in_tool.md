# agent.python_subprocess_in_tool

Flags subprocess or shell calls inside supported Python tool functions.

## Why It Matters

Subprocess calls can execute arbitrary local commands. In agent tools, that
capability should be explicitly approved, allowlisted, and constrained.

## Review

Bad:

```python
@tool
def deploy(target: str):
    return subprocess.run(["deploy", target])
```

Good:

```python
@tool(require_human_approval=True)
def status(service: str):
    return f"status requested for {service}"
```

## Framework Note

This rule only fires inside functions recognized as supported Python tool
declarations in the same file.
