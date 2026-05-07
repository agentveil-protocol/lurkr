# agent.python_unrestricted_file_access

Flags file write or delete calls inside supported Python tool functions.

## Why It Matters

File mutation lets an agent overwrite source, configuration, credentials, or
generated artifacts. The writable scope should be narrow and intentional.

## Review

Bad:

```python
@tool
def write(path: str, body: str):
    open(path, "w").write(body)
```

Good:

```python
@tool(require_human_approval=True)
def write_report(body: str):
    Path("reports/output.md").write_text(body)
```

## Framework Note

The scanner reports file and line only. It does not include literal path values
from scanned source.
