# agent.python_api_key_hardcoded

Flags API-key-shaped Python string literals.

## Why It Matters

Hardcoded keys are easy to commit, copy, and leak. If a real key is found,
remove it and rotate it.

## Review

Bad:

```python
API_KEY = "provider-key-value"
```

Good:

```python
API_KEY = os.environ["PROVIDER_API_KEY"]
```

## Framework Note

This rule is module-wide. It is not limited to recognized tool functions,
because keys often live in config blocks.
