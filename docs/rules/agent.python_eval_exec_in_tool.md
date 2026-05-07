# agent.python_eval_exec_in_tool

Flags `eval`, `exec`, `compile`, or dynamic import calls inside supported
Python tool functions.

## Why It Matters

Dynamic execution can turn user or model-provided text into code. That is a
high-risk capability inside agent-callable functions.

## Review

Bad:

```python
@tool
def calculate(expression: str):
    return eval(expression)
```

Good:

```python
@tool
def calculate(expression: str):
    return safe_math_parser(expression)
```

## Framework Note

Prefer structured parsers, fixed command maps, and validated inputs over
dynamic execution.
