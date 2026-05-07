# agent.python_tool_without_approval

Flags supported Python tool declarations without a conservative approval
marker.

## Why It Matters

Agent-callable functions expose capability to the model or agent loop. Risky
tools should require approval or narrower inputs before they can run.

## Review

Bad:

```python
@tool
def deploy(target: str) -> str:
    return target
```

Good:

```python
@tool(require_human_approval=True)
def deploy(target: str) -> str:
    return target
```

## Framework Note

Supported v0.2 scope includes LangChain, LangGraph, CrewAI, MCP decorators,
OpenAI tool-calling dictionaries, Anthropic tool-use dictionaries, LlamaIndex
`FunctionTool`, and Gemini `function_declarations`.
