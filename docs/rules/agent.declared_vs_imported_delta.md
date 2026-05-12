# agent.declared_vs_imported_delta

Detects Python tool registrations that are not declared in agent manifest
files. Surfaces shadow capabilities that bypass the declared agent scope.

## What It Flags

This rule compares declared tool names from supported agent manifests with
reachable Python tool registrations found in bounded AST analysis. It emits a
finding when a Python tool is registered but the normalized tool name is absent
from every supported manifest in the repository.

Supported manifest discovery follows Lurkr's existing manifest scope:

- MCP-style `.mcp.json`, `.cursor/mcp.json`, `mcp.json`, and `mcp_config.json`
- CrewAI `crew*.yaml`, `crew*.yml`, and `crews/<name>/config/agents.yaml`
  or `crews/<name>/config/tasks.yaml`
- AutoGen `autogen*.json` and `autogen*.yaml`
- LangChain `langchain*.json` and `langchain*.yaml`

Tool identifiers are normalized to `snake_case` before comparison. This is a
framework-independent identifier comparison so names such as `getUser` and
`get_user` are treated as the same declared capability.

## Why It Matters

Agent manifests are often used as the reviewable scope of what an agent should
be able to do. Python code can still register additional tools that are
reachable at runtime. Those shadow capabilities may not appear in the manifest
review path, CI checklist, or deployment approval process.

This rule catches that mismatch before deployment. It is designed for the case
where a reviewer believes an agent can call a narrow declared set, while the
code exposes a broader set of actions.

## Triggers

Bad:

```json
{
  "tools": [
    {
      "name": "get_repo"
    }
  ]
}
```

```python
from langchain.tools import tool


@tool
def get_repo():
    return "repo"


@tool
def delete_files():
    return "deleted"
```

The manifest declares `get_repo`, but Python also registers `delete_files`.
Lurkr reports `delete_files` as a shadow capability.

Good:

```json
{
  "tools": [
    {
      "name": "get_repo"
    },
    {
      "name": "delete_files"
    }
  ]
}
```

```python
from langchain.tools import tool


@tool
def get_repo():
    return "repo"


@tool
def delete_files():
    return "deleted"
```

Both reachable tools are declared, so this rule does not fire.

## Known Limitations

- If no supported manifest is present, the rule does not fire. Without a
  declared baseline, Lurkr cannot establish a declared-vs-imported delta.
- Dynamic tool names such as `name=tool_name_from_config` are out of scope for
  v0.2.1. Only static string literal names and function-name fallbacks are
  compared.
- Cross-file function resolution such as `Tool(func=external_module.helper)` is
  out of scope for v0.2.1.
- Reverse-delta detection, where a manifest declares a tool that is absent from
  Python code, is a v0.3 candidate.
- Off-spec manifests may not be parsed. Lurkr supports the schema locations
  used by the manifest formats listed above.
- `snake_case` normalization is intentionally conservative. Acronym-heavy names
  can still have edge cases, so review findings in context.

## Remediation

Add the tool to the agent manifest if the capability is intended to be exposed
and reviewed. Remove the Python tool registration if the capability is not
intended to be reachable. For sensitive tools, also require explicit approval
and narrow input constraints before deployment.
