# agent.declared_vs_imported_delta

Detects tool registrations in Python and TypeScript/JavaScript agent code
that are not declared in agent manifest files. Surfaces shadow capabilities
that bypass the declared agent scope.

## What It Flags

This rule compares declared tool names from supported agent manifests with
reachable tool registrations found in bounded source analysis. It emits a
finding when a tool is registered in code but the normalized tool name is
absent from every supported manifest in the repository.

Supported manifest discovery follows Lurkr's existing manifest scope:

- MCP-style `.mcp.json`, `.cursor/mcp.json`, `mcp.json`, and `mcp_config.json`
- CrewAI `crew*.yaml`, `crew*.yml`, and `crews/<name>/config/agents.yaml`
  or `crews/<name>/config/tasks.yaml`
- AutoGen `autogen*.json` and `autogen*.yaml`
- LangChain `langchain*.json` and `langchain*.yaml`

Tool identifiers are normalized to `snake_case` before comparison. This is a
framework-independent identifier comparison so names such as `getUser` and
`get_user` are treated as the same declared capability.

### Python source coverage

Bounded Python AST analysis covers:

- LangChain-style `@tool` and MCP-style `@call_tool` decorators on functions
- `FunctionTool`, `Tool`, and `StructuredTool` constructors (including
  `FunctionTool.from_defaults(fn=...)`)
- Provider tool dictionaries inside `create`, `generate_content`, and
  `GenerativeModel` calls (OpenAI `{"type": "function", "function": {"name": ...}}`,
  Anthropic `{"name": ..., "input_schema": ...}`, Gemini `function_declarations`)

Only static string tool names are extracted. Function-name fallback applies
to decorator forms.

### TypeScript / JavaScript source coverage

Bounded tree-sitter parsing of `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`, `.mts`,
and `.cts` sources covers canonical Model Context Protocol TypeScript
SDK tool registration sites in several call shapes:

- Identifier-bound:
  `const server = new McpServer(...); server.registerTool("name", config, handler)`
- Direct chained construction:
  `new McpServer(...).registerTool("name", config, handler)`
- Parenthesised chained construction:
  `(new McpServer(...)).registerTool("name", config, handler)`
- Namespace-qualified construction (named or chained):
  `new mcp.McpServer(...).registerTool("name", config, handler)`
- Typed helper-wrapper parameter:
  `export const registerXTool = (server: McpServer) => { server.registerTool("name", config, handler); }`

The MCP provenance gate accepts these forms of bringing `McpServer` into
local scope:

- Named ES import: `import { McpServer } from "@modelcontextprotocol/server"`
- Aliased named ES import:
  `import { McpServer as Server } from "@modelcontextprotocol/server"`
- Destructured CommonJS require:
  `const { McpServer } = require("@modelcontextprotocol/server")`
- Aliased destructured require:
  `const { McpServer: Server } = require("@modelcontextprotocol/server")`
- Namespace ES import paired with qualified construction:
  `import * as mcp from "@modelcontextprotocol/server"`
  then `new mcp.McpServer(...)`
- Namespace CommonJS require paired with qualified construction:
  `const mcp = require("@modelcontextprotocol/server")`
  then `new mcp.McpServer(...)`

Tool names are accepted as:

- Static string literals (`"my_tool"`).
- Same-file top-level `const NAME = "literal"` bindings referenced as
  the first `registerTool` argument. Local shadows in enclosing
  function / block scopes suppress the fallback.

The gate does NOT match in any of the following cases:

- A locally declared `class McpServer { ... }` with no official MCP import
- `import { McpServer } from "not-mcp"` (non-MCP package)
- `import { NotMcpServer } from "@modelcontextprotocol/server"` (other symbol)
- Default import from the MCP package
  (`import Anything from "@modelcontextprotocol/server"`)
- An untyped JavaScript helper-wrapper parameter without a TypeScript
  `: McpServer` annotation
- `<server>.tool("name", ...)` shorthand
- `<server>.setRequestHandler("tools/call", ...)` low-level API
- Dynamic / computed tool names (template literals with interpolation,
  function-call results, variable references whose binding cannot be
  resolved through the same-file top-level `const` map)
- Helper wrappers that hide the receiver from the static call site
  beyond the supported TypeScript-typed-parameter form (wrapper-name
  heuristics, tool arrays / `forEach` loops, and CommonJS namespace
  require shapes are out of v1)
- Deeper-than-one chained ``registerTool`` calls
  (`new McpServer(...).registerTool(...).registerTool(...)`) and
  intermediate property access on the chain

The rule is a bounded static signal. Cross-file references and dataflow
between scopes are not resolved.

## Why It Matters

Agent manifests are often used as the reviewable scope of what an agent should
be able to do. Python code can still register additional tools that are
reachable at runtime. Those shadow capabilities may not appear in the manifest
review path, CI checklist, or deployment approval process.

This rule catches that mismatch before deployment. It is designed for the case
where a reviewer believes an agent can call a narrow declared set, while the
code exposes a broader set of actions.

## Triggers

### Python

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

### TypeScript / JavaScript

Bad:

```json
{
  "tools": [
    {
      "name": "search_docs"
    }
  ]
}
```

```typescript
import { McpServer } from '@modelcontextprotocol/server';

const server = new McpServer({ name: 'agent-server', version: '1.0.0' });
server.registerTool('search_docs', { description: 'd' }, async () => ({}));
server.registerTool('delete_files', { description: 'd' }, async () => ({}));
```

The manifest declares `search_docs`, but
`server.registerTool('delete_files', ...)` adds an unannounced capability on
the McpServer-bound `server` identifier. Lurkr reports `delete_files` as a
shadow capability.

Good:

```typescript
import { McpServer } from '@modelcontextprotocol/server';

const server = new McpServer({ name: 'agent-server', version: '1.0.0' });
server.registerTool('search_docs', { description: 'd' }, async () => ({}));
```

The single reachable tool is declared, so this rule does not fire.

## Known Limitations

- If no supported manifest is present, the rule does not fire. Without a
  declared baseline, Lurkr cannot establish a declared-vs-imported delta.
- Dynamic tool names such as `name=tool_name_from_config` (Python) or
  `registerTool(getName(), ...)` (TypeScript/JavaScript) are out of scope.
  Only static string literal names are compared. For Python decorator forms,
  the decorated function name is used as a fallback.
- Cross-file function resolution such as `Tool(func=external_module.helper)`
  or handler references imported from another module is out of scope.
- Reverse-delta detection, where a manifest declares a tool that is absent
  from code, is a future candidate.
- Off-spec manifests may not be parsed. Lurkr supports the schema locations
  used by the manifest formats listed above.
- `snake_case` normalization is intentionally conservative. Acronym-heavy
  names can still have edge cases, so review findings in context.
- TypeScript / JavaScript: identifier-bound, direct chained,
  parenthesised chained, namespace-qualified construction, and
  TypeScript-typed helper-wrapper parameter shapes are matched. The
  `server.tool(...)` shorthand and the low-level
  `server.setRequestHandler("tools/call", ...)` API are intentionally
  not flagged in this version.
- TypeScript / JavaScript: untyped JavaScript helper wrappers, wrapper-name
  heuristics, tool arrays / `forEach`-style registration loops, and
  CommonJS namespace require shapes for registration sites are out of
  scope. Static tool names supplied via same-file top-level
  `const NAME = "literal"` ARE resolved when not locally shadowed; deeper
  resolution forms (`let` / `var` / call-result, template strings with
  interpolation, cross-file constants, dataflow) remain out of scope.
- TypeScript / JavaScript: malformed sources (tree-sitter reports an error on
  the parsed root) and oversized sources (greater than 1 MB) are skipped
  silently.
- TypeScript / JavaScript: a file may import McpServer from an official MCP
  package without constructing it locally. Without one of the supported
  registration shapes (identifier-bound `new McpServer(...)`, direct or
  parenthesised chained construction, namespace-qualified construction,
  or a TypeScript-typed helper-wrapper parameter), the rule does not
  fire on calls in that file.

## Remediation

Add the tool to the agent manifest if the capability is intended to be exposed
and reviewed. Remove the tool registration (Python `@tool` / `Tool(...)` or
TypeScript/JavaScript `server.registerTool(...)`) if the capability is not
intended to be reachable. For sensitive tools, also require explicit approval
and narrow input constraints before deployment.
