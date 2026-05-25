# agent.javascript_child_process_in_tool

Flags Node.js `child_process` command execution inside a canonical MCP
`registerTool` handler in TypeScript or JavaScript source.

## Why It Matters

`child_process` APIs (`exec`, `spawn`, `execFile`, `fork`, and their `*Sync`
variants) execute arbitrary local commands. When that capability lives inside
an MCP tool handler reachable by a model, it should be explicitly approved,
allowlisted, and constrained instead of running on every tool call.

## Review

Bad:

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("run", { description: "d" }, async () => {
  exec("ls");
});
```

Good:

```ts
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("status", { description: "d" }, async () => {
  return { status: "ok" };
});
```

## MCP Context Gate

The rule only fires when both of the following hold in the same file:

- An import or `require` of an official `@modelcontextprotocol/*` package
  binds the `McpServer` symbol locally, and the server instance is created
  via `new McpServer(...)` (or `new <ns>.McpServer(...)` for namespace
  imports).
- The call site is the canonical
  `<server>.registerTool("static_name", config, handler)` form. Dynamic tool
  names, `server.tool(...)`, and `server.setRequestHandler(...)` are out of
  scope.

The handler argument is resolved within the same file as an inline arrow or
function expression, or as an identifier reference to a same-file `function`
declaration or `const` arrow / function expression. Handlers imported from
other files are intentionally not resolved.

## Supported child_process Forms

Imports from `child_process` or `node:child_process`:

- `import { exec } from "node:child_process"`
- `import { exec as run } from "child_process"`
- `import * as cp from "node:child_process"`
- `import cp from "node:child_process"`
- `const { exec } = require("node:child_process")`
- `const { exec: run } = require("child_process")`
- `const cp = require("child_process")`

APIs covered: `exec`, `execSync`, `spawn`, `spawnSync`, `execFile`,
`execFileSync`, `fork`.

## Shadow Handling

If the handler's own scope binds an identifier that collides with a
`child_process` import binding, calls through that name within the handler
are not flagged. This covers:

- Handler parameters (including TypeScript-typed and destructured forms):
  `async (exec) => { exec("safe"); }`
- Top-level `const` / `let` / `var` declarations inside the handler body:
  `const exec = (cmd) => cmd; exec("safe");`
- Same-scope `function` declarations inside the handler body.

Shadowing applies symmetrically to direct names and to namespace aliases
(e.g. `async (cp) => cp.exec(...)`). Shadowing introduced inside nested
function, method, or class scopes is intentionally not v1 — calls through
a name shadowed only in a nested inner scope can still be flagged.

## Out of Scope

- Bun / Deno shell APIs
- Third-party shell wrappers (`execa`, `shelljs`, `zx`, etc.)
- Dynamic `import("node:child_process")`
- Imported handler bodies from other files
- Dataflow or reachability analysis beyond bounded same-file AST
- Shadowing introduced in nested function / method / class scopes
