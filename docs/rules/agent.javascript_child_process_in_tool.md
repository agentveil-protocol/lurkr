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

The rule only fires when both of the following hold in the scanning file:

- An import or `require` of an official `@modelcontextprotocol/*` package
  binds the `McpServer` symbol locally, and the server instance is created
  via `new McpServer(...)` (or `new <ns>.McpServer(...)` for namespace
  imports).
- The call site is the canonical
  `<server>.registerTool("static_name", config, handler)` form. Dynamic tool
  names, `server.tool(...)`, and `server.setRequestHandler(...)` are out of
  scope.

## Handler Resolution

The handler argument is resolved in priority order:

1. Inline arrow or function expression in the third position.
2. Identifier reference to a same-file `function` declaration or `const`
   arrow / function expression.
3. Identifier bound by a named import from a same-repo relative path
   (`./tools`, `../lib/x`) where the target file exports the same symbol
   as a `function` declaration or a `const` arrow / function expression.
   Aliased named imports (`import { foo as handler } from "./x"`) are
   supported. Aliased exports (`export { foo as runTool }`) are supported
   when the local symbol resolves to a function or const arrow / function
   in the same target file.
4. Identifier bound by a default import from a same-repo relative path
   (`import handler from "./tools"`) where the target file's
   `export default` is a function declaration or an arrow / function
   expression. Default exports of classes, objects, literals, or a bare
   identifier (`export default runTool`) are intentionally not v1.

When the resolved body lives in a different file, the handler is analysed
in that target file's context: the call-site walk uses the target file's
`child_process` imports, the handler's own scope shadow set is computed
in the target file, and the finding's file path and line number point at
the target file (relative to the scan root). Cross-file resolution fails
closed on missing, oversized, or malformed target files, and on targets
outside the scan root.

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
- Dynamic `import("node:child_process")` / dynamic handler imports
- Package imports (`import { x } from "@pkg/name"`) for handler resolution
- tsconfig path aliases (`@/lib/x`, etc.)
- Barrel re-exports (`export { x } from "./y"`)
- Default exports of class / object / literal / bare-identifier shapes
  (function-like default exports ARE resolved; see Handler Resolution)
- Namespace imports from local files (`import * as t from "./tools"`)
- Cross-package monorepo resolution
- Dataflow or reachability analysis beyond bounded same-file AST in the
  target file
- Shadowing introduced in nested function / method / class scopes
