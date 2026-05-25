# agent.javascript_env_secret_access_in_tool

Flags secret-like `process.env` reads inside a canonical MCP `registerTool`
handler in TypeScript or JavaScript source.

## Why It Matters

MCP tool handlers are reachable from model-driven calls. When a handler reads
a secret-shaped environment variable directly, the value can be returned in a
tool response, written into logs, or otherwise relayed into model context.
Credentials should be passed in explicitly, scoped to the call, and gated by
approval — not picked up implicitly from process state.

## Review

Bad:

```ts
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("lookup", { description: "d" }, async () => {
  const key = process.env.OPENAI_API_KEY;
  return { key };
});
```

Good:

```ts
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "demo", version: "1.0.0" });
function makeServer(openAiKey: string) {
  const server = new McpServer({ name: "demo", version: "1.0.0" });
  server.registerTool("lookup", { description: "d" }, async () => {
    return { status: "ok" };
  });
  return server;
}
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
   Aliased named imports and aliased exports are supported through the
   same shared logic as the `child_process` and `fs` rules.
4. Identifier bound by a default import from a same-repo relative path
   (`import handler from "./tools"`) where the target file's
   `export default` is a function declaration or an arrow / function
   expression. Default exports of classes, objects, literals, or a bare
   identifier (`export default runTool`) are intentionally not v1.
5. Member expression `<ns>.<name>` where `<ns>` is a local namespace
   alias bound by `import * as <ns> from "./x"` and `<name>` is a named
   export of the target file resolvable through the existing
   named-export logic (function declaration, const arrow / function
   expression, or aliased export clause). Nested member access
   (`<ns>.<group>.<name>`) and dynamic member access (`<ns>[<expr>]`)
   are intentionally not v1; package-namespace imports are not
   resolved.

When the resolved body lives in a different file, the env access walk runs
in the target file's source and the finding's file path and line number
point at the target file (relative to the scan root). Cross-file resolution
fails closed on missing, oversized, or malformed target files and on
targets outside the scan root.

## Detected Access Shapes

- Direct property access: `process.env.<NAME>` where `<NAME>` is a
  property identifier (e.g. `process.env.OPENAI_API_KEY`).
- Bracket-indexed access with a static string literal:
  `process.env["<NAME>"]` (e.g. `process.env["GITHUB_TOKEN"]`).

Both shapes only match when `process.env` is the direct base of the access —
nested chains such as `process.env.A.OPENAI_API_KEY` and aliased reads such
as `const env = process.env; env.OPENAI_API_KEY` are intentionally not v1.

## Secret-Like Names

Name match is case-sensitive. A name is treated as secret-like when it is
either:

- One of the exact names `PASSWORD`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `GITHUB_TOKEN`, `NPM_TOKEN`; or
- Ends with one of the suffixes `_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`.

Benign reads such as `process.env.NODE_ENV`, `process.env.PATH`, or
`process.env.PORT` do not match either branch and are not flagged.

## Shadow Handling

If the handler's own scope binds an identifier `process` (handler
parameter, top-level `const` / `let` / `var`, or same-scope `function`
declaration), accesses through that name are not flagged. This covers
patterns where the handler intentionally injects a mock or scoped object
in place of the global `process`. Shadowing introduced inside nested
function, method, or class scopes is intentionally not v1.

## Out of Scope

- Broad `process.env.<ANY_NAME>` flagging
- Nested property chains (`process.env.A.B`) and aliased reads
- `globalThis.process.env`, `Deno.env`, `Bun.env`, or any non-Node
  runtime
- Dynamic bracket indices (variables, template strings with
  interpolation, computed expressions)
- Package imports for handler resolution
- tsconfig path aliases
- Barrel re-exports
- Default exports of class / object / literal / bare-identifier shapes
  (function-like default exports ARE resolved; see Handler Resolution)
- Package-source namespace imports (local-source namespace imports
  (`import * as t from "./tools"`) ARE resolved; see Handler Resolution)
- Nested or dynamic namespace member access (`t.group.runTool`,
  `t[name]`)
- Cross-package monorepo resolution
- Dataflow or reachability analysis beyond bounded same-file AST in the
  target file
- Shadowing introduced in nested function / method / class scopes
