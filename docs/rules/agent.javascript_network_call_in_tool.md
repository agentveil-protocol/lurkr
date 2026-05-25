# agent.javascript_network_call_in_tool

Flags outbound network calls inside a canonical MCP `registerTool` handler
in TypeScript or JavaScript source.

## Why It Matters

MCP tool handlers are reachable from model-driven calls. A handler that can
issue arbitrary outbound HTTP requests can be used to exfiltrate data,
proxy untrusted content into model context, or call paid services without
review. Outbound network access should be allowlisted, scoped, and gated by
approval — not picked up implicitly from runtime-global APIs.

## Review

Bad:

```ts
import { McpServer } from "@modelcontextprotocol/server";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("lookup", { description: "d" }, async () => {
  const r = await fetch("https://api.example.com");
  return { r };
});
```

Good:

```ts
import { McpServer } from "@modelcontextprotocol/server";

function makeServer(httpClient: { request(url: string): Promise<unknown> }) {
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
  `<server>.registerTool("static_name", config, handler)` form. Dynamic
  tool names, `server.tool(...)`, and `server.setRequestHandler(...)` are
  out of scope.

## Handler Resolution

The handler argument is resolved in priority order:

1. Inline arrow or function expression in the third position.
2. Identifier reference to a same-file `function` declaration or `const`
   arrow / function expression.
3. Identifier bound by a named import from a same-repo relative path
   (`./tools`, `../lib/x`) where the target file exports the same symbol
   as a `function` declaration or a `const` arrow / function expression.
   Aliased named imports and aliased exports are supported through the
   same shared logic as the other JS/TS MCP rules.
4. Identifier bound by a default import from a same-repo relative path
   (`import handler from "./tools"`) where the target file's
   `export default` is a function declaration or an arrow / function
   expression. Default exports of classes, objects, literals, or a bare
   identifier (`export default runTool`) are intentionally not v1.

When the resolved body lives in a different file, the network call walk
runs in the target file's source. The target file's own network imports
(default / namespace / named / destructured-require) are used, and the
finding's file path and line number point at the target file (relative
to the scan root). Cross-file resolution fails closed on missing,
oversized, or malformed target files and on targets outside the scan
root.

## Detected Call Shapes

- Global `fetch(...)` — always recognised, no import required.
- Direct callable bindings from a supported network package:
  `import { fetch } from "undici"; fetch(...)`,
  `const { request } = require("node:http"); request(...)`,
  `import { get } from "axios"; get(...)`.
- Member calls on a namespace alias bound to a supported network package:
  `axios.get`, `axios.post`, `axios.put`, `axios.delete`, `axios.patch`,
  `http.request`, `https.request`, `undici.fetch`.

A namespace alias is created by a default import (`import axios from
"axios"`), a namespace import (`import * as undici from "undici"`), or a
whole-module require (`const http = require("node:http")`).

## Supported Network Packages

`axios`, `got`, `undici`, `http`, `node:http`, `https`, `node:https`.

## Static Localhost Suppression

When the first positional argument is a string literal whose URL starts
with an explicit `http://` or `https://` scheme (case-insensitive) and the
host part is `localhost`, `127.0.0.1`, or `[::1]`, the call site is
silently skipped. Optional port, path, query, and fragment after the host
are allowed.

Scheme-less inputs (e.g. `fetch("localhost:3000/api")` or
`axios.get("//127.0.0.1/x")`) are NOT suppressed: bare-host URLs are
ambiguous (relative path vs. host:port) and the runtime semantics differ
across clients, so the rule errs on the side of flagging. Dynamic first
arguments (variables, template strings with interpolation, computed
expressions) cannot be checked and are NOT suppressed.

## Shadow Handling

If the handler's own scope binds an identifier whose name collides with a
network direct binding or namespace alias (handler parameter, top-level
`const` / `let` / `var`, or same-scope `function` declaration), calls
through that name within the handler are not flagged. This covers patterns
where the handler intentionally injects a scoped client in place of the
global / module binding. Shadowing introduced inside nested function,
method, or class scopes is intentionally not v1.

## Out of Scope

- Network calls reached through factory results (`axios.create(...).get`)
  or chained instance methods on returned clients
- Bun / Deno / Workers fetch alternatives (`globalThis.fetch` aliasing,
  `Deno.fetch`, `Bun.fetch`)
- Streams-only `https.get(url).on(...)` style chains where the URL is
  obscured behind chained instance calls
- Package imports / tsconfig path aliases / barrel re-exports / default
  exports / namespace imports from local files for handler resolution
- Dataflow or reachability analysis beyond bounded same-file AST in the
  target file
- An allowlist / config system for what counts as a "safe" host
- Shadowing introduced in nested function / method / class scopes
