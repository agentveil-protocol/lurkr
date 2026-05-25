# agent.javascript_file_mutation_in_tool

Flags Node.js `fs` or `fs/promises` file write/delete-style APIs inside a
canonical MCP `registerTool` handler in TypeScript or JavaScript source.

## Why It Matters

File mutation lets an MCP tool overwrite source, configuration, credentials,
or generated artifacts. The writable scope should be narrow, intentional, and
reviewed before a model can trigger it through a tool call.

## Review

Bad:

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { writeFile } from "node:fs/promises";

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("write", { description: "d" }, async () => {
  await writeFile("out.txt", "data");
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

When the resolved body lives in a different file, the handler is analysed
in that target file's context: the call-site walk uses the target file's
`fs` / `fs/promises` imports, the handler's own scope shadow set is computed
in the target file, and the finding's file path and line number point at the
target file (relative to the scan root). Cross-file resolution fails closed
on missing, oversized, or malformed target files, and on targets outside the
scan root.

## Supported fs Forms

Imports from `fs`, `node:fs`, `fs/promises`, or `node:fs/promises`:

- `import { writeFile } from "node:fs/promises"`
- `import { writeFile as write } from "fs"`
- `import * as fs from "node:fs"`
- `import fs from "node:fs"`
- `const { writeFile } = require("node:fs/promises")`
- `const { writeFile: write } = require("fs")`
- `const fs = require("fs")`

APIs covered: `writeFile`, `writeFileSync`, `appendFile`,
`appendFileSync`, `rm`, `rmSync`, `unlink`, `unlinkSync`, `rename`,
`renameSync`, `mkdir`, `mkdirSync`, `createWriteStream`.

Namespace calls through `fs.promises.<api>(...)` are also covered for the
same API names.

## Shadow Handling

If the handler's own scope binds an identifier that collides with an `fs`
import binding, calls through that name within the handler are not flagged.
This covers:

- Handler parameters (including TypeScript-typed and destructured forms):
  `async (writeFile) => { writeFile("safe"); }`
- Top-level `const` / `let` / `var` declarations inside the handler body:
  `const writeFile = (path) => path; writeFile("safe");`
- Same-scope `function` declarations inside the handler body.

Shadowing applies symmetrically to direct names and to namespace aliases
(e.g. `async (fs) => fs.writeFile(...)`). Shadowing introduced inside nested
function, method, or class scopes is intentionally not v1.

## Out of Scope

- Read-only file APIs (`readFile`, `stat`, `readdir`, etc.)
- Bun / Deno file APIs
- Third-party file wrappers
- Dynamic `import("node:fs")` / dynamic handler imports
- Package imports (`import { x } from "@pkg/name"`) for handler resolution
- tsconfig path aliases (`@/lib/x`, etc.)
- Barrel re-exports (`export { x } from "./y"`)
- Default exports (`export default ...`)
- Namespace imports from local files (`import * as t from "./tools"`)
- Directory / `index` file resolution (`./tools` -> `./tools/index.ts`)
- Cross-package monorepo resolution
- Dataflow or reachability analysis beyond bounded same-file AST in the
  target file
- Shadowing introduced in nested function / method / class scopes
