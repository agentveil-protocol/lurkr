# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## v0.4.0 — 2026-06-01

- New rule `agent.python_fastapi_path_auth_no_host_validation` (high
  severity). Flags FastAPI / Starlette middleware that reads
  `request.url.path` for path-based security decisions when the same file
  shows no `TrustedHostMiddleware` configuration. This is the deployment
  surface for [GHSA-86qp-5c8j-p5mr / CVE-2026-48710](https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr)
  ("Missing Host header validation poisons `request.url.path`, bypassing
  path-based security checks", Starlette `<= 1.0.0`, fixed in `1.0.1`,
  published 2026-05-21). Detection covers `BaseHTTPMiddleware` subclasses
  (including aliased and module-qualified imports) and `@app.middleware(...)`
  decorated functions. The rule is single-file: project-wide
  `TrustedHostMiddleware` configuration in a separate module is treated as
  unverified and the file is still flagged.

## v0.3.0 — 2026-05-25

**Bounded TypeScript / JavaScript MCP coverage.** Lurkr now flags risky
operations inside canonical Model Context Protocol `registerTool`
handlers in TypeScript / JavaScript source. Four new high-severity rules
join the existing fourteen:

- `agent.javascript_child_process_in_tool` — Node.js `child_process`
  commands inside MCP tool handlers.
- `agent.javascript_file_mutation_in_tool` — Node.js `fs` /
  `fs/promises` write / delete calls inside MCP tool handlers.
- `agent.javascript_env_secret_access_in_tool` — secret-like
  `process.env.<NAME>` reads inside MCP tool handlers (case-sensitive
  allowlist plus `_KEY` / `_TOKEN` / `_SECRET` / `_PASSWORD` suffixes;
  benign reads such as `process.env.NODE_ENV` are not flagged).
- `agent.javascript_network_call_in_tool` — outbound network calls
  inside MCP tool handlers (`fetch`, `axios`, `got`, `undici`, `http`,
  `https`). Static localhost URLs (`http://localhost`, `http://127.0.0.1`,
  `http://[::1]`) are intentionally skipped.

`agent.declared_vs_imported_delta` is extended to detect TS/JS MCP
`registerTool` registrations as shadow capabilities alongside Python tool
registrations.

TS/JS coverage is bounded to canonical MCP `registerTool` registration
patterns:

- Identifier-bound: `const server = new McpServer(...); server.registerTool(...)`
- Direct chained construction: `new McpServer(...).registerTool(...)`
- Parenthesised chained construction: `(new McpServer(...)).registerTool(...)`
- Namespace-qualified construction:
  `new mcp.McpServer(...).registerTool(...)`
- Typed helper-wrapper parameter: `(server: McpServer) => server.registerTool(...)`

Tool names accept static string literals AND same-file top-level
`const NAME = "literal"` bindings (with local-scope shadow guard).

Cross-file handler resolution is restricted to relative-path imports
inside the scan root:

- Named imports (`import { x } from "./tools"`), with aliased forms.
- Default imports (`import x from "./tools"`) for function-like
  `export default` shapes (declarations, anonymous functions, arrow
  functions). Bare-identifier `export default x` is not resolved.
- Namespace local imports (`import * as t from "./tools"; t.runTool`).
  Nested or dynamic member access is not resolved.
- Directory / `index` file probing (`./tools` → `./tools/index.ts` etc.)
  with sibling-file precedence preserved.

Scan-root boundary is enforced before any target file is parsed; targets
outside the scan root are silently dropped.

Out of scope (not detected): untyped JS helper wrappers, wrapper-name
heuristics, tool arrays / `forEach` loops, `setRequestHandler("tools/call",
...)`, CommonJS `module.exports` shapes, barrel re-exports, tsconfig
path aliases, package imports for handler resolution, and dataflow /
reachability analysis beyond bounded same-file AST in the target file.

Backward-compatible. Existing reports and rule IDs unchanged.

## v0.2.5 — 2026-05-14

**Version-sync bug fix.** `SCANNER_VERSION` in `report.py` and
`semanticVersion` in the SARIF output were hardcoded literals that drifted
from `__version__` across releases. Fixed by deriving both from the canonical
`lurkr.__version__` at import time, so JSON and SARIF reports always reflect
the installed package version. Also bumps the `v0.2.3` release-pin references
in `README.md` and `PYPI_README.md` to `v0.2.5` for consistency.

Includes the v0.2.4 promotion to `Development Status :: 4 - Beta`.

## v0.2.4 — 2026-05-14

**Beta release.** Promotes the PyPI `Development Status` classifier from
`3 - Alpha` to `4 - Beta`. No code changes — feature set, rule coverage,
and CLI behavior are identical to v0.2.3.

The promotion reflects readiness for production-trial use: 316 tests
passing, 14 high-severity rules, benchmark methodology documented, and
baseline mode shipped in v0.2.3. Real-world adoption feedback drives the
remaining gap to a `5 - Production/Stable` classification.

Note: a hardcoded `scanner_version` literal in `report.py` made
`report.json` continue to report `lurkr/0.2.3` after the bump. Fixed in
v0.2.5.

## v0.2.3 — 2026-05-13

**Baseline mode.** Adds `--baseline` and `--save-baseline` CLI flags for
adoption-friendly CI integration. Teams can run Lurkr once on an existing repo,
save a baseline, and then enable Lurkr in CI to only flag new findings:
existing findings are grandfathered until intentionally addressed.

This follows the standard static-scanner adoption pattern used by tools such as
Snyk, SonarCloud, and Bandit. It removes the main adoption friction for
existing repositories with current findings.

See `docs/BASELINE.md` for the workflow.

Backward-compatible. Existing reports, rule IDs, and CLI behavior without
`--baseline` or `--save-baseline` are unchanged.

## v0.2.2 — 2026-05-12

**Three new rules.** Adds AI-specific detection surfaces no other static
scanner catches:

- `agent.credential_to_llm_context` — credentials passed into LLM completion
  calls as message content (leak via conversation history and provider logs).
- `agent.dynamic_prompt_from_user_input` — prompt templates built via f-string
  or concatenation from function parameters (prompt injection setup,
  statically detectable).
- `agent.unverified_mcp_endpoint` — MCP server entries pointing to
  non-allowlisted external hosts (untrusted server-side prompt injection or
  tool-poisoning risk).

All three rules use existing AST and manifest parser foundations.
Backward-compatible. Existing reports and rule IDs unchanged.

Total rules: 14.

## v0.2.1 — 2026-05-12

**New rule.** Adds `agent.declared_vs_imported_delta` detecting shadow
capabilities: Python tool registrations not declared in agent manifest files
(MCP/CrewAI/AutoGen/LangChain).

This is Lurkr's first rule that cross-references declared capabilities against
reachable code. It surfaces a class of pre-deployment risk that token/secret
scanners cannot detect: tools that exist in code but bypass the declared agent
scope.

Backward-compatible. Existing reports and rule IDs unchanged.

## v0.2.0 — 2026-05-12

**BREAKING — rebrand.** Package, CLI, GitHub Action, pre-commit hook, and
Python import surfaces are now branded as `lurkr`, `lurkr scan`,
`agentveil-protocol/lurkr`, hook ID `lurkr`, and `import lurkr`.

Detection logic, rules, and finding shapes are byte-identical to the unreleased
internal v0.2.0 before the rename. This is a pure rebrand, not a behavior
change.

Install: `pip install lurkr`.

## [0.2.0] - 2026-05-07

### Added

- Added bounded Python AST agent rules for Python tool decorators,
  tool constructors, subprocess/shell calls, dynamic execution, file mutation,
  and API-key-shaped literals.
- Extended Python agent detection to LlamaIndex (`FunctionTool`,
  `FunctionTool.from_defaults`) and Gemini (`function_declarations` dict
  pattern in `tools=[...]` arguments).
- Added static `.py` discovery using the Phase 6a bounded AST parser.
- Added redacted SARIF/JSON coverage for Python agent findings.
- Added per-rule remediation documentation under `docs/rules/<rule-id>.md`
  with capability-aware code examples.
- SARIF rule descriptors now point `helpUri` at per-rule docs pages.

### Fixed

- Scoped deployment approval detection to the deploy job or deploy step so
  unrelated review or approval text elsewhere in a workflow no longer suppresses
  `workflow.deploy_without_approval`.

## [0.1.1] - 2026-05-07

### Changed

- Expanded deployment workflow markers to cover common CLI deploy and publish
  commands while preserving command-body redaction.
- Tightened deployment false-positive exclusions for build, preview, plan, and
  package-only commands.
- Detect `actions/github-script` usage under `pull_request_target` via parsed
  workflow `uses:` fields.
- Detect exact shell-capable tool names in pinned agent manifests without
  matching substrings such as `search_tool` or `shellfish`.
- Updated repository README logo handling for public GitHub rendering.

## [0.1.0] - 2026-05-07

### Added

- Initial `lurkr scan` CLI for static, local-only AI agent capability checks.
- GitHub Action wrapper for repository capability scans.
- Pre-commit hook manifest for local capability review before commits.
- PyPI package metadata for `lurkr`.
- Five high-severity v0.1 rules covering GitHub token exposure surfaces,
  deployment approval gaps, privileged pull request workflows, shell-capable
  tool manifests, and committed unencrypted private keys.
- Redacted JSON report output with rule ID, severity, file path, line number
  when available, message, and remediation.
- SARIF v2.1.0 report output for GitHub Code Scanning upload.
- Optional `--fail-on` threshold for CI and pre-commit blocking.

### Security

- Scanner is read-only, offline, telemetry-free, and static-only.
- Findings never include raw secrets, command bodies, or private key material.
