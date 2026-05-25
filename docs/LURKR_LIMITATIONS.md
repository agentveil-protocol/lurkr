# Static Analysis Limits

Lurkr is an agent / MCP posture scanner, not a general JS/TS or Python
SAST. It is a sound-by-design static analyzer targeting risky agent and
Model Context Protocol capability surfaces; it is not a complete model
of all possible agent behavior. It flags a bounded set of risky
capability patterns that can be identified from repository files
without executing code, calling the network, or collecting telemetry.

False negatives are expected by design. A finding that Lurkr does not report
is not a proof that a repository has no risky capability surface; it means the
surface was outside the current static rule set or could not be identified
within the scanner's bounded analysis model.

## The Undecidability Foundation

Henry G. Rice proved in 1953 that every non-trivial semantic property of
program behavior is undecidable in the general case. In practical terms, no
static analyzer can promise to determine every possible behavior a program may
exhibit across all inputs, runtime environments, imports, generated code, and
dynamic dispatch paths.

That result matters for AI agents because "can this agent do something risky?"
is a behavioral question about code and configuration. If a tool is assembled
dynamically, imported through indirection, or guarded by runtime-only state, a
purely static scanner cannot fully reconstruct every reachable capability
without accepting either unsound conclusions or broad false positives.

Reference: Rice's theorem, introduced by Henry G. Rice in 1953 —
https://en.wikipedia.org/wiki/Rice%27s_theorem

## Sound Approximation As Engineering Choice

Patrick Cousot and Radhia Cousot's 1977 abstract interpretation work gives the
engineering foundation for useful static analysis: approximate program
behavior in a constrained model, then make the approximation explicit. Lurkr
uses that discipline. It chooses precise, reviewable rules over broad claims of
complete behavioral coverage.

For v0.2, that means Lurkr prioritizes confidence over recall. It reports
capability surfaces that the scanner can identify from bounded repository
inspection, and it accepts that subtle bypass paths may slip through until
there is enough evidence to add a rule with low false-positive cost. This is
the same tradeoff credible static analyzers make: catch the patterns that can
be decided reliably, document the boundaries, and keep expanding the decidable
subset as evidence justifies it.

Reference: Patrick Cousot and Radhia Cousot, "Abstract Interpretation: A
Unified Lattice Model for Static Analysis of Programs by Construction or
Approximation of Fixpoints", Proceedings of POPL 1977 —
https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml

## What This Means In Practice

- Cross-file `Tool(func=external_module.helper)` resolution is intentionally
  not detected in v0.2. The false-positive cost of approximate
  interprocedural analysis outweighs the marginal recall gain at this stage.
- Python analysis is bounded to regular `.py` files. Stub files, generated
  code, notebook cells, and runtime-created tools are outside the current
  static model.
- `agent.python_tool_without_approval` flags supported Python tool declaration
  patterns where the scanner cannot see a conservative approval marker. It
  does not prove that every possible tool in the repository has been
  enumerated.
- `agent.python_subprocess_in_tool`, `agent.python_eval_exec_in_tool`, and
  `agent.python_unrestricted_file_access` fire inside recognized same-file
  tool functions. Indirect sinks reached through helper functions remain a
  documented boundary for future deeper analysis.
- `agent.python_api_key_hardcoded` is module-wide and string-literal based. It
  catches obvious provider-key shapes without printing raw keys, but it is not
  a replacement for full secret scanning.
- `workflow.deploy_without_approval` looks for deploy, release, publish, and
  registry-push steps without visible approval signals. Static analysis cannot
  see every external approval process, branch protection rule, or manual
  reviewer chain.
- `workflow.pull_request_target_secrets_risk` reports risky combinations of
  privileged PR context with checkout, execution, or secrets access. It does
  not classify every possible `pull_request_target` workflow as unsafe.
- `tool.shell_without_approval` inspects pinned manifest formats and exact
  shell-capable tool names. Tools hidden behind project-specific names or
  constructed at runtime are outside v0.2 scope.
- TypeScript / JavaScript MCP coverage is bounded to canonical Model
  Context Protocol `registerTool` registration patterns. Supported
  shapes today: identifier-bound (`const server = new McpServer(...);
  server.registerTool(...)`), direct chained construction
  (`new McpServer(...).registerTool(...)` plus the parenthesised
  variant), namespace-qualified construction
  (`new <ns>.McpServer(...).registerTool(...)`), and typed
  helper-wrapper parameters (`(server: McpServer) =>
  server.registerTool(...)`). Static tool names may be resolved through
  same-file top-level `const NAME = "literal"` bindings; dynamic / template
  / call-result names remain skipped. Cross-file handler resolution is
  restricted to relative-path imports inside the scan root: named
  imports, default imports of function-like exports, namespace local
  imports (`tools.runTool` member access), and directory/index probing.
  Untyped JS helper wrappers, wrapper-name heuristics, tool arrays /
  forEach loops, `setRequestHandler("tools/call", ...)`, CommonJS
  `module.exports` shapes, barrel re-exports, tsconfig path aliases,
  package imports for handler resolution, and dataflow / reachability
  analysis beyond bounded same-file AST in the target file are all
  outside v0.2 scope. Lurkr is not a general JS/TS scanner.
- Oversized, unreadable, malformed, alias-heavy, deeply nested, binary, or
  undecodable files may be skipped before parsing to preserve scanner safety.
- Symlinks are skipped. Lurkr does not follow links inside or outside the
  scan root because scanned repositories are untrusted input.

## What Lurkr Does Not Replace

- General-purpose SAST for application vulnerabilities, dependency issues, and
  language-specific bug classes outside the agent capability surface.
- Dedicated secret scanning for broad credential formats, historical commits,
  cloud-provider token families, and rotation workflows.
- Runtime mediation, policy decisions, or proof of executed actions. Lurkr is
  the pre-deployment scanner workstream in the broader AgentVeil ecosystem: it
  finds risky capabilities before deployment, but it does not approve, block,
  or execute agent actions.
- Human security review. Findings are review items that help teams focus on
  high-risk capability surfaces; they are not incident declarations by
  themselves.
