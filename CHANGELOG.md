# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
