"""Tests for the TypeScript/JavaScript agent posture rules.

Covers:

- ``agent.javascript_child_process_in_tool`` — Node.js ``child_process`` shell
  execution inside canonical MCP ``registerTool`` handlers.
- ``agent.javascript_file_mutation_in_tool`` — Node.js ``fs`` / ``fs/promises``
  file mutation inside canonical MCP ``registerTool`` handlers.
- ``agent.javascript_env_secret_access_in_tool`` — secret-like ``process.env``
  reads inside canonical MCP ``registerTool`` handlers.
- ``agent.javascript_network_call_in_tool`` — outbound network calls inside
  canonical MCP ``registerTool`` handlers.
"""

from __future__ import annotations

from pathlib import Path

from lurkr.scanner import scan_path


RULE_ID = "agent.javascript_child_process_in_tool"
FS_RULE_ID = "agent.javascript_file_mutation_in_tool"
ENV_RULE_ID = "agent.javascript_env_secret_access_in_tool"
NETWORK_RULE_ID = "agent.javascript_network_call_in_tool"


def _cp_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == RULE_ID]


def _fs_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == FS_RULE_ID]


def _env_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == ENV_RULE_ID]


def _network_findings(path: Path):
    report = scan_path(path)
    return [
        finding for finding in report.findings if finding.rule_id == NETWORK_RULE_ID
    ]


# --------- positive cases: handler resolution × child_process import form ---------


def test_inline_arrow_named_import_exec_ts(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity == "high"
    assert finding.file == "server.ts"
    assert finding.line == 5
    assert "child_process" in finding.message
    assert "TypeScript/JavaScript" in finding.message
    assert "approval" in finding.remediation
    assert "allowlist" in finding.remediation


def test_inline_function_namespace_import_spawn_ts(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as cp from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, function () {\n"
        "  cp.spawn('sh');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_same_file_function_declaration_destructured_require_execsync_cjs(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { execSync } = require('child_process');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "async function runTool() {\n"
        "  execSync('ls');\n"
        "}\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.cjs"
    assert findings[0].line == 5


def test_same_file_const_arrow_aliased_import_spawn_as_run_mts(tmp_path):
    (tmp_path / "server.mts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { spawn as run } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "const runTool = async () => {\n"
        "  run('sh');\n"
        "};\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.mts"
    assert findings[0].line == 5


def test_inline_arrow_destructured_require_exec_js(tmp_path):
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { exec } = require('child_process');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.js"
    assert findings[0].line == 5


# --------- clean controls: handler / context / scope ---------


def test_child_process_call_outside_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('safe', { description: 'd' }, async () => ({}));\n"
        "exec('ls');\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_non_mcp_register_tool_like_object_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('delete', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_local_class_named_mcp_server_without_official_import_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "class McpServer {\n"
        "  registerTool(name: string, cfg: unknown, fn: unknown) {}\n"
        "}\n"
        "const server = new McpServer();\n"
        "server.registerTool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_official_mcp_import_without_new_mcp_server_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_default_mcp_import_does_not_satisfy_context(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import Anything from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new Anything({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_server_tool_shorthand_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.tool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_set_request_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.setRequestHandler('tools/call', async (req) => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


# --------- cross-file: bounded relative-import handler resolution ---------


def test_imported_function_handler_with_child_process_exec_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file == "tools.ts"
    assert finding.line == 3
    assert finding.severity == "high"
    assert "TypeScript/JavaScript" in finding.message


def test_imported_const_arrow_handler_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export const runTool = async () => {\n"
        "  exec('ls');\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_aliased_import_handler_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool as handler } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_aliased_export_clause_resolves_through_local_function(tmp_path):
    # `export { runTool as handler }` — importer asks for `handler`; resolver
    # routes back to the local same-file `function runTool` in the target file.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { handler } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, handler);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "async function runTool() {\n"
        "  exec('ls');\n"
        "}\n"
        "export { runTool as handler };\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_package_import_handler_not_resolved(tmp_path):
    # `@some/package` is a package import, not a relative path. The handler is
    # not resolved through cross-file lookup, so no finding is emitted even if
    # a file named `some-package.ts` happens to exist alongside.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from '@some/package';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_namespace_local_import_handler_not_resolved(tmp_path):
    # `import * as tools from "./tools"; ...registerTool(_, _, tools.runTool)`
    # is a namespace-from-local form; v1 does not resolve the member access.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as tools from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, tools.runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_default_export_handler_not_resolved(tmp_path):
    # Default-export resolution is intentionally not v1. Even though the
    # importer's identifier `runTool` would point at the default export here,
    # the resolver does not match it.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import runTool from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export default async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_missing_local_target_file_does_not_crash(tmp_path):
    # The scanning file imports from a relative path that does not exist on
    # disk. Resolution must silently produce no handler body and no crash.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './missing';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_barrel_re_export_not_resolved_in_v1(tmp_path):
    # `export { runTool } from './deep'` is a re-export with a source clause.
    # The resolver intentionally does not traverse this in v1, so the handler
    # body in `./deep.ts` is unreachable through `./tools`.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "export { runTool } from './deep';\n",
        encoding="utf-8",
    )
    (tmp_path / "deep.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_malformed_imported_target_does_not_crash(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls'\nincomplete syntax here\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_imported_handler_parameter_shadow_in_target_does_not_fire(tmp_path):
    # The handler-scope shadow rule must apply in the TARGET file's context:
    # an `exec` parameter in the imported function declaration shadows the
    # target file's imported `exec`. No finding should be emitted.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool(exec) {\n"
        "  exec('safe local');\n"
        "}\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


# --------- robustness ---------


def test_malformed_ts_does_not_crash_and_emits_no_finding(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls'\nincomplete syntax here\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_oversized_ts_does_not_crash_and_emits_no_finding(tmp_path):
    big = tmp_path / "big.ts"
    big.write_text("// pad\n" * 200_000, encoding="utf-8")

    assert _cp_findings(tmp_path) == []


# --------- sub-cases: child_process detection breadth ---------


def test_namespace_require_cp_exec_fires(tmp_path):
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const cp = require('child_process');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  cp.exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.js"
    assert findings[0].line == 5


def test_destructured_require_aliased_execsync_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { execSync: runSync } = require('child_process');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  runSync('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.cjs"
    assert findings[0].line == 5


# --------- SARIF integration ---------


def test_sarif_includes_js_child_process_finding(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    findings = [f for f in report.findings if f.rule_id == RULE_ID]
    assert len(findings) == 1

    sarif = report.to_sarif()
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert RULE_ID in rule_ids

    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == RULE_ID]
    assert len(results) == 1
    result = results[0]
    assert result["level"] == "error"
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == "server.ts"
    assert physical_location["region"]["startLine"] == 5


# --------- regression: comment in argument list must not hide the handler ---------


def test_comment_between_config_and_handler_still_fires(tmp_path):
    # A line comment placed between the inline config and the handler argument
    # is exposed by tree-sitter as a `comment` child of the call's `arguments`
    # node. Such children must NOT be treated as a positional argument or the
    # third-arg handler resolution would mis-point at the comment.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool(\n"
        "  'run',\n"
        "  { description: 'd' },\n"
        "  // handler comment\n"
        "  async () => {\n"
        "    exec('ls');\n"
        "  }\n"
        ");\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 9


def test_block_comment_between_config_and_handler_still_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool(\n"
        "  'run',\n"
        "  { description: 'd' },\n"
        "  /* block comment */ async () => {\n"
        "    exec('ls');\n"
        "  }\n"
        ");\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 8


# --------- regression: handler-scope shadow control for FP suppression ---------


def test_handler_parameter_shadows_direct_name_does_not_fire(tmp_path):
    # The handler's own parameter `exec` shadows the imported `exec`. The
    # ``exec('safe local')`` call refers to the local parameter, not the
    # child_process API.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async (exec) => {\n"
        "  exec('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_handler_parameter_shadows_namespace_alias_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as cp from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async (cp) => {\n"
        "  cp.exec('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_handler_top_level_const_shadows_direct_name_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  const exec = (cmd: string) => cmd;\n"
        "  exec('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_handler_top_level_function_shadows_direct_name_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, async () => {\n"
        "  function exec(cmd: string) {\n"
        "    return cmd;\n"
        "  }\n"
        "  exec('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_handler_param_shadows_direct_name_for_function_declaration_handler(tmp_path):
    # The handler is a same-file ``function`` declaration that takes a parameter
    # named `exec` — shadow must apply through identifier-handler resolution.
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { exec } = require('child_process');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "async function runTool(exec) {\n"
        "  exec('safe local');\n"
        "}\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


# --------- cross-file: scan-root boundary and fail-closed regressions ---------


def test_relative_import_outside_scan_root_is_not_parsed(tmp_path, monkeypatch):
    # A scanned repo can syntactically reference ``../outside.ts``. Lurkr must
    # NOT read or parse files outside the requested scan root, no matter
    # whether the resulting handler resolution would emit a finding. The
    # boundary check has to run BEFORE the target file is parsed.
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    outside_target = tmp_path / "outside.ts"
    outside_target.write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )
    (scan_root / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from '../outside';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    from lurkr.rules import js_agent as js_agent_mod

    parsed_paths: list[Path] = []
    original_load = js_agent_mod.load_js_ast_document

    def tracking_load(path, *args, **kwargs):
        try:
            parsed_paths.append(Path(path).resolve())
        except OSError:
            parsed_paths.append(Path(path))
        return original_load(path, *args, **kwargs)

    monkeypatch.setattr(js_agent_mod, "load_js_ast_document", tracking_load)

    findings = _cp_findings(scan_root)

    assert findings == []
    outside_resolved = outside_target.resolve()
    assert outside_resolved not in parsed_paths, (
        "outside target was parsed despite being outside scan root: "
        f"parsed={parsed_paths}"
    )


def test_oversized_imported_target_does_not_crash(tmp_path):
    # An imported relative target exceeding the JS/TS source byte cap must
    # cause cross-file resolution to fail closed: no crash, no finding.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    # ~1.4 MB > MAX_SOURCE_BYTES (1 MB).
    (tmp_path / "tools.ts").write_text("// pad\n" * 200_000, encoding="utf-8")

    assert _cp_findings(tmp_path) == []


# --------- file mutation rule: fs imports inside MCP handlers ---------


def test_inline_arrow_named_import_writefile_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('write', { description: 'd' }, async () => {\n"
        "  await writeFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == FS_RULE_ID
    assert finding.severity == "high"
    assert finding.file == "server.ts"
    assert finding.line == 5
    assert "write or delete files" in finding.message
    assert "Restrict file-write/delete access" in finding.remediation


def test_inline_arrow_namespace_import_rmsync_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as fs from 'node:fs';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete', { description: 'd' }, async () => {\n"
        "  fs.rmSync('out.txt');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_inline_arrow_fs_promises_namespace_appendfile_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as fsp from 'fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('append', { description: 'd' }, async () => {\n"
        "  await fsp.appendFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_inline_arrow_fs_promises_member_chain_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import fs from 'node:fs';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('write', { description: 'd' }, async () => {\n"
        "  await fs.promises.writeFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_same_file_const_arrow_destructured_require_unlink_alias_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { unlink: remove } = require('fs');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "const runTool = async () => {\n"
        "  remove('out.txt');\n"
        "};\n"
        "server.registerTool('delete', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.cjs"
    assert findings[0].line == 5


def test_imported_function_handler_with_fs_mkdir_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('mkdir', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { mkdir } from 'node:fs/promises';\n"
        "export async function runTool() {\n"
        "  await mkdir('out');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_file_read_inside_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { readFile } from 'node:fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('read', { description: 'd' }, async () => {\n"
        "  await readFile('out.txt');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _fs_findings(tmp_path) == []


def test_file_write_outside_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('status', { description: 'd' }, async () => ({}));\n"
        "writeFile('out.txt', 'body');\n",
        encoding="utf-8",
    )

    assert _fs_findings(tmp_path) == []


def test_non_mcp_register_tool_file_write_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { writeFile } from 'node:fs/promises';\n"
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('write', {}, async () => {\n"
        "  await writeFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _fs_findings(tmp_path) == []


def test_handler_parameter_shadows_file_direct_name_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('write', { description: 'd' }, async (writeFile) => {\n"
        "  await writeFile('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _fs_findings(tmp_path) == []


def test_handler_parameter_shadows_file_namespace_alias_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as fs from 'node:fs';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('write', { description: 'd' }, async (fs) => {\n"
        "  await fs.promises.writeFile('safe local');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _fs_findings(tmp_path) == []


def test_sarif_includes_js_file_mutation_finding(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('write', { description: 'd' }, async () => {\n"
        "  await writeFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    findings = [f for f in report.findings if f.rule_id == FS_RULE_ID]
    assert len(findings) == 1

    sarif = report.to_sarif()
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert FS_RULE_ID in rule_ids

    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == FS_RULE_ID]
    assert len(results) == 1
    result = results[0]
    assert result["level"] == "error"
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == "server.ts"
    assert physical_location["region"]["startLine"] == 5


# --------- env-secret rule: secret-like process.env access inside handlers ---------


def test_inline_arrow_process_env_openai_api_key_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  const key = process.env.OPENAI_API_KEY;\n"
        "  return { key };\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == ENV_RULE_ID
    assert finding.severity == "high"
    assert finding.file == "server.ts"
    assert finding.line == 4
    assert "secret-like" in finding.message
    assert "process.env" in finding.remediation
    assert "approval" in finding.remediation


def test_bracket_access_process_env_github_token_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  const token = process.env[\"GITHUB_TOKEN\"];\n"
        "  return { token };\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_suffix_secret_name_custom_secret_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  const value = process.env.CUSTOM_SECRET;\n"
        "  return { value };\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


def test_suffix_secret_name_my_token_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  return process.env.MY_TOKEN;\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


def test_suffix_secret_name_db_password_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  return process.env.DB_PASSWORD;\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


def test_imported_handler_with_process_env_secret_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "export async function runTool() {\n"
        "  const key = process.env.ANTHROPIC_API_KEY;\n"
        "  return { key };\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 2


def test_process_env_node_env_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  const env = process.env.NODE_ENV;\n"
        "  return { env };\n"
        "});\n",
        encoding="utf-8",
    )

    assert _env_findings(tmp_path) == []


def test_process_env_secret_outside_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "const k = process.env.OPENAI_API_KEY;\n"
        "server.registerTool('lookup', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    assert _env_findings(tmp_path) == []


def test_non_mcp_register_tool_process_env_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('lookup', {}, async () => {\n"
        "  const key = process.env.OPENAI_API_KEY;\n"
        "  return { key };\n"
        "});\n",
        encoding="utf-8",
    )

    assert _env_findings(tmp_path) == []


def test_handler_parameter_shadows_process_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async (process) => {\n"
        "  const key = process.env.OPENAI_API_KEY;\n"
        "  return { key };\n"
        "});\n",
        encoding="utf-8",
    )

    assert _env_findings(tmp_path) == []


def test_nested_process_env_member_chain_does_not_fire(tmp_path):
    # `process.env.A.OPENAI_API_KEY` is not a direct `process.env.<NAME>`
    # access; v1 deliberately restricts to one level of property access.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  return (process.env as any).A.OPENAI_API_KEY;\n"
        "});\n",
        encoding="utf-8",
    )

    assert _env_findings(tmp_path) == []


def test_sarif_includes_js_env_secret_finding(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "  const key = process.env.OPENAI_API_KEY;\n"
        "  return { key };\n"
        "});\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    findings = [f for f in report.findings if f.rule_id == ENV_RULE_ID]
    assert len(findings) == 1

    sarif = report.to_sarif()
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert ENV_RULE_ID in rule_ids

    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == ENV_RULE_ID]
    assert len(results) == 1
    result = results[0]
    assert result["level"] == "error"
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == "server.ts"
    assert physical_location["region"]["startLine"] == 4


# --------- network rule: outbound network calls inside MCP handlers ---------


def test_global_fetch_https_external_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  const r = await fetch('https://api.example.com');\n"
        "  return { r };\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == NETWORK_RULE_ID
    assert finding.severity == "high"
    assert finding.file == "server.ts"
    assert finding.line == 4
    assert "outbound network calls" in finding.message
    assert "allowlist" in finding.remediation
    assert "approval" in finding.remediation


def test_axios_default_import_get_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  const r = await axios.get('https://api.example.com');\n"
        "  return { r };\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_axios_default_import_post_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return axios.post('https://api.example.com', { a: 1 });\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_axios_default_import_callable_form_fires(tmp_path):
    # `import axios from "axios"` binds ``axios`` as a callable network
    # primitive (axios is a callable package). The bare ``axios(...)`` form
    # must be flagged in addition to the member-style ``axios.get(...)``.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return axios({ url: 'https://api.example.com' });\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_axios_whole_require_callable_form_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const axios = require('axios');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return axios({ url: 'https://api.example.com' });\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_axios_namespace_import_callable_form_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return axios({ url: 'https://api.example.com' });\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_https_request_node_prefix_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import https from 'node:https';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return https.request('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_http_request_namespace_import_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as http from 'http';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return http.request('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_undici_namespace_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import * as undici from 'undici';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return undici.fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_undici_named_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { fetch } from 'undici';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_got_destructured_require_callable_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { got } = require('got');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return got('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_got_default_import_callable_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import got from 'got';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return got('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_got_whole_require_callable_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const got = require('got');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return got('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_destructured_require_fetch_from_undici_fires(tmp_path):
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { fetch } = require('undici');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 5


def test_imported_handler_with_axios_get_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import axios from 'axios';\n"
        "export async function runTool() {\n"
        "  return axios.get('https://api.example.com');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_static_localhost_fetch_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('http://localhost:3000/api');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_static_127_0_0_1_fetch_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('http://127.0.0.1:8080');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_static_ipv6_local_fetch_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('http://[::1]/healthz');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_dynamic_url_first_arg_still_fires(tmp_path):
    # Non-static first arg cannot be checked against the localhost rule, so
    # the rule errs on the side of flagging. This preserves coverage when the
    # URL is computed from a variable.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async (url: string) => {\n"
        "  return fetch(url);\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


def test_handler_parameter_shadows_fetch_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async (fetch) => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_handler_parameter_shadows_axios_namespace_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async (axios) => {\n"
        "  return axios.get('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_network_call_outside_handler_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "fetch('https://api.example.com');\n"
        "server.registerTool('call', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_non_mcp_register_tool_network_call_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('call', {}, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_sarif_includes_js_network_call_finding(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  const r = await fetch('https://api.example.com');\n"
        "  return { r };\n"
        "});\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    findings = [f for f in report.findings if f.rule_id == NETWORK_RULE_ID]
    assert len(findings) == 1

    sarif = report.to_sarif()
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert NETWORK_RULE_ID in rule_ids

    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == NETWORK_RULE_ID]
    assert len(results) == 1
    result = results[0]
    assert result["level"] == "error"
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == "server.ts"
    assert physical_location["region"]["startLine"] == 4


# --------- regression: callable-package shadow + scheme-required localhost ---------


def test_handler_parameter_shadows_axios_callable_form_does_not_fire(tmp_path):
    # Shadow handling must work uniformly for the callable form as well as
    # the member-method form: a handler parameter named ``axios`` must
    # suppress both ``axios.get(...)`` and ``axios(...)``.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import axios from 'axios';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async (axios) => {\n"
        "  return axios({ url: 'https://api.example.com' });\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_handler_parameter_shadows_got_callable_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import got from 'got';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async (got) => {\n"
        "  return got('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _network_findings(tmp_path) == []


def test_bare_host_localhost_string_still_fires(tmp_path):
    # The localhost suppression only matches when the URL carries an
    # explicit ``http://`` / ``https://`` scheme. A scheme-less
    # ``localhost:3000`` string is ambiguous (relative path vs host:port),
    # so the rule errs on the side of flagging.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('localhost:3000/api');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


# --------- chained construction: new McpServer(...).registerTool(...) ---------


def test_chained_construction_cp_exec_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_chained_construction_fs_writefile_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('write', { description: 'd' }, async () => {\n"
        "  await writeFile('out.txt', 'body');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_chained_construction_env_secret_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('lookup', { description: 'd' }, async () => {\n"
        "  return process.env.OPENAI_API_KEY;\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 3


def test_chained_construction_network_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 3


def test_chained_construction_namespace_network_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import * as mcp from '@modelcontextprotocol/server';\n"
        "new mcp.McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 3


def test_chained_construction_local_class_does_not_fire(tmp_path):
    # `new McpServer(...).registerTool(...)` with a locally-declared
    # ``McpServer`` class and no official MCP import must not produce any
    # risk-rule findings — the MCP gate is still required for chained
    # registrations.
    (tmp_path / "server.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "class McpServer {\n"
        "  registerTool(name: string, cfg: unknown, fn: unknown) {}\n"
        "}\n"
        "new McpServer().registerTool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []
    assert _fs_findings(tmp_path) == []
    assert _env_findings(tmp_path) == []
    assert _network_findings(tmp_path) == []


# --------- typed-parameter helper wrappers: per-rule TPs + scope discipline ---------


def test_typed_wrapper_cp_exec_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  server.registerTool('run', { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_typed_wrapper_fs_writefile_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "export const registerWriteTool = (server: McpServer) => {\n"
        "  server.registerTool('write', { description: 'd' }, async () => {\n"
        "    await writeFile('out.txt', 'body');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_typed_wrapper_env_secret_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "export const registerLookupTool = (server: McpServer) => {\n"
        "  server.registerTool('lookup', { description: 'd' }, async () => {\n"
        "    return process.env.OPENAI_API_KEY;\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_typed_wrapper_network_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "export const registerCallTool = (server: McpServer) => {\n"
        "  server.registerTool('call', { description: 'd' }, async () => {\n"
        "    return fetch('https://api.example.com');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_typed_wrapper_namespace_type_cp_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import * as mcp from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "export function registerRunTool(server: mcp.McpServer) {\n"
        "  server.registerTool('run', { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_typed_wrapper_param_name_does_not_leak_to_untyped_wrapper(tmp_path):
    # Two wrappers in the same file: the first has ``(server: McpServer)``
    # (typed — MCP context); the second has the same parameter name
    # ``(server)`` but no type annotation (NOT MCP context). Only the typed
    # wrapper's handler should be walked; the untyped one's exec must be
    # silent.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "export const registerInside = (server: McpServer) => {\n"
        "  server.registerTool('inside', { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n"
        "export const noTypeAnnotation = (server) => {\n"
        "  server.registerTool('outside', { description: 'd' }, async () => {\n"
        "    exec('rm -rf /');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


def test_typed_wrapper_untyped_only_does_not_fire(tmp_path):
    # No typed wrappers present, just one untyped param wrapper with an
    # official MCP import. Gate must NOT recognise this as MCP context.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "export const registerRunTool = (server) => {\n"
        "  server.registerTool('run', { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []
    assert _fs_findings(tmp_path) == []
    assert _env_findings(tmp_path) == []
    assert _network_findings(tmp_path) == []


def test_typed_wrapper_nested_function_with_typed_param_isolates_scope(tmp_path):
    # An outer typed wrapper contains a nested typed wrapper that also has
    # ``(server: McpServer)``. Each wrapper's body is walked independently;
    # the outer body's _iter_typed_wrapper_scope does NOT cross into the
    # nested function. Both wrappers' calls are emitted by their own pass.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "export const registerOuter = (server: McpServer) => {\n"
        "  server.registerTool('outer', { description: 'd' }, async () => {\n"
        "    exec('outer');\n"
        "  });\n"
        "  const registerInner = (server: McpServer) => {\n"
        "    server.registerTool('inner', { description: 'd' }, async () => {\n"
        "      exec('inner');\n"
        "    });\n"
        "  };\n"
        "  return registerInner;\n"
        "};\n",
        encoding="utf-8",
    )

    findings = sorted(_cp_findings(tmp_path), key=lambda f: f.line)

    assert len(findings) == 2
    assert findings[0].line == 5  # outer exec
    assert findings[1].line == 9  # inner exec


# --------- same-file const-resolved tool names: per-rule TPs + cleans ---------


def test_const_resolved_tool_name_typed_wrapper_cp_fires(tmp_path):
    # The canonical `modelcontextprotocol/servers/everything/tools/*.ts`
    # shape: top-level `const name = "literal"` referenced inside a typed
    # wrapper. The cp rule must fire through the resolved registration.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'run';\n"
        "const config = { description: 'd' };\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  server.registerTool(name, config, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 7


def test_const_resolved_tool_name_typed_wrapper_fs_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { writeFile } from 'node:fs/promises';\n"
        "const name = 'write';\n"
        "const config = { description: 'd' };\n"
        "export const registerWriteTool = (server: McpServer) => {\n"
        "  server.registerTool(name, config, async () => {\n"
        "    await writeFile('out.txt', 'body');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _fs_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 7


def test_const_resolved_tool_name_typed_wrapper_env_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const name = 'lookup';\n"
        "const config = { description: 'd' };\n"
        "export const registerLookupTool = (server: McpServer) => {\n"
        "  server.registerTool(name, config, async () => {\n"
        "    return process.env.OPENAI_API_KEY;\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _env_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 6


def test_const_resolved_tool_name_typed_wrapper_network_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const name = 'call';\n"
        "const config = { description: 'd' };\n"
        "export const registerCallTool = (server: McpServer) => {\n"
        "  server.registerTool(name, config, async () => {\n"
        "    return fetch('https://api.example.com');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 6


def test_const_resolved_tool_name_helper_wrapper_cp_fires(tmp_path):
    # Same const-name pattern but the wrapper uses ``function`` declaration
    # syntax instead of arrow.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'run';\n"
        "const config = { description: 'd' };\n"
        "export function registerRunTool(server: McpServer) {\n"
        "  server.registerTool(name, config, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 7


def test_let_tool_name_skipped_in_typed_wrapper(tmp_path):
    # `let` is not resolved — v1 supports `const` only.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "let name = 'run';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


# --------- shadowing guard for top-level const-name fallback ---------


def test_local_const_shadows_top_level_const_in_typed_wrapper_no_fire(tmp_path):
    # Operator's exact P1 reproducer: top-level `const name = "..."` AND a
    # local `const name = computeName()` inside the typed wrapper. The
    # registerTool first arg refers to the LOCAL shadow, so resolution must
    # fail (not fall through to the top-level binding) and the rule must
    # emit zero findings.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  const name = computeName();\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_local_let_shadows_top_level_const_in_typed_wrapper_no_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  let name = 'reassignable';\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_wrapper_parameter_shadows_top_level_const_no_fire(tmp_path):
    # The typed wrapper's own parameter is named ``name``, which shadows
    # the top-level ``const name``. The registerTool first arg refers to
    # the parameter — not statically resolvable to a string.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer, name: string) => {\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_local_var_shadows_top_level_const_no_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  var name = 'var_local';\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_local_function_decl_shadows_top_level_const_no_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  function name() { return 'fn'; }\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    exec('ls');\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_nested_block_const_shadows_top_level_const_no_fire(tmp_path):
    # Block-level shadow: the registerTool sits inside an ``if`` block whose
    # body declares its own ``const name``. The walk-up must visit that
    # block's statement_block as a scope and find the shadow.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'top_level_literal';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  if (true) {\n"
        "    const name = 'block_local';\n"
        "    server.registerTool(name, { description: 'd' }, async () => {\n"
        "      exec('ls');\n"
        "    });\n"
        "  }\n"
        "};\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_sibling_scope_const_does_not_shadow_top_level(tmp_path):
    # Inner handler's body contains its own ``const name``, but it is in a
    # SIBLING scope to the registerTool call's first argument — the
    # walk-up from the first arg goes through the wrapper's body, not
    # through the handler's body. Top-level ``const name`` must still
    # resolve, and the rule must fire on the handler's exec.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const name = 'run';\n"
        "export const registerRunTool = (server: McpServer) => {\n"
        "  server.registerTool(name, { description: 'd' }, async () => {\n"
        "    const name = 'inner_unused';\n"
        "    exec('ls');\n"
        "    return name;\n"
        "  });\n"
        "};\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 7  # exec line


# --------- B1: parenthesized chained construction ---------


def test_parenthesized_chained_construction_cp_exec_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "(new McpServer({ name: 'demo', version: '1.0.0' }))"
        ".registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4


def test_parenthesized_chained_construction_network_fetch_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "(new McpServer({ name: 'demo', version: '1.0.0' }))"
        ".registerTool('call', { description: 'd' }, async () => {\n"
        "  return fetch('https://api.example.com');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _network_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 3


def test_parenthesized_chained_local_class_does_not_fire(tmp_path):
    # Parenthesized chained construction over a locally-declared `McpServer`
    # class (no official MCP import) must NOT satisfy the gate.
    (tmp_path / "server.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "class McpServer {\n"
        "  registerTool(name: string, cfg: unknown, fn: unknown) {}\n"
        "}\n"
        "(new McpServer()).registerTool('run', {}, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_parenthesized_identifier_bound_registerTool_fires(tmp_path):
    # Side benefit of the same `_unwrap_parentheses` helper: identifier-bound
    # ``(server).registerTool(...)`` (paren around the receiver identifier)
    # is also recognised through the same code path.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "(server).registerTool('run', { description: 'd' }, async () => {\n"
        "  exec('ls');\n"
        "});\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 5


# --------- B2: directory / index relative-import resolution ---------


def test_imported_handler_from_directory_index_cp_fires(tmp_path):
    # `import { runTool } from './tools'` resolves to `./tools/index.ts`.
    # The cross-file handler resolution must reach into that index file
    # and the cp rule must fire on the handler body's exec call.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "index.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools/index.ts"
    assert findings[0].line == 3


def test_imported_handler_from_directory_index_js_extension_cp_fires(tmp_path):
    # Same as above but the target is `./tools/index.js`.
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const { runTool } = require('./tools');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "index.js").write_text(
        "const { exec } = require('node:child_process');\n"
        "exports.runTool = async function runTool() {\n"
        "  exec('ls');\n"
        "};\n",
        encoding="utf-8",
    )

    # NB: CommonJS `exports.runTool = ...` is NOT one of the supported export
    # shapes (only `export function` / `export const arrow`), so the handler
    # body cannot be reached even though the directory/index resolution
    # itself succeeded. The negative assertion here pins that v1 limitation:
    # directory/index resolution lands the right file but ES-module export
    # shapes are still required for body walking.
    assert _cp_findings(tmp_path) == []


def test_imported_handler_from_directory_index_tsx_fires(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "index.tsx").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools/index.tsx"
    assert findings[0].line == 3


def test_imported_handler_directory_index_missing_does_not_crash(tmp_path):
    # `./tools` exists as a directory but has no `index.<suffix>`. Resolution
    # must fall through to None, the binding is dropped silently, and no
    # findings appear.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "not-index.ts").write_text(
        "export async function runTool() {}\n",
        encoding="utf-8",
    )

    assert _cp_findings(tmp_path) == []


def test_sibling_file_wins_over_directory_index(tmp_path):
    # Both `./tools.ts` AND `./tools/index.ts` exist; the file probe wins
    # per Node-style resolution precedence. The handler body in
    # `tools.ts` (not the directory's) must be walked.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from './tools';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('file');\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "index.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('directory-index');\n"
        "}\n",
        encoding="utf-8",
    )

    findings = _cp_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "tools.ts"
    assert findings[0].line == 3


def test_directory_index_outside_scan_root_is_not_parsed(tmp_path, monkeypatch):
    # The scan-root boundary check applies equally to directory/index
    # resolution: if `../outside/index.ts` resolves outside the scan root,
    # the binding is dropped BEFORE any parse occurs.
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_target = outside_dir / "index.ts"
    outside_target.write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
        "}\n",
        encoding="utf-8",
    )
    (scan_root / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { runTool } from '../outside';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', { description: 'd' }, runTool);\n",
        encoding="utf-8",
    )

    from lurkr.rules import js_agent as js_agent_mod

    parsed_paths: list[Path] = []
    original_load = js_agent_mod.load_js_ast_document

    def tracking_load(path, *args, **kwargs):
        try:
            parsed_paths.append(Path(path).resolve())
        except OSError:
            parsed_paths.append(Path(path))
        return original_load(path, *args, **kwargs)

    monkeypatch.setattr(js_agent_mod, "load_js_ast_document", tracking_load)

    findings = _cp_findings(scan_root)

    assert findings == []
    outside_resolved = outside_target.resolve()
    assert outside_resolved not in parsed_paths, (
        "outside directory/index target was parsed despite being outside "
        f"scan root: parsed={parsed_paths}"
    )
