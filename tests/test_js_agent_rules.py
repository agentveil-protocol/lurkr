"""Tests for the TypeScript/JavaScript agent posture rules.

Covers:

- ``agent.javascript_child_process_in_tool`` — Node.js ``child_process`` shell
  execution inside canonical MCP ``registerTool`` handlers.
- ``agent.javascript_file_mutation_in_tool`` — Node.js ``fs`` / ``fs/promises``
  file mutation inside canonical MCP ``registerTool`` handlers.
"""

from __future__ import annotations

from pathlib import Path

from lurkr.scanner import scan_path


RULE_ID = "agent.javascript_child_process_in_tool"
FS_RULE_ID = "agent.javascript_file_mutation_in_tool"


def _cp_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == RULE_ID]


def _fs_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == FS_RULE_ID]


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
