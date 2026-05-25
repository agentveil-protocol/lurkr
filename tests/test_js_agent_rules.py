"""Tests for the TypeScript/JavaScript agent posture rules.

Covers ``agent.javascript_child_process_in_tool`` — Node.js ``child_process``
shell execution inside canonical MCP ``registerTool`` handlers.
"""

from __future__ import annotations

from pathlib import Path

from lurkr.scanner import scan_path


RULE_ID = "agent.javascript_child_process_in_tool"


def _cp_findings(path: Path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == RULE_ID]


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


def test_imported_handler_reference_from_another_file_does_not_fire(tmp_path):
    # Handler is an imported identifier — cross-file resolution is intentionally
    # out of scope. There is no same-file `function runTool() {}` or `const
    # runTool = ...` to walk, so the handler body is not reachable.
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "import { exec } from 'node:child_process';\n"
        "import { runTool } from './tool';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('run', {}, runTool);\n",
        encoding="utf-8",
    )
    # Bystander file with the body — must not be cross-file resolved.
    (tmp_path / "tool.ts").write_text(
        "import { exec } from 'node:child_process';\n"
        "export async function runTool() {\n"
        "  exec('ls');\n"
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
