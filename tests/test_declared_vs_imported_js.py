"""Tests for the declared-vs-imported delta rule, JavaScript/TypeScript branch."""

from __future__ import annotations

import json

from lurkr.cli import main as cli_main
from lurkr.scanner import scan_path


RULE_ID = "agent.declared_vs_imported_delta"


def _delta_findings(path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == RULE_ID]


# --------- TP / clean match cases ---------


def test_ts_clean_match_has_no_findings(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('search_docs', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_ts_shadow_mismatch_fires_once_per_shadow(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('search_docs', { description: 'd' }, async () => ({}));\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 4
    assert "delete_files" in findings[0].message
    assert "TypeScript/JavaScript" in findings[0].message
    assert "delete_files" in findings[0].remediation


def test_js_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.js"
    assert "delete_files" in findings[0].message


def test_tsx_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.tsx").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    assert any(f.file == "server.tsx" for f in _delta_findings(tmp_path))


def test_mjs_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.mjs").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    assert any(f.file == "server.mjs" for f in _delta_findings(tmp_path))


# --------- gate / context tests ---------


def test_no_mcp_context_does_not_fire(tmp_path):
    # No `new McpServer(...)` anywhere — registration on an unrelated object.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "const router = { registerTool(name, cfg, fn) {} };\n"
        "router.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_arbitrary_require_mcp_package_without_new_does_not_fire(tmp_path):
    # Import/require from MCP package but no `new McpServer(...)`.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import * as mcp from '@modelcontextprotocol/server';\n"
        "const router = mcp.makeFakeRouter();\n"
        "router.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_unrelated_register_tool_in_same_file_as_mcp_server_not_flagged(tmp_path):
    # Both McpServer present AND unrelated object with registerTool — only
    # calls on McpServer-bound identifier should be considered.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "const unrelated = { registerTool(name, cfg, fn) {} };\n"
        "unrelated.registerTool('delete_files', {}, () => ({}));\n"
        "server.registerTool('search_docs', {}, () => ({}));\n",
        encoding="utf-8",
    )

    # Only server-bound call is considered. It matches declared 'search_docs'.
    assert _delta_findings(tmp_path) == []


def test_server_tool_shorthand_does_not_fire(tmp_path):
    # `server.tool(...)` is not the canonical current MCP API; explicitly skipped.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.tool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_set_request_handler_does_not_fire(tmp_path):
    # Low-level handler API does not surface static tool names; explicitly skipped.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.setRequestHandler('tools/call', async (req) => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_dynamic_tool_name_skipped_silently(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "const name = 'delete_files';\n"
        "server.registerTool(name, {}, () => ({}));\n"
        "server.registerTool(`tool_${name}`, {}, () => ({}));\n"
        "server.registerTool(getName(), {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_no_manifest_does_not_fire(tmp_path):
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_multiple_manifests_union_covers_ts(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "langchain_agent.yaml").write_text(
        "tools:\n  - delete_files\n",
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('search_docs', {}, () => ({}));\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_duplicate_ts_registrations_dedupe(tmp_path):
    # Two distinct call sites with same tool name — both yield findings
    # at different lines, but same (rule_id, file, line) should dedupe a
    # double-emit at the same site.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    # Both call sites are different lines; dedupe is (rule_id, file, line)
    # so two findings (lines 3 and 4) are expected, not one.
    assert len(findings) == 2
    assert sorted(f.line for f in findings) == [3, 4]


# --------- robustness ---------


def test_malformed_ts_skipped_no_crash_no_finding(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', \nincomplete syntax here\n",
        encoding="utf-8",
    )

    # No crash. Malformed file is skipped silently — no findings emitted from it.
    assert _delta_findings(tmp_path) == []


def test_oversized_ts_skipped_no_crash(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    big = tmp_path / "big.ts"
    # ~1.2 MB > MAX_SOURCE_BYTES (1MB)
    big.write_text("// pad\n" * 200_000, encoding="utf-8")

    # No crash. Oversized file is skipped — no finding emitted from it.
    assert _delta_findings(tmp_path) == []


def test_node_modules_dist_build_ignored(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    for excluded_dir in ("node_modules", "dist", "build"):
        sub = tmp_path / excluded_dir / "pkg"
        sub.mkdir(parents=True)
        (sub / "server.ts").write_text(
            "import { McpServer } from '@modelcontextprotocol/server';\n"
            "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
            "server.registerTool('delete_files', {}, () => ({}));\n",
            encoding="utf-8",
        )

    assert _delta_findings(tmp_path) == []


# --------- report shape ---------


def test_ts_finding_has_severity_high_and_remediation(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.rule_id == "agent.declared_vs_imported_delta"
    assert "delete_files" in finding.remediation
    assert "TypeScript/JavaScript" in finding.remediation


# --------- additional source-suffix coverage ---------


def test_mts_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.mts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "server.mts"
    assert "delete_files" in findings[0].message


def test_cts_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.cts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "server.cts"
    assert "delete_files" in findings[0].message


def test_cjs_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.cjs").write_text(
        "const { McpServer } = require('@modelcontextprotocol/server');\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "server.cjs"
    assert "delete_files" in findings[0].message


# --------- SARIF + baseline integration for JS/TS findings ---------


def test_ts_finding_emits_correct_sarif_result(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    delta_findings = [f for f in report.findings if f.rule_id == RULE_ID]
    assert len(delta_findings) == 1

    sarif = report.to_sarif()
    results = sarif["runs"][0]["results"]
    matching = [r for r in results if r.get("ruleId") == RULE_ID]
    assert len(matching) == 1

    result = matching[0]
    assert result["level"] == "error"
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location["artifactLocation"]["uri"] == "server.ts"
    assert physical_location["region"]["startLine"] == 3


def test_ts_finding_baseline_suppresses_known_shadow(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (project / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"
    filtered = tmp_path / "filtered.json"

    save_exit = cli_main(
        [
            "scan",
            "--path",
            str(project),
            "--save-baseline",
            str(baseline),
        ]
    )
    assert save_exit == 0
    baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
    delta_entries = [
        entry
        for entry in baseline_data["entries"]
        if entry["rule_id"] == RULE_ID
    ]
    assert len(delta_entries) == 1

    filtered_exit = cli_main(
        [
            "scan",
            "--path",
            str(project),
            "--baseline",
            str(baseline),
            "--output",
            str(filtered),
        ]
    )
    assert filtered_exit == 0
    filtered_report = json.loads(filtered.read_text(encoding="utf-8"))
    js_findings_after_baseline = [
        finding
        for finding in filtered_report["findings"]
        if finding["rule_id"] == RULE_ID
    ]
    assert js_findings_after_baseline == []


# --------- MCP-context gate: import provenance ---------


def test_ts_namespace_import_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import * as mcp from '@modelcontextprotocol/server';\n"
        "const server = new mcp.McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert "delete_files" in findings[0].message


def test_local_class_named_mcp_server_not_flagged(tmp_path):
    # No official MCP import. A locally-declared `class McpServer { ... }`
    # is NOT enough to satisfy the gate — registrations on it must not fire.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "class McpServer {\n"
        "  registerTool(name: string, cfg: unknown, fn: unknown) {}\n"
        "}\n"
        "const server = new McpServer();\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_import_mcp_server_from_non_mcp_package_not_flagged(tmp_path):
    # `McpServer` symbol is imported from a non-official package.
    # The gate requires the source package prefix `@modelcontextprotocol/`.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from 'not-mcp';\n"
        "const server = new McpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_named_import_without_new_mcp_server_not_flagged(tmp_path):
    # Official MCP import present, but no `new McpServer(...)` in the file.
    # Calls on unrelated objects must not be flagged.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const router = { registerTool(name: string, cfg: unknown, fn: unknown) {} };\n"
        "router.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


# --------- MCP-context gate: symbol-specific provenance ---------


def test_named_import_other_symbol_from_mcp_package_not_flagged(tmp_path):
    # Symbol other than `McpServer` imported from official MCP package.
    # Even though the import is from the official package and `new
    # NotMcpServer(...)` is called, the gate must NOT treat it as an MCP
    # server context. Only `McpServer` (with optional alias) qualifies.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { NotMcpServer } from '@modelcontextprotocol/server';\n"
        "const server = new NotMcpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_destructured_require_other_symbol_from_mcp_package_not_flagged(tmp_path):
    # Symbol other than `McpServer` destructured from `require("@mcp/...")`.
    # Same invariant as the named-import case.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "const { NotMcpServer } = require('@modelcontextprotocol/server');\n"
        "const server = new NotMcpServer({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_aliased_named_import_of_mcp_server_fires(tmp_path):
    # `import { McpServer as Server } from "@mcp/..."` — original imported
    # symbol is `McpServer`, local binding is `Server`. The gate must accept
    # `new Server(...)` because the imported symbol matches.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer as Server } from '@modelcontextprotocol/server';\n"
        "const instance = new Server({ name: 'demo', version: '1.0.0' });\n"
        "instance.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert "delete_files" in findings[0].message


def test_aliased_destructured_require_of_mcp_server_fires(tmp_path):
    # `const { McpServer: Server } = require("@mcp/...")` — original property
    # name is `McpServer`, local binding is `Server`. Same accept rule as the
    # ES aliased-named-import case.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.js").write_text(
        "const { McpServer: Server } = require('@modelcontextprotocol/server');\n"
        "const instance = new Server({ name: 'demo', version: '1.0.0' });\n"
        "instance.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)
    assert len(findings) == 1
    assert findings[0].file == "server.js"
    assert "delete_files" in findings[0].message


def test_default_import_from_mcp_package_not_flagged(tmp_path):
    # Default imports are intentionally not accepted in v1: the official MCP
    # SDK exposes `McpServer` as a named export, so a default-import binding
    # cannot be assumed to be the McpServer class.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import Anything from '@modelcontextprotocol/server';\n"
        "const server = new Anything({ name: 'demo', version: '1.0.0' });\n"
        "server.registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


# --------- chained construction: new McpServer(...).registerTool(...) ---------


def test_chained_construction_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 2
    assert "delete_files" in findings[0].message
    assert "TypeScript/JavaScript" in findings[0].message


def test_chained_namespace_construction_shadow_mismatch_fires(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import * as mcp from '@modelcontextprotocol/server';\n"
        "new mcp.McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool('delete_files', { description: 'd' }, async () => ({}));\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "server.ts"
    assert findings[0].line == 2
    assert "delete_files" in findings[0].message


def test_chained_construction_local_class_mcp_server_not_flagged(tmp_path):
    # `new McpServer(...).registerTool(...)` where `McpServer` is a locally
    # declared class (no official MCP import) must not fire — the chained
    # branch still requires the MCP provenance gate.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "class McpServer {\n"
        "  registerTool(name: string, cfg: unknown, fn: unknown) {}\n"
        "}\n"
        "new McpServer().registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_chained_construction_default_mcp_import_not_flagged(tmp_path):
    # A default import from the official MCP package does not satisfy the
    # gate (v1 only recognises named / namespace imports for `McpServer`),
    # so the chained shape must also be silent.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import Anything from '@modelcontextprotocol/server';\n"
        "new Anything({ name: 'demo', version: '1.0.0' })"
        ".registerTool('delete_files', {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_chained_construction_dynamic_tool_name_skipped(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "search_docs"}]}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/server';\n"
        "const name = 'delete_files';\n"
        "new McpServer({ name: 'demo', version: '1.0.0' })"
        ".registerTool(name, {}, () => ({}));\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []
