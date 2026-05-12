from __future__ import annotations

import json

from lurkr.manifest import (
    collect_declared,
    extract_mcp_servers,
    normalize_capability_name,
    parse_manifest,
)


def test_mcp_parser_returns_declared_tool_names(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text(
        json.dumps({"tools": [{"name": "getRepo"}, {"name": "list_files"}]}),
        encoding="utf-8",
    )

    capabilities = parse_manifest(manifest)

    assert [capability.name for capability in capabilities] == ["get_repo", "list_files"]
    assert capabilities[0].raw_name == "getRepo"
    assert capabilities[0].source_line == 1


def test_crewai_parser_returns_nested_agent_tool_names(tmp_path):
    manifest = tmp_path / "crew_agents.yaml"
    manifest.write_text(
        "researcher:\n"
        "  role: Researcher\n"
        "  tools:\n"
        "    - SearchDocs\n"
        "    - name: summarize_page\n",
        encoding="utf-8",
    )

    assert [capability.name for capability in parse_manifest(manifest)] == [
        "search_docs",
        "summarize_page",
    ]


def test_autogen_parser_returns_function_tool_names(tmp_path):
    manifest = tmp_path / "autogen_team.json"
    manifest.write_text(
        json.dumps(
            {
                "tools": [
                    {"function": {"name": "get_weather"}},
                    {"config": {"name": "transferToUser"}},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert [capability.name for capability in parse_manifest(manifest)] == [
        "get_weather",
        "transfer_to_user",
    ]


def test_langchain_parser_returns_tool_list_names(tmp_path):
    manifest = tmp_path / "langchain_agent.yaml"
    manifest.write_text("tools:\n  - getUser\n  - search_docs\n", encoding="utf-8")

    assert [capability.name for capability in parse_manifest(manifest)] == [
        "get_user",
        "search_docs",
    ]


def test_malformed_yaml_returns_empty_list(tmp_path):
    manifest = tmp_path / "crew_agents.yaml"
    manifest.write_text("tools:\n  - [unterminated\n", encoding="utf-8")

    assert parse_manifest(manifest) == []


def test_malformed_json_returns_empty_list(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text('{"tools": [', encoding="utf-8")

    assert parse_manifest(manifest) == []


def test_empty_file_returns_empty_list(tmp_path):
    manifest = tmp_path / "mcp.json"
    manifest.write_text("", encoding="utf-8")

    assert parse_manifest(manifest) == []


def test_file_with_no_tools_section_returns_empty_list(tmp_path):
    manifest = tmp_path / "langchain_agent.yaml"
    manifest.write_text("agent:\n  name: helper\n", encoding="utf-8")

    assert parse_manifest(manifest) == []


def test_multiple_manifests_union_expected_set(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "getRepo"}]}),
        encoding="utf-8",
    )
    (tmp_path / "langchain_agent.yaml").write_text(
        "tools:\n  - listFiles\n",
        encoding="utf-8",
    )

    assert collect_declared(tmp_path) == {"get_repo", "list_files"}


def test_normalize_capability_name_snake_cases_framework_identifiers():
    assert normalize_capability_name("admin.tools.getUser") == "admin_tools_get_user"
    assert normalize_capability_name("DATA_EXPORT-v2") == "data_export_v2"


def test_extract_mcp_servers_stdio_server_has_no_url():
    servers = extract_mcp_servers(
        {"mcpServers": {"filesystem": {"command": "npx", "args": ["server"]}}}
    )

    assert len(servers) == 1
    assert servers[0].name == "filesystem"
    assert servers[0].url is None
    assert servers[0].transport == "stdio"
    assert servers[0].line is None


def test_extract_mcp_servers_localhost_url():
    servers = extract_mcp_servers(
        {"mcpServers": {"local": {"url": "http://localhost:3000/mcp"}}}
    )

    assert servers[0].url == "http://localhost:3000/mcp"
    assert servers[0].transport == "http"


def test_extract_mcp_servers_external_https_url():
    servers = extract_mcp_servers(
        {"mcpServers": {"remote": {"serverUrl": "https://mcp.example.com/sse"}}}
    )

    assert servers[0].name == "remote"
    assert servers[0].url == "https://mcp.example.com/sse"
    assert servers[0].transport == "https"


def test_extract_mcp_servers_http_url_from_server_list():
    servers = extract_mcp_servers(
        {"servers": [{"name": "public", "httpUrl": "http://mcp.example.com"}]}
    )

    assert servers[0].name == "public"
    assert servers[0].url == "http://mcp.example.com"
    assert servers[0].transport == "http"


def test_extract_mcp_servers_malformed_url_still_returns_candidate_for_rule():
    servers = extract_mcp_servers(
        {"mcpServers": {"remote": {"endpoint": "not a url"}}}
    )

    assert servers[0].url == "not a url"
    assert servers[0].transport == "unknown"
