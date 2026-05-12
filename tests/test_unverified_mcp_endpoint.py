from __future__ import annotations

import json

from lurkr.scanner import scan_path


RULE_ID = "agent.unverified_mcp_endpoint"


def _write_manifest(tmp_path, data):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _findings(tmp_path):
    return [finding for finding in scan_path(tmp_path).findings if finding.rule_id == RULE_ID]


def test_stdio_server_is_clean(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"fs": {"command": "npx", "args": ["server"]}}})

    assert _findings(tmp_path) == []


def test_localhost_url_is_clean(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"local": {"url": "http://localhost:3000/mcp"}}})

    assert _findings(tmp_path) == []


def test_loopback_ip_url_is_clean(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"local": {"url": "http://127.0.0.1:3000/mcp"}}})

    assert _findings(tmp_path) == []


def test_private_ip_url_is_clean(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"internal": {"url": "https://10.0.0.5/mcp"}}})

    assert _findings(tmp_path) == []


def test_public_https_host_fires(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"remote": {"url": "https://mcp.example.com/sse"}}})

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "mcp.json"
    assert findings[0].line == 4
    assert "mcp.example.com" in findings[0].message


def test_public_http_host_fires(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}})

    assert len(_findings(tmp_path)) == 1


def test_dot_local_host_is_clean(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"dev": {"url": "https://mcp.local/sse"}}})

    assert _findings(tmp_path) == []


def test_host_docker_internal_is_clean(tmp_path):
    _write_manifest(
        tmp_path,
        {"mcpServers": {"docker": {"url": "http://host.docker.internal:8080/sse"}}},
    )

    assert _findings(tmp_path) == []


def test_malformed_url_is_skipped(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"remote": {"endpoint": "not a url"}}})

    assert _findings(tmp_path) == []


def test_missing_url_field_is_skipped(tmp_path):
    _write_manifest(tmp_path, {"mcpServers": {"remote": {"transport": "http"}}})

    assert _findings(tmp_path) == []


def test_multiple_servers_mixed(tmp_path):
    _write_manifest(
        tmp_path,
        {
            "mcpServers": {
                "stdio": {"command": "npx"},
                "local": {"url": "http://localhost:3000/sse"},
                "remote": {"serverUrl": "https://mcp.example.com/sse"},
            }
        },
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "mcp.example.com" in findings[0].message
