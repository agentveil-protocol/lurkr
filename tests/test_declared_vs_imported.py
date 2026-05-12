from __future__ import annotations

import json

from lurkr.scanner import scan_path


RULE_ID = "agent.declared_vs_imported_delta"


def _delta_findings(path):
    report = scan_path(path)
    return [finding for finding in report.findings if finding.rule_id == RULE_ID]


def test_declared_vs_imported_clean_case_has_no_findings(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "get_repo"}, {"name": "list_files"}]}),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def get_repo():\n"
        "    return 'ok'\n\n"
        "@tool\n"
        "def list_files():\n"
        "    return []\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_shadow_case_fires_once_per_shadow(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "get_repo"}]}),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def get_repo():\n"
        "    return 'ok'\n\n"
        "@tool\n"
        "def delete_files():\n"
        "    return 'deleted'\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file == "agent.py"
    assert findings[0].line == 7
    assert "delete_files" in findings[0].message
    assert "delete_files" in findings[0].remediation


def test_declared_vs_imported_no_manifest_does_not_fire(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def delete_files():\n"
        "    return 'deleted'\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_no_python_tools_does_not_fire(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "get_repo"}]}),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text("def helper():\n    return 'ok'\n", encoding="utf-8")

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_multiple_manifests_use_union(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "get_repo"}]}),
        encoding="utf-8",
    )
    (tmp_path / "langchain_agent.yaml").write_text(
        "tools:\n  - delete_files\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def get_repo():\n"
        "    return 'ok'\n\n"
        "@tool\n"
        "def delete_files():\n"
        "    return 'deleted'\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_snake_case_normalization_matches(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "get_user"}]}),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def getUser():\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_malformed_manifest_does_not_crash(tmp_path):
    (tmp_path / "mcp.json").write_text('{"tools": [', encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def delete_files():\n"
        "    return 'deleted'\n",
        encoding="utf-8",
    )

    assert _delta_findings(tmp_path) == []


def test_declared_vs_imported_uses_static_explicit_constructor_name(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"tools": [{"name": "safe_delete"}]}),
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from langchain.tools import Tool\n\n"
        "def delete_files():\n"
        "    return 'deleted'\n\n"
        "tool = Tool(name='delete-files', func=delete_files, description='Delete files')\n",
        encoding="utf-8",
    )

    findings = _delta_findings(tmp_path)

    assert len(findings) == 1
    assert "delete-files" in findings[0].message
