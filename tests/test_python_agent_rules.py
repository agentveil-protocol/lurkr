from __future__ import annotations

import json

from agentveil_posture.scanner import scan_path
from agentveil_posture.python_ast import MAX_SOURCE_BYTES


def test_tool_decorator_without_approval_fires(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import tool",
                "",
                "@tool",
                "def search(query):",
                "    return query",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_tool_without_approval"]
    assert report.findings[0].file == "agent.py"
    assert report.findings[0].line == 3


def test_tool_decorator_with_positive_approval_marker_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import tool",
                "",
                "@tool(require_human_approval=True)",
                "def search(query):",
                "    return query",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_tool_decorator_with_false_approval_marker_still_fires(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import tool",
                "",
                "@tool(approval=False)",
                "def search(query):",
                "    return query",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_tool_without_approval"]


def test_tool_constructor_func_reference_scopes_body_rules(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import Tool",
                "import subprocess",
                "",
                "def deploy(name):",
                "    return subprocess.run(['echo', name])",
                "",
                "tool = Tool(name='deploy', func=deploy)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_tool_constructor_with_positive_approval_marker_does_not_fire_tool_rule(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import Tool",
                "",
                "def deploy(name):",
                "    return name",
                "",
                "tool = Tool(name='deploy', func=deploy, human_in_the_loop=True)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_structured_tool_constructor_detection(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import StructuredTool",
                "",
                "def deploy(name):",
                "    return name",
                "",
                "tool = StructuredTool(name='deploy', func=deploy)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_tool_without_approval"]


def test_llamaindex_function_tool_constructor_detection(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from llama_index.core.tools import FunctionTool",
                "import subprocess",
                "",
                "def deploy(name):",
                "    return subprocess.run(['deploy', name])",
                "",
                "tool = FunctionTool(fn=deploy)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_llamaindex_function_tool_constructor_with_approval_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from llama_index.core.tools import FunctionTool",
                "",
                "def deploy(name):",
                "    return name",
                "",
                "tool = FunctionTool(fn=deploy, requires_approval=True)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_llamaindex_function_tool_from_defaults_alias_detection(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from llama_index.core.tools import FunctionTool as LlamaFunctionTool",
                "import os",
                "",
                "def cleanup(path):",
                "    return os.system('rm -rf ' + path)",
                "",
                "tool = LlamaFunctionTool.from_defaults(fn=cleanup)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_llamaindex_function_tool_from_defaults_with_approval_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from llama_index.core.tools import FunctionTool",
                "",
                "def cleanup(path):",
                "    return path",
                "",
                "tool = FunctionTool.from_defaults(fn=cleanup, approval_required=True)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_external_tool_func_reference_is_out_of_scope_for_body_rules(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from langchain.tools import Tool",
                "import external_tools",
                "",
                "tool = Tool(name='deploy', func=external_tools.deploy)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_tool_without_approval"]


def test_subprocess_outside_tool_function_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "def helper():",
                "    return subprocess.run(['echo', 'safe'])",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_mcp_call_tool_decorator_detection(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from mcp.server import Server",
                "",
                "server = Server('demo')",
                "",
                "@server.call_tool()",
                "def deploy(name):",
                "    return name",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_tool_without_approval"]


def test_aliases_resolve_decorator_and_subprocess_calls(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from crewai.tools import tool as crew_tool",
                "import subprocess as sp",
                "",
                "@crew_tool",
                "def deploy(name):",
                "    return sp.run(['echo', name])",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_eval_exec_rule_fires_inside_tool_function(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from crewai.tools import tool",
                "",
                "@tool",
                "def calculate(expression):",
                "    return eval(expression)",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_eval_exec_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_file_access_rule_fires_inside_tool_function(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from crewai.tools import tool",
                "",
                "@tool",
                "def overwrite():",
                "    with open('/etc/passwd', 'w') as handle:",
                "        handle.write('x')",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_tool_without_approval",
        "agent.python_unrestricted_file_access",
    ]


def test_pathlib_file_mutation_fires_inside_tool_function(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "from pathlib import Path",
                "from crewai.tools import tool",
                "",
                "@tool",
                "def overwrite():",
                "    Path('/tmp/out').write_text('x')",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert "agent.python_unrestricted_file_access" in _rule_ids(report)


def test_api_key_rule_is_module_wide(tmp_path):
    path = tmp_path / "agent.py"
    secret = "sk" + "-ant-" + "FAKEKEY12345"
    path.write_text(
        "\n".join(
            [
                f"ANTHROPIC_API_KEY = {secret!r}",
                "",
                "def helper():",
                "    return 'safe'",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == ["agent.python_api_key_hardcoded"]
    assert report.findings[0].line == 1


def test_openai_tool_dict_reference_scopes_body_rules(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "def ship(target):",
                "    return subprocess.run(['deploy', target])",
                "",
                "client.chat.completions.create(",
                "    model='gpt-4.1',",
                "    tools=[",
                "        {'type': 'function', 'function': {'name': 'ship'}}",
                "    ],",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_openai_tool_dict_without_matching_function_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "client.chat.completions.create(",
                "    model='gpt-4.1',",
                "    tools=[",
                "        {'type': 'function', 'function': {'name': 'missing'}}",
                "    ],",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_anthropic_tool_dict_reference_scopes_body_rules(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def read_file(path):",
                "    with open(path, 'w') as handle:",
                "        handle.write('x')",
                "",
                "client.messages.create(",
                "    model='claude-sonnet-4-5',",
                "    tools=[",
                "        {'name': 'read_file', 'input_schema': {'type': 'object'}}",
                "    ],",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_tool_without_approval",
        "agent.python_unrestricted_file_access",
    ]


def test_anthropic_tool_dict_without_input_schema_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def read_file(path):",
                "    return path",
                "",
                "client.messages.create(",
                "    model='claude-sonnet-4-5',",
                "    tools=[{'name': 'read_file'}],",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_gemini_tool_dict_reference_scopes_body_rules(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "import subprocess",
                "",
                "def deploy(target):",
                "    return subprocess.run(['deploy', target])",
                "",
                "client.models.generate_content(",
                "    contents='ship',",
                "    config={",
                "        'tools': [",
                "            {'function_declarations': [{'name': 'deploy'}]}",
                "        ]",
                "    },",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
    ]


def test_gemini_tool_dict_without_declaration_list_does_not_fire(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def deploy(target):",
                "    return target",
                "",
                "client.models.generate_content(",
                "    contents='ship',",
                "    config={'tools': [{'function_declarations': {'name': 'deploy'}}]},",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_gemini_tool_dict_multiple_functions_are_detected(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def first():",
                "    return 'first'",
                "",
                "def second():",
                "    return 'second'",
                "",
                "def third():",
                "    return 'third'",
                "",
                "model = genai.GenerativeModel(",
                "    'gemini-2.5-pro',",
                "    tools=[",
                "        {'function_declarations': [",
                "            {'name': 'first'},",
                "            {'name': 'second'},",
                "            {'name': 'third'},",
                "        ]}",
                "    ],",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_tool_without_approval",
        "agent.python_tool_without_approval",
        "agent.python_tool_without_approval",
    ]


def test_openai_and_anthropic_tool_dicts_both_detected(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def openai_tool():",
                "    return 'ok'",
                "",
                "def anthropic_tool():",
                "    return 'ok'",
                "",
                "client.responses.create(",
                "    tools=[{'type': 'function', 'function': {'name': 'openai_tool'}}]",
                ")",
                "client.messages.create(",
                "    tools=[{'name': 'anthropic_tool', 'input_schema': {'type': 'object'}}]",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_tool_without_approval",
        "agent.python_tool_without_approval",
    ]


def test_openai_anthropic_and_gemini_tool_dicts_all_detected(tmp_path):
    path = tmp_path / "agent.py"
    path.write_text(
        "\n".join(
            [
                "def openai_tool():",
                "    return 'ok'",
                "",
                "def anthropic_tool():",
                "    return 'ok'",
                "",
                "def gemini_tool():",
                "    return 'ok'",
                "",
                "client.responses.create(",
                "    tools=[{'type': 'function', 'function': {'name': 'openai_tool'}}]",
                ")",
                "client.messages.create(",
                "    tools=[{'name': 'anthropic_tool', 'input_schema': {'type': 'object'}}]",
                ")",
                "client.models.generate_content(",
                "    contents='ok',",
                "    config={",
                "        'tools': [",
                "            {'function_declarations': [{'name': 'gemini_tool'}]}",
                "        ]",
                "    },",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert _rule_ids(report) == [
        "agent.python_tool_without_approval",
        "agent.python_tool_without_approval",
        "agent.python_tool_without_approval",
    ]


def test_python_rule_redaction_in_json_and_sarif(tmp_path):
    path = tmp_path / "agent.py"
    secret = "sk" + "-ant-" + "FAKEKEY12345"
    command_body = "rm -rf /sensitive/path"
    protected_path = "/etc/passwd"
    path.write_text(
        "\n".join(
            [
                "from crewai.tools import tool",
                "import subprocess",
                f"API_KEY = '{secret}'",
                "",
                "@tool",
                "def deploy():",
                f"    subprocess.run({command_body!r}, shell=True)",
                f"    with open({protected_path!r}, 'w') as handle:",
                "        handle.write('x')",
            ]
        ),
        encoding="utf-8",
    )

    report = scan_path(tmp_path)
    report_json = report.to_json()
    sarif_json = json.dumps(report.to_sarif(), sort_keys=True)

    assert {
        "agent.python_api_key_hardcoded",
        "agent.python_subprocess_in_tool",
        "agent.python_tool_without_approval",
        "agent.python_unrestricted_file_access",
    } <= set(_rule_ids(report))
    for forbidden in (secret, command_body, protected_path):
        assert forbidden not in report_json
        assert forbidden not in sarif_json
    assert "snippet" not in sarif_json
    assert "contextRegion" not in sarif_json


def test_malformed_oversized_and_deep_python_files_are_skipped(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "large.py").write_text("x" * (MAX_SOURCE_BYTES + 1), encoding="utf-8")
    (tmp_path / "deep.py").write_text(_nested_ifs(60), encoding="utf-8")

    report = scan_path(tmp_path)

    assert report.findings == []


def _rule_ids(report) -> list[str]:
    return sorted(finding.rule_id for finding in report.findings)


def _nested_ifs(depth: int) -> str:
    lines = []
    for index in range(depth):
        lines.append(f"{'    ' * index}if True:")
    lines.append(f"{'    ' * depth}value = 1")
    return "\n".join(lines) + "\n"
