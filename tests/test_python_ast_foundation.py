from __future__ import annotations

import ast
from pathlib import Path

from lurkr import python_ast


def test_valid_python_parses_with_import_aliases_and_positions(tmp_path):
    source = "\n".join(
        [
            "import langchain as lc",
            "from langchain.tools import Tool as LCTool",
            "from crewai.tools import tool",
            "",
            "@tool('ship')",
            "def deploy():",
            "    return LCTool(name='deploy', func=deploy)",
            "",
            "class CustomTool(lc.tools.BaseTool):",
            "    pass",
        ]
    )
    path = tmp_path / "agent.py"
    path.write_text(source, encoding="utf-8")

    document = python_ast.load_python_ast_document(path)

    assert document is not None
    assert document.imports["lc"] == "langchain"
    assert document.imports["LCTool"] == "langchain.tools.Tool"
    assert document.imports["tool"] == "crewai.tools.tool"
    assert python_ast.decorator_names(document) == [
        python_ast.PythonName("crewai.tools.tool", 5, 1)
    ]
    assert python_ast.call_names(document)[0] == python_ast.PythonName(
        "crewai.tools.tool", 5, 1
    )
    assert python_ast.call_names(document)[1] == python_ast.PythonName(
        "langchain.tools.Tool", 7, 11
    )
    assert python_ast.class_base_names(document) == [
        python_ast.PythonName("langchain.tools.BaseTool", 9, 17)
    ]


def test_malformed_python_returns_none_without_source_leakage(tmp_path, caplog):
    path = tmp_path / "broken.py"
    path.write_text("def broken(:\n    RAW_SECRET_VALUE\n", encoding="utf-8")

    document = python_ast.load_python_ast_document(path)

    assert document is None
    assert "RAW_SECRET_VALUE" not in caplog.text


def test_oversized_python_skips_before_parse(monkeypatch, tmp_path):
    path = tmp_path / "large.py"
    path.write_text("x = 1\n", encoding="utf-8")

    def blocked_parse(*args, **kwargs):
        raise AssertionError("ast.parse should not run for oversized Python")

    monkeypatch.setattr(python_ast.ast, "parse", blocked_parse)

    assert python_ast.load_python_ast_document(path, max_bytes=1) is None


def test_pep_263_latin_1_source_parses(tmp_path):
    path = tmp_path / "latin1.py"
    path.write_bytes("# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n".encode("latin-1"))

    document = python_ast.load_python_ast_document(path)

    assert document is not None
    assert "cafe" not in document.text
    assert "café" in document.text


def test_empty_python_file_parses(tmp_path):
    path = tmp_path / "empty.py"
    path.write_text("", encoding="utf-8")

    document = python_ast.load_python_ast_document(path)

    assert document is not None
    assert document.lines == []


def test_invalid_encoding_and_invalid_bytes_return_none(tmp_path):
    path = tmp_path / "bad_encoding.py"
    path.write_bytes(b"# coding: unknown-codec\n\xff\xfe\n")

    assert python_ast.load_python_ast_document(path) is None


def test_non_python_binary_content_returns_none(tmp_path):
    path = tmp_path / "binary.py"
    path.write_bytes(b"\x00\x01\x02not python")

    assert python_ast.load_python_ast_document(path) is None


def test_node_count_boundary_accepts_max_nodes_exactly_and_rejects_one_over(tmp_path):
    exact_path = tmp_path / "exact.py"
    exact_path.write_text("".join(f"name_{index}\n" for index in range(3333)), encoding="utf-8")
    over_path = tmp_path / "over.py"
    over_path.write_text("".join(f"name_{index}\n" for index in range(3334)), encoding="utf-8")

    assert _node_count(exact_path.read_text(encoding="utf-8")) == python_ast.MAX_NODES
    assert _node_count(over_path.read_text(encoding="utf-8")) > python_ast.MAX_NODES
    assert python_ast.load_python_ast_document(exact_path) is not None
    assert python_ast.load_python_ast_document(over_path) is None


def test_depth_limit_rejects_before_helper_traversal(tmp_path):
    path = tmp_path / "deep.py"
    path.write_text(_nested_ifs(python_ast.MAX_DEPTH + 1), encoding="utf-8")

    assert python_ast.load_python_ast_document(path) is None


def test_deep_iterative_traversal_does_not_raise_recursion_error(tmp_path):
    path = tmp_path / "nested.py"
    path.write_text("x = " + ("lambda: " * 120) + "1\n", encoding="utf-8")

    document = python_ast.load_python_ast_document(path, max_depth=300)

    assert document is not None
    assert sum(1 for _ in python_ast.iter_ast_nodes(document.tree)) > 120


def test_collect_import_aliases_inside_try_except(tmp_path):
    path = tmp_path / "conditional_imports.py"
    path.write_text(
        "\n".join(
            [
                "try:",
                "    from langchain_core.tools import tool as lc_tool",
                "except ImportError:",
                "    from crewai.tools import tool as lc_tool",
            ]
        ),
        encoding="utf-8",
    )

    document = python_ast.load_python_ast_document(path)

    assert document is not None
    assert document.imports["lc_tool"] == "crewai.tools.tool"


def test_foundation_constants_match_phase6a_limits():
    assert python_ast.MAX_SOURCE_BYTES == 1_000_000
    assert python_ast.MAX_NODES == 10_000
    assert python_ast.MAX_DEPTH == 50


def test_python_ast_module_uses_iterative_helpers_not_nodevisitor():
    source = Path(python_ast.__file__).read_text(encoding="utf-8")

    assert "NodeVisitor" not in source
    assert "eval(" not in source
    assert "exec(" not in source
    assert "compile(" not in source
    assert "import_module(" not in source
    assert "__import__(" not in source


def _node_count(source: str) -> int:
    return sum(1 for _ in ast.walk(ast.parse(source)))


def _nested_ifs(depth: int) -> str:
    lines = []
    for index in range(depth):
        lines.append(f"{'    ' * index}if True:")
    lines.append(f"{'    ' * depth}value = 1")
    return "\n".join(lines) + "\n"
