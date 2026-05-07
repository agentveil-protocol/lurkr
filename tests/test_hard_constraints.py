from __future__ import annotations

import builtins
import hashlib
import http.client
import importlib
import os
from pathlib import Path
import socket
import subprocess
import urllib.request

from agentveil_posture import python_ast
from agentveil_posture.scanner import scan_path


def test_scan_does_not_call_network_or_subprocess(monkeypatch, tmp_path):
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nopaque\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    def blocked(*args, **kwargs):
        raise AssertionError("network or subprocess call attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(os, "system", blocked)

    report = scan_path(tmp_path)

    assert len(report.findings) == 1


def test_scan_does_not_mutate_scanned_files(tmp_path):
    scanned_file = tmp_path / "id_rsa"
    scanned_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nopaque\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    before = _sha256_tree(tmp_path)

    scan_path(tmp_path)

    assert _sha256_tree(tmp_path) == before


def test_scanner_source_does_not_use_unsafe_yaml_load():
    src_root = Path(__file__).resolve().parents[1] / "src" / "agentveil_posture"
    source = "\n".join(path.read_text(encoding="utf-8") for path in src_root.rglob("*.py"))

    assert "yaml.load(" not in source


def test_python_ast_does_not_call_runtime_side_effects(monkeypatch, tmp_path):
    python_file = tmp_path / "agent.py"
    python_file.write_text(
        "\n".join(
            [
                "import os",
                "from langchain.tools import tool",
                "",
                "@tool",
                "def list_files():",
                "    return os.listdir('.')",
            ]
        ),
        encoding="utf-8",
    )

    def blocked(*args, **kwargs):
        raise AssertionError("runtime side effect attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(os, "system", blocked)
    monkeypatch.setattr(builtins, "eval", blocked)
    monkeypatch.setattr(builtins, "exec", blocked)
    monkeypatch.setattr(importlib, "import_module", blocked)
    monkeypatch.setattr(builtins, "__import__", blocked)

    document = python_ast.load_python_ast_document(python_file)

    assert document is not None


def test_python_ast_helpers_do_not_call_compile_or_runtime_side_effects(monkeypatch, tmp_path):
    python_file = tmp_path / "agent.py"
    python_file.write_text(
        "\n".join(
            [
                "from crewai.tools import tool",
                "",
                "@tool",
                "def list_files():",
                "    return 1",
            ]
        ),
        encoding="utf-8",
    )
    document = python_ast.load_python_ast_document(python_file)
    assert document is not None

    def blocked(*args, **kwargs):
        raise AssertionError("runtime side effect attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(os, "system", blocked)
    monkeypatch.setattr(builtins, "eval", blocked)
    monkeypatch.setattr(builtins, "exec", blocked)
    monkeypatch.setattr(builtins, "compile", blocked)
    monkeypatch.setattr(importlib, "import_module", blocked)
    monkeypatch.setattr(builtins, "__import__", blocked)

    assert python_ast.decorator_names(document) == [
        python_ast.PythonName("crewai.tools.tool", 3, 1)
    ]
    assert list(python_ast.iter_ast_nodes(document.tree))


def _sha256_tree(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes
