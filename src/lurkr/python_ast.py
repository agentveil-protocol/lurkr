"""Bounded Python AST helpers for untrusted scanned source files."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import tokenize
from typing import Iterator

from lurkr.rules.parsing import MAX_TEXT_BYTES


MAX_SOURCE_BYTES = MAX_TEXT_BYTES
MAX_NODES = 10_000
MAX_DEPTH = 50


@dataclass(frozen=True)
class PythonName:
    """Resolved dotted name plus its source position."""

    name: str
    lineno: int
    col_offset: int


@dataclass(frozen=True)
class PythonAstDocument:
    """Bounded parsed AST plus import aliases used by name helpers."""

    tree: ast.AST
    text: str
    lines: list[str]
    imports: dict[str, str]


def load_python_ast_document(
    path: Path,
    *,
    max_bytes: int = MAX_SOURCE_BYTES,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> PythonAstDocument | None:
    """Parse a Python file statically, returning None when bounds are exceeded."""
    text = read_bounded_python_source(path, max_bytes=max_bytes)
    if text is None:
        return None
    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError):
        return None
    if not ast_within_bounds(tree, max_nodes=max_nodes, max_depth=max_depth):
        return None
    imports = collect_import_aliases(tree)
    return PythonAstDocument(tree=tree, text=text, lines=text.splitlines(), imports=imports)


def read_bounded_python_source(path: Path, *, max_bytes: int = MAX_SOURCE_BYTES) -> str | None:
    """Read Python source with PEP 263 encoding support after a byte-size cap."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        with tokenize.open(path) as source:
            return source.read()
    except (OSError, SyntaxError, UnicodeDecodeError, LookupError):
        return None


def ast_within_bounds(
    tree: ast.AST,
    *,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> bool:
    """Return whether an AST fits node-count and depth limits."""
    nodes_seen = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            return False
        nodes_seen += 1
        if nodes_seen > max_nodes:
            return False
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1))
    return True


def iter_ast_nodes(tree: ast.AST) -> Iterator[ast.AST]:
    """Iterate AST nodes without recursive visitor dispatch."""
    stack = [tree]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Collect import aliases without importing scanned modules."""
    aliases: dict[str, str] = {}
    for node in iter_ast_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                aliases[local_name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                aliases[local_name] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def resolve_name(node: ast.AST, imports: dict[str, str]) -> PythonName | None:
    """Resolve a Name/Attribute expression to a dotted name with position."""
    raw_name = _raw_dotted_name(node)
    if raw_name is None:
        return None
    first, dot, rest = raw_name.partition(".")
    resolved = imports.get(first, first)
    if dot:
        resolved = f"{resolved}.{rest}"
    return PythonName(
        name=resolved,
        lineno=getattr(node, "lineno", 0),
        col_offset=getattr(node, "col_offset", 0),
    )


def call_names(document: PythonAstDocument) -> list[PythonName]:
    """Return resolved call target names with source positions."""
    names: list[PythonName] = []
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, ast.Call):
            name = resolve_name(node.func, document.imports)
            if name is not None:
                names.append(name)
    return _sort_names(names)


def decorator_names(document: PythonAstDocument) -> list[PythonName]:
    """Return resolved decorator names with decorator source positions."""
    names: list[PythonName] = []
    decorated_types = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, decorated_types):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                name = resolve_name(target, document.imports)
                if name is not None:
                    names.append(
                        PythonName(
                            name=name.name,
                            lineno=getattr(decorator, "lineno", name.lineno),
                            col_offset=getattr(decorator, "col_offset", name.col_offset),
                        )
                    )
    return _sort_names(names)


def class_base_names(document: PythonAstDocument) -> list[PythonName]:
    """Return resolved class base names with source positions."""
    names: list[PythonName] = []
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                name = resolve_name(base, document.imports)
                if name is not None:
                    names.append(name)
    return _sort_names(names)


def _raw_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _raw_dotted_name(node.value)
        if value is None:
            return None
        return f"{value}.{node.attr}"
    return None


def _sort_names(names: list[PythonName]) -> list[PythonName]:
    return sorted(names, key=lambda name: (name.lineno, name.col_offset, name.name))
