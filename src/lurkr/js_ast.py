"""Bounded JavaScript/TypeScript AST helpers for untrusted scanned source files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import tree_sitter
import tree_sitter_javascript as _tsjs
import tree_sitter_typescript as _tsts


MAX_SOURCE_BYTES = 1_000_000
MAX_NODES = 10_000
MAX_DEPTH = 50


_LANGUAGE_TYPESCRIPT = tree_sitter.Language(_tsts.language_typescript())
_LANGUAGE_TSX = tree_sitter.Language(_tsts.language_tsx())
_LANGUAGE_JAVASCRIPT = tree_sitter.Language(_tsjs.language())


_TYPESCRIPT_SUFFIXES = frozenset({".ts", ".mts", ".cts"})
_TSX_SUFFIXES = frozenset({".tsx"})
_JAVASCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})


@dataclass(frozen=True)
class JsAstDocument:
    """Bounded parsed JS/TS AST plus source bytes for byte-level slicing."""

    tree: tree_sitter.Tree
    source: bytes
    lines: list[str]


def is_js_or_ts_source(path: Path) -> bool:
    """Return whether path has a JS/TS source suffix recognised by Lurkr."""
    suffix = path.suffix.lower()
    return (
        suffix in _TYPESCRIPT_SUFFIXES
        or suffix in _TSX_SUFFIXES
        or suffix in _JAVASCRIPT_SUFFIXES
    )


def language_for_path(path: Path) -> tree_sitter.Language | None:
    """Return the tree-sitter language for a known JS/TS suffix, else None."""
    suffix = path.suffix.lower()
    if suffix in _TYPESCRIPT_SUFFIXES:
        return _LANGUAGE_TYPESCRIPT
    if suffix in _TSX_SUFFIXES:
        return _LANGUAGE_TSX
    if suffix in _JAVASCRIPT_SUFFIXES:
        return _LANGUAGE_JAVASCRIPT
    return None


def load_js_ast_document(
    path: Path,
    *,
    max_bytes: int = MAX_SOURCE_BYTES,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> JsAstDocument | None:
    """Parse a JS/TS file statically, returning None when bounds are exceeded."""
    language = language_for_path(path)
    if language is None:
        return None
    source = _read_bounded_source(path, max_bytes=max_bytes)
    if source is None:
        return None
    parser = tree_sitter.Parser(language)
    try:
        tree = parser.parse(source)
    except (ValueError, TypeError, RecursionError, MemoryError):
        return None
    if not tree_within_bounds(tree, max_nodes=max_nodes, max_depth=max_depth):
        return None
    text = source.decode("utf-8", errors="replace")
    return JsAstDocument(tree=tree, source=source, lines=text.splitlines())


def _read_bounded_source(path: Path, *, max_bytes: int) -> bytes | None:
    """Read raw bytes from a file under a byte-size cap."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_bytes()
    except OSError:
        return None


def tree_within_bounds(
    tree: tree_sitter.Tree,
    *,
    max_nodes: int = MAX_NODES,
    max_depth: int = MAX_DEPTH,
) -> bool:
    """Return whether tree fits node-count and depth limits."""
    nodes_seen = 0
    stack: list[tuple[tree_sitter.Node, int]] = [(tree.root_node, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            return False
        nodes_seen += 1
        if nodes_seen > max_nodes:
            return False
        for child in node.children:
            stack.append((child, depth + 1))
    return True


def iter_nodes(tree: tree_sitter.Tree) -> Iterator[tree_sitter.Node]:
    """Iterate AST nodes without recursive visitor dispatch."""
    stack: list[tree_sitter.Node] = [tree.root_node]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def node_text(node: tree_sitter.Node, source: bytes) -> str:
    """Return UTF-8-decoded source slice for a node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def static_string_value(node: tree_sitter.Node, source: bytes) -> str | None:
    """Return the literal string value if node is a static string literal, else None.

    Returns None for template literals containing interpolation, for non-string
    nodes, and for nodes whose children indicate dynamic content. Escape
    sequences inside otherwise-static strings are preserved verbatim (the raw
    bytes) rather than expanded.
    """
    if node.type == "string":
        parts: list[str] = []
        for child in node.children:
            child_type = child.type
            if child_type in {"string_fragment", "string_content"}:
                parts.append(node_text(child, source))
            elif child_type in {'"', "'"}:
                continue
            elif child_type == "escape_sequence":
                parts.append(node_text(child, source))
            else:
                return None
        return "".join(parts)
    if node.type == "template_string":
        # Static only if no template_substitution children.
        parts = []
        for child in node.children:
            if child.type == "template_substitution":
                return None
            if child.type in {"`", "string_fragment", "escape_sequence"}:
                if child.type != "`":
                    parts.append(node_text(child, source))
        return "".join(parts)
    return None
