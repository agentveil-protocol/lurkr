"""Shared JavaScript/TypeScript MCP detection helpers.

This module owns the bounded static analysis of:

- Official `@modelcontextprotocol/*` import / require bindings in one file
- Local `new McpServer(...)` constructor identifier collection
- Canonical `<server>.registerTool("static_name", config, handler)` call sites

Helpers exposed here are intended to be reused by `lurkr.rules` modules that
need to reason about the same MCP context boundary. Today the only consumer
is `lurkr.rules.declared_vs_imported`; future TS/JS rules (e.g., handler-body
risk rules) are expected to reuse the same gate without duplicating logic.

No behavior change: this module moves logic from
`lurkr.rules.declared_vs_imported` without altering the gate or any rule
output. All identifiers, patterns, and bounded-static guarantees match the
prior in-place implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lurkr.js_ast import (
    JsAstDocument,
    iter_nodes,
    node_text,
    static_string_value,
)


MCP_PACKAGE_PREFIX = "@modelcontextprotocol/"


@dataclass(frozen=True)
class McpImports:
    """Locally-bound symbols imported from an official MCP package in one file.

    `direct_names` — local identifiers from named ES imports or destructured
    CommonJS require where the imported symbol is `McpServer` (with optional
    alias). Examples: `McpServer` after
    `import { McpServer } from "@modelcontextprotocol/server"`, or `Server`
    after `import { McpServer as Server } from "@modelcontextprotocol/server"`.

    `namespace_aliases` — local identifiers for namespace imports / whole-module
    requires (e.g., `mcp` after
    `import * as mcp from "@modelcontextprotocol/server"`).
    """

    direct_names: frozenset[str]
    namespace_aliases: frozenset[str]

    @property
    def empty(self) -> bool:
        return not self.direct_names and not self.namespace_aliases


@dataclass(frozen=True)
class JsRegisteredTool:
    """Single statically-named MCP tool registration call site.

    `handler` is the third argument node of the `registerTool(name, config,
    handler)` call when present, or None when the call has fewer than three
    arguments. The node is intentionally excluded from equality and hashing so
    consumers that key registrations by `(name, line)` are unaffected by the
    presence of this field. Downstream rule modules use the handler node to
    walk the handler body within bounded same-file scope.
    """

    name: str
    line: int
    handler: Any = field(default=None, compare=False)


def collect_mcp_imports(document: JsAstDocument) -> McpImports:
    """Walk AST for ES import statements and CommonJS require calls sourced
    from an official `@modelcontextprotocol/*` package, and return the local
    binding set in one file.

    Bounded static signal — does not resolve cross-file references or
    indirect re-exports.
    """
    direct: set[str] = set()
    namespaces: set[str] = set()

    for node in iter_nodes(document.tree):
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node is None:
                continue
            pkg = static_string_value(source_node, document.source)
            if pkg is None or not pkg.startswith(MCP_PACKAGE_PREFIX):
                continue
            for child in node.children:
                if child.type != "import_clause":
                    continue
                for sub in child.children:
                    if sub.type == "named_imports":
                        for spec in sub.children:
                            if spec.type != "import_specifier":
                                continue
                            name_node = spec.child_by_field_name("name")
                            if (
                                name_node is None
                                or node_text(name_node, document.source) != "McpServer"
                            ):
                                continue
                            alias_node = spec.child_by_field_name("alias")
                            local_node = alias_node if alias_node is not None else name_node
                            if local_node.type == "identifier":
                                direct.add(node_text(local_node, document.source))
                    elif sub.type == "namespace_import":
                        for ns_child in sub.children:
                            if ns_child.type == "identifier":
                                namespaces.add(node_text(ns_child, document.source))
        elif node.type == "variable_declarator":
            value_node = node.child_by_field_name("value")
            if value_node is None or value_node.type != "call_expression":
                continue
            call_fn = value_node.child_by_field_name("function")
            if call_fn is None or node_text(call_fn, document.source) != "require":
                continue
            call_args = value_node.child_by_field_name("arguments")
            if call_args is None:
                continue
            arg_children = _argument_nodes(call_args)
            if not arg_children:
                continue
            pkg = static_string_value(arg_children[0], document.source)
            if pkg is None or not pkg.startswith(MCP_PACKAGE_PREFIX):
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            if name_node.type == "identifier":
                namespaces.add(node_text(name_node, document.source))
            elif name_node.type == "object_pattern":
                for prop in name_node.children:
                    if prop.type == "shorthand_property_identifier_pattern":
                        if node_text(prop, document.source) == "McpServer":
                            direct.add("McpServer")
                    elif prop.type == "pair_pattern":
                        key_field = prop.child_by_field_name("key")
                        value_field = prop.child_by_field_name("value")
                        if (
                            key_field is not None
                            and value_field is not None
                            and value_field.type == "identifier"
                            and node_text(key_field, document.source) == "McpServer"
                        ):
                            direct.add(node_text(value_field, document.source))

    return McpImports(
        direct_names=frozenset(direct),
        namespace_aliases=frozenset(namespaces),
    )


def is_mcp_server_new_expression(
    node, source: bytes, mcp_imports: McpImports
) -> bool:
    """Return True if node is a `new <X>(...)` whose constructor resolves to
    the official MCP server class through the file's MCP imports.

    A locally-defined class named `McpServer` that is NOT imported from an
    official `@modelcontextprotocol/*` package does not satisfy the gate.
    """
    if node.type != "new_expression":
        return False
    constructor = node.child_by_field_name("constructor")
    if constructor is None:
        return False
    if constructor.type == "identifier":
        return node_text(constructor, source) in mcp_imports.direct_names
    if constructor.type == "member_expression":
        obj = constructor.child_by_field_name("object")
        prop = constructor.child_by_field_name("property")
        if obj is None or prop is None or obj.type != "identifier":
            return False
        if node_text(obj, source) not in mcp_imports.namespace_aliases:
            return False
        return node_text(prop, source) == "McpServer"
    return False


def collect_mcp_server_identifiers(document: JsAstDocument) -> set[str]:
    """Return the set of local variable names bound to an official MCP server
    instance in this file.

    The gate requires both:

    1. An import or `require(...)` of `@modelcontextprotocol/*` that binds a
       direct name or namespace alias locally, AND
    2. A `<id> = new <symbol>(...)` (or `<id> = new <ns>.McpServer(...)`)
       expression where `<symbol>` / `<ns>` resolves through (1).

    Bounded static signal: cross-file references, factory functions, and
    dynamic constructor patterns are intentionally not resolved. A locally
    declared `class McpServer { ... }` without an MCP import does NOT
    satisfy the gate.
    """
    mcp_imports = collect_mcp_imports(document)
    if mcp_imports.empty:
        return set()

    identifiers: set[str] = set()
    for node in iter_nodes(document.tree):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            if name_node.type != "identifier":
                continue
            if not is_mcp_server_new_expression(
                value_node, document.source, mcp_imports
            ):
                continue
            identifiers.add(node_text(name_node, document.source))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type != "identifier":
                continue
            if not is_mcp_server_new_expression(
                right, document.source, mcp_imports
            ):
                continue
            identifiers.add(node_text(left, document.source))
    return identifiers


def collect_registered_tools_js(
    document: JsAstDocument,
    server_identifiers: set[str],
) -> list[JsRegisteredTool]:
    """Collect static-named `<server_id>.registerTool('name', ...)` calls.

    Only call sites where the receiver identifier is in `server_identifiers`
    (the set of locally-bound McpServer instances) are accepted. Tool name
    must be a static string literal; dynamic names are skipped silently.
    Bounded static signal — does not resolve cross-file references.
    """
    if not server_identifiers:
        return []
    tools: list[JsRegisteredTool] = []
    seen: set[tuple[str, int]] = set()
    for node in iter_nodes(document.tree):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        obj = fn.child_by_field_name("object")
        if obj is None or obj.type != "identifier":
            continue
        if node_text(obj, document.source) not in server_identifiers:
            continue
        prop = fn.child_by_field_name("property")
        if prop is None or node_text(prop, document.source) != "registerTool":
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_nodes = _argument_nodes(args)
        if not arg_nodes:
            continue
        name = static_string_value(arg_nodes[0], document.source)
        if name is None:
            continue
        line = node.start_point[0] + 1
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        handler_node = arg_nodes[2] if len(arg_nodes) >= 3 else None
        tools.append(JsRegisteredTool(name=name, line=line, handler=handler_node))
    return tools


_NON_ARGUMENT_CHILD_TYPES = frozenset({"(", ")", ",", "comment"})


def _argument_nodes(arguments_node) -> list:
    """Return positional argument nodes from a tree-sitter ``arguments`` node.

    Filters out punctuation tokens and comment nodes. Tree-sitter exposes both
    line and block comments as ``comment`` children of the arguments list when
    they appear between commas; treating them as positional arguments breaks
    handler resolution for the common formatter pattern of placing a comment
    between an inline config object and the handler.
    """
    return [
        child
        for child in arguments_node.children
        if child.type not in _NON_ARGUMENT_CHILD_TYPES
    ]
