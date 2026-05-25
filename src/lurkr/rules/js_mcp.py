"""Shared JavaScript/TypeScript MCP detection helpers.

This module owns the bounded static analysis of:

- Official `@modelcontextprotocol/*` import / require bindings in one file
- Local `new McpServer(...)` constructor identifier collection
- Canonical `<server>.registerTool("static_name", config, handler)` call
  sites, in two registration shapes:
  - Identifier-bound:
    `const server = new McpServer(...); server.registerTool("name", ...)`
  - Direct chained construction:
    `new McpServer(...).registerTool("name", ...)` (and the namespace import
    equivalent ``new mcp.McpServer(...).registerTool("name", ...)``)

Helpers exposed here are reused by `lurkr.rules` modules that need to reason
about the same MCP context boundary (today: `lurkr.rules.declared_vs_imported`
and `lurkr.rules.js_agent`). The chained-construction extension keeps the
function signatures of `collect_mcp_server_identifiers` and
`collect_registered_tools_js` stable: an internal sentinel is added to the
identifier set when chained sites exist, so callers that gate on
``if not server_identifiers: skip`` continue to see a truthy set in
chained-only files, and the receiver-matching branch in
`collect_registered_tools_js` walks both identifier-bound and chained call
sites.
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

# Internal sentinel added to the set returned by
# :func:`collect_mcp_server_identifiers` whenever the file contains at least
# one direct chained ``new McpServer(...).registerTool(...)`` call. Angle
# brackets cannot appear in JavaScript identifiers, so this value is
# guaranteed not to collide with any real identifier text returned by
# ``node_text``. The sentinel keeps callers that gate on "is there MCP
# context in this file?" via ``if not server_identifiers: skip`` working in
# chained-only files; it is never matched against actual receiver text in
# :func:`collect_registered_tools_js`, which validates chained sites
# directly through :func:`is_mcp_server_new_expression`.
_CHAINED_MCP_SENTINEL = "<lurkr:chained-mcp-server>"


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
    instance in this file, plus an internal sentinel when chained MCP
    construction is present.

    The gate requires an import or ``require(...)`` of
    ``@modelcontextprotocol/*`` that binds a direct name or namespace alias
    locally. Two registration shapes are then recognised:

    1. Identifier-bound: ``<id> = new <symbol>(...)`` (or
       ``<id> = new <ns>.McpServer(...)``) where ``<symbol>`` / ``<ns>``
       resolves through the MCP imports. The local identifier name is
       included in the returned set.
    2. Direct chained construction: at least one
       ``new McpServer(...).registerTool(...)`` (or namespace equivalent)
       call site. When present, the internal :data:`_CHAINED_MCP_SENTINEL`
       string is added to the returned set so callers gating on
       ``if not server_identifiers: skip`` continue to see MCP context.
       The sentinel itself is never compared against real receiver text in
       :func:`collect_registered_tools_js`.

    Bounded static signal: cross-file references, factory functions, and
    dynamic constructor patterns are intentionally not resolved. A locally
    declared ``class McpServer { ... }`` without an MCP import does NOT
    satisfy the gate. Deeper-than-one chains
    (``new McpServer(...).x.registerTool(...)``,
    ``new McpServer(...).registerTool(...).registerTool(...)``) are out of
    v1.
    """
    mcp_imports = collect_mcp_imports(document)
    if mcp_imports.empty:
        return set()

    identifiers: set[str] = set()
    has_chained_register = False
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
        elif node.type == "call_expression" and _is_chained_register_tool_call(
            node, document.source, mcp_imports
        ):
            has_chained_register = True

    if has_chained_register:
        identifiers.add(_CHAINED_MCP_SENTINEL)
    return identifiers


def _is_chained_register_tool_call(
    node, source: bytes, mcp_imports: McpImports
) -> bool:
    """Return True if ``node`` is the direct chained shape
    ``new <McpServer>(...).registerTool(...)``.

    Walks one level: the call's function field must be a member_expression
    whose property is ``registerTool`` and whose object is a
    ``new_expression`` whose constructor resolves to the official MCP
    server through ``mcp_imports``. Deeper indirections (parenthesised
    expressions, intermediate property access, second-level chained
    ``registerTool`` calls) are intentionally not v1.
    """
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "member_expression":
        return False
    prop = fn.child_by_field_name("property")
    if prop is None or prop.type != "property_identifier":
        return False
    if node_text(prop, source) != "registerTool":
        return False
    obj = fn.child_by_field_name("object")
    if obj is None or obj.type != "new_expression":
        return False
    return is_mcp_server_new_expression(obj, source, mcp_imports)


def collect_registered_tools_js(
    document: JsAstDocument,
    server_identifiers: set[str],
) -> list[JsRegisteredTool]:
    """Collect static-named ``<receiver>.registerTool('name', ...)`` calls.

    Two receiver shapes are accepted:

    1. Identifier receiver: ``<id>.registerTool(...)`` where ``<id>`` is in
       ``server_identifiers`` (a locally-bound McpServer instance).
    2. Chained construction receiver:
       ``new McpServer(...).registerTool(...)`` (and the namespace import
       equivalent), validated through
       :func:`is_mcp_server_new_expression` against the file's
       ``McpImports``. This branch is enabled when ``server_identifiers``
       contains the internal :data:`_CHAINED_MCP_SENTINEL`, which is added
       by :func:`collect_mcp_server_identifiers` whenever a chained site is
       present in the file.

    Tool name must be a static string literal; dynamic names are skipped
    silently. Bounded static signal — does not resolve cross-file
    references.
    """
    if not server_identifiers:
        return []
    chained_enabled = _CHAINED_MCP_SENTINEL in server_identifiers
    mcp_imports = collect_mcp_imports(document) if chained_enabled else None
    tools: list[JsRegisteredTool] = []
    seen: set[tuple[str, int]] = set()
    for node in iter_nodes(document.tree):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        prop = fn.child_by_field_name("property")
        if prop is None or node_text(prop, document.source) != "registerTool":
            continue
        obj = fn.child_by_field_name("object")
        if obj is None:
            continue
        if obj.type == "identifier":
            if node_text(obj, document.source) not in server_identifiers:
                continue
        elif obj.type == "new_expression":
            if (
                not chained_enabled
                or mcp_imports is None
                or not is_mcp_server_new_expression(
                    obj, document.source, mcp_imports
                )
            ):
                continue
        else:
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
