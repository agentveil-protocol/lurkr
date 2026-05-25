"""Shared JavaScript/TypeScript MCP detection helpers.

This module owns the bounded static analysis of:

- Official `@modelcontextprotocol/*` import / require bindings in one file
- Local `new McpServer(...)` constructor identifier collection
- Canonical `<server>.registerTool("static_name", config, handler)` call
  sites, in three registration shapes:
  - Identifier-bound:
    `const server = new McpServer(...); server.registerTool("name", ...)`
  - Direct chained construction:
    `new McpServer(...).registerTool("name", ...)` (and the namespace import
    equivalent ``new mcp.McpServer(...).registerTool("name", ...)``)
  - Typed-parameter helper wrapper: a function or arrow whose TypeScript
    type-annotated parameter resolves to the file's imported MCP server
    (``server: McpServer`` or ``server: mcp.McpServer``). Within that
    function body only, the typed parameter is treated as an MCP receiver
    and ``<param>.registerTool("name", ...)`` calls are collected. Untyped
    parameters in JavaScript files and wrapper-name heuristics are
    intentionally not v1.

Helpers exposed here are reused by `lurkr.rules` modules that need to reason
about the same MCP context boundary (today: `lurkr.rules.declared_vs_imported`
and `lurkr.rules.js_agent`). Both registration extensions keep the function
signatures of `collect_mcp_server_identifiers` and
`collect_registered_tools_js` stable: an internal sentinel is added to the
identifier set when chained sites OR typed-wrapper sites exist, so callers
that gate on ``if not server_identifiers: skip`` continue to see a truthy
set in chained-only or wrapper-only files, and the receiver-matching branch
in `collect_registered_tools_js` walks identifier-bound, chained, AND
typed-parameter wrapper call sites.
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

# Internal sentinel added to the set returned by
# :func:`collect_mcp_server_identifiers` whenever the file contains at least
# one function or arrow whose TypeScript-typed parameter resolves to the
# imported MCP server. The sentinel keeps callers that gate on MCP context
# truthy in wrapper-only files. Receiver matching for the typed-parameter
# shape is done inside :func:`collect_registered_tools_js`'s Pass B by
# walking each typed wrapper's body with bounded scope discipline (nested
# function / class scopes are skipped to avoid leaking the parameter name
# across closures).
_TYPED_WRAPPER_MCP_SENTINEL = "<lurkr:typed-wrapper-mcp-server>"

# Function / class scope-barrier types used by the typed-wrapper Pass B
# walk to avoid descending into nested closures where the wrapper's typed
# parameter may be shadowed.
_TYPED_WRAPPER_SCOPE_BARRIERS = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "class_declaration",
        "class_body",
    }
)

_TYPED_WRAPPER_FUNCTION_TYPES = frozenset(
    {"arrow_function", "function_expression", "function_declaration"}
)


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

    Strips one or more enclosing ``parenthesized_expression`` layers from
    ``node`` so the parenthesised form (``(new McpServer(...))``) is
    recognised on equal footing with the bare ``new_expression``. A
    locally-defined class named `McpServer` that is NOT imported from an
    official `@modelcontextprotocol/*` package does not satisfy the gate.
    """
    node = _unwrap_parentheses(node)
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
    instance in this file, plus internal sentinels when chained MCP
    construction or a typed-parameter wrapper is present.

    The gate requires an import or ``require(...)`` of
    ``@modelcontextprotocol/*`` that binds a direct name or namespace alias
    locally. Three registration shapes are then recognised:

    1. Identifier-bound: ``<id> = new <symbol>(...)`` (or
       ``<id> = new <ns>.McpServer(...)``) where ``<symbol>`` / ``<ns>``
       resolves through the MCP imports. The local identifier name is
       included in the returned set.
    2. Direct chained construction: at least one
       ``new McpServer(...).registerTool(...)`` (or namespace equivalent)
       call site. When present, the internal :data:`_CHAINED_MCP_SENTINEL`
       string is added to the returned set so callers gating on
       ``if not server_identifiers: skip`` continue to see MCP context.
    3. Typed-parameter helper wrapper: a function or arrow whose
       TypeScript-typed parameter resolves to the file's imported
       ``McpServer`` (``server: McpServer`` or
       ``server: mcp.McpServer``). When at least one such wrapper exists,
       :data:`_TYPED_WRAPPER_MCP_SENTINEL` is added. The typed parameter
       name itself is NOT added to the returned set — it is only valid
       within the wrapper's body, and matching is done in
       :func:`collect_registered_tools_js`'s scope-aware Pass B.

    Neither sentinel is ever compared against real receiver text in
    :func:`collect_registered_tools_js`; both are gate markers only.

    Bounded static signal: cross-file references, factory functions, and
    dynamic constructor patterns are intentionally not resolved. A locally
    declared ``class McpServer { ... }`` without an MCP import does NOT
    satisfy the gate. Untyped JavaScript wrappers, wrapper-name heuristics,
    and deeper-than-one chains are out of v1.
    """
    mcp_imports = collect_mcp_imports(document)
    if mcp_imports.empty:
        return set()

    identifiers: set[str] = set()
    has_chained_register = False
    has_typed_wrapper = False
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
        elif node.type in _TYPED_WRAPPER_FUNCTION_TYPES and _mcp_typed_parameter_names(
            node, document.source, mcp_imports
        ):
            has_typed_wrapper = True

    if has_chained_register:
        identifiers.add(_CHAINED_MCP_SENTINEL)
    if has_typed_wrapper:
        identifiers.add(_TYPED_WRAPPER_MCP_SENTINEL)
    return identifiers


def _is_chained_register_tool_call(
    node, source: bytes, mcp_imports: McpImports
) -> bool:
    """Return True if ``node`` is the direct chained shape
    ``new <McpServer>(...).registerTool(...)`` (or the parenthesised
    variant ``(new <McpServer>(...)).registerTool(...)``).

    Walks one level: the call's function field must be a member_expression
    whose property is ``registerTool`` and whose object is a
    ``new_expression`` (possibly wrapped in one or more
    ``parenthesized_expression`` layers) whose constructor resolves to the
    official MCP server through ``mcp_imports``. Intermediate property
    access and second-level chained ``registerTool`` calls are
    intentionally not v1.
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
    if obj is None:
        return False
    unwrapped = _unwrap_parentheses(obj)
    if unwrapped.type != "new_expression":
        return False
    return is_mcp_server_new_expression(unwrapped, source, mcp_imports)


def _unwrap_parentheses(node):
    """Strip one or more enclosing ``parenthesized_expression`` layers.

    Tree-sitter for JS/TS exposes ``parenthesized_expression`` with three
    direct children: ``(``, the inner expression, ``)``. The inner
    expression is not exposed through a field name, so this helper picks
    the first non-punctuation child. Returns the input node unchanged if
    it is not parenthesised.
    """
    while node is not None and node.type == "parenthesized_expression":
        inner = None
        for child in node.children:
            if child.type in ("(", ")"):
                continue
            inner = child
            break
        if inner is None:
            break
        node = inner
    return node


def _mcp_typed_parameter_names(
    fn_node, source: bytes, mcp_imports: McpImports
) -> set[str]:
    """Return the set of parameter names typed as the file's imported MCP
    server in this function / arrow node.

    Supports the TypeScript shapes ``(server: McpServer)`` (direct named
    import) and ``(server: mcp.McpServer)`` (namespace import). Optional
    parameters (``server?: McpServer``) use the same field structure and
    are handled. Untyped JavaScript parameters return an empty set.
    """
    names: set[str] = set()
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        # Arrow with a single un-parenthesised identifier param has no type
        # annotation, so it cannot resolve to an MCP server. Nothing to add.
        return names
    for child in params.children:
        if child.type not in ("required_parameter", "optional_parameter"):
            continue
        pattern = child.child_by_field_name("pattern")
        if pattern is None or pattern.type != "identifier":
            continue
        type_annotation = child.child_by_field_name("type")
        if type_annotation is None:
            continue
        if not _type_annotation_is_mcp_server(
            type_annotation, source, mcp_imports
        ):
            continue
        names.add(node_text(pattern, source))
    return names


def _type_annotation_is_mcp_server(
    type_annotation_node, source: bytes, mcp_imports: McpImports
) -> bool:
    """Return True if the type-annotation node resolves to the file's MCP
    server import — either as the direct ``McpServer`` symbol or the
    namespace-qualified ``<ns>.McpServer`` form.
    """
    for child in type_annotation_node.children:
        if child.type in (":", "?"):
            continue
        if child.type == "type_identifier":
            return node_text(child, source) in mcp_imports.direct_names
        if child.type == "nested_type_identifier":
            module_node = child.child_by_field_name("module")
            name_node = child.child_by_field_name("name")
            if module_node is None or name_node is None:
                return False
            if (
                module_node.type != "identifier"
                or name_node.type != "type_identifier"
            ):
                return False
            return (
                node_text(module_node, source) in mcp_imports.namespace_aliases
                and node_text(name_node, source) == "McpServer"
            )
        return False
    return False


def _iter_typed_wrapper_scope(node):
    """Iterate descendants of ``node`` without crossing nested function /
    class scope barriers.

    Bounded for the typed-wrapper Pass B walk: the wrapper's typed
    parameter is only valid in its own body, so nested function /
    arrow / class scopes (which may shadow the parameter or introduce
    their own typed parameters) are excluded from this walk and handled
    by their own iteration of the outer ``iter_nodes`` pass.
    """
    stack = list(reversed(node.children))
    while stack:
        current = stack.pop()
        yield current
        if current.type not in _TYPED_WRAPPER_SCOPE_BARRIERS:
            stack.extend(reversed(current.children))


def _collect_typed_wrapper_registered_tools(
    document: JsAstDocument,
    mcp_imports: McpImports,
    seen: set[tuple[str, int]],
    const_bindings: dict[str, str],
) -> list[JsRegisteredTool]:
    """Yield ``JsRegisteredTool`` for each ``<typed_param>.registerTool(...)``
    inside a typed-wrapper function body.

    Bounded scope discipline: only same-function-body call sites are
    walked. Nested function / class scopes inside the wrapper are not
    descended into here — each nested scope is independently visited by
    the outer ``iter_nodes`` pass and matched against its own typed
    parameters (if any). Calls whose (name, line) key is already in
    ``seen`` are silently deduped. The shared ``const_bindings`` map lets
    Pass B resolve a tool-name identifier (e.g. ``const name = "echo"``)
    the same way Pass A does.
    """
    tools: list[JsRegisteredTool] = []
    for fn_node in iter_nodes(document.tree):
        if fn_node.type not in _TYPED_WRAPPER_FUNCTION_TYPES:
            continue
        typed_param_names = _mcp_typed_parameter_names(
            fn_node, document.source, mcp_imports
        )
        if not typed_param_names:
            continue
        body = fn_node.child_by_field_name("body")
        if body is None:
            continue
        for call_node in _iter_typed_wrapper_scope(body):
            if call_node.type != "call_expression":
                continue
            call_fn = call_node.child_by_field_name("function")
            if call_fn is None or call_fn.type != "member_expression":
                continue
            obj = call_fn.child_by_field_name("object")
            if obj is None:
                continue
            obj = _unwrap_parentheses(obj)
            if obj.type != "identifier":
                continue
            if node_text(obj, document.source) not in typed_param_names:
                continue
            prop = call_fn.child_by_field_name("property")
            if prop is None or node_text(prop, document.source) != "registerTool":
                continue
            args = call_node.child_by_field_name("arguments")
            if args is None:
                continue
            arg_nodes = _argument_nodes(args)
            if not arg_nodes:
                continue
            name = _resolve_static_string_or_const(
                arg_nodes[0], document.source, const_bindings
            )
            if name is None:
                continue
            line = call_node.start_point[0] + 1
            key = (name, line)
            if key in seen:
                continue
            seen.add(key)
            handler_node = arg_nodes[2] if len(arg_nodes) >= 3 else None
            tools.append(
                JsRegisteredTool(name=name, line=line, handler=handler_node)
            )
    return tools


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
    typed_wrapper_enabled = _TYPED_WRAPPER_MCP_SENTINEL in server_identifiers
    mcp_imports = (
        collect_mcp_imports(document)
        if chained_enabled or typed_wrapper_enabled
        else None
    )
    const_bindings = _collect_top_level_const_string_bindings(document)
    tools: list[JsRegisteredTool] = []
    seen: set[tuple[str, int]] = set()
    # Pass A: identifier-bound + chained construction (global walk).
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
        obj = _unwrap_parentheses(obj)
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
        name = _resolve_static_string_or_const(
            arg_nodes[0], document.source, const_bindings
        )
        if name is None:
            continue
        line = node.start_point[0] + 1
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        handler_node = arg_nodes[2] if len(arg_nodes) >= 3 else None
        tools.append(JsRegisteredTool(name=name, line=line, handler=handler_node))
    # Pass B: typed-parameter helper wrappers. Bounded to each wrapper's own
    # body; the typed parameter name is not added to the global identifier
    # set so identifier-bound matching above never picks it up out of scope.
    if typed_wrapper_enabled and mcp_imports is not None:
        tools.extend(
            _collect_typed_wrapper_registered_tools(
                document, mcp_imports, seen, const_bindings
            )
        )
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


def _collect_top_level_const_string_bindings(
    document: JsAstDocument,
) -> dict[str, str]:
    """Return a map of ``identifier → static string literal`` for top-level
    ``const`` declarations in the file.

    Considers only ``lexical_declaration`` nodes whose first child is the
    ``const`` keyword AND whose parent is either the program root or a
    top-level ``export_statement`` (i.e. ``const x = "literal"`` and
    ``export const x = "literal"``). Block-scoped or function-scoped const
    declarations are intentionally not v1 — this avoids ambiguity when two
    different scopes bind the same identifier name to different literals.

    Values are only captured when ``static_string_value`` returns a non-None
    string. ``let``/``var`` declarations, computed initialisers, template
    literals with interpolation, destructured patterns, and imported
    bindings are silently dropped.
    """
    bindings: dict[str, str] = {}
    program = document.tree.root_node
    if program.type != "program":
        return bindings
    for child in program.children:
        lex_decl = child
        if lex_decl.type == "export_statement":
            inner = lex_decl.child_by_field_name("declaration")
            if inner is None:
                continue
            lex_decl = inner
        if lex_decl.type != "lexical_declaration":
            continue
        if not lex_decl.children or lex_decl.children[0].type != "const":
            continue
        for decl in lex_decl.children:
            if decl.type != "variable_declarator":
                continue
            name_node = decl.child_by_field_name("name")
            value_node = decl.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            if name_node.type != "identifier":
                continue
            literal = static_string_value(value_node, document.source)
            if literal is None:
                continue
            bindings[node_text(name_node, document.source)] = literal
    return bindings


def _resolve_static_string_or_const(
    arg_node, source: bytes, const_bindings: dict[str, str]
) -> str | None:
    """Return the static string value of an argument node, falling back to a
    same-file top-level ``const`` binding when the argument is a bare
    identifier that is NOT shadowed in any enclosing local scope.

    The shadow check walks upward from ``arg_node`` and stops just before
    the program root. If any function / arrow / method parameter, or any
    immediate ``const`` / ``let`` / ``var`` / ``function`` declaration in
    an enclosing function or block scope binds the identifier name, the
    bare-identifier reference at the call site is treated as dynamic and
    the top-level fallback is suppressed (returns ``None``). This keeps
    block-scoped consts unsupported under v1 while preventing the
    top-level const map from masking local shadows.

    Returns ``None`` for any value that cannot be statically resolved to a
    string under the v1 contract: template literals with interpolation,
    member expressions, calls, destructuring, identifiers shadowed in
    enclosing local scope, and identifiers without a matching top-level
    const binding.
    """
    direct = static_string_value(arg_node, source)
    if direct is not None:
        return direct
    if arg_node.type != "identifier":
        return None
    name = node_text(arg_node, source)
    if _identifier_shadowed_in_enclosing_local_scope(arg_node, source, name):
        return None
    return const_bindings.get(name)


def _identifier_shadowed_in_enclosing_local_scope(
    identifier_node, source: bytes, name: str
) -> bool:
    """Return True if any enclosing non-program function / block / class
    scope binds ``name`` via parameter or immediate local declaration.

    Walks ``identifier_node.parent`` chain until a program-root or sentinel
    is reached. Each visited node is asked whether it declares ``name`` at
    its own scope (parameters for function-like nodes; direct
    ``lexical_declaration`` / ``variable_declaration`` / ``function_declaration``
    children for block-like and function-like nodes). Top-level (program)
    declarations are intentionally NOT counted as shadows — that case is
    exactly what the top-level const map exists to resolve.
    """
    parent = identifier_node.parent
    while parent is not None and parent.type != "program":
        if _scope_declares_name(parent, source, name):
            return True
        parent = parent.parent
    return False


def _scope_declares_name(scope_node, source: bytes, name: str) -> bool:
    """Return True if ``scope_node`` itself binds ``name`` at its own scope.

    For function-like nodes (``arrow_function``, ``function_expression``,
    ``function_declaration``, ``generator_function_declaration``,
    ``method_definition``), checks formal parameters AND the body's
    immediate declarations. For ``statement_block``, ``class_body``, and
    similar block scopes, checks the block's immediate declarations only.
    Returns False for other node types (they are not binding scopes for
    our purposes).
    """
    scope_type = scope_node.type
    if scope_type in _TYPED_WRAPPER_FUNCTION_TYPES or scope_type in (
        "generator_function_declaration",
        "method_definition",
    ):
        if _function_parameters_declare_name(scope_node, source, name):
            return True
        body = scope_node.child_by_field_name("body")
        if body is not None and _block_immediately_declares_name(
            body, source, name
        ):
            return True
        return False
    if scope_type in ("statement_block", "class_body"):
        return _block_immediately_declares_name(scope_node, source, name)
    return False


def _function_parameters_declare_name(
    fn_node, source: bytes, name: str
) -> bool:
    """Return True if the function-like node's formal parameters bind ``name``.

    Handles arrow functions with a single unparenthesised parameter
    (``parameter`` field) and regular ``formal_parameters``. Walks
    ``required_parameter`` / ``optional_parameter`` wrappers and the
    common destructuring patterns enough to detect identifier-shaped
    bindings.
    """
    single = fn_node.child_by_field_name("parameter")
    if single is not None and _pattern_binds_name(single, source, name):
        return True
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        return False
    for child in params.children:
        if child.type in ("required_parameter", "optional_parameter"):
            pattern = child.child_by_field_name("pattern")
            if pattern is not None and _pattern_binds_name(
                pattern, source, name
            ):
                return True
        elif _pattern_binds_name(child, source, name):
            return True
    return False


def _pattern_binds_name(node, source: bytes, name: str) -> bool:
    """Return True if a parameter / binding pattern node binds ``name``.

    Walks ``identifier``, ``assignment_pattern`` (default values),
    ``rest_pattern``, ``object_pattern`` (with shorthand and pair
    sub-patterns), and ``array_pattern`` shapes. Anything else returns
    False.
    """
    if node is None:
        return False
    t = node.type
    if t == "identifier":
        return node_text(node, source) == name
    if t == "assignment_pattern":
        left = node.child_by_field_name("left")
        return _pattern_binds_name(left, source, name)
    if t == "rest_pattern":
        for child in node.children:
            if child.type != "..." and _pattern_binds_name(child, source, name):
                return True
        return False
    if t == "object_pattern":
        for child in node.children:
            if child.type == "shorthand_property_identifier_pattern":
                if node_text(child, source) == name:
                    return True
            elif child.type == "pair_pattern":
                value_field = child.child_by_field_name("value")
                if _pattern_binds_name(value_field, source, name):
                    return True
            elif child.type == "rest_pattern":
                if _pattern_binds_name(child, source, name):
                    return True
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                if _pattern_binds_name(left, source, name):
                    return True
        return False
    if t == "array_pattern":
        for child in node.children:
            if child.type in (
                "identifier",
                "assignment_pattern",
                "rest_pattern",
                "object_pattern",
                "array_pattern",
            ) and _pattern_binds_name(child, source, name):
                return True
        return False
    return False


def _block_immediately_declares_name(
    block_node, source: bytes, name: str
) -> bool:
    """Return True if a direct child of ``block_node`` is a
    ``lexical_declaration`` / ``variable_declaration`` / ``function_declaration``
    that binds ``name`` at the block's own scope.

    Nested declarations inside inner blocks or inner functions are NOT
    counted here — the outer ``_identifier_shadowed_in_enclosing_local_scope``
    walks parent by parent, so each scope is visited at its own level.
    """
    for child in block_node.children:
        if child.type in ("lexical_declaration", "variable_declaration"):
            for decl in child.children:
                if decl.type != "variable_declarator":
                    continue
                name_node = decl.child_by_field_name("name")
                if name_node is None:
                    continue
                if _pattern_binds_name(name_node, source, name):
                    return True
        elif child.type == "function_declaration":
            name_node = child.child_by_field_name("name")
            if (
                name_node is not None
                and name_node.type == "identifier"
                and node_text(name_node, source) == name
            ):
                return True
    return False
