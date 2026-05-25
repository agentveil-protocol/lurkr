"""TypeScript/JavaScript agent posture rules.

v1 rule:

- ``agent.javascript_child_process_in_tool`` — flag Node.js ``child_process``
  command execution inside a canonical MCP ``registerTool`` handler.

Detection is bounded same-file static analysis:

- The MCP server context gate (`new McpServer(...)` reached through an official
  `@modelcontextprotocol/*` import) is reused from
  :mod:`lurkr.rules.js_mcp`.
- Only ``server.registerTool("static_name", config, handler)`` calls are
  considered. Dynamic tool names, ``server.tool(...)``, and
  ``setRequestHandler(...)`` are intentionally out of scope.
- Handler resolution covers (a) an inline arrow or function expression as the
  third argument, or (b) an identifier reference to a same-file
  ``function`` declaration or ``const`` arrow / function expression. Imported
  handler references are intentionally not resolved across files.
- Shell APIs from ``child_process`` or ``node:child_process`` are recognised
  through named imports (with optional alias), namespace imports, default
  imports, destructured requires (with optional alias), and namespace-bound
  ``require`` calls.
- Same-handler shadow handling: when the handler's own scope binds an
  identifier whose name collides with a ``child_process`` import binding
  (handler parameters, top-level ``const`` / ``let`` / ``var``, or a
  same-scope ``function`` declaration), calls through that name within the
  handler are not flagged. Shadowing introduced inside nested function or
  class scopes is intentionally not v1.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from lurkr.js_ast import (
    JsAstDocument,
    iter_nodes,
    load_js_ast_document,
    node_text,
    static_string_value,
)
from lurkr.report import Finding
from lurkr.rules.js_mcp import (
    collect_mcp_server_identifiers,
    collect_registered_tools_js,
)


CHILD_PROCESS_PACKAGES = frozenset({"child_process", "node:child_process"})
CHILD_PROCESS_APIS = frozenset(
    {
        "exec",
        "execSync",
        "spawn",
        "spawnSync",
        "execFile",
        "execFileSync",
        "fork",
    }
)

_HANDLER_INLINE_TYPES = frozenset({"arrow_function", "function_expression"})

_FUNCTION_LIKE_TYPES = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function_declaration",
        "generator_function_declaration",
    }
)

_SCOPE_BARRIER_TYPES = _FUNCTION_LIKE_TYPES | frozenset(
    {"method_definition", "class_declaration", "class_body"}
)


@dataclass(frozen=True)
class ChildProcessImports:
    """Local symbols in one file bound to Node.js ``child_process`` APIs.

    ``direct_names`` — local identifiers whose original imported symbol is one
    of :data:`CHILD_PROCESS_APIS`. Examples include ``exec`` after
    ``import { exec } from "child_process"`` and ``run`` after
    ``import { exec as run } from "node:child_process"`` or
    ``const { exec: run } = require("child_process")``.

    ``namespace_aliases`` — local identifiers bound to the entire
    ``child_process`` module via namespace import, default import, or
    whole-module require. Calls on these identifiers reach the rule through
    member-expression form (e.g. ``cp.exec(...)``).
    """

    direct_names: frozenset[str]
    namespace_aliases: frozenset[str]

    @property
    def empty(self) -> bool:
        return not self.direct_names and not self.namespace_aliases


def scan_js_agent_rules(root: Path, path: Path) -> list[Finding]:
    """Return TypeScript/JavaScript agent rule findings for one file."""
    document = load_js_ast_document(path)
    if document is None:
        return []
    if document.tree.root_node.has_error:
        return []

    server_identifiers = collect_mcp_server_identifiers(document)
    if not server_identifiers:
        return []

    cp_imports = _collect_child_process_imports(document)
    if cp_imports.empty:
        return []

    declarations, lex_handlers = _collect_handler_bindings(document)
    file_rel = path.relative_to(root).as_posix()

    findings: list[Finding] = []
    seen_lines: set[int] = set()
    for tool in collect_registered_tools_js(document, server_identifiers):
        body = _resolve_handler_body(
            tool.handler, document.source, declarations, lex_handlers
        )
        if body is None:
            continue
        handler_locals = _handler_local_names(body, document.source)
        effective_imports = ChildProcessImports(
            direct_names=cp_imports.direct_names - handler_locals,
            namespace_aliases=cp_imports.namespace_aliases - handler_locals,
        )
        if effective_imports.empty:
            continue
        for line in _child_process_call_lines(body, effective_imports, document.source):
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(
                Finding(
                    rule_id="agent.javascript_child_process_in_tool",
                    severity="high",
                    file=file_rel,
                    line=line,
                    message=(
                        "TypeScript/JavaScript MCP tool handler appears to run "
                        "child_process commands."
                    ),
                    remediation=(
                        "Require approval and a narrow allowlist before MCP tool "
                        "handlers run child_process commands."
                    ),
                )
            )
    return findings


def _collect_child_process_imports(document: JsAstDocument) -> ChildProcessImports:
    direct: set[str] = set()
    namespaces: set[str] = set()

    for node in iter_nodes(document.tree):
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node is None:
                continue
            pkg = static_string_value(source_node, document.source)
            if pkg not in CHILD_PROCESS_PACKAGES:
                continue
            for child in node.children:
                if child.type != "import_clause":
                    continue
                for sub in child.children:
                    if sub.type == "identifier":
                        # Default import: `import cp from "child_process"`.
                        namespaces.add(node_text(sub, document.source))
                    elif sub.type == "named_imports":
                        for spec in sub.children:
                            if spec.type != "import_specifier":
                                continue
                            name_node = spec.child_by_field_name("name")
                            if name_node is None:
                                continue
                            original = node_text(name_node, document.source)
                            if original not in CHILD_PROCESS_APIS:
                                continue
                            alias_node = spec.child_by_field_name("alias")
                            local_node = (
                                alias_node if alias_node is not None else name_node
                            )
                            if local_node.type == "identifier":
                                direct.add(node_text(local_node, document.source))
                    elif sub.type == "namespace_import":
                        for ns_child in sub.children:
                            if ns_child.type == "identifier":
                                namespaces.add(
                                    node_text(ns_child, document.source)
                                )
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
            arg_children = [
                c
                for c in call_args.children
                if c.type not in ("(", ")", ",", "comment")
            ]
            if not arg_children:
                continue
            pkg = static_string_value(arg_children[0], document.source)
            if pkg not in CHILD_PROCESS_PACKAGES:
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            if name_node.type == "identifier":
                namespaces.add(node_text(name_node, document.source))
            elif name_node.type == "object_pattern":
                for prop in name_node.children:
                    if prop.type == "shorthand_property_identifier_pattern":
                        name = node_text(prop, document.source)
                        if name in CHILD_PROCESS_APIS:
                            direct.add(name)
                    elif prop.type == "pair_pattern":
                        key_field = prop.child_by_field_name("key")
                        value_field = prop.child_by_field_name("value")
                        if (
                            key_field is not None
                            and value_field is not None
                            and value_field.type == "identifier"
                            and node_text(key_field, document.source)
                            in CHILD_PROCESS_APIS
                        ):
                            direct.add(node_text(value_field, document.source))

    return ChildProcessImports(
        direct_names=frozenset(direct),
        namespace_aliases=frozenset(namespaces),
    )


def _collect_handler_bindings(
    document: JsAstDocument,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return same-file handler resolution tables for ``identifier`` handlers.

    The first mapping is name -> ``function_declaration`` node (`function foo()
    {...}` forms, including async and exported). The second is name ->
    ``arrow_function`` or ``function_expression`` node (``const foo = ...``
    initialiser forms). Re-assignment after declaration is intentionally not
    tracked.
    """
    declarations: dict[str, Any] = {}
    lex_handlers: dict[str, Any] = {}
    for node in iter_nodes(document.tree):
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                declarations[node_text(name_node, document.source)] = node
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if (
                name_node is not None
                and value_node is not None
                and name_node.type == "identifier"
                and value_node.type in _HANDLER_INLINE_TYPES
            ):
                lex_handlers[node_text(name_node, document.source)] = value_node
    return declarations, lex_handlers


def _resolve_handler_body(
    handler_node: Any,
    source: bytes,
    declarations: dict[str, Any],
    lex_handlers: dict[str, Any],
) -> Any | None:
    if handler_node is None:
        return None
    if handler_node.type in _HANDLER_INLINE_TYPES:
        return handler_node
    if handler_node.type == "identifier":
        name = node_text(handler_node, source)
        return declarations.get(name) or lex_handlers.get(name)
    return None


def _child_process_call_lines(
    handler_body: Any,
    cp_imports: ChildProcessImports,
    source: bytes,
) -> Iterator[int]:
    for node in _iter_subtree(handler_body):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        if fn.type == "identifier":
            local = node_text(fn, source)
            if local in cp_imports.direct_names:
                yield node.start_point[0] + 1
        elif fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            prop = fn.child_by_field_name("property")
            if (
                obj is None
                or prop is None
                or obj.type != "identifier"
                or prop.type != "property_identifier"
            ):
                continue
            if node_text(obj, source) not in cp_imports.namespace_aliases:
                continue
            if node_text(prop, source) in CHILD_PROCESS_APIS:
                yield node.start_point[0] + 1


def _iter_subtree(node: Any) -> Iterator[Any]:
    stack: list[Any] = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _handler_local_names(handler_node: Any, source: bytes) -> set[str]:
    """Names bound at the handler's own scope.

    Collects the handler function's formal parameter identifiers plus any
    ``variable_declarator`` or ``function_declaration`` whose binding name is
    introduced at the handler's own scope. Nested function / method / class
    scopes are not descended into when scanning the handler body, so a name
    shadow introduced inside an inner function does not count as a
    handler-level shadow.
    """
    if handler_node is None or handler_node.type not in _FUNCTION_LIKE_TYPES:
        return set()
    names: set[str] = set()
    names.update(_function_parameter_names(handler_node, source))
    body = handler_node.child_by_field_name("body")
    if body is not None:
        for node in _iter_within_scope(body):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                if name_node is not None:
                    names.update(_pattern_identifier_names(name_node, source))
            elif node.type == "function_declaration":
                name_node = node.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    names.add(node_text(name_node, source))
    return names


def _function_parameter_names(fn_node: Any, source: bytes) -> set[str]:
    """Extract identifier names introduced by a function's formal parameters.

    Handles arrow functions with a single unparenthesised parameter
    (``x => ...``) via the ``parameter`` field and ordinary
    ``formal_parameters`` via the ``parameters`` field. Recurses into
    destructuring and TypeScript parameter wrappers.
    """
    names: set[str] = set()
    single = fn_node.child_by_field_name("parameter")
    if single is not None:
        names.update(_pattern_identifier_names(single, source))
    params = fn_node.child_by_field_name("parameters")
    if params is not None:
        for child in params.children:
            names.update(_pattern_identifier_names(child, source))
    return names


def _pattern_identifier_names(node: Any, source: bytes) -> set[str]:
    """Recursively collect identifier names bound by a parameter or
    destructuring pattern.

    Bounded-static: only structural patterns produced by tree-sitter for
    parameter and variable bindings are walked. Computed property names and
    spread-of-call-result are not unrolled. Returns an empty set for nodes
    whose shape is not recognised.
    """
    names: set[str] = set()
    if node is None:
        return names
    t = node.type
    if t == "identifier":
        names.add(node_text(node, source))
    elif t in {"required_parameter", "optional_parameter"}:
        pattern = node.child_by_field_name("pattern")
        names.update(_pattern_identifier_names(pattern, source))
    elif t == "assignment_pattern":
        left = node.child_by_field_name("left")
        names.update(_pattern_identifier_names(left, source))
    elif t == "rest_pattern":
        for child in node.children:
            if child.type != "...":
                names.update(_pattern_identifier_names(child, source))
    elif t == "object_pattern":
        for child in node.children:
            if child.type == "shorthand_property_identifier_pattern":
                names.add(node_text(child, source))
            elif child.type == "pair_pattern":
                value_field = child.child_by_field_name("value")
                names.update(_pattern_identifier_names(value_field, source))
            elif child.type == "rest_pattern":
                names.update(_pattern_identifier_names(child, source))
            elif child.type == "object_assignment_pattern":
                left = child.child_by_field_name("left")
                names.update(_pattern_identifier_names(left, source))
    elif t == "array_pattern":
        for child in node.children:
            if child.type == "identifier":
                names.add(node_text(child, source))
            elif child.type in {
                "assignment_pattern",
                "rest_pattern",
                "object_pattern",
                "array_pattern",
            }:
                names.update(_pattern_identifier_names(child, source))
    return names


def _iter_within_scope(node: Any) -> Iterator[Any]:
    """Iterate descendants of ``node`` without crossing nested function /
    class scope barriers."""
    stack: list[Any] = list(reversed(node.children))
    while stack:
        current = stack.pop()
        yield current
        if current.type not in _SCOPE_BARRIER_TYPES:
            stack.extend(reversed(current.children))
