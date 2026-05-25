"""TypeScript/JavaScript agent posture rules.

Rules:

- ``agent.javascript_child_process_in_tool`` — flag Node.js ``child_process``
  command execution inside a canonical MCP ``registerTool`` handler.
- ``agent.javascript_file_mutation_in_tool`` — flag Node.js ``fs`` /
  ``fs/promises`` file write/delete-style APIs inside a canonical MCP
  ``registerTool`` handler.

Detection is bounded static analysis over either the scanned file or a
relative-imported same-repo file:

- The MCP server context gate (`new McpServer(...)` reached through an official
  `@modelcontextprotocol/*` import) is reused from
  :mod:`lurkr.rules.js_mcp`.
- Only ``server.registerTool("static_name", config, handler)`` calls are
  considered. Dynamic tool names, ``server.tool(...)``, and
  ``setRequestHandler(...)`` are intentionally out of scope.
- Handler resolution covers, in priority order: (a) an inline arrow or
  function expression as the third argument, (b) an identifier reference to
  a same-file ``function`` declaration or ``const`` arrow / function
  expression, or (c) an identifier bound by a named import from a same-repo
  relative path (``./tools``, ``../lib/x``) where the target file exports
  the named symbol as a ``function`` declaration or a ``const`` arrow /
  function expression. Package imports, tsconfig path aliases, namespace
  local imports, dynamic imports, barrel re-exports
  (``export { x } from './y'``), and default exports are intentionally not
  resolved.
- For cross-file resolution the rule analyses the handler in the TARGET
  file's context: the call-site walk uses the target file's risky imports,
  the handler's parameter / same-scope bindings in the target file, and the
  target file's source for line numbers. The emitted finding points at the
  target file relative to the scan root.
- Risky APIs from ``child_process``, ``node:child_process``, ``fs``,
  ``node:fs``, ``fs/promises``, or ``node:fs/promises`` are recognised
  through named imports (with optional alias), namespace imports, default
  imports, destructured requires (with optional alias), and namespace-bound
  ``require`` calls.
- Same-handler shadow handling: when the handler's own scope binds an
  identifier whose name collides with a risky module import binding
  (handler parameters, top-level ``const`` / ``let`` / ``var``, or a
  same-scope ``function`` declaration), calls through that name within the
  handler are not flagged. Shadowing introduced inside nested function or
  class scopes is intentionally not v1.
- Cross-file resolution fails closed: missing target files, oversized
  target files, target files with parse errors, and target files outside
  the scan root all cause the handler to silently not resolve.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from lurkr.js_ast import (
    JsAstDocument,
    is_js_or_ts_source,
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
FILE_SYSTEM_PACKAGES = frozenset(
    {"fs", "node:fs", "fs/promises", "node:fs/promises"}
)
FILE_MUTATION_APIS = frozenset(
    {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "rm",
        "rmSync",
        "unlink",
        "unlinkSync",
        "rename",
        "renameSync",
        "mkdir",
        "mkdirSync",
        "createWriteStream",
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

_RELATIVE_PATH_PREFIXES = ("./", "../")
_RESOLUTION_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")


@dataclass(frozen=True)
class _ImportBinding:
    """A named import bound from a same-repo relative path.

    ``local_name`` — identifier visible in the scanning file.
    ``imported_name`` — original symbol name in the target file (before any
    alias rebinding).
    ``source`` — resolved absolute path to the target ``.ts`` / ``.tsx`` /
    ``.js`` / ``.mjs`` / ``.cjs`` / ``.mts`` / ``.cts`` file.
    """

    local_name: str
    imported_name: str
    source: Path


@dataclass(frozen=True)
class _HandlerLocation:
    """Resolved handler body plus the analysis context it should be walked in.

    For same-file handlers, ``source`` / ``file_path`` / risky import sets
    match the scanning file. For cross-file handlers, they reflect the target
    file so that call-site resolution and line numbers come from the file
    where the body actually lives.
    """

    body: Any
    source: bytes
    file_path: Path
    cp_imports: "ChildProcessImports"
    fs_imports: "FileSystemImports"


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


@dataclass(frozen=True)
class FileSystemImports:
    """Local symbols in one file bound to Node.js ``fs`` mutation APIs.

    ``direct_names`` — local identifiers whose original imported symbol is one
    of :data:`FILE_MUTATION_APIS`. Examples include ``writeFile`` after
    ``import { writeFile } from "node:fs/promises"`` and ``write`` after
    ``import { writeFile as write } from "fs"``.

    ``namespace_aliases`` — local identifiers bound to the entire ``fs`` or
    ``fs/promises`` module via namespace import, default import, or
    whole-module require. Calls on these identifiers reach the rule through
    member-expression form (e.g. ``fs.writeFile(...)`` or
    ``fs.promises.writeFile(...)``).
    """

    direct_names: frozenset[str]
    namespace_aliases: frozenset[str]

    @property
    def empty(self) -> bool:
        return not self.direct_names and not self.namespace_aliases


def scan_js_agent_rules(root: Path, path: Path) -> list[Finding]:
    """Return TypeScript/JavaScript agent rule findings for one file.

    Handlers reachable from this file's MCP ``registerTool`` call sites are
    analysed in the file where their body actually lives — that may be the
    scanning file (same-file resolution) or a relative-imported same-repo
    target file (cross-file resolution). Findings are reported relative to
    the scan root using the body's file path.
    """
    document = load_js_ast_document(path)
    if document is None:
        return []
    if document.tree.root_node.has_error:
        return []

    server_identifiers = collect_mcp_server_identifiers(document)
    if not server_identifiers:
        return []

    scan_cp_imports = _collect_child_process_imports(document)
    scan_fs_imports = _collect_file_system_imports(document)
    import_bindings = _collect_relative_import_bindings(document, path, root)

    if scan_cp_imports.empty and scan_fs_imports.empty and not import_bindings:
        return []

    declarations, lex_handlers = _collect_handler_bindings(document)

    parsed_cache: dict[Path, JsAstDocument | None] = {path: document}
    cp_imports_cache: dict[Path, ChildProcessImports] = {path: scan_cp_imports}
    fs_imports_cache: dict[Path, FileSystemImports] = {path: scan_fs_imports}

    findings: list[Finding] = []
    seen_locations: set[tuple[str, str, int]] = set()

    for tool in collect_registered_tools_js(document, server_identifiers):
        location = _resolve_handler_location(
            handler_node=tool.handler,
            scan_document=document,
            scan_path=path,
            scan_cp_imports=scan_cp_imports,
            scan_fs_imports=scan_fs_imports,
            same_file_declarations=declarations,
            same_file_lex_handlers=lex_handlers,
            import_bindings=import_bindings,
            parsed_cache=parsed_cache,
            cp_imports_cache=cp_imports_cache,
            fs_imports_cache=fs_imports_cache,
        )
        if location is None:
            continue

        try:
            file_rel = location.file_path.relative_to(root).as_posix()
        except ValueError:
            continue

        handler_locals = _handler_local_names(location.body, location.source)

        if not location.cp_imports.empty:
            effective_cp_imports = ChildProcessImports(
                direct_names=location.cp_imports.direct_names - handler_locals,
                namespace_aliases=(
                    location.cp_imports.namespace_aliases - handler_locals
                ),
            )
            for line in _child_process_call_lines(
                location.body, effective_cp_imports, location.source
            ):
                key = ("agent.javascript_child_process_in_tool", file_rel, line)
                if key in seen_locations:
                    continue
                seen_locations.add(key)
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

        if not location.fs_imports.empty:
            effective_fs_imports = FileSystemImports(
                direct_names=location.fs_imports.direct_names - handler_locals,
                namespace_aliases=(
                    location.fs_imports.namespace_aliases - handler_locals
                ),
            )
            for line in _file_mutation_call_lines(
                location.body, effective_fs_imports, location.source
            ):
                key = ("agent.javascript_file_mutation_in_tool", file_rel, line)
                if key in seen_locations:
                    continue
                seen_locations.add(key)
                findings.append(
                    Finding(
                        rule_id="agent.javascript_file_mutation_in_tool",
                        severity="high",
                        file=file_rel,
                        line=line,
                        message=(
                            "TypeScript/JavaScript MCP tool handler appears to "
                            "write or delete files."
                        ),
                        remediation=(
                            "Restrict file-write/delete access to explicit safe "
                            "paths and require approval for destructive file "
                            "operations."
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


def _collect_file_system_imports(document: JsAstDocument) -> FileSystemImports:
    direct: set[str] = set()
    namespaces: set[str] = set()

    for node in iter_nodes(document.tree):
        if node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node is None:
                continue
            pkg = static_string_value(source_node, document.source)
            if pkg not in FILE_SYSTEM_PACKAGES:
                continue
            for child in node.children:
                if child.type != "import_clause":
                    continue
                for sub in child.children:
                    if sub.type == "identifier":
                        # Default import: `import fs from "node:fs"`.
                        namespaces.add(node_text(sub, document.source))
                    elif sub.type == "named_imports":
                        for spec in sub.children:
                            if spec.type != "import_specifier":
                                continue
                            name_node = spec.child_by_field_name("name")
                            if name_node is None:
                                continue
                            original = node_text(name_node, document.source)
                            if original not in FILE_MUTATION_APIS:
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
            if pkg not in FILE_SYSTEM_PACKAGES:
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
                        if name in FILE_MUTATION_APIS:
                            direct.add(name)
                    elif prop.type == "pair_pattern":
                        key_field = prop.child_by_field_name("key")
                        value_field = prop.child_by_field_name("value")
                        if (
                            key_field is not None
                            and value_field is not None
                            and value_field.type == "identifier"
                            and node_text(key_field, document.source)
                            in FILE_MUTATION_APIS
                        ):
                            direct.add(node_text(value_field, document.source))

    return FileSystemImports(
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


def _resolve_handler_location(
    *,
    handler_node: Any,
    scan_document: JsAstDocument,
    scan_path: Path,
    scan_cp_imports: ChildProcessImports,
    scan_fs_imports: FileSystemImports,
    same_file_declarations: dict[str, Any],
    same_file_lex_handlers: dict[str, Any],
    import_bindings: dict[str, _ImportBinding],
    parsed_cache: dict[Path, JsAstDocument | None],
    cp_imports_cache: dict[Path, ChildProcessImports],
    fs_imports_cache: dict[Path, FileSystemImports],
) -> _HandlerLocation | None:
    """Resolve a registerTool ``handler`` argument to the function/arrow node
    plus the analysis context for the file the body lives in.

    Priority order:

    1. Inline ``arrow_function`` / ``function_expression`` → scanning-file
       context.
    2. Identifier matching a same-file ``function`` declaration or
       ``const`` arrow / function expression → scanning-file context.
    3. Identifier matching a relative-import binding whose target file
       exists, parses cleanly, and exports the symbol as a function /
       const arrow / const function expression → target-file context.

    Returns None when none of the above produces a body.
    """
    if handler_node is None:
        return None
    if handler_node.type in _HANDLER_INLINE_TYPES:
        return _HandlerLocation(
            body=handler_node,
            source=scan_document.source,
            file_path=scan_path,
            cp_imports=scan_cp_imports,
            fs_imports=scan_fs_imports,
        )
    if handler_node.type != "identifier":
        return None

    name = node_text(handler_node, scan_document.source)
    same_file_body = same_file_declarations.get(name) or same_file_lex_handlers.get(
        name
    )
    if same_file_body is not None:
        return _HandlerLocation(
            body=same_file_body,
            source=scan_document.source,
            file_path=scan_path,
            cp_imports=scan_cp_imports,
            fs_imports=scan_fs_imports,
        )

    binding = import_bindings.get(name)
    if binding is None:
        return None

    target_document = _get_parsed_document(binding.source, parsed_cache)
    if target_document is None:
        return None

    target_body = _find_exported_binding(target_document, binding.imported_name)
    if target_body is None:
        return None

    target_cp_imports = cp_imports_cache.get(binding.source)
    if target_cp_imports is None:
        target_cp_imports = _collect_child_process_imports(target_document)
        cp_imports_cache[binding.source] = target_cp_imports
    target_fs_imports = fs_imports_cache.get(binding.source)
    if target_fs_imports is None:
        target_fs_imports = _collect_file_system_imports(target_document)
        fs_imports_cache[binding.source] = target_fs_imports

    return _HandlerLocation(
        body=target_body,
        source=target_document.source,
        file_path=binding.source,
        cp_imports=target_cp_imports,
        fs_imports=target_fs_imports,
    )


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


def _file_mutation_call_lines(
    handler_body: Any,
    fs_imports: FileSystemImports,
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
            if local in fs_imports.direct_names:
                yield node.start_point[0] + 1
        elif fn.type == "member_expression":
            member = _member_expression_parts(fn, source)
            if member is None:
                continue
            base, props = member
            if base not in fs_imports.namespace_aliases:
                continue
            if len(props) == 1 and props[0] in FILE_MUTATION_APIS:
                yield node.start_point[0] + 1
            elif (
                len(props) == 2
                and props[0] == "promises"
                and props[1] in FILE_MUTATION_APIS
            ):
                yield node.start_point[0] + 1


def _member_expression_parts(node: Any, source: bytes) -> tuple[str, tuple[str, ...]] | None:
    """Return ``(base_identifier, property_chain)`` for dotted member access.

    Supports bounded static chains such as ``fs.writeFile`` and
    ``fs.promises.writeFile``. Computed access (``fs[method]``) and chains
    rooted in non-identifiers are skipped.
    """
    props: list[str] = []
    current = node
    while current.type == "member_expression":
        prop = current.child_by_field_name("property")
        obj = current.child_by_field_name("object")
        if prop is None or obj is None or prop.type != "property_identifier":
            return None
        props.append(node_text(prop, source))
        if obj.type == "identifier":
            return node_text(obj, source), tuple(reversed(props))
        current = obj
    return None


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


def _collect_relative_import_bindings(
    document: JsAstDocument, scan_path: Path, scan_root: Path
) -> dict[str, _ImportBinding]:
    """Map local binding name -> ``_ImportBinding`` for named imports whose
    source path starts with ``./`` or ``../`` and resolves to a same-repo
    JS/TS source file inside ``scan_root``.

    Bindings whose target does not resolve (missing file, non-JS suffix,
    OS error) are silently dropped. Bindings whose resolved target falls
    outside ``scan_root`` are also dropped here, BEFORE any target file is
    parsed — Lurkr must not read files outside the scan path. Namespace
    imports, default imports, and dynamic imports are not collected.
    """
    bindings: dict[str, _ImportBinding] = {}
    base_dir = scan_path.parent
    for node in iter_nodes(document.tree):
        if node.type != "import_statement":
            continue
        source_node = node.child_by_field_name("source")
        if source_node is None:
            continue
        spec = static_string_value(source_node, document.source)
        if spec is None or not spec.startswith(_RELATIVE_PATH_PREFIXES):
            continue
        target = _resolve_relative_module(base_dir, spec)
        if target is None:
            continue
        try:
            target.relative_to(scan_root)
        except ValueError:
            continue
        for clause in node.children:
            if clause.type != "import_clause":
                continue
            for sub in clause.children:
                if sub.type != "named_imports":
                    continue
                for spec_node in sub.children:
                    if spec_node.type != "import_specifier":
                        continue
                    name_node = spec_node.child_by_field_name("name")
                    if name_node is None or name_node.type != "identifier":
                        continue
                    alias_node = spec_node.child_by_field_name("alias")
                    local_node = (
                        alias_node if alias_node is not None else name_node
                    )
                    if local_node.type != "identifier":
                        continue
                    local_name = node_text(local_node, document.source)
                    imported = node_text(name_node, document.source)
                    bindings[local_name] = _ImportBinding(
                        local_name=local_name,
                        imported_name=imported,
                        source=target,
                    )
    return bindings


def _resolve_relative_module(base_dir: Path, spec: str) -> Path | None:
    """Resolve a relative module spec to a same-repo JS/TS source file path.

    Tries the spec as-is when it carries a recognised JS/TS suffix; otherwise
    appends each candidate suffix in
    ``.ts, .tsx, .mts, .cts, .js, .mjs, .cjs`` order until a file exists.
    Directory / ``index`` files, tsconfig path mappings, and package imports
    are intentionally not handled.
    """
    try:
        base = (base_dir / spec).resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    try:
        if base.suffix and is_js_or_ts_source(base) and base.is_file():
            return base
    except OSError:
        return None
    base_str = str(base)
    for suffix in _RESOLUTION_SUFFIXES:
        candidate = Path(base_str + suffix)
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _get_parsed_document(
    path: Path, parsed_cache: dict[Path, JsAstDocument | None]
) -> JsAstDocument | None:
    """Return a parsed AST document for ``path``, caching None on failure.

    Treats trees with parse errors the same as parse failure so that
    downstream cross-file resolution fails closed on malformed targets.
    """
    if path in parsed_cache:
        return parsed_cache[path]
    document = load_js_ast_document(path)
    if document is not None and document.tree.root_node.has_error:
        document = None
    parsed_cache[path] = document
    return document


def _find_exported_binding(document: JsAstDocument, name: str) -> Any | None:
    """Locate the function/arrow node exported under ``name`` in ``document``.

    Supports direct declaration exports (``export function name`` /
    ``export async function name`` / ``export const name = arrow`` /
    ``export const name = function``) and clauseless ``export { name }`` /
    ``export { local as name }`` that route back to a same-file function or
    const arrow/function declaration. Re-exports (``export {} from './y'``),
    default exports, and namespace re-exports are intentionally not v1.
    """
    local_decls: dict[str, Any] = {}
    local_lex: dict[str, Any] = {}
    for node in iter_nodes(document.tree):
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                local_decls[node_text(name_node, document.source)] = node
        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if (
                name_node is not None
                and value_node is not None
                and name_node.type == "identifier"
                and value_node.type in _HANDLER_INLINE_TYPES
            ):
                local_lex[node_text(name_node, document.source)] = value_node

    for node in iter_nodes(document.tree):
        if node.type != "export_statement":
            continue
        if node.child_by_field_name("source") is not None:
            continue
        if any(child.type == "default" for child in node.children):
            continue

        declaration = node.child_by_field_name("declaration")
        if declaration is not None:
            body = _exported_declaration_body(declaration, name, document.source)
            if body is not None:
                return body
            continue

        for child in node.children:
            if child.type != "export_clause":
                continue
            for spec in child.children:
                if spec.type != "export_specifier":
                    continue
                spec_name = spec.child_by_field_name("name")
                if spec_name is None or spec_name.type != "identifier":
                    continue
                spec_alias = spec.child_by_field_name("alias")
                exported_as = (
                    node_text(spec_alias, document.source)
                    if spec_alias is not None and spec_alias.type == "identifier"
                    else node_text(spec_name, document.source)
                )
                if exported_as != name:
                    continue
                local = node_text(spec_name, document.source)
                if local in local_decls:
                    return local_decls[local]
                if local in local_lex:
                    return local_lex[local]
    return None


def _exported_declaration_body(
    declaration: Any, name: str, source: bytes
) -> Any | None:
    if declaration.type == "function_declaration":
        name_node = declaration.child_by_field_name("name")
        if (
            name_node is not None
            and name_node.type == "identifier"
            and node_text(name_node, source) == name
        ):
            return declaration
        return None
    if declaration.type in {"lexical_declaration", "variable_declaration"}:
        for decl_child in declaration.children:
            if decl_child.type != "variable_declarator":
                continue
            name_node = decl_child.child_by_field_name("name")
            value_node = decl_child.child_by_field_name("value")
            if (
                name_node is not None
                and value_node is not None
                and name_node.type == "identifier"
                and value_node.type in _HANDLER_INLINE_TYPES
                and node_text(name_node, source) == name
            ):
                return value_node
        return None
    return None
