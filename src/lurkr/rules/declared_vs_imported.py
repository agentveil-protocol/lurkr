"""Declared-vs-imported agent capability delta rule."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from lurkr.js_ast import (
    JsAstDocument,
    iter_nodes as _iter_js_nodes,
    load_js_ast_document,
    node_text as _js_node_text,
    static_string_value as _js_static_string_value,
)
from lurkr.manifest import collect_declared, normalize_capability_name
from lurkr.python_ast import (
    PythonAstDocument,
    iter_ast_nodes,
    load_python_ast_document,
    resolve_name,
)
from lurkr.report import Finding


TOOL_DECORATOR_BASENAMES = {
    "tool",
    "call_tool",
}
TOOL_CONSTRUCTOR_BASENAMES = {
    "FunctionTool",
    "Tool",
    "StructuredTool",
}
TOOL_CONSTRUCTOR_METHODS = {
    ("FunctionTool", "from_defaults"),
}
PROVIDER_TOOL_CALL_BASENAMES = {
    "create",
    "generate_content",
    "GenerativeModel",
}


@dataclass(frozen=True)
class ScanContext:
    scan_root: Path
    python_files: tuple[Path, ...]
    js_files: tuple[Path, ...] = ()


@dataclass(frozen=True)
class _RegisteredTool:
    name: str
    line: int


class DeclaredVsImportedRule:
    rule_id = "agent.declared_vs_imported_delta"
    severity = "high"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        declared_set = collect_declared(context.scan_root)
        if not declared_set:
            return []

        findings: list[Finding] = []
        for python_file in context.python_files:
            document = load_python_ast_document(python_file)
            if document is None:
                continue
            for tool in _collect_registered_tools(document):
                normalized = normalize_capability_name(tool.name)
                if not normalized or normalized in declared_set:
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=python_file.relative_to(context.scan_root).as_posix(),
                        line=tool.line,
                        message=(
                            f"Tool '{tool.name}' is registered in Python code but "
                            "not declared in any agent manifest."
                        ),
                        remediation=(
                            f"Add '{tool.name}' to your agent manifest declared tools, "
                            "or remove the Python tool registration if the capability "
                            "is not intended to be exposed."
                        ),
                    )
                )
        for js_file in context.js_files:
            js_document = load_js_ast_document(js_file)
            if js_document is None:
                continue
            if js_document.tree.root_node.has_error:
                continue
            server_identifiers = _collect_mcp_server_identifiers(js_document)
            if not server_identifiers:
                continue
            for js_tool in _collect_registered_tools_js(js_document, server_identifiers):
                normalized = normalize_capability_name(js_tool.name)
                if not normalized or normalized in declared_set:
                    continue
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        file=js_file.relative_to(context.scan_root).as_posix(),
                        line=js_tool.line,
                        message=(
                            f"Tool '{js_tool.name}' is registered in TypeScript/JavaScript code but "
                            "not declared in any agent manifest."
                        ),
                        remediation=(
                            f"Add '{js_tool.name}' to your agent manifest declared tools, "
                            "or remove the TypeScript/JavaScript tool registration if the capability "
                            "is not intended to be exposed."
                        ),
                    )
                )
        return _dedupe_findings(findings)


def scan_declared_vs_imported_delta(
    root: Path,
    python_files: list[Path],
    js_files: list[Path] | None = None,
) -> list[Finding]:
    context = ScanContext(
        scan_root=root,
        python_files=tuple(python_files),
        js_files=tuple(js_files or ()),
    )
    return DeclaredVsImportedRule().evaluate(context)


def _collect_registered_tools(document: PythonAstDocument) -> list[_RegisteredTool]:
    functions = _collect_functions(document)
    tools: list[_RegisteredTool] = []

    for function in functions.values():
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = resolve_name(target, document.imports)
            if name is None or not _is_tool_decorator_name(name.name):
                continue
            tool_name = _decorator_tool_name(decorator, function.name)
            if tool_name is None:
                continue
            tools.append(
                _RegisteredTool(
                    name=tool_name,
                    line=getattr(decorator, "lineno", function.lineno),
                )
            )

    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Call):
            continue
        name = resolve_name(node.func, document.imports)
        if name is None or not _is_tool_constructor_name(name.name):
            continue
        tool_name = _constructor_tool_name(node, name.name)
        if tool_name is None:
            continue
        tools.append(_RegisteredTool(name=tool_name, line=getattr(node, "lineno", name.lineno)))

    tools.extend(_collect_provider_tools(document, functions))
    return _dedupe_tools(tools)


def _collect_functions(document: PythonAstDocument) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
    return functions


def _decorator_tool_name(
    decorator: ast.expr, function_name: str
) -> str | None:
    if not isinstance(decorator, ast.Call):
        return function_name
    explicit = _explicit_static_tool_name(decorator)
    if explicit.found_dynamic:
        return None
    if explicit.name is not None:
        return explicit.name
    return function_name


def _constructor_tool_name(call: ast.Call, constructor_name: str) -> str | None:
    explicit = _explicit_static_tool_name(call)
    if explicit.found_dynamic:
        return None
    if explicit.name is not None:
        return explicit.name
    return _local_tool_function_keyword(call, constructor_name)


@dataclass(frozen=True)
class _ExplicitToolName:
    name: str | None
    found_dynamic: bool


def _explicit_static_tool_name(call: ast.Call) -> _ExplicitToolName:
    for keyword in call.keywords:
        if keyword.arg == "name":
            name = _const_str(keyword.value)
            return _ExplicitToolName(name=name, found_dynamic=name is None)
    if call.args:
        name = _const_str(call.args[0])
        if name is not None:
            return _ExplicitToolName(name=name, found_dynamic=False)
        if _call_target_basename(call) in TOOL_DECORATOR_BASENAMES:
            return _ExplicitToolName(name=None, found_dynamic=True)
    return _ExplicitToolName(name=None, found_dynamic=False)


def _local_tool_function_keyword(call: ast.Call, constructor_name: str) -> str | None:
    keyword_names = ("fn",) if _is_function_tool_constructor_name(constructor_name) else ("func",)
    for keyword in call.keywords:
        if keyword.arg not in keyword_names:
            continue
        if isinstance(keyword.value, ast.Name):
            return keyword.value.id
    return None


def _collect_provider_tools(
    document: PythonAstDocument,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[_RegisteredTool]:
    tools: list[_RegisteredTool] = []
    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Call) or not _is_provider_tool_call_with_tools(node):
            continue
        for tools_value in _provider_tools_values(node):
            if not isinstance(tools_value, ast.List):
                continue
            for item in tools_value.elts:
                if not isinstance(item, ast.Dict):
                    continue
                for function_name, line in _extract_tool_names_from_dict(item):
                    if function_name not in functions:
                        continue
                    tools.append(_RegisteredTool(name=function_name, line=line))
    return tools


def _is_tool_decorator_name(name: str) -> bool:
    return name.rsplit(".", 1)[-1] in TOOL_DECORATOR_BASENAMES


def _is_tool_constructor_name(name: str) -> bool:
    parts = name.split(".")
    if parts[-1] in TOOL_CONSTRUCTOR_BASENAMES:
        return True
    return len(parts) >= 2 and (parts[-2], parts[-1]) in TOOL_CONSTRUCTOR_METHODS


def _is_function_tool_constructor_name(name: str) -> bool:
    parts = name.split(".")
    return parts[-1] == "FunctionTool" or (
        len(parts) >= 2 and (parts[-2], parts[-1]) in TOOL_CONSTRUCTOR_METHODS
    )


def _is_provider_tool_call_with_tools(call: ast.Call) -> bool:
    raw_name = _raw_call_name(call)
    if raw_name is None or raw_name.rsplit(".", 1)[-1] not in PROVIDER_TOOL_CALL_BASENAMES:
        return False
    return bool(_provider_tools_values(call))


def _provider_tools_values(call: ast.Call) -> list[ast.AST]:
    values: list[ast.AST] = []
    for keyword in call.keywords:
        if keyword.arg == "tools":
            values.append(keyword.value)
        elif keyword.arg == "config" and isinstance(keyword.value, ast.Dict):
            tools = _dict_values_by_string_key(keyword.value).get("tools")
            if tools is not None:
                values.append(tools)
    return values


def _extract_tool_names_from_dict(dict_node: ast.Dict) -> list[tuple[str, int]]:
    values = _dict_values_by_string_key(dict_node)
    names: list[tuple[str, int]] = []
    fallback_line = getattr(dict_node, "lineno", 0)

    if _const_str(values.get("type")) == "function":
        function_dict = values.get("function")
        if isinstance(function_dict, ast.Dict):
            name = _extract_dict_value(function_dict, "name")
            if name is not None:
                names.append((name, getattr(function_dict, "lineno", fallback_line)))

    if "name" in values and "input_schema" in values:
        name = _const_str(values["name"])
        if name is not None:
            names.append((name, fallback_line))

    declarations = values.get("function_declarations")
    if isinstance(declarations, ast.List):
        for declaration in declarations.elts:
            if not isinstance(declaration, ast.Dict):
                continue
            name = _extract_dict_value(declaration, "name")
            if name is not None:
                names.append((name, getattr(declaration, "lineno", fallback_line)))

    return names


def _dict_values_by_string_key(dict_node: ast.Dict) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}
    for key, value in zip(dict_node.keys, dict_node.values):
        key_name = _const_str(key)
        if key_name is not None:
            values[key_name] = value
    return values


def _extract_dict_value(dict_node: ast.Dict, key: str) -> str | None:
    return _const_str(_dict_values_by_string_key(dict_node).get(key))


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_target_basename(call: ast.Call) -> str | None:
    raw_name = _raw_call_name(call)
    if raw_name is None:
        return None
    return raw_name.rsplit(".", 1)[-1]


def _raw_call_name(call: ast.Call) -> str | None:
    return _raw_dotted_name(call.func)


def _raw_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _raw_dotted_name(node.value)
        if value is None:
            return None
        return f"{value}.{node.attr}"
    return None


def _dedupe_tools(tools: list[_RegisteredTool]) -> list[_RegisteredTool]:
    seen: set[tuple[str, int]] = set()
    deduped: list[_RegisteredTool] = []
    for tool in tools:
        key = (tool.name, tool.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(tool)
    return deduped


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


@dataclass(frozen=True)
class _JsRegisteredTool:
    name: str
    line: int


def _collect_mcp_server_identifiers(document: JsAstDocument) -> set[str]:
    """Return the set of local variable names bound to `new McpServer(...)` in
    this file.

    Bounded static signal: only direct `<id> = new McpServer(...)` or
    `<id> = new <ns>.McpServer(...)` bindings are tracked. Cross-file
    references, factory functions, and dynamic constructor patterns are
    intentionally not resolved.
    """
    identifiers: set[str] = set()
    for node in _iter_js_nodes(document.tree):
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is None or value_node is None:
                continue
            if name_node.type != "identifier":
                continue
            if not _is_mcp_server_new_expression(value_node, document.source):
                continue
            identifiers.add(_js_node_text(name_node, document.source))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type != "identifier":
                continue
            if not _is_mcp_server_new_expression(right, document.source):
                continue
            identifiers.add(_js_node_text(left, document.source))
    return identifiers


def _is_mcp_server_new_expression(node, source: bytes) -> bool:
    """Return True if node is `new McpServer(...)` or `new <ns>.McpServer(...)`."""
    if node.type != "new_expression":
        return False
    constructor = node.child_by_field_name("constructor")
    if constructor is None:
        return False
    if constructor.type == "identifier":
        return _js_node_text(constructor, source) == "McpServer"
    if constructor.type == "member_expression":
        prop = constructor.child_by_field_name("property")
        if prop is not None and _js_node_text(prop, source) == "McpServer":
            return True
    return False


def _collect_registered_tools_js(
    document: JsAstDocument,
    server_identifiers: set[str],
) -> list[_JsRegisteredTool]:
    """Collect static-named `<server_id>.registerTool('name', ...)` calls.

    Only call sites where the receiver identifier is in `server_identifiers`
    (the set of locally-bound McpServer instances) are accepted. Tool name
    must be a static string literal; dynamic names are skipped silently.
    Bounded static signal — does not resolve cross-file references.
    """
    if not server_identifiers:
        return []
    tools: list[_JsRegisteredTool] = []
    seen: set[tuple[str, int]] = set()
    for node in _iter_js_nodes(document.tree):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            continue
        obj = fn.child_by_field_name("object")
        if obj is None or obj.type != "identifier":
            continue
        if _js_node_text(obj, document.source) not in server_identifiers:
            continue
        prop = fn.child_by_field_name("property")
        if prop is None or _js_node_text(prop, document.source) != "registerTool":
            continue
        args = node.child_by_field_name("arguments")
        if args is None:
            continue
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
        if not arg_nodes:
            continue
        name = _js_static_string_value(arg_nodes[0], document.source)
        if name is None:
            continue
        line = node.start_point[0] + 1
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        tools.append(_JsRegisteredTool(name=name, line=line))
    return tools
