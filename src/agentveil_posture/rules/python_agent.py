"""Python AST agent posture rules."""

from __future__ import annotations

import ast
from pathlib import Path
import re

from agentveil_posture.python_ast import (
    PythonAstDocument,
    PythonName,
    iter_ast_nodes,
    load_python_ast_document,
    resolve_name,
)
from agentveil_posture.report import Finding


TOOL_DECORATOR_BASENAMES = {
    "tool",
    "call_tool",
}
TOOL_CONSTRUCTOR_BASENAMES = {
    "Tool",
    "StructuredTool",
}
APPROVAL_MARKER_KEYS = {
    "require_human_approval",
    "requires_approval",
    "human_in_the_loop",
    "approval_required",
    "approval",
}
SUBPROCESS_CALL_NAMES = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
    "os.popen",
}
EVAL_EXEC_NAMES = {"eval", "exec", "compile", "__import__"}
DESTRUCTIVE_FILE_CALL_NAMES = {
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
}
PATH_MUTATION_METHODS = {"write_text", "write_bytes", "unlink"}
WRITE_MODES = {"w", "a", "x", "w+", "a+", "x+", "wb", "ab", "xb", "wb+", "ab+", "xb+"}
OPENAI_KEY_PREFIX = "sk" + "-"
ANTHROPIC_KEY_PREFIX = OPENAI_KEY_PREFIX + "ant" + "-"
API_KEY_RE = re.compile(
    r"^("
    + re.escape(ANTHROPIC_KEY_PREFIX)
    + r"[A-Za-z0-9_-]{8,}|"
    + re.escape(OPENAI_KEY_PREFIX)
    + r"[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|hf_[A-Za-z0-9]{8,})$"
)


def scan_python_agent_rules(root: Path, path: Path) -> list[Finding]:
    document = load_python_ast_document(path)
    if document is None:
        return []

    functions = _collect_functions(document)
    tool_sites = _collect_tool_sites(document, functions)
    findings: list[Finding] = []
    findings.extend(_tool_without_approval_findings(root, path, tool_sites))
    findings.extend(
        _tool_body_findings(
            root,
            path,
            tool_sites,
            functions,
            document,
            rule_id="agent.python_subprocess_in_tool",
            call_names=SUBPROCESS_CALL_NAMES,
            message="Python agent tool appears to run subprocess or shell commands.",
            remediation=(
                "Require approval and a narrow allowlist before agent tools run "
                "subprocesses or shell commands."
            ),
        )
    )
    findings.extend(
        _tool_body_findings(
            root,
            path,
            tool_sites,
            functions,
            document,
            rule_id="agent.python_eval_exec_in_tool",
            call_names=EVAL_EXEC_NAMES,
            message="Python agent tool appears to evaluate or import dynamic code.",
            remediation=(
                "Remove eval/exec-style dynamic execution from agent tools, or gate "
                "it behind explicit human approval and strict input validation."
            ),
        )
    )
    findings.extend(_file_access_findings(root, path, tool_sites, functions, document))
    findings.extend(_api_key_findings(root, path, document))
    return findings


class _ToolSite:
    def __init__(self, function_name: str | None, line: int, approved: bool) -> None:
        self.function_name = function_name
        self.line = line
        self.approved = approved


def _collect_functions(document: PythonAstDocument) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
    return functions


def _collect_tool_sites(
    document: PythonAstDocument,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[_ToolSite]:
    sites: list[_ToolSite] = []
    for function in functions.values():
        for decorator in function.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = resolve_name(target, document.imports)
            if name is not None and _is_tool_decorator_name(name.name):
                sites.append(
                    _ToolSite(
                        function_name=function.name,
                        line=getattr(decorator, "lineno", function.lineno),
                        approved=_call_has_approval(decorator) if isinstance(decorator, ast.Call) else False,
                    )
                )

    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Call):
            continue
        name = resolve_name(node.func, document.imports)
        if name is None or not _is_tool_constructor_name(name.name):
            continue
        sites.append(
            _ToolSite(
                function_name=_local_func_keyword(node),
                line=getattr(node, "lineno", name.lineno),
                approved=_call_has_approval(node),
            )
        )
    sites.extend(_collect_provider_tool_sites(document, functions))
    return sites


def _tool_without_approval_findings(root: Path, path: Path, sites: list[_ToolSite]) -> list[Finding]:
    findings: list[Finding] = []
    for site in sites:
        if site.approved:
            continue
        findings.append(
            Finding(
                rule_id="agent.python_tool_without_approval",
                severity="high",
                file=path.relative_to(root).as_posix(),
                line=site.line,
                message="Python agent tool appears to be exposed without an approval marker.",
                remediation=(
                    "Add an explicit human-approval marker or scope constraint before "
                    "exposing this Python function as an agent tool."
                ),
            )
        )
    return _dedupe_findings(findings)


def _tool_body_findings(
    root: Path,
    path: Path,
    sites: list[_ToolSite],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    document: PythonAstDocument,
    *,
    rule_id: str,
    call_names: set[str],
    message: str,
    remediation: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for function in _tool_functions(sites, functions):
        for node in iter_ast_nodes(function):
            if not isinstance(node, ast.Call):
                continue
            resolved = resolve_name(node.func, document.imports)
            name = resolved.name if resolved is not None else _raw_call_name(node)
            if name in call_names:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity="high",
                        file=path.relative_to(root).as_posix(),
                        line=getattr(node, "lineno", function.lineno),
                        message=message,
                        remediation=remediation,
                    )
                )
    return _dedupe_findings(findings)


def _file_access_findings(
    root: Path,
    path: Path,
    sites: list[_ToolSite],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    document: PythonAstDocument,
) -> list[Finding]:
    findings: list[Finding] = []
    for function in _tool_functions(sites, functions):
        for node in iter_ast_nodes(function):
            if not isinstance(node, ast.Call):
                continue
            name = resolve_name(node.func, document.imports)
            raw_name = _raw_call_name(node)
            if _is_dynamic_write_open(node, raw_name) or _is_path_mutation_method(node) or (
                name is not None and name.name in DESTRUCTIVE_FILE_CALL_NAMES
            ):
                findings.append(
                    Finding(
                        rule_id="agent.python_unrestricted_file_access",
                        severity="high",
                        file=path.relative_to(root).as_posix(),
                        line=getattr(node, "lineno", function.lineno),
                        message="Python agent tool appears to write or delete files.",
                        remediation=(
                            "Restrict file-write/delete access to explicit safe paths "
                            "and require approval for destructive file operations."
                        ),
                    )
                )
    return _dedupe_findings(findings)


def _api_key_findings(root: Path, path: Path, document: PythonAstDocument) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if API_KEY_RE.match(node.value):
                findings.append(
                    Finding(
                        rule_id="agent.python_api_key_hardcoded",
                        severity="high",
                        file=path.relative_to(root).as_posix(),
                        line=getattr(node, "lineno", None),
                        message="Python source appears to contain a hardcoded API key.",
                        remediation=(
                            "Move API keys to a secret manager or environment-specific "
                            "secret storage, then rotate any exposed key."
                        ),
                    )
                )
    return _dedupe_findings(findings)


def _tool_functions(
    sites: list[_ToolSite],
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    names = {site.function_name for site in sites if site.function_name is not None}
    return [function for name, function in sorted(functions.items()) if name in names]


def _is_tool_decorator_name(name: str) -> bool:
    return name.rsplit(".", 1)[-1] in TOOL_DECORATOR_BASENAMES


def _is_tool_constructor_name(name: str) -> bool:
    return name.rsplit(".", 1)[-1] in TOOL_CONSTRUCTOR_BASENAMES


def _collect_provider_tool_sites(
    document: PythonAstDocument,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[_ToolSite]:
    sites: list[_ToolSite] = []
    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Call) or not _is_create_call_with_tools(node):
            continue
        tools = _tools_keyword_value(node)
        if not isinstance(tools, ast.List):
            continue
        for item in tools.elts:
            if not isinstance(item, ast.Dict):
                continue
            function_name = _extract_tool_name_from_dict(item)
            if function_name is None or function_name not in functions:
                continue
            sites.append(
                _ToolSite(
                    function_name=function_name,
                    line=getattr(item, "lineno", getattr(node, "lineno", 0)),
                    approved=False,
                )
            )
    return sites


def _is_create_call_with_tools(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr == "create" and _tools_keyword_value(call) is not None


def _tools_keyword_value(call: ast.Call) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == "tools":
            return keyword.value
    return None


def _extract_tool_name_from_dict(dict_node: ast.Dict) -> str | None:
    values = _dict_values_by_string_key(dict_node)

    if _const_str(values.get("type")) == "function":
        function_dict = values.get("function")
        if isinstance(function_dict, ast.Dict):
            return _extract_dict_value(function_dict, "name")

    if "name" in values and "input_schema" in values:
        return _const_str(values["name"])

    return None


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


def _call_has_approval(call: ast.AST) -> bool:
    if not isinstance(call, ast.Call):
        return False
    for keyword in call.keywords:
        if keyword.arg in APPROVAL_MARKER_KEYS and _truthy_ast_value(keyword.value):
            return True
    return False


def _truthy_ast_value(value: ast.AST) -> bool:
    if isinstance(value, ast.Constant):
        return bool(value.value)
    return True


def _local_func_keyword(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg != "func":
            continue
        if isinstance(keyword.value, ast.Name):
            return keyword.value.id
    return None


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


def _is_dynamic_write_open(call: ast.Call, raw_name: str | None) -> bool:
    if raw_name != "open":
        return False
    mode: ast.AST | None = call.args[1] if len(call.args) >= 2 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
            break
    if mode is None:
        return False
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and mode.value in WRITE_MODES


def _is_path_mutation_method(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr in PATH_MUTATION_METHODS


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
