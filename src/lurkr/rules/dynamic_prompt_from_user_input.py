"""Detect prompt templates built by direct user-input interpolation."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re

from lurkr.python_ast import PythonAstDocument, iter_ast_nodes, load_python_ast_document
from lurkr.report import Finding
from lurkr.rules.llm_calls import (
    call_target_name,
    collect_chat_model_vars,
    is_llm_completion_call,
)


PROMPT_NAME_RE = re.compile(r"(prompt|prompt_template|system_prompt|user_message|instruction|template|query)", re.I)
PROMPT_TEMPLATE_CALLS = {
    "ChatPromptTemplate.from_template",
    "PromptTemplate",
    "PromptTemplate.from_template",
    "Template",
}


@dataclass(frozen=True)
class _DynamicPrompt:
    param_name: str
    line: int


def scan_dynamic_prompt_from_user_input(root: Path, path: Path) -> list[Finding]:
    document = load_python_ast_document(path)
    if document is None:
        return []

    param_sources = _collect_parameter_sources(document)
    if not param_sources:
        return []

    findings: list[Finding] = []
    chat_model_vars = collect_chat_model_vars(document)
    for node in iter_ast_nodes(document.tree):
        dynamic: _DynamicPrompt | None = None
        if isinstance(node, ast.Assign):
            dynamic = _dynamic_prompt_assignment(node, param_sources)
        elif isinstance(node, ast.Call):
            dynamic = _dynamic_prompt_call(node, document, param_sources, chat_model_vars)
        if dynamic is None:
            continue
        findings.append(
            Finding(
                rule_id="agent.dynamic_prompt_from_user_input",
                severity="high",
                file=path.relative_to(root).as_posix(),
                line=dynamic.line,
                message=(
                    f"Prompt template constructed from function parameter "
                    f"'{dynamic.param_name}' via direct interpolation — prompt "
                    "injection setup."
                ),
                remediation=(
                    "Use a prompt template with explicit placeholders (e.g., "
                    "ChatPromptTemplate.from_template) and pass user input via "
                    "the template's input dict, not via f-string or string "
                    "concatenation."
                ),
            )
        )
    return _dedupe_findings(findings)


def _collect_parameter_sources(document: PythonAstDocument) -> dict[str, str]:
    sources: dict[str, str] = {}
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
                sources[arg.arg] = arg.arg

    changed = True
    while changed:
        changed = False
        for node in iter_ast_nodes(document.tree):
            if not isinstance(node, ast.Assign):
                continue
            source = _first_source_name(node.value, sources)
            if source is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in sources:
                    sources[target.id] = source
                    changed = True
    return sources


def _dynamic_prompt_assignment(
    node: ast.Assign,
    param_sources: dict[str, str],
) -> _DynamicPrompt | None:
    if not any(isinstance(target, ast.Name) and PROMPT_NAME_RE.search(target.id) for target in node.targets):
        return None
    return _dynamic_interpolation(node.value, param_sources, getattr(node, "lineno", 0))


def _dynamic_prompt_call(
    node: ast.Call,
    document: PythonAstDocument,
    param_sources: dict[str, str],
    chat_model_vars: set[str],
) -> _DynamicPrompt | None:
    call_name = call_target_name(node, document)
    if call_name is not None and _is_prompt_template_call(call_name):
        for value in list(node.args) + [
            keyword.value for keyword in node.keywords if keyword.arg == "template"
        ]:
            dynamic = _dynamic_interpolation(value, param_sources, getattr(value, "lineno", getattr(node, "lineno", 0)))
            if dynamic is not None:
                return dynamic

    if is_llm_completion_call(node, document, chat_model_vars):
        for keyword in node.keywords:
            if keyword.arg != "prompt":
                continue
            return _dynamic_interpolation(
                keyword.value,
                param_sources,
                getattr(keyword.value, "lineno", getattr(node, "lineno", 0)),
            )
    return None


def _is_prompt_template_call(call_name: str) -> bool:
    parts = call_name.split(".")
    if parts[-1] == "Template":
        return True
    return ".".join(parts[-2:]) in {"PromptTemplate.from_template", "ChatPromptTemplate.from_template"} or (
        parts[-1] == "PromptTemplate"
    )


def _dynamic_interpolation(
    node: ast.AST,
    param_sources: dict[str, str],
    line: int,
) -> _DynamicPrompt | None:
    source = _fstring_source(node, param_sources)
    if source is not None:
        return _DynamicPrompt(param_name=source, line=line)
    source = _format_call_source(node, param_sources)
    if source is not None:
        return _DynamicPrompt(param_name=source, line=line)
    source = _binop_source(node, param_sources)
    if source is not None:
        return _DynamicPrompt(param_name=source, line=line)
    source = _percent_format_source(node, param_sources)
    if source is not None:
        return _DynamicPrompt(param_name=source, line=line)
    return None


def _fstring_source(node: ast.AST, param_sources: dict[str, str]) -> str | None:
    if not isinstance(node, ast.JoinedStr):
        return None
    return _first_source_name(node, param_sources)


def _format_call_source(node: ast.AST, param_sources: dict[str, str]) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "format":
        return None
    return _first_source_name_list(list(node.args) + [keyword.value for keyword in node.keywords], param_sources)


def _binop_source(node: ast.AST, param_sources: dict[str, str]) -> str | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    if not _contains_string_literal(node):
        return None
    return _first_source_name(node, param_sources)


def _percent_format_source(node: ast.AST, param_sources: dict[str, str]) -> str | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mod):
        return None
    if not isinstance(node.left, ast.Constant) or not isinstance(node.left.value, str):
        return None
    return _first_source_name(node.right, param_sources)


def _contains_string_literal(node: ast.AST) -> bool:
    return any(isinstance(child, ast.Constant) and isinstance(child.value, str) for child in iter_ast_nodes(node))


def _first_source_name(node: ast.AST, param_sources: dict[str, str]) -> str | None:
    for child in iter_ast_nodes(node):
        if isinstance(child, ast.Name) and child.id in param_sources:
            return param_sources[child.id]
    return None


def _first_source_name_list(nodes: list[ast.AST], param_sources: dict[str, str]) -> str | None:
    for node in nodes:
        source = _first_source_name(node, param_sources)
        if source is not None:
            return source
    return None


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int | None, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
