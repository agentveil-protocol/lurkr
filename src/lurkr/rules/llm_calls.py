"""Shared static helpers for recognized LLM completion call sites."""

from __future__ import annotations

import ast

from lurkr.python_ast import PythonAstDocument, iter_ast_nodes, resolve_name


CHAT_MODEL_BASENAMES = {
    "ChatAnthropic",
    "ChatGoogleGenerativeAI",
    "ChatOpenAI",
    "GenerativeModel",
}
LLM_CREATE_SUFFIXES = (
    ".chat.completions.create",
    ".messages.create",
)
LLM_METHOD_BASENAMES = {
    "create",
    "generate_content",
    "invoke",
}


def collect_chat_model_vars(document: PythonAstDocument) -> set[str]:
    names: set[str] = set()
    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        call_name = call_target_name(node.value, document)
        if call_name is None or call_name.rsplit(".", 1)[-1] not in CHAT_MODEL_BASENAMES:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def is_llm_completion_call(
    call: ast.Call,
    document: PythonAstDocument,
    chat_model_vars: set[str] | None = None,
) -> bool:
    name = call_target_name(call, document)
    raw_name = raw_call_name(call)
    candidates = {candidate for candidate in (name, raw_name) if candidate is not None}
    if any(candidate.endswith(LLM_CREATE_SUFFIXES) for candidate in candidates):
        return True
    if any(candidate.rsplit(".", 1)[-1] == "generate_content" for candidate in candidates):
        return True
    if raw_name is not None and raw_name.endswith(".invoke"):
        receiver = raw_name.rsplit(".", 1)[0]
        first = receiver.split(".", 1)[0]
        if chat_model_vars is not None and first in chat_model_vars:
            return True
        if _looks_like_chat_model_name(first):
            return True
    if isinstance(call.func, ast.Attribute) and call.func.attr == "invoke":
        if isinstance(call.func.value, ast.Call):
            value_name = call_target_name(call.func.value, document)
            return value_name is not None and value_name.rsplit(".", 1)[-1] in CHAT_MODEL_BASENAMES
    return False


def call_target_name(call: ast.Call, document: PythonAstDocument) -> str | None:
    name = resolve_name(call.func, document.imports)
    if name is not None:
        return name.name
    return raw_call_name(call)


def raw_call_name(call: ast.Call) -> str | None:
    return raw_dotted_name(call.func)


def raw_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = raw_dotted_name(node.value)
        if value is None:
            return None
        return f"{value}.{node.attr}"
    if isinstance(node, ast.Call):
        return raw_call_name(node)
    return None


def _looks_like_chat_model_name(name: str) -> bool:
    lowered = name.lower()
    return "chat" in lowered or "llm" in lowered or lowered in {"model", "llm"}
