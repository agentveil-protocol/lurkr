"""Detect credentials flowing into LLM completion context."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re

from lurkr.python_ast import PythonAstDocument, iter_ast_nodes, load_python_ast_document
from lurkr.report import Finding
from lurkr.rules.llm_calls import collect_chat_model_vars, is_llm_completion_call
from lurkr.rules.python_agent import API_KEY_RE


CREDENTIAL_NAME_RE = re.compile(r"(api[_-]?key|token|secret|password|bearer|auth)", re.I)
CREDENTIAL_ENV_RE = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|API_KEY|BEARER|AUTH)", re.I)


@dataclass(frozen=True)
class _CredentialUse:
    name: str
    line: int


def scan_credential_to_llm_context(root: Path, path: Path) -> list[Finding]:
    document = load_python_ast_document(path)
    if document is None:
        return []

    credentials = _collect_credential_variables(document)
    if not credentials:
        return []

    findings: list[Finding] = []
    chat_model_vars = collect_chat_model_vars(document)
    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Call):
            continue
        if not is_llm_completion_call(node, document, chat_model_vars):
            continue
        for use in _credential_uses_in_call(node, credentials):
            findings.append(
                Finding(
                    rule_id="agent.credential_to_llm_context",
                    severity="high",
                    file=path.relative_to(root).as_posix(),
                    line=getattr(node, "lineno", use.line),
                    message=(
                        f"Credential variable '{use.name}' passed to LLM completion "
                        "call — risks exposure via conversation history."
                    ),
                    remediation=(
                        "Pass credential only through provider client headers/config. "
                        "Do not include credentials in chat messages, prompt templates, "
                        "or tool function arguments to LLM completions."
                    ),
                )
            )
    return _dedupe_findings(findings)


def _collect_credential_variables(document: PythonAstDocument) -> dict[str, str]:
    credentials: dict[str, str] = {}
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
                if CREDENTIAL_NAME_RE.search(arg.arg):
                    credentials[arg.arg] = arg.arg

    for node in iter_ast_nodes(document.tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and CREDENTIAL_NAME_RE.search(target.id):
                credentials[target.id] = target.id
            elif isinstance(target, ast.Name) and _is_credential_source(node.value):
                credentials[target.id] = target.id

    changed = True
    while changed:
        changed = False
        for node in iter_ast_nodes(document.tree):
            if not isinstance(node, ast.Assign):
                continue
            source_names = _credential_names_in_node(node.value, credentials)
            if not source_names:
                continue
            source = sorted(source_names)[0]
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id not in credentials:
                    credentials[target.id] = source
                    changed = True
    return credentials


def _is_credential_source(node: ast.AST) -> bool:
    if _is_env_credential_lookup(node):
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return API_KEY_RE.match(node.value) is not None
    return False


def _is_env_credential_lookup(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        raw = _raw_dotted_name(node.func)
        if raw in {"os.getenv", "os.environ.get"}:
            env_name = _first_string_arg(node)
            return env_name is not None and CREDENTIAL_ENV_RE.search(env_name) is not None
    if isinstance(node, ast.Subscript) and _raw_dotted_name(node.value) == "os.environ":
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return CREDENTIAL_ENV_RE.search(key.value) is not None
    return False


def _credential_uses_in_call(
    call: ast.Call,
    credentials: dict[str, str],
) -> list[_CredentialUse]:
    uses: list[_CredentialUse] = []
    for child in list(call.args) + [keyword.value for keyword in call.keywords]:
        for name in sorted(_credential_names_in_node(child, credentials)):
            uses.append(_CredentialUse(name=name, line=getattr(child, "lineno", getattr(call, "lineno", 0))))
    return _dedupe_uses(uses)


def _credential_names_in_node(node: ast.AST, credentials: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for child in iter_ast_nodes(node):
        if isinstance(child, ast.Name) and child.id in credentials:
            names.add(credentials[child.id])
    return names


def _first_string_arg(call: ast.Call) -> str | None:
    if not call.args:
        return None
    arg = call.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


def _raw_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _raw_dotted_name(node.value)
        if value is None:
            return None
        return f"{value}.{node.attr}"
    return None


def _dedupe_uses(uses: list[_CredentialUse]) -> list[_CredentialUse]:
    seen: set[str] = set()
    deduped: list[_CredentialUse] = []
    for use in uses:
        if use.name in seen:
            continue
        seen.add(use.name)
        deduped.append(use)
    return deduped


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
