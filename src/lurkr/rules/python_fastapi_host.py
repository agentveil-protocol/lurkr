"""Detect FastAPI/Starlette middleware that uses request.url.path for security decisions without same-file Host header validation evidence."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from lurkr.python_ast import (
    PythonAstDocument,
    iter_ast_nodes,
    load_python_ast_document,
    resolve_name,
)
from lurkr.report import Finding


RULE_ID = "agent.python_fastapi_path_auth_no_host_validation"

FASTAPI_STARLETTE_PREFIXES = ("fastapi.", "starlette.")
FASTAPI_STARLETTE_BARE = {"fastapi", "starlette"}

BASE_HTTP_MIDDLEWARE_SUFFIX = ".BaseHTTPMiddleware"
TRUSTED_HOST_MIDDLEWARE_SUFFIX = ".TrustedHostMiddleware"
TRUSTED_HOST_NAME = "TrustedHostMiddleware"
MIDDLEWARE_DECORATOR_ATTR = "middleware"

MESSAGE = (
    "FastAPI/Starlette middleware reads 'request.url.path' for path-based security "
    "decisions, but this file shows no TrustedHostMiddleware configuration. On "
    "Starlette <= 1.0.0 (GHSA-86qp-5c8j-p5mr / CVE-2026-48710) a malformed 'Host' "
    "header can poison 'request.url.path' and bypass the check."
)
REMEDIATION = (
    "Add 'TrustedHostMiddleware' with an explicit 'allowed_hosts' allowlist before "
    "the path-based middleware in the FastAPI/Starlette app, or read 'scope[\"path\"]' "
    "directly instead of 'request.url.path' for security decisions. Also upgrade "
    "Starlette to 1.0.1 or later, which validates the Host header before "
    "reconstructing request.url."
)


def scan_python_fastapi_path_auth_no_host_validation(root: Path, path: Path) -> list[Finding]:
    """Emit findings for FastAPI/Starlette middleware that reads request.url.path with no same-file Host header validation."""
    document = load_python_ast_document(path)
    if document is None:
        return []

    if not _file_imports_fastapi_or_starlette(document):
        return []

    if _has_trusted_host_evidence(document):
        return []

    findings: list[Finding] = []
    relative_path = path.relative_to(root).as_posix()
    for body in _iter_middleware_bodies(document):
        line = _first_url_path_read_line(body)
        if line is None:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity="high",
                file=relative_path,
                line=line,
                message=MESSAGE,
                remediation=REMEDIATION,
            )
        )
    return _dedupe_findings(findings)


def _file_imports_fastapi_or_starlette(document: PythonAstDocument) -> bool:
    for resolved in document.imports.values():
        if resolved in FASTAPI_STARLETTE_BARE:
            return True
        if resolved.startswith(FASTAPI_STARLETTE_PREFIXES):
            return True
    return False


def _has_trusted_host_evidence(document: PythonAstDocument) -> bool:
    for resolved in document.imports.values():
        if _resolved_name_matches_trusted_host(resolved):
            return True

    for node in iter_ast_nodes(document.tree):
        if isinstance(node, ast.Attribute):
            resolved = resolve_name(node, document.imports)
            if resolved is not None and _resolved_name_matches_trusted_host(resolved.name):
                return True
    return False


def _iter_middleware_bodies(document: PythonAstDocument) -> Iterator[list[ast.stmt]]:
    for node in iter_ast_nodes(document.tree):
        if isinstance(node, ast.ClassDef) and _class_is_base_http_middleware(node, document):
            yield list(node.body)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _function_has_http_middleware_decorator(node):
            yield list(node.body)


def _class_is_base_http_middleware(node: ast.ClassDef, document: PythonAstDocument) -> bool:
    for base in node.bases:
        resolved = resolve_name(base, document.imports)
        if resolved is None:
            continue
        if _resolved_name_matches_base_http_middleware(resolved.name):
            return True
    return False


def _function_has_http_middleware_decorator(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not (
            isinstance(target, ast.Attribute)
            and target.attr == MIDDLEWARE_DECORATOR_ATTR
        ):
            continue
        if not isinstance(decorator, ast.Call):
            continue
        if not decorator.args:
            continue
        first_arg = decorator.args[0]
        if isinstance(first_arg, ast.Constant) and first_arg.value == "http":
            return True
    return False


def _first_url_path_read_line(body: list[ast.stmt]) -> int | None:
    earliest: int | None = None
    for stmt in body:
        for node in iter_ast_nodes(stmt):
            if not _is_url_path_attribute_chain(node):
                continue
            lineno = getattr(node, "lineno", None)
            if lineno is None:
                continue
            if earliest is None or lineno < earliest:
                earliest = lineno
    return earliest


def _is_url_path_attribute_chain(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "url"
    )


def _resolved_name_matches_base_http_middleware(resolved: str) -> bool:
    if not resolved.endswith(BASE_HTTP_MIDDLEWARE_SUFFIX):
        return False
    return resolved.startswith(FASTAPI_STARLETTE_PREFIXES)


def _resolved_name_matches_trusted_host(resolved: str) -> bool:
    if not resolved.endswith(TRUSTED_HOST_MIDDLEWARE_SUFFIX):
        return False
    return resolved.startswith(FASTAPI_STARLETTE_PREFIXES)


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
