"""Detect MCP server endpoints that point to external hosts."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from lurkr.manifest import McpServer, extract_mcp_servers
from lurkr.report import Finding
from lurkr.rules.manifest import load_manifest


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}
LOCAL_SUFFIXES = (".local",)
LOCAL_TRANSPORTS = {"stdio", "pipe"}


def scan_unverified_mcp_endpoint(root: Path, path: Path) -> list[Finding]:
    document = load_manifest(path)
    if document is None or not isinstance(document.data, dict):
        return []

    findings: list[Finding] = []
    for server in extract_mcp_servers(document.data):
        parsed = _external_endpoint(server)
        if parsed is None:
            continue
        host, url = parsed
        findings.append(
            Finding(
                rule_id="agent.unverified_mcp_endpoint",
                severity="high",
                file=path.relative_to(root).as_posix(),
                line=_line_for_url(document.lines, url),
                message=(
                    f"MCP server endpoint '{host}' points to external host — "
                    "review the server's trust posture before deployment."
                ),
                remediation=(
                    "Verify the MCP server identity, transport security, and tool "
                    "surface. If using a self-hosted server, document the trust "
                    "justification. Consider pinning to a known-good version or "
                    "sandboxing the connection."
                ),
            )
        )
    return _dedupe_findings(findings)


def _external_endpoint(server: McpServer) -> tuple[str, str] | None:
    if server.transport.lower() in LOCAL_TRANSPORTS:
        return None
    if server.url is None:
        return None
    parsed = urlparse(server.url)
    if parsed.scheme.lower() in LOCAL_TRANSPORTS:
        return None
    if parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
        return None
    host = parsed.hostname
    if host is None or _is_allowlisted_host(host):
        return None
    return host, server.url


def _is_allowlisted_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized in LOCAL_HOSTS or normalized.endswith(LOCAL_SUFFIXES):
        return True
    try:
        ip = ip_address(normalized)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _line_for_url(lines: list[str], url: str) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if url in line:
            return line_number
    return 1


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
