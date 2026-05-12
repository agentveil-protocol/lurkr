"""Declared capability extraction for agent manifest files."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import urlparse

from lurkr.rules.manifest import is_agent_manifest, load_manifest


@dataclass(frozen=True)
class DeclaredCapability:
    """Single declared tool/capability entry from a manifest file."""

    name: str
    raw_name: str
    source_file: Path
    source_line: int


@dataclass(frozen=True)
class McpServer:
    """Single MCP server entry declared in an MCP-style manifest."""

    name: str
    url: str | None
    transport: str
    line: int | None


def discover_manifests(scan_root: Path) -> Iterable[Path]:
    """Yield manifest file paths under scan_root per current Lurkr discovery scope."""
    root = scan_root.resolve()
    for dirpath, _dirnames, filenames in os.walk(str(root), followlinks=False):
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if is_agent_manifest(root, path):
                yield path


def parse_manifest(manifest_path: Path) -> list[DeclaredCapability]:
    """Parse declared capabilities from a manifest, returning [] on malformed input."""
    document = load_manifest(manifest_path)
    if document is None or not isinstance(document.data, dict):
        return []

    parser = _parser_for_path(manifest_path)
    if parser is None:
        return []

    try:
        raw_names = parser(document.data)
    except (TypeError, ValueError, RecursionError):
        return []

    capabilities: list[DeclaredCapability] = []
    seen: set[str] = set()
    for raw_name in raw_names:
        normalized = normalize_capability_name(raw_name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        capabilities.append(
            DeclaredCapability(
                name=normalized,
                raw_name=raw_name,
                source_file=manifest_path,
                source_line=_line_for_raw_name(document.lines, raw_name),
            )
        )
    return capabilities


def collect_declared(scan_root: Path) -> set[str]:
    """Collect normalized declared capability names across all discovered manifests."""
    declared: set[str] = set()
    for manifest_path in discover_manifests(scan_root):
        declared.update(capability.name for capability in parse_manifest(manifest_path))
    return declared


def extract_mcp_servers(data: dict[str, Any]) -> list[McpServer]:
    """Extract MCP server entries from an MCP-style manifest payload."""
    servers: list[McpServer] = []
    for field_name in ("mcpServers", "mcp_servers", "servers"):
        value = data.get(field_name)
        if isinstance(value, dict):
            servers.extend(_servers_from_mapping(value))
        elif isinstance(value, list):
            servers.extend(_servers_from_list(value))
    return servers


def normalize_capability_name(name: str) -> str:
    """Normalize framework-specific tool identifiers to snake_case for comparison."""
    value = name.strip()
    value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_").lower()


def _parse_mcp(data: dict[str, Any]) -> list[str]:
    return _names_from_tools_value(data.get("tools"))


def _servers_from_mapping(value: dict[str, Any]) -> list[McpServer]:
    servers: list[McpServer] = []
    for name, config in value.items():
        if isinstance(config, dict):
            servers.append(_server_from_config(str(name), config))
    return servers


def _servers_from_list(value: list[Any]) -> list[McpServer]:
    servers: list[McpServer] = []
    for index, config in enumerate(value, start=1):
        if not isinstance(config, dict):
            continue
        raw_name = config.get("name")
        name = raw_name if isinstance(raw_name, str) and raw_name.strip() else f"server_{index}"
        servers.append(_server_from_config(name, config))
    return servers


def _server_from_config(name: str, config: dict[str, Any]) -> McpServer:
    url = _server_url(config)
    return McpServer(
        name=name,
        url=url,
        transport=_server_transport(config, url),
        line=None,
    )


def _server_url(config: dict[str, Any]) -> str | None:
    for key in ("url", "serverUrl", "endpoint", "httpUrl", "wsUrl"):
        value = config.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _server_transport(config: dict[str, Any], url: str | None) -> str:
    transport = config.get("transport")
    if isinstance(transport, str) and transport.strip():
        return transport.strip().lower()
    if url is not None:
        scheme = urlparse(url).scheme.strip().lower()
        if scheme:
            return scheme
    if "command" in config or "args" in config:
        return "stdio"
    return "unknown"


def _parse_crewai(data: dict[str, Any]) -> list[str]:
    return _names_from_nested_tools(data)


def _parse_autogen(data: dict[str, Any]) -> list[str]:
    return _names_from_nested_tools(data)


def _parse_langchain(data: dict[str, Any]) -> list[str]:
    return _names_from_nested_tools(data)


def _parser_for_path(path: Path):
    from lurkr.rules.manifest import CREWAI_PATH_REGEX, EXACT_MANIFEST_PATHS

    relative = path.as_posix()
    name = path.name.lower()
    if name in EXACT_MANIFEST_PATHS or relative.endswith("/.cursor/mcp.json"):
        return _parse_mcp
    if CREWAI_PATH_REGEX.search(relative) or name.startswith("crew"):
        return _parse_crewai
    if name.startswith("autogen"):
        return _parse_autogen
    if name.startswith("langchain"):
        return _parse_langchain
    return None


def _names_from_nested_tools(value: Any, depth: int = 0) -> list[str]:
    if depth > 100:
        return []
    names: list[str] = []
    if isinstance(value, dict):
        if "tools" in value:
            names.extend(_names_from_tools_value(value["tools"]))
        if value.get("component_type") == "tool":
            names.extend(_name_from_tool_object(value))
        for child in value.values():
            names.extend(_names_from_nested_tools(child, depth + 1))
    elif isinstance(value, list):
        for item in value:
            names.extend(_names_from_nested_tools(item, depth + 1))
    return names


def _names_from_tools_value(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        names: list[str] = []
        for item in value:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                names.extend(_name_from_tool_object(item))
        return names
    if isinstance(value, dict):
        return _name_from_tool_object(value)
    return []


def _name_from_tool_object(value: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("name", "tool", "tool_name"):
        raw_name = value.get(key)
        if isinstance(raw_name, str):
            names.append(raw_name)
    function = value.get("function")
    if isinstance(function, dict):
        raw_name = function.get("name")
        if isinstance(raw_name, str):
            names.append(raw_name)
    config = value.get("config")
    if isinstance(config, dict):
        raw_name = config.get("name")
        if isinstance(raw_name, str):
            names.append(raw_name)
    return names


def _line_for_raw_name(lines: list[str], raw_name: str) -> int:
    for line_number, line in enumerate(lines, start=1):
        if raw_name in line:
            return line_number
    return 1
