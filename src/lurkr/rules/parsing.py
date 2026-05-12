"""Bounded parsers for untrusted scanned configuration files."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import yaml


MAX_TEXT_BYTES = 1_000_000
MAX_YAML_ALIAS_TOKENS = 25


@dataclass(frozen=True)
class ParsedDocument:
    data: Any
    text: str
    lines: list[str]


def load_yaml_document(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> ParsedDocument | None:
    text = read_bounded_text(path, max_bytes=max_bytes)
    if text is None or has_excessive_yaml_aliases(text):
        return None
    try:
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        return None
    return ParsedDocument(data=data, text=text, lines=text.splitlines())


def load_json_document(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> ParsedDocument | None:
    text = read_bounded_text(path, max_bytes=max_bytes)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    return ParsedDocument(data=data, text=text, lines=text.splitlines())


def read_bounded_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None


def has_excessive_yaml_aliases(text: str) -> bool:
    aliases = 0
    try:
        for token in yaml.scan(text):
            if isinstance(token, yaml.AliasToken):
                aliases += 1
                if aliases > MAX_YAML_ALIAS_TOKENS:
                    return True
    except yaml.YAMLError:
        return True
    return False


def first_matching_line(lines: list[str], pattern) -> int | None:
    for line_number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return line_number
    return None
