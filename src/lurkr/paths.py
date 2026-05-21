"""Shared path traversal helpers for Lurkr scans."""

from __future__ import annotations


DEFAULT_EXCLUDED_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "venv",
    }
)


def prune_excluded_dirnames(dirnames: list[str]) -> None:
    """Remove dependency, VCS, cache, and build directories from os.walk traversal."""
    dirnames[:] = [
        dirname for dirname in dirnames if dirname not in DEFAULT_EXCLUDED_DIR_NAMES
    ]
