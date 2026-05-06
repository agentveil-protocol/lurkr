from __future__ import annotations

import hashlib
import http.client
import os
from pathlib import Path
import socket
import subprocess
import urllib.request

from agentveil_posture.scanner import scan_path


def test_scan_does_not_call_network_or_subprocess(monkeypatch, tmp_path):
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nopaque\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    def blocked(*args, **kwargs):
        raise AssertionError("network or subprocess call attempted")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(http.client, "HTTPConnection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(os, "system", blocked)

    report = scan_path(tmp_path)

    assert len(report.findings) == 1


def test_scan_does_not_mutate_scanned_files(tmp_path):
    scanned_file = tmp_path / "id_rsa"
    scanned_file.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nopaque\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    before = _sha256_tree(tmp_path)

    scan_path(tmp_path)

    assert _sha256_tree(tmp_path) == before


def test_scanner_source_does_not_use_unsafe_yaml_load():
    src_root = Path(__file__).resolve().parents[1] / "src" / "agentveil_posture"
    source = "\n".join(path.read_text(encoding="utf-8") for path in src_root.rglob("*.py"))

    assert "yaml.load(" not in source


def _sha256_tree(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes
