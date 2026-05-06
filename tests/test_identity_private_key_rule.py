from __future__ import annotations

import json

from agentveil_posture.scanner import scan_path


def test_unencrypted_private_key_fires_with_redacted_report(tmp_path):
    key = tmp_path / "id_rsa"
    key.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nSECRET_KEY_BYTES\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "identity.private_key_unencrypted"
    assert finding.severity == "high"
    assert finding.file == "id_rsa"
    assert finding.line == 1

    report_json = report.to_json()
    assert "SECRET_KEY_BYTES" not in report_json
    assert "BEGIN RSA PRIVATE KEY" not in report_json
    assert json.loads(report_json)["summary"]["total"] == 1


def test_encrypted_pkcs8_private_key_does_not_fire(tmp_path):
    key = tmp_path / "encrypted.pem"
    key.write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_legacy_encrypted_private_key_does_not_fire(tmp_path):
    key = tmp_path / "legacy.pem"
    key.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0000000000000000\n"
        "opaque\n"
        "-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings == []


def test_nested_finding_file_is_repo_relative_posix(tmp_path):
    nested = tmp_path / "keys" / "deploy.pem"
    nested.parent.mkdir()
    nested.write_text(
        "-----BEGIN PRIVATE KEY-----\nopaque\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = scan_path(tmp_path)

    assert report.findings[0].file == "keys/deploy.pem"


def test_symlink_is_skipped(tmp_path):
    target = tmp_path / "target.pem"
    target.write_text(
        "-----BEGIN PRIVATE KEY-----\nopaque\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    link = tmp_path / "linked.pem"
    link.symlink_to(target)

    target.unlink()
    report = scan_path(tmp_path)

    assert report.findings == []


def test_symlink_leaf_to_outside_pem_is_skipped(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_key = outside / "external.pem"
    outside_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nopaque\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    root = tmp_path / "repo"
    root.mkdir()
    (root / "external.pem").symlink_to(outside_key)

    report = scan_path(root)

    assert report.findings == []


def test_symlink_directory_to_outside_pem_is_not_traversed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_key = outside / "external.pem"
    outside_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nopaque\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    root = tmp_path / "repo"
    root.mkdir()
    (root / "external").symlink_to(outside, target_is_directory=True)

    report = scan_path(root)

    assert report.findings == []
