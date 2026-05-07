from __future__ import annotations

from pathlib import Path

from agentveil_posture.scanner import scan_path
from validation import phase10c


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_phase10c_link_checker_catches_broken_relative_link(tmp_path):
    (tmp_path / "README.md").write_text("[missing](missing.md)\n", encoding="utf-8")

    result = phase10c.check_markdown_links(tmp_path)

    assert not result.passed
    assert "missing.md" in result.failures[0]


def test_phase10c_link_checker_uses_github_heading_slugs(tmp_path):
    (tmp_path / "README.md").write_text(
        "[scope](#detection-scope-v02)\n\n## Detection Scope (v0.2)\n",
        encoding="utf-8",
    )

    result = phase10c.check_markdown_links(tmp_path)

    assert result.passed


def test_phase10c_public_term_scanner_catches_forbidden_fixture(tmp_path):
    forbidden = "Runtime " + "Gate"
    (tmp_path / "README.md").write_text(f"{forbidden}\n", encoding="utf-8")

    result = phase10c.check_public_terms(tmp_path)

    assert not result.passed
    assert forbidden in result.failures[0]


def test_phase10c_rule_doc_check_catches_missing_anchor(tmp_path, monkeypatch):
    docs = tmp_path / "docs" / "rules"
    docs.mkdir(parents=True)
    (docs / "example.rule.md").write_text("# example.rule\n\n## Review\n", encoding="utf-8")
    monkeypatch.setattr(
        phase10c,
        "RULE_DESCRIPTORS",
        {
            "example.rule": {
                "help": "https://github.com/example/project/blob/main/docs/rules/example.rule.md#missing"
            }
        },
    )

    result = phase10c.check_rule_doc_links(tmp_path)

    assert not result.passed
    assert "missing docs anchor" in result.failures[0]


def test_phase10c_sarif_validator_accepts_scanner_output():
    report = scan_path(FIXTURES / "dangerous_github_project")
    schema = {
        "type": "object",
        "required": ["version", "runs"],
        "properties": {
            "version": {"const": "2.1.0"},
            "runs": {"type": "array", "minItems": 1},
        },
    }

    phase10c.validate_sarif_document(report.to_sarif(), schema)
