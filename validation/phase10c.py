#!/usr/bin/env python3
"""Phase 10c reviewer checks for AgentVeil Posture."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentveil_posture.report import RULE_DESCRIPTORS, SARIF_SCHEMA  # noqa: E402
from agentveil_posture.scanner import scan_path  # noqa: E402


SARIF_SCHEMA_CACHE = REPO_ROOT / "validation" / ".cache" / "sarif-2.1.0.json"
INLINE_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
REFERENCE_DEF_RE = re.compile(r"^\[([^\]]+)\]:\s+(\S+)", re.MULTILINE)
REFERENCE_USE_RE = re.compile(r"(?<!!)\[[^\]]+\]\[([^\]]*)\]")
HTML_HREF_RE = re.compile(r"<a\s+[^>]*href=[\"']([^\"']+)[\"']", re.IGNORECASE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$", re.MULTILINE)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str
    failures: list[str]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    results = [
        check_sarif_schema(REPO_ROOT),
        check_markdown_links(REPO_ROOT, check_external=args.check_external),
        check_public_terms(REPO_ROOT),
        check_rule_doc_links(REPO_ROOT),
    ]
    print("=== Phase 10c reviewer checks ===")
    for index, result in enumerate(results, start=1):
        status = "PASS" if result.passed else "FAIL"
        print(f"[{index}/4] {result.name:<32} {status} {result.detail}".rstrip())
        for failure in result.failures:
            print(f"      {failure}")
    print(f"=== Overall: {'PASS' if all(result.passed for result in results) else 'FAIL'} ===")
    return 0 if all(result.passed for result in results) else 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Phase 10c reviewer checks.")
    parser.add_argument(
        "--check-external",
        action="store_true",
        help="Check external HTTP(S) links with a 5 second timeout.",
    )
    return parser.parse_args(argv)


def check_sarif_schema(repo_root: Path) -> CheckResult:
    try:
        schema = load_sarif_schema()
        report = scan_path(repo_root / "fixtures" / "dangerous_github_project")
        validate_sarif_document(report.to_sarif(), schema)
    except Exception as exc:  # noqa: BLE001
        return CheckResult("SARIF schema validation:", False, "", [str(exc)])
    return CheckResult("SARIF schema validation:", True, "", [])


def load_sarif_schema(
    *,
    cache_path: Path = SARIF_SCHEMA_CACHE,
    fetcher: Callable[[str], bytes] | None = None,
) -> dict[str, object]:
    if cache_path.exists():
        return json.loads(cache_path.read_text(encoding="utf-8"))

    fetch = fetcher or _default_fetcher
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    payload = fetch(SARIF_SCHEMA)
    cache_path.write_bytes(payload)
    return json.loads(payload.decode("utf-8"))


def _default_fetcher(url: str) -> bytes:
    with urlopen(url, timeout=10) as response:  # noqa: S310
        return response.read()


def validate_sarif_document(document: dict[str, object], schema: dict[str, object]) -> None:
    try:
        import jsonschema
    except ImportError as exc:  # pragma: no cover - exercised by script users without deps
        raise RuntimeError("jsonschema is required; install the validation extra") from exc

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator_cls(schema).validate(document)


def check_markdown_links(repo_root: Path, *, check_external: bool = False) -> CheckResult:
    files = markdown_files(repo_root)
    failures: list[str] = []
    total = 0
    for source in files:
        links = extract_markdown_links(source)
        total += len(links)
        failures.extend(validate_links(source, links, repo_root, check_external=check_external))
    valid = total - len(failures)
    detail = f"({valid} of {total} valid)"
    return CheckResult("Markdown link check:", not failures, detail, failures)


def markdown_files(repo_root: Path) -> list[Path]:
    candidates = [
        repo_root / "README.md",
        repo_root / "PLAN.md",
        repo_root / "CHANGELOG.md",
        repo_root / "CONTRIBUTING.md",
        repo_root / "CODE_OF_CONDUCT.md",
        repo_root / "validation" / "README.md",
    ]
    candidates.extend(sorted((repo_root / "docs").glob("**/*.md")))
    return [path for path in candidates if path.exists()]


def extract_markdown_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    reference_defs = {key.lower(): url for key, url in REFERENCE_DEF_RE.findall(text)}
    links = [match.group(1) for match in INLINE_LINK_RE.finditer(text)]
    links.extend(match.group(1) for match in HTML_HREF_RE.finditer(text))
    for match in REFERENCE_USE_RE.finditer(text):
        label = match.group(1)
        if label:
            target = reference_defs.get(label.lower())
            if target is not None:
                links.append(target)
    links.extend(reference_defs.values())
    return links


def validate_links(
    source: Path,
    links: Iterable[str],
    repo_root: Path,
    *,
    check_external: bool = False,
) -> list[str]:
    failures: list[str] = []
    for link in links:
        parsed = urlparse(link)
        if parsed.scheme in {"http", "https"}:
            if check_external:
                failures.extend(_check_external_link(source, link))
            continue
        if parsed.scheme in {"mailto", "tel"}:
            continue

        target_text = unquote(parsed.path)
        anchor = parsed.fragment
        target = source if not target_text else (source.parent / target_text).resolve()
        if not _is_within(repo_root, target):
            failures.append(f"{source.relative_to(repo_root)}: outside-repo link {link}")
            continue
        if not target.exists():
            failures.append(f"{source.relative_to(repo_root)}: missing link target {link}")
            continue
        if anchor and anchor not in markdown_anchors(target):
            failures.append(f"{source.relative_to(repo_root)}: missing anchor {link}")
    return failures


def _check_external_link(source: Path, link: str) -> list[str]:
    try:
        request = Request(link, method="HEAD")
        with urlopen(request, timeout=5) as response:  # noqa: S310
            if response.status >= 400:
                return [f"{source.relative_to(REPO_ROOT)}: external link {link} returned {response.status}"]
    except Exception as exc:  # noqa: BLE001
        return [f"{source.relative_to(REPO_ROOT)}: external link {link} failed: {exc}"]
    return []


def _is_within(root: Path, path: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def markdown_anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return {github_anchor(match.group(2)) for match in HEADING_RE.finditer(text)}


def github_anchor(heading: str) -> str:
    heading = re.sub(r"`([^`]*)`", r"\1", heading)
    heading = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", heading)
    heading = heading.strip().lower()
    heading = re.sub(r"[^a-z0-9 _-]", "", heading)
    heading = re.sub(r"\s+", "-", heading)
    heading = re.sub(r"-+", "-", heading)
    return heading.strip("-")


def check_public_terms(repo_root: Path) -> CheckResult:
    failures: list[str] = []
    excluded = 0
    terms = strategy_terms()
    for path in public_surface_files(repo_root):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for term in terms:
                if term.lower() not in line.lower():
                    continue
                if is_allowed_strategy_hit(path, line):
                    excluded += 1
                    continue
                failures.append(f"{path.relative_to(repo_root)}:{line_number}: {term}")
    detail = f"({excluded} known-deferred excluded)" if excluded else "(0 hits)"
    return CheckResult("Public strategy term sweep:", not failures, detail, failures)


def strategy_terms() -> list[str]:
    return [
        "Runtime " + "Gate",
        "Proof " + "Packet",
        "Production " + "Gateway",
        "Project " + "Control",
        "Mode " + "A",
        "MCP " + "proxy",
        "deleg" + "ation",
        "runtime " + "control",
        "policy " + "enforcement",
        "action " + "enforcement",
        "AVP " + "runtime",
        "execution " + "boundary",
        "attest" + "ation",
        "rece" + "ipt",
    ]


def public_surface_files(repo_root: Path) -> list[Path]:
    files = [
        repo_root / "README.md",
        repo_root / "PLAN.md",
        repo_root / "CHANGELOG.md",
        repo_root / "CONTRIBUTING.md",
        repo_root / "CODE_OF_CONDUCT.md",
        repo_root / "action.yml",
        repo_root / "validation" / "README.md",
    ]
    files.extend(sorted((repo_root / "docs").glob("**/*.md")))
    files.extend(sorted((repo_root / ".github").glob("**/*.yml")))
    return [path for path in files if path.exists()]


def is_allowed_strategy_hit(path: Path, line: str) -> bool:
    return path.name == "PLAN.md" and (
        "Production " + "Gateway enforcement remains roadmap"
    ) in line


def check_rule_doc_links(repo_root: Path) -> CheckResult:
    failures: list[str] = []
    for rule_id, descriptor in RULE_DESCRIPTORS.items():
        help_url = str(descriptor["help"])
        parsed = urlparse(help_url)
        path = Path(parsed.path)
        try:
            docs_index = path.parts.index("docs")
        except ValueError:
            failures.append(f"{rule_id}: help URL does not point at docs: {help_url}")
            continue
        target = repo_root.joinpath(*path.parts[docs_index:])
        if not target.exists():
            failures.append(f"{rule_id}: missing docs file {target.relative_to(repo_root)}")
            continue
        if parsed.fragment and parsed.fragment not in markdown_anchors(target):
            failures.append(f"{rule_id}: missing docs anchor #{parsed.fragment}")
    detail = f"({len(RULE_DESCRIPTORS) - len(failures)} of {len(RULE_DESCRIPTORS)} valid)"
    return CheckResult("Per-rule docs links:", not failures, detail, failures)


if __name__ == "__main__":
    raise SystemExit(main())
