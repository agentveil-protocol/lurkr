#!/usr/bin/env python3
"""Run the Lurkr empirical benchmark against a pinned corpus."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = REPO_ROOT / "benchmark" / "corpus.yaml"
DEFAULT_OUTPUT = REPO_ROOT / "benchmark" / "results.json"
DEFAULT_CLONE_ROOT = Path("/tmp/lurkr-benchmark-clones")
DEFAULT_REPORT_ROOT = Path("/tmp/lurkr-benchmark-reports")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    corpus = _load_corpus(args.corpus)
    clone_root = Path(corpus.get("clone_root") or DEFAULT_CLONE_ROOT)
    report_root = Path(corpus.get("report_root") or DEFAULT_REPORT_ROOT)
    clone_root.mkdir(parents=True, exist_ok=True)
    report_root.mkdir(parents=True, exist_ok=True)

    gitleaks = _gitleaks_info()
    public_results = [
        _run_public_entry(entry, clone_root=clone_root, report_root=report_root, gitleaks=gitleaks)
        for entry in corpus.get("public_references", [])
    ]
    synthetic_results = [
        _run_synthetic_entry(entry, report_root=report_root)
        for entry in corpus.get("synthetic", [])
    ]
    result = {
        "schema_version": 1,
        "corpus_snapshot_date": corpus.get("snapshot_date"),
        "clone_root": str(clone_root),
        "report_root": str(report_root),
        "environment": {
            "gitleaks_available": gitleaks["available"],
            "gitleaks_version": gitleaks.get("version"),
        },
        "public_references": public_results,
        "synthetic": synthetic_results,
        "aggregate": {
            "public_references": _aggregate_public(public_results),
            "synthetic": _aggregate_synthetic(synthetic_results),
            "baseline": _aggregate_baseline(public_results, gitleaks),
        },
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args(argv)


def _load_corpus(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_public_entry(
    entry: dict[str, Any],
    *,
    clone_root: Path,
    report_root: Path,
    gitleaks: dict[str, Any],
) -> dict[str, Any]:
    clone_path = _ensure_checkout(entry, clone_root)
    report_path = clone_path / "lurkr-report.json"
    scan_result = _scan_path(clone_path, report_path)
    gitleaks_result = _run_gitleaks(entry, clone_path, report_root, gitleaks)
    findings = _finding_rows(scan_result)
    return {
        "id": entry["id"],
        "tier": "public_reference",
        "repo": entry["repo"],
        "commit_sha": entry["commit_sha"],
        "category": entry["category"],
        "license": entry["license"],
        "stars_at_curation": entry["stars_at_curation"],
        "description": entry["description"],
        "scan_path": ".",
        "finding_count": len(findings),
        "rule_counts": _rule_counts(findings),
        "findings": findings,
        "gitleaks": gitleaks_result,
    }


def _run_synthetic_entry(entry: dict[str, Any], *, report_root: Path) -> dict[str, Any]:
    scan_path = REPO_ROOT / entry["path"]
    report_path = report_root / f"{entry['id']}-lurkr-report.json"
    scan_result = _scan_path(scan_path, report_path)
    findings = _finding_rows(scan_result)
    expected = {str(rule): int(count) for rule, count in (entry.get("expected_findings") or {}).items()}
    observed = _rule_counts(findings)
    return {
        "id": entry["id"],
        "tier": "synthetic",
        "kind": entry["kind"],
        "path": entry["path"],
        "description": entry["description"],
        "expected_findings": expected,
        "finding_count": len(findings),
        "rule_counts": observed,
        "findings": findings,
        "comparison": _compare_expected(expected, observed),
    }


def _ensure_checkout(entry: dict[str, Any], clone_root: Path) -> Path:
    repo = entry["repo"]
    commit_sha = entry["commit_sha"]
    clone_path = clone_root / repo.replace("/", "__")
    repo_url = f"https://github.com/{repo}.git"
    if not (clone_path / ".git").exists():
        clone_path.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", "--quiet"], cwd=clone_path, env=_git_env())
        _run(["git", "remote", "add", "origin", repo_url], cwd=clone_path, env=_git_env())
    else:
        _run(["git", "remote", "set-url", "origin", repo_url], cwd=clone_path, env=_git_env())

    current = _run(["git", "rev-parse", "HEAD"], cwd=clone_path, check=False, env=_git_env())
    if current.returncode == 0 and current.stdout.strip() == commit_sha:
        return clone_path

    _run(["git", "fetch", "--quiet", "--depth", "1", "origin", commit_sha], cwd=clone_path, env=_git_env())
    _run(
        [
            "git",
            "-c",
            "filter.lfs.process=",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            "checkout",
            "--quiet",
            "--force",
            "--detach",
            commit_sha,
        ],
        cwd=clone_path,
        env=_git_env(),
    )
    return clone_path


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    return env


def _scan_path(scan_path: Path, report_path: Path) -> dict[str, Any]:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    src = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    _run(
        [
            sys.executable,
            "-m",
            "lurkr.cli",
            "scan",
            "--path",
            str(scan_path),
            "--output",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        env=env,
    )
    return json.loads(report_path.read_text(encoding="utf-8"))


def _gitleaks_info() -> dict[str, Any]:
    executable = shutil.which("gitleaks")
    if executable is None:
        return {"available": False, "executable": None, "version": None}
    version = _run([executable, "version"], check=False)
    return {
        "available": True,
        "executable": executable,
        "version": version.stdout.strip() if version.returncode == 0 else None,
    }


def _run_gitleaks(
    entry: dict[str, Any],
    source: Path,
    report_root: Path,
    gitleaks: dict[str, Any],
) -> dict[str, Any]:
    if not gitleaks["available"]:
        return {"available": False, "finding_count": None, "rule_counts": {}}
    report_path = report_root / f"{entry['id']}-gitleaks-report.json"
    completed = _run(
        [
            str(gitleaks["executable"]),
            "detect",
            "--no-git",
            "--source",
            str(source),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact",
            "--exit-code",
            "0",
        ],
        check=False,
    )
    if completed.returncode != 0:
        return {
            "available": True,
            "error": completed.stderr.strip() or completed.stdout.strip(),
            "finding_count": None,
            "rule_counts": {},
        }
    if not report_path.exists():
        return {"available": True, "finding_count": 0, "rule_counts": {}}
    try:
        findings = json.loads(report_path.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        return {"available": True, "error": "invalid JSON report", "finding_count": None, "rule_counts": {}}
    counts = Counter(str(item.get("RuleID") or item.get("Rule") or "unknown") for item in findings)
    return {
        "available": True,
        "finding_count": len(findings),
        "rule_counts": dict(sorted(counts.items())),
    }


def _finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {
            "rule_id": finding["rule_id"],
            "file": finding["file"],
            "line": finding.get("line"),
        }
        for finding in report.get("findings", [])
    ]
    return sorted(rows, key=lambda row: (row["rule_id"], row["file"], row["line"] or 0))


def _rule_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(finding["rule_id"] for finding in findings)
    return dict(sorted(counts.items()))


def _compare_expected(expected: dict[str, int], observed: dict[str, int]) -> dict[str, dict[str, int]]:
    comparison: dict[str, dict[str, int]] = {}
    for rule in sorted(set(expected) | set(observed)):
        exp = expected.get(rule, 0)
        obs = observed.get(rule, 0)
        comparison[rule] = {
            "expected": exp,
            "observed": obs,
            "true_positive": min(exp, obs),
            "false_negative": max(exp - obs, 0),
            "extra_observed": max(obs - exp, 0),
        }
    return comparison


def _aggregate_public(results: list[dict[str, Any]]) -> dict[str, Any]:
    rule_totals: Counter[str] = Counter()
    rule_repo_counts: Counter[str] = Counter()
    repos_with_findings = 0
    for result in results:
        if result["finding_count"] > 0:
            repos_with_findings += 1
        for rule, count in result["rule_counts"].items():
            rule_totals[rule] += count
            rule_repo_counts[rule] += 1
    total = len(results)
    return {
        "repo_count": total,
        "repos_with_findings": repos_with_findings,
        "repos_without_findings": total - repos_with_findings,
        "percent_with_findings": _percent(repos_with_findings, total),
        "total_findings": sum(rule_totals.values()),
        "average_findings_per_repo": round(sum(rule_totals.values()) / total, 2) if total else 0.0,
        "rule_totals": dict(sorted(rule_totals.items())),
        "rule_repo_counts": dict(sorted(rule_repo_counts.items())),
    }


def _aggregate_synthetic(results: list[dict[str, Any]]) -> dict[str, Any]:
    expected: Counter[str] = Counter()
    observed: Counter[str] = Counter()
    true_positive: Counter[str] = Counter()
    false_negative: Counter[str] = Counter()
    extra_observed: Counter[str] = Counter()
    clean_controls = 0
    clean_controls_with_findings = 0
    for result in results:
        if result["kind"] == "clean_control":
            clean_controls += 1
            if result["finding_count"] > 0:
                clean_controls_with_findings += 1
        for rule, values in result["comparison"].items():
            expected[rule] += values["expected"]
            observed[rule] += values["observed"]
            true_positive[rule] += values["true_positive"]
            false_negative[rule] += values["false_negative"]
            extra_observed[rule] += values["extra_observed"]
    per_rule: dict[str, dict[str, Any]] = {}
    for rule in sorted(set(expected) | set(observed)):
        per_rule[rule] = {
            "expected": expected[rule],
            "observed": observed[rule],
            "true_positive": true_positive[rule],
            "false_negative": false_negative[rule],
            "extra_observed": extra_observed[rule],
            "tp_rate": _percent(true_positive[rule], expected[rule]),
        }
    return {
        "entry_count": len(results),
        "adversarial_count": sum(1 for result in results if result["kind"] == "adversarial"),
        "clean_control_count": clean_controls,
        "clean_controls_with_findings": clean_controls_with_findings,
        "clean_control_fp_rate": _percent(clean_controls_with_findings, clean_controls),
        "per_rule": per_rule,
    }


def _aggregate_baseline(results: list[dict[str, Any]], gitleaks: dict[str, Any]) -> dict[str, Any]:
    if not gitleaks["available"]:
        return {
            "gitleaks_available": False,
            "note": "gitleaks executable was not available on this runner.",
        }
    repos_with_findings = sum(1 for result in results if (result["gitleaks"].get("finding_count") or 0) > 0)
    total_findings = sum(result["gitleaks"].get("finding_count") or 0 for result in results)
    return {
        "gitleaks_available": True,
        "repos_with_findings": repos_with_findings,
        "total_findings": total_findings,
        "rule_class_coverage": 1,
    }


def _percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 100, 1)


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


if __name__ == "__main__":
    raise SystemExit(main())
