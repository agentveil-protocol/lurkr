#!/usr/bin/env python3
"""Labeled validation harness for Lurkr rules."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from lurkr.report import RULE_DESCRIPTORS  # noqa: E402
from lurkr.scanner import ScanError, scan_path  # noqa: E402


DEFAULT_PRECISION = 0.85
DEFAULT_RECALL = 0.80
DEFAULT_WORKDIR = Path(os.environ.get("AGENTVEIL_POSTURE_VALIDATION_WORKDIR", "/tmp/agentveil-posture-validation"))
WORKTREE_COMMIT = "WORKTREE"


@dataclass(frozen=True, order=True)
class FindingKey:
    rule_id: str
    file: str
    line: int | None

    @classmethod
    def from_mapping(cls, data: dict[str, object]) -> "FindingKey":
        return cls(
            rule_id=str(data["rule_id"]),
            file=str(data["file"]).replace("\\", "/"),
            line=data.get("line") if isinstance(data.get("line"), int) else None,
        )


@dataclass
class RuleStats:
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        total_observed = self.true_positive + self.false_positive
        if total_observed == 0:
            return 1.0
        return self.true_positive / total_observed

    @property
    def recall(self) -> float:
        total_expected = self.true_positive + self.false_negative
        if total_expected == 0:
            return 1.0
        return self.true_positive / total_expected


@dataclass
class ValidationResult:
    stats: dict[str, RuleStats]
    failures: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 1 if self.failures else 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    label_paths = _label_paths(args.labels)
    result = run_validation(
        label_paths,
        workdir=args.workdir,
        precision_threshold=args.precision,
        recall_threshold=args.recall,
        require_all_rules=True,
        repo_root=REPO_ROOT,
    )
    print(_format_result(result))
    return result.exit_code


def run_validation(
    label_paths: Iterable[Path],
    *,
    workdir: Path = DEFAULT_WORKDIR,
    precision_threshold: float = DEFAULT_PRECISION,
    recall_threshold: float = DEFAULT_RECALL,
    require_all_rules: bool = True,
    repo_root: Path = REPO_ROOT,
) -> ValidationResult:
    active_rules = set(RULE_DESCRIPTORS)
    stats = {rule_id: RuleStats() for rule_id in sorted(active_rules)}
    failures: list[str] = []
    positive_coverage: set[str] = set()

    for label_path in sorted(label_paths):
        label = _load_label(label_path)
        expected = {FindingKey.from_mapping(item) for item in label["expected_findings"]}
        positive_coverage.update(finding.rule_id for finding in expected)
        forbidden_rules = set(label.get("rules_that_should_not_fire_in_this_repo", []))
        checkout = _resolve_checkout(label, workdir=workdir, repo_root=repo_root)
        scan_root = checkout / str(label["scan_path"])
        observed = _scan_findings(scan_root, label_path, failures)

        forbidden_observed = sorted(finding for finding in observed if finding.rule_id in forbidden_rules)
        for finding in forbidden_observed:
            failures.append(
                f"{label_path.name}: forbidden rule fired: "
                f"{finding.rule_id} {finding.file}:{finding.line}"
            )

        for rule_id in active_rules:
            expected_for_rule = {finding for finding in expected if finding.rule_id == rule_id}
            observed_for_rule = {finding for finding in observed if finding.rule_id == rule_id}
            stats[rule_id].true_positive += len(expected_for_rule & observed_for_rule)
            stats[rule_id].false_positive += len(observed_for_rule - expected_for_rule)
            stats[rule_id].false_negative += len(expected_for_rule - observed_for_rule)

    if require_all_rules:
        missing_coverage = sorted(active_rules - positive_coverage)
        if missing_coverage:
            failures.append("missing positive label coverage: " + ", ".join(missing_coverage))

    for rule_id, rule_stats in stats.items():
        if rule_stats.precision < precision_threshold:
            failures.append(
                f"{rule_id}: precision {rule_stats.precision:.2f} "
                f"is below {precision_threshold:.2f}"
            )
        if rule_stats.recall < recall_threshold:
            failures.append(
                f"{rule_id}: recall {rule_stats.recall:.2f} "
                f"is below {recall_threshold:.2f}"
            )

    return ValidationResult(stats=stats, failures=failures)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run labeled Lurkr validation.")
    parser.add_argument(
        "--labels",
        type=Path,
        default=REPO_ROOT / "validation" / "labels",
        help="Label file or directory. Defaults to validation/labels.",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=DEFAULT_WORKDIR,
        help="Directory for public repository checkouts.",
    )
    parser.add_argument(
        "--precision",
        type=float,
        default=DEFAULT_PRECISION,
        help="Minimum per-rule precision threshold.",
    )
    parser.add_argument(
        "--recall",
        type=float,
        default=DEFAULT_RECALL,
        help="Minimum per-rule recall threshold.",
    )
    return parser.parse_args(argv)


def _label_paths(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(path.glob("*.json"))


def _load_label(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    required = {"repo", "commit", "scan_path", "expected_findings"}
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"{path} missing required fields: {', '.join(missing)}")
    for finding in data["expected_findings"]:
        FindingKey.from_mapping(finding)
    return data


def _resolve_checkout(label: dict[str, object], *, workdir: Path, repo_root: Path) -> Path:
    checkout_env = label.get("checkout_env")
    if isinstance(checkout_env, str) and os.environ.get(checkout_env):
        checkout = Path(os.environ[checkout_env]).expanduser().resolve()
    elif label.get("checkout_path") is not None:
        checkout = Path(str(label["checkout_path"])).expanduser()
        if not checkout.is_absolute():
            checkout = repo_root / checkout
        checkout = checkout.resolve()
    else:
        checkout = _ensure_public_checkout(label, workdir)

    if not checkout.exists():
        raise FileNotFoundError(f"checkout does not exist: {checkout}")
    _verify_commit(checkout, str(label["commit"]))
    return checkout


def _ensure_public_checkout(label: dict[str, object], workdir: Path) -> Path:
    repo = str(label["repo"])
    checkout = workdir / repo.replace("/", "__")
    clone_url = str(label.get("clone_url") or f"https://github.com/{repo}.git")
    commit = str(label["commit"])
    workdir.mkdir(parents=True, exist_ok=True)
    if not (checkout / ".git").exists():
        subprocess.run(["git", "clone", "--quiet", clone_url, str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "fetch", "--quiet", "origin", commit], check=False)
    subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", commit], check=True)
    return checkout


def _verify_commit(checkout: Path, expected: str) -> None:
    if expected == WORKTREE_COMMIT:
        return
    actual = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual != expected:
        raise ValueError(f"{checkout} is at {actual}, expected {expected}")


def _scan_findings(scan_root: Path, label_path: Path, failures: list[str]) -> set[FindingKey]:
    try:
        report = scan_path(scan_root)
    except (OSError, ScanError) as exc:
        failures.append(f"{label_path.name}: scan failed: {exc}")
        return set()
    return {
        FindingKey(rule_id=finding.rule_id, file=finding.file, line=finding.line)
        for finding in report.findings
    }


def _format_result(result: ValidationResult) -> str:
    lines = [
        "rule_id,tp,fp,fn,precision,recall",
    ]
    for rule_id, stats in result.stats.items():
        lines.append(
            f"{rule_id},{stats.true_positive},{stats.false_positive},"
            f"{stats.false_negative},{stats.precision:.2f},{stats.recall:.2f}"
        )
    if result.failures:
        lines.append("")
        lines.append("FAILURES")
        lines.extend(f"- {failure}" for failure in result.failures)
    else:
        lines.append("")
        lines.append("validation passed")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
