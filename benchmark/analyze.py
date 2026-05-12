#!/usr/bin/env python3
"""Render a Markdown summary from benchmark/results.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO_ROOT / "benchmark" / "results.json"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    data = json.loads(args.results.read_text(encoding="utf-8"))
    print(render_markdown(data))
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    return parser.parse_args(argv)


def render_markdown(data: dict[str, Any]) -> str:
    public = data["aggregate"]["public_references"]
    synthetic = data["aggregate"]["synthetic"]
    baseline = data["aggregate"]["baseline"]
    lines: list[str] = []
    lines.append("# Lurkr Benchmark Summary")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(
        f"- Tier 1 public references: {public['repos_with_findings']} of "
        f"{public['repo_count']} repos ({public['percent_with_findings']}%) "
        "had at least one Lurkr finding."
    )
    lines.append(
        f"- Tier 1 total findings: {public['total_findings']} "
        f"(average {public['average_findings_per_repo']} per repo)."
    )
    lines.append(
        f"- Tier 2 synthetic adversarial controls: {synthetic['adversarial_count']} "
        f"known-positive fixtures, {synthetic['clean_control_count']} clean controls."
    )
    lines.append(
        f"- Tier 2 clean-control FP rate: {synthetic['clean_control_fp_rate']}% "
        f"({synthetic['clean_controls_with_findings']} of {synthetic['clean_control_count']})."
    )
    lines.append("")
    lines.append("## Tier 1 Per-Rule Fire Rate")
    lines.append("")
    lines.append("| Rule | Repos with finding | Findings |")
    lines.append("|---|---:|---:|")
    for rule in sorted(public["rule_totals"]):
        lines.append(
            f"| `{rule}` | {public['rule_repo_counts'].get(rule, 0)} | "
            f"{public['rule_totals'][rule]} |"
        )
    if not public["rule_totals"]:
        lines.append("| None | 0 | 0 |")
    lines.append("")
    lines.append("## Tier 2 Expected-Vs-Observed")
    lines.append("")
    lines.append("| Rule | Expected | Observed | TP rate | Extra observed |")
    lines.append("|---|---:|---:|---:|---:|")
    for rule, stats in sorted(synthetic["per_rule"].items()):
        lines.append(
            f"| `{rule}` | {stats['expected']} | {stats['observed']} | "
            f"{stats['tp_rate']}% | {stats['extra_observed']} |"
        )
    lines.append("")
    lines.append("## Public Corpus")
    lines.append("")
    lines.append("| Repo | Category | SHA | Findings |")
    lines.append("|---|---|---|---:|")
    for result in data["public_references"]:
        lines.append(
            f"| `{result['repo']}` | {result['category']} | "
            f"`{result['commit_sha'][:12]}` | {result['finding_count']} |"
        )
    lines.append("")
    lines.append("## Baseline")
    lines.append("")
    if baseline.get("gitleaks_available"):
        lines.append(
            f"- gitleaks was available and found {baseline['total_findings']} findings "
            f"across {baseline['repos_with_findings']} public-reference repos."
        )
        lines.append("- gitleaks baseline class coverage: 1 generic secret-scanning class.")
    else:
        lines.append("- gitleaks was not available on this runner; baseline comparison was skipped.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
