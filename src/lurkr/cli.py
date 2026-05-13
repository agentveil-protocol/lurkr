"""Command-line interface for Lurkr."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from lurkr.baseline import filter_findings_by_baseline, load_baseline, save_baseline
from lurkr.report import SEVERITIES, Finding, PostureReport, build_report
from lurkr.scanner import ScanError, scan_path


DEFAULT_BASELINE_PATH = ".lurkr-baseline.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lurkr",
        description="Find risky AI agent capabilities before deployment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a project and write a posture report.",
    )
    scan_parser.add_argument(
        "--path",
        default=".",
        help="Project path to scan. Defaults to the current directory.",
    )
    scan_parser.add_argument(
        "--output",
        default=None,
        help="Path where the report will be written.",
    )
    scan_parser.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Report format to write. Defaults to json.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        help="Exit 1 when findings at or above this severity are present.",
    )
    scan_parser.add_argument(
        "--baseline",
        nargs="?",
        const=DEFAULT_BASELINE_PATH,
        default=None,
        metavar="PATH",
        help=(
            "Read a baseline file and report only findings not already present. "
            f"If PATH is omitted, uses {DEFAULT_BASELINE_PATH} under --path."
        ),
    )
    scan_parser.add_argument(
        "--save-baseline",
        default=None,
        metavar="PATH",
        help="Save current finding fingerprints to a baseline file.",
    )
    scan_parser.set_defaults(handler=_handle_scan)

    return parser


def _finding_meets_threshold(finding: Finding, threshold: str) -> bool:
    return SEVERITIES.index(finding.severity) <= SEVERITIES.index(threshold)


def _report_meets_threshold(report: PostureReport, threshold: str | None) -> bool:
    if threshold is None:
        return False
    return any(_finding_meets_threshold(finding, threshold) for finding in report.findings)


def _handle_scan(args: argparse.Namespace) -> int:
    if args.baseline is not None and args.save_baseline is not None:
        print("lurkr scan: Cannot use --baseline and --save-baseline together", file=sys.stderr)
        return 2
    if args.output is None and args.baseline is None and args.save_baseline is None:
        print(
            "lurkr scan: --output is required unless --baseline or --save-baseline is used",
            file=sys.stderr,
        )
        return 2

    try:
        report = scan_path(Path(args.path))
        if args.save_baseline is not None:
            baseline_path = _resolve_baseline_path(args.save_baseline, Path(args.path))
            save_baseline(baseline_path, report.findings)
            print(f"Saved {len(report.findings)} fingerprints to {baseline_path}")
        if args.baseline is not None:
            baseline_path = _resolve_baseline_path(args.baseline, Path(args.path))
            try:
                baseline = load_baseline(baseline_path)
            except FileNotFoundError:
                print(f"lurkr scan: Baseline file not found: {baseline_path}", file=sys.stderr)
                return 2
            except ValueError as exc:
                print(f"lurkr scan: Baseline file is malformed: {exc}", file=sys.stderr)
                return 2
            filtered_findings, suppressed_count = filter_findings_by_baseline(
                report.findings, baseline
            )
            report = build_report(report.scanned_path, list(filtered_findings))
            print(
                f"Baseline applied: {len(report.findings)} new findings "
                f"({suppressed_count} suppressed)"
            )
        if args.format == "json":
            output = report.to_json()
        else:
            output = json.dumps(report.to_sarif(), indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            Path(args.output).write_text(output, encoding="utf-8")
        if _report_meets_threshold(report, args.fail_on):
            return 1
        return 0
    except (OSError, ScanError) as exc:
        print(f"lurkr scan: {exc}", file=sys.stderr)
        return 1


def _resolve_baseline_path(raw_path: str, scan_path: Path) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return scan_path / path


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("missing command")
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
