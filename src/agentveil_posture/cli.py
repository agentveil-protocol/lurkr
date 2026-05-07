"""Command-line interface for AgentVeil Posture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from agentveil_posture.report import SEVERITIES, Finding, PostureReport
from agentveil_posture.scanner import ScanError, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentveil",
        description="AgentVeil developer tools.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    posture_parser = subparsers.add_parser(
        "posture",
        help="Run static posture checks.",
    )
    posture_subparsers = posture_parser.add_subparsers(
        dest="posture_command",
        required=True,
    )

    scan_parser = posture_subparsers.add_parser(
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
        required=True,
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
    scan_parser.set_defaults(handler=_handle_posture_scan)

    return parser


def _finding_meets_threshold(finding: Finding, threshold: str) -> bool:
    return SEVERITIES.index(finding.severity) <= SEVERITIES.index(threshold)


def _report_meets_threshold(report: PostureReport, threshold: str | None) -> bool:
    if threshold is None:
        return False
    return any(_finding_meets_threshold(finding, threshold) for finding in report.findings)


def _handle_posture_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_path(Path(args.path))
        if args.format == "json":
            output = report.to_json()
        else:
            output = json.dumps(report.to_sarif(), indent=2, sort_keys=True) + "\n"
        Path(args.output).write_text(output, encoding="utf-8")
        if _report_meets_threshold(report, args.fail_on):
            return 1
        return 0
    except (OSError, ScanError) as exc:
        print(f"agentveil posture scan: {exc}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("missing command")
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
