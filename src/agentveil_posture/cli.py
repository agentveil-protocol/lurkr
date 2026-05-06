"""Command-line interface for AgentVeil Posture."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from agentveil_posture.scanner import scan_path


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
        help="Scan a project and write a JSON posture report.",
    )
    scan_parser.add_argument(
        "--path",
        default=".",
        help="Project path to scan. Defaults to the current directory.",
    )
    scan_parser.add_argument(
        "--output",
        required=True,
        help="Path where the JSON report will be written.",
    )
    scan_parser.set_defaults(handler=_handle_posture_scan)

    return parser


def _handle_posture_scan(args: argparse.Namespace) -> int:
    report = scan_path(Path(args.path))
    Path(args.output).write_text(report.to_json(), encoding="utf-8")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("missing command")
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())

