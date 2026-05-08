#!/usr/bin/env python3
"""Phase 10e installed-framework fixture validation."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = REPO_ROOT / "validation" / "fixtures" / "installed_frameworks"
DEFAULT_VENV_ROOT = Path(tempfile.gettempdir()) / "agentveil-posture-phase10e-venvs"


@dataclass(frozen=True)
class FindingKey:
    rule_id: str
    file: str
    line: int | None


@dataclass
class FixtureResult:
    framework: str
    expected: int
    observed: int
    extra: list[FindingKey]
    missing: list[FindingKey]
    passed: bool
    error: str = ""


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    fixture_dirs = discover_fixture_dirs(args.framework)
    if not fixture_dirs:
        print("No matching fixtures found.")
        return 1

    results: list[FixtureResult] = []
    for fixture_dir in fixture_dirs:
        result = run_fixture(
            fixture_dir,
            venv_root=args.venv_root,
            no_cache=args.no_cache,
            python_executable=args.python,
        )
        results.append(result)

    print("=== Phase 10e installed-framework fixtures ===")
    print("framework,expected,observed,extra,missing,status")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(
            f"{result.framework},{result.expected},{result.observed},"
            f"{len(result.extra)},{len(result.missing)},{status}"
        )
        if result.error:
            print(f"  error: {result.error}")
        for finding in result.extra:
            print(f"  extra: {format_key(finding)}")
        for finding in result.missing:
            print(f"  missing: {format_key(finding)}")
    print(f"\n=== Overall: {'PASS' if all(result.passed for result in results) else 'FAIL'} ===")
    return 0 if all(result.passed for result in results) else 1


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run installed-framework fixture validation.")
    parser.add_argument("--framework", help="Run one fixture by directory name.")
    parser.add_argument("--no-cache", action="store_true", help="Rebuild framework venvs.")
    parser.add_argument(
        "--venv-root",
        type=Path,
        default=DEFAULT_VENV_ROOT,
        help=f"Virtualenv cache root. Default: {DEFAULT_VENV_ROOT}",
    )
    parser.add_argument(
        "--python",
        default=default_python_executable(),
        help="Python executable used to create fixture virtualenvs.",
    )
    return parser.parse_args(argv)


def default_python_executable() -> str:
    return os.environ.get("PHASE10E_PYTHON") or shutil.which("python3.13") or sys.executable


def discover_fixture_dirs(framework: str | None = None) -> list[Path]:
    if framework:
        return [FIXTURES_ROOT / framework] if (FIXTURES_ROOT / framework).is_dir() else []
    return [
        path
        for path in sorted(FIXTURES_ROOT.iterdir())
        if path.is_dir() and (path / "expected_findings.json").exists()
    ]


def run_fixture(
    fixture_dir: Path,
    *,
    venv_root: Path = DEFAULT_VENV_ROOT,
    no_cache: bool = False,
    python_executable: str | None = None,
) -> FixtureResult:
    label = load_expected(fixture_dir)
    framework = str(label["framework"])
    expected = finding_set(label["expected_findings"])
    try:
        venv = ensure_venv(
            fixture_dir,
            venv_root=venv_root,
            no_cache=no_cache,
            python_executable=python_executable or default_python_executable(),
        )
        verify_imports(venv, [str(item) for item in label.get("import_checks", [])])
        observed = run_scan(fixture_dir, venv)
    except Exception as exc:  # noqa: BLE001
        return FixtureResult(
            framework=framework,
            expected=len(expected),
            observed=0,
            extra=[],
            missing=sorted(expected, key=sort_key),
            passed=False,
            error=str(exc),
        )

    extra, missing = compare_findings(expected, observed)
    return FixtureResult(
        framework=framework,
        expected=len(expected),
        observed=len(observed),
        extra=extra,
        missing=missing,
        passed=not extra and not missing,
    )


def load_expected(fixture_dir: Path) -> dict[str, object]:
    return json.loads((fixture_dir / "expected_findings.json").read_text(encoding="utf-8"))


def ensure_venv(
    fixture_dir: Path,
    *,
    venv_root: Path,
    no_cache: bool,
    python_executable: str,
) -> Path:
    requirements = fixture_dir / "requirements.txt"
    digest = requirements_hash(requirements)
    venv = venv_root / f"{fixture_dir.name}-{digest[:12]}"
    marker = venv / ".phase10e-ready"
    if no_cache and venv.exists():
        shutil.rmtree(venv)
    if marker.exists():
        return venv

    venv_root.mkdir(parents=True, exist_ok=True)
    if venv.exists():
        shutil.rmtree(venv)
    run_command([python_executable, "-m", "venv", str(venv)])
    run_command([str(venv_python(venv)), "-m", "pip", "install", "--quiet", "-r", str(requirements)])
    run_command([str(venv_python(venv)), "-m", "pip", "install", "--quiet", "-e", str(REPO_ROOT)])
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(digest, encoding="utf-8")
    return venv


def requirements_hash(requirements: Path) -> str:
    payload = requirements.read_bytes()
    return hashlib.sha256(payload).hexdigest()


def venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def venv_agentveil(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "agentveil.exe"
    return venv / "bin" / "agentveil"


def verify_imports(venv: Path, module_names: list[str]) -> None:
    if not module_names:
        return
    script = (
        "import importlib.util, sys; "
        "missing=[name for name in sys.argv[1:] if importlib.util.find_spec(name) is None]; "
        "raise SystemExit('missing import specs: ' + ', '.join(missing) if missing else 0)"
    )
    run_command([str(venv_python(venv)), "-c", script, *module_names])


def run_scan(fixture_dir: Path, venv: Path) -> set[FindingKey]:
    report_path = Path(tempfile.gettempdir()) / f"agentveil-posture-phase10e-{fixture_dir.name}.json"
    run_command(
        [
            str(venv_agentveil(venv)),
            "posture",
            "scan",
            "--path",
            str(fixture_dir),
            "--output",
            str(report_path),
        ]
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    return finding_set(payload["findings"])


def finding_set(findings: object) -> set[FindingKey]:
    keys: set[FindingKey] = set()
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("finding entries must be objects")
        keys.add(
            FindingKey(
                rule_id=str(finding["rule_id"]),
                file=str(finding["file"]),
                line=finding.get("line"),
            )
        )
    return keys


def compare_findings(
    expected: set[FindingKey],
    observed: set[FindingKey],
) -> tuple[list[FindingKey], list[FindingKey]]:
    extra = sorted(observed - expected, key=sort_key)
    missing = sorted(expected - observed, key=sort_key)
    return extra, missing


def sort_key(finding: FindingKey) -> tuple[str, str, int]:
    return (finding.rule_id, finding.file, finding.line if finding.line is not None else -1)


def format_key(finding: FindingKey) -> str:
    return f"{finding.rule_id},{finding.file},{finding.line}"


def run_command(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        output = "\n".join(part for part in [exc.stdout, exc.stderr] if part)
        tail = "\n".join(output.splitlines()[-20:])
        raise RuntimeError(f"command failed ({exc.returncode}): {' '.join(command)}\n{tail}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
