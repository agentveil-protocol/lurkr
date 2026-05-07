#!/usr/bin/env bash
set -euo pipefail

DIST_DIR="${DIST_DIR:-/tmp/agentveil-posture-v0.2.0-release-dist}"
PYTHON_BIN="${PYTHON:-python3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

rm -rf "$DIST_DIR"
(
  cd "$(mktemp -d)"
  "$PYTHON_BIN" -m build --sdist --wheel --outdir "$DIST_DIR" "$REPO_ROOT"
)
twine check "$DIST_DIR"/*

"$PYTHON_BIN" - "$DIST_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path

for path in sorted(Path(sys.argv[1]).iterdir()):
    if path.suffix in {".whl", ".gz"}:
        print(f"{path.name} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")
PY

"$PYTHON_BIN" -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/pip" install --quiet "$DIST_DIR"/*.whl

set +e
"$TMPDIR/venv/bin/agentveil" posture scan \
  --path "$REPO_ROOT/fixtures/dangerous_github_project" \
  --output "$TMPDIR/report.json" \
  --fail-on high
json_status=$?
set -e

if [ "$json_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from JSON --fail-on high"
  exit 1
fi

"$TMPDIR/venv/bin/python" - "$TMPDIR/report.json" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["summary"]["total"] != 5:
    raise SystemExit("FAIL: expected 5 findings")
PY

set +e
"$TMPDIR/venv/bin/agentveil" posture scan \
  --path "$REPO_ROOT/fixtures/dangerous_github_project" \
  --output "$TMPDIR/report.sarif" \
  --format sarif \
  --fail-on high
sarif_status=$?
set -e

if [ "$sarif_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from SARIF --fail-on high"
  exit 1
fi

"$TMPDIR/venv/bin/python" - "$TMPDIR/report.sarif" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report["version"] != "2.1.0":
    raise SystemExit("FAIL: expected SARIF version 2.1.0")
PY

echo "PASS: release dry-run smoke"
