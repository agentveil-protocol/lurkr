#!/usr/bin/env bash
set -euo pipefail

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

python3 -m venv "$TMPDIR/venv"
"$TMPDIR/venv/bin/pip" install --quiet -e .
"$TMPDIR/venv/bin/lurkr" --help > "$TMPDIR/help.txt"

set +e
"$TMPDIR/venv/bin/lurkr" scan \
  --path fixtures/dangerous_github_project \
  --output "$TMPDIR/report.json" \
  --fail-on high
fail_on_status=$?
set -e

if [ "$fail_on_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from --fail-on high"
  exit 1
fi

"$TMPDIR/venv/bin/lurkr" scan \
  --path fixtures/dangerous_github_project \
  --output "$TMPDIR/report.json"

test "$(jq '.summary.total' "$TMPDIR/report.json")" = "5" || {
  echo "FAIL: expected 5 findings"
  exit 1
}

echo "PASS: local fresh venv install + scan"
