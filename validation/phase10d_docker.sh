#!/usr/bin/env bash
set -euo pipefail

IMAGE="lurkr:phase10d"
TMPDIR="$(mktemp -d)"
cleanup() {
  docker rmi "$IMAGE" > /dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

docker build -t "$IMAGE" . > /dev/null
mkdir -p "$TMPDIR/output-default" "$TMPDIR/output-override"
chmod 777 "$TMPDIR/output-default" "$TMPDIR/output-override"

docker run --rm --entrypoint id "$IMAGE" 2>&1 | grep -q "uid=1000" || {
  echo "FAIL: container default user is not UID 1000"
  exit 1
}

set +e
docker run --rm \
  -v "$PWD/fixtures/dangerous_github_project:/workspace:ro" \
  -v "$TMPDIR/output-default:/output" \
  "$IMAGE" \
  --output /output/report.json --fail-on high
default_scan_status=$?
set -e

if [ "$default_scan_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from Docker default-user --fail-on high"
  exit 1
fi

test "$(jq '.summary.total' "$TMPDIR/output-default/report.json")" = "5" || {
  echo "FAIL: expected 5 findings from Docker default-user scan"
  exit 1
}

echo "PASS: docker default user = UID 1000 (non-root)"

set +e
docker run --rm \
  -v "$PWD/fixtures/dangerous_github_project:/workspace:ro" \
  -v "$TMPDIR/output-override:/output" \
  -u "$(id -u):$(id -g)" \
  "$IMAGE" \
  --output /output/report.json --fail-on high
override_scan_status=$?
set -e

if [ "$override_scan_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from Docker --fail-on high"
  exit 1
fi

test "$(jq '.summary.total' "$TMPDIR/output-override/report.json")" = "5" || {
  echo "FAIL: expected 5 findings"
  exit 1
}

echo "PASS: docker build + scan"
