#!/usr/bin/env bash
set -euo pipefail

IMAGE="agentveil-posture:phase10d"
TMPDIR="$(mktemp -d)"
cleanup() {
  docker rmi "$IMAGE" > /dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

docker build -t "$IMAGE" . > /dev/null
mkdir -p "$TMPDIR/output"

set +e
docker run --rm \
  -v "$PWD/fixtures/dangerous_github_project:/workspace:ro" \
  -v "$TMPDIR/output:/output" \
  -u "$(id -u):$(id -g)" \
  "$IMAGE" \
  --output /output/report.json --fail-on high
scan_status=$?
set -e

if [ "$scan_status" -ne 1 ]; then
  echo "FAIL: expected exit 1 from Docker --fail-on high"
  exit 1
fi

test "$(jq '.summary.total' "$TMPDIR/output/report.json")" = "5" || {
  echo "FAIL: expected 5 findings"
  exit 1
}

echo "PASS: docker build + scan"
